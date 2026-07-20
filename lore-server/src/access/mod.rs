// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Per-repository access control backed by the server's own stores.
//!
//! [`AccessControl`] resolves a caller's role (`read`/`write`/`admin`) for a
//! repository from grants persisted via [`lore_revision::access`], plus a
//! server-administrator set (bootstrapped from configuration, extendable at
//! runtime through global grants). Access is deny-by-default: an
//! authenticated user with no grant cannot see a repository at all.
//!
//! The instance is installed process-globally at startup (mirroring the
//! client-side authentication registry) so the repository handlers and the
//! auth service consult it without threading it through every call chain.
//! When no instance is installed the server behaves as before: external
//! auth-service delegation when an `auth_url` is configured, open otherwise.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::Instant;

use lore_revision::access::AccessGrants;
pub use lore_revision::access::AccessRole;
use lore_revision::lore::RepositoryId;
use parking_lot::Mutex;
use thiserror::Error;
use tokio_stream::StreamExt;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::JwtVerifier;

/// How long grant reads may be served from cache. Bounded well below the
/// client's 60-second token re-exchange cadence.
const CACHE_TTL: Duration = Duration::from_secs(5);

static INSTALLED: OnceLock<Arc<AccessControl>> = OnceLock::new();

/// Install the process-global access control. Called once at server startup
/// when server-local auth is enabled.
pub fn install(access: Arc<AccessControl>) {
    if INSTALLED.set(access).is_err() {
        warn!("Access control was already installed; ignoring duplicate");
    }
}

/// The installed access control, when server-local auth is enabled.
pub fn installed() -> Option<Arc<AccessControl>> {
    INSTALLED.get().cloned()
}

#[derive(Debug, Error)]
pub enum AccessError {
    #[error("Access store operation failed: {0}")]
    Store(String),
}

/// The identities a caller may be granted under: the canonical user id
/// (`<idp>:<subject>`) plus the email alias admins may have typed.
#[derive(Debug, Clone)]
pub struct Principals(Vec<String>);

impl Principals {
    pub fn from_claims(claims: &AuthorizationToken) -> Self {
        let mut principals = vec![claims.user_id.clone()];
        if !claims.preferred_username.is_empty() && claims.preferred_username != claims.user_id {
            principals.push(claims.preferred_username.clone());
        }
        Self(principals)
    }

    fn matches(&self, grants: &AccessGrants) -> Option<AccessRole> {
        self.0
            .iter()
            .filter_map(|principal| grants.get(principal))
            .copied()
            .max()
    }
}

struct CacheEntry {
    grants: AccessGrants,
    fetched: Instant,
}

pub struct AccessControl {
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    /// Verifier for resolving raw bearer headers into claims where request
    /// extensions are not available.
    verifier: JwtVerifier,
    /// Configuration-supplied administrators, unioned with runtime global
    /// grants.
    bootstrap_admins: Vec<String>,
    cache: Mutex<HashMap<RepositoryId, CacheEntry>>,
}

impl AccessControl {
    pub fn new(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        verifier: JwtVerifier,
        bootstrap_admins: Vec<String>,
    ) -> Self {
        Self {
            immutable_store,
            mutable_store,
            verifier,
            bootstrap_admins,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// The storage layer requires a `LORE_CONTEXT`; gRPC entry points that
    /// are not otherwise scoped (the auth service) rely on this wrapper.
    async fn scoped<T>(future: impl Future<Output = T>) -> T {
        let execution =
            crate::util::setup_execution(module_path!(), String::default(), String::default());
        lore_base::runtime::LORE_CONTEXT
            .scope(execution, future)
            .await
    }

    fn context(
        &self,
        repository: RepositoryId,
    ) -> Arc<lore_revision::repository::RepositoryContext> {
        lore_revision::access::server_context(
            self.immutable_store.clone(),
            self.mutable_store.clone(),
            repository,
        )
    }

    /// Resolve claims from a raw `authorization` header value.
    pub async fn claims_from_header(
        &self,
        authorization: Option<&str>,
    ) -> Result<AuthorizationToken, tonic::Status> {
        let header =
            authorization.ok_or_else(|| tonic::Status::unauthenticated("missing bearer token"))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| tonic::Status::unauthenticated("malformed authorization header"))?;
        self.verifier
            .verify_token(token)
            .await
            .map_err(|e| tonic::Status::unauthenticated(format!("invalid token: {e}")))
    }

    /// The grant set for a repository, served from a short-lived cache.
    pub async fn grants(&self, repository: RepositoryId) -> Result<AccessGrants, AccessError> {
        if let Some(entry) = self.cache.lock().get(&repository)
            && entry.fetched.elapsed() < CACHE_TTL
        {
            return Ok(entry.grants.clone());
        }

        let grants = Self::scoped(lore_revision::access::load_grants(self.context(repository)))
            .await
            .map_err(|e| AccessError::Store(e.to_string()))?;
        self.cache.lock().insert(
            repository,
            CacheEntry {
                grants: grants.clone(),
                fetched: Instant::now(),
            },
        );
        Ok(grants)
    }

    fn invalidate(&self, repository: RepositoryId) {
        self.cache.lock().remove(&repository);
    }

    /// Whether any of the principals is a server administrator
    /// (configuration bootstrap list or runtime global grant).
    pub async fn is_server_admin(&self, principals: &Principals) -> Result<bool, AccessError> {
        if principals
            .0
            .iter()
            .any(|principal| self.bootstrap_admins.contains(principal))
        {
            return Ok(true);
        }
        let global = self.grants(RepositoryId::default()).await?;
        Ok(matches!(
            principals.matches(&global),
            Some(AccessRole::Admin)
        ))
    }

    /// The caller's effective role on a repository: the strongest matching
    /// grant, or `Admin` everywhere for server administrators.
    pub async fn role_for(
        &self,
        principals: &Principals,
        repository: RepositoryId,
    ) -> Result<Option<AccessRole>, AccessError> {
        if self.is_server_admin(principals).await? {
            return Ok(Some(AccessRole::Admin));
        }
        Ok(principals.matches(&self.grants(repository).await?))
    }

    pub async fn grant(
        &self,
        repository: RepositoryId,
        principal: &str,
        role: AccessRole,
    ) -> Result<(), AccessError> {
        let principal = principal.to_string();
        Self::scoped(lore_revision::access::modify_grants(
            self.context(repository),
            move |grants| {
                grants.insert(principal.clone(), role);
            },
        ))
        .await
        .map_err(|e| AccessError::Store(e.to_string()))?;
        self.invalidate(repository);
        info!(%repository, role = role.as_str(), "Access granted");
        Ok(())
    }

    /// Returns whether a grant existed.
    pub async fn revoke(
        &self,
        repository: RepositoryId,
        principal: &str,
    ) -> Result<bool, AccessError> {
        let principal = principal.to_string();
        let existed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = existed.clone();
        Self::scoped(lore_revision::access::modify_grants(
            self.context(repository),
            move |grants| {
                flag.store(
                    grants.remove(&principal).is_some(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            },
        ))
        .await
        .map_err(|e| AccessError::Store(e.to_string()))?;
        self.invalidate(repository);
        info!(%repository, "Access revoked");
        Ok(existed.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Record the creator's automatic `admin` grant on a new repository.
    pub async fn on_repository_created(
        &self,
        repository: RepositoryId,
        creator: &str,
    ) -> Result<(), AccessError> {
        self.grant(repository, creator, AccessRole::Admin).await
    }

    /// Remove all grants when a repository is deleted.
    pub async fn on_repository_deleted(&self, repository: RepositoryId) -> Result<(), AccessError> {
        Self::scoped(lore_revision::access::clear_grants(
            self.context(repository),
        ))
        .await
        .map_err(|e| AccessError::Store(e.to_string()))?;
        self.invalidate(repository);
        Ok(())
    }

    /// Repositories visible to the caller: all for server admins, granted
    /// ones otherwise. Iterates the repository list; acceptable at the
    /// 60-second exchange cadence with the grant cache in front.
    pub async fn authorized_repositories(
        &self,
        principals: &Principals,
    ) -> Result<Vec<RepositoryId>, AccessError> {
        let context = self.context(RepositoryId::default());
        let mut all = Self::scoped(lore_revision::repository::list_local(context))
            .await
            .map_err(|e| AccessError::Store(e.to_string()))?;

        let admin = self.is_server_admin(principals).await?;
        let mut visible = Vec::new();
        while let Some(id) = Self::scoped(all.next()).await {
            let id: RepositoryId = id.into();
            if admin || principals.matches(&self.grants(id).await?).is_some() {
                visible.push(id);
            }
        }
        Ok(visible)
    }

    /// Authorization check used by repository query/get: any role grants
    /// visibility.
    pub async fn check_visibility(
        &self,
        authorization: Option<&str>,
        repository: RepositoryId,
    ) -> Result<(), tonic::Status> {
        let claims = self.claims_from_header(authorization).await?;
        let principals = Principals::from_claims(&claims);
        match self.role_for(&principals, repository).await {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(tonic::Status::permission_denied(
                "Not authorized for this repository",
            )),
            Err(e) => Err(tonic::Status::internal(format!("Access check failed: {e}"))),
        }
    }

    /// Authorization check requiring the `admin` role (repository deletion,
    /// grant management).
    pub async fn check_admin(
        &self,
        authorization: Option<&str>,
        repository: RepositoryId,
    ) -> Result<AuthorizationToken, tonic::Status> {
        let claims = self.claims_from_header(authorization).await?;
        let principals = Principals::from_claims(&claims);
        match self.role_for(&principals, repository).await {
            Ok(Some(AccessRole::Admin)) => Ok(claims),
            Ok(_) => Err(tonic::Status::permission_denied(
                "Repository administrator role required",
            )),
            Err(e) => Err(tonic::Status::internal(format!("Access check failed: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::store::test_store_create;

    async fn access_with_admins(
        admins: Vec<String>,
    ) -> (
        AccessControl,
        Arc<lore_revision::interface::ExecutionContext>,
    ) {
        let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
        // Verifier is unused by the store-level tests; any instance works.
        let verifier = JwtVerifier {
            jwk_service: Arc::new(crate::auth::jwk::JwkServiceImpl::default()),
            jwt_issuer: None,
            jwt_audience: None,
        };
        (
            AccessControl::new(immutable, mutable, verifier, admins),
            execution,
        )
    }

    fn repo(hex: &str) -> RepositoryId {
        RepositoryId::from_str(hex).expect("repo id")
    }

    fn principals(user_id: &str, email: &str) -> Principals {
        Principals::from_claims(&claims(user_id, email))
    }

    #[tokio::test]
    async fn deny_by_default_then_grant_then_revoke() {
        let (access, execution) = access_with_admins(vec![]).await;
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project = repo("0194b726b34e72b0b45550b88a967076");
                let alice = principals("static:alice", "alice@example.com");

                assert_eq!(access.role_for(&alice, project).await.expect("role"), None);

                access
                    .grant(project, "static:alice", AccessRole::Write)
                    .await
                    .expect("grant");
                assert_eq!(
                    access.role_for(&alice, project).await.expect("role"),
                    Some(AccessRole::Write)
                );

                // Upgrading the grant replaces it.
                access
                    .grant(project, "static:alice", AccessRole::Admin)
                    .await
                    .expect("regrant");
                assert_eq!(
                    access.role_for(&alice, project).await.expect("role"),
                    Some(AccessRole::Admin)
                );

                assert!(
                    access
                        .revoke(project, "static:alice")
                        .await
                        .expect("revoke")
                );
                assert_eq!(access.role_for(&alice, project).await.expect("role"), None);
                // Revoking again reports no grant existed.
                assert!(
                    !access
                        .revoke(project, "static:alice")
                        .await
                        .expect("revoke")
                );
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn grants_are_scoped_per_repository() {
        let (access, execution) = access_with_admins(vec![]).await;
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project1 = repo("0194b726b34e72b0b45550b88a967076");
                let project2 = repo("f6ca55437aa34198ba0f0fdc33154d51");
                let ben = principals("google:ben", "ben@example.com");

                access
                    .grant(project1, "google:ben", AccessRole::Read)
                    .await
                    .expect("grant");

                assert_eq!(
                    access.role_for(&ben, project1).await.expect("role"),
                    Some(AccessRole::Read)
                );
                // ben can see project1 but not project2 unless somebody adds him.
                assert_eq!(access.role_for(&ben, project2).await.expect("role"), None);
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn email_alias_grants_match() {
        let (access, execution) = access_with_admins(vec![]).await;
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project = repo("0194b726b34e72b0b45550b88a967076");

                access
                    .grant(project, "ben@example.com", AccessRole::Write)
                    .await
                    .expect("grant");
                let ben = principals("google:ben-subject", "ben@example.com");
                assert_eq!(
                    access.role_for(&ben, project).await.expect("role"),
                    Some(AccessRole::Write)
                );
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn server_admins_hold_admin_everywhere() {
        let (access, execution) = access_with_admins(vec!["ben@example.com".to_string()]).await;
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project = repo("0194b726b34e72b0b45550b88a967076");
                let ben = principals("google:ben", "ben@example.com");
                let carol = principals("google:carol", "carol@example.com");

                assert!(access.is_server_admin(&ben).await.expect("admin"));
                assert!(!access.is_server_admin(&carol).await.expect("admin"));
                assert_eq!(
                    access.role_for(&ben, project).await.expect("role"),
                    Some(AccessRole::Admin)
                );

                // Runtime global grant also confers server admin.
                access
                    .grant(RepositoryId::default(), "google:carol", AccessRole::Admin)
                    .await
                    .expect("grant");
                assert!(access.is_server_admin(&carol).await.expect("admin"));
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn creator_auto_grant_and_deletion_cleanup() {
        let (access, execution) = access_with_admins(vec![]).await;
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project = repo("0194b726b34e72b0b45550b88a967076");
                let alice = principals("static:alice", "alice@example.com");

                access
                    .on_repository_created(project, "static:alice")
                    .await
                    .expect("created");
                assert_eq!(
                    access.role_for(&alice, project).await.expect("role"),
                    Some(AccessRole::Admin)
                );

                access
                    .on_repository_deleted(project)
                    .await
                    .expect("deleted");
                assert_eq!(access.role_for(&alice, project).await.expect("role"), None);
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn concurrent_grants_do_not_lose_writes() {
        let (access, execution) = access_with_admins(vec![]).await;
        let access = Arc::new(access);
        Box::pin(
            lore_base::runtime::LORE_CONTEXT.scope(execution, async move {
                let project = repo("0194b726b34e72b0b45550b88a967076");

                let mut tasks = tokio::task::JoinSet::new();
                for index in 0..8 {
                    let access = access.clone();
                    // lore_spawn! propagates LORE_CONTEXT into the task.
                    lore_base::lore_spawn!(tasks, async move {
                        access
                            .grant(project, &format!("user-{index}"), AccessRole::Read)
                            .await
                    });
                }
                while let Some(result) = tasks.join_next().await {
                    result.expect("join").expect("grant");
                }

                let grants = access.grants(project).await.expect("grants");
                assert_eq!(
                    grants.len(),
                    8,
                    "all concurrent grants survived: {grants:?}"
                );
            }),
        )
        .await;
    }

    fn claims(user_id: &str, email: &str) -> AuthorizationToken {
        AuthorizationToken {
            user_id: user_id.to_string(),
            preferred_username: email.to_string(),
            ..AuthorizationToken::default()
        }
    }

    #[test]
    fn principals_match_canonical_id_and_email_alias() {
        let mut grants = AccessGrants::new();
        grants.insert("google:123".to_string(), AccessRole::Read);
        grants.insert("alice@example.com".to_string(), AccessRole::Write);

        let by_id = Principals::from_claims(&claims("google:123", "other@example.com"));
        assert_eq!(by_id.matches(&grants), Some(AccessRole::Read));

        let by_email = Principals::from_claims(&claims("google:999", "alice@example.com"));
        assert_eq!(by_email.matches(&grants), Some(AccessRole::Write));

        let both = Principals::from_claims(&claims("google:123", "alice@example.com"));
        // Strongest grant wins.
        assert_eq!(both.matches(&grants), Some(AccessRole::Write));

        let neither = Principals::from_claims(&claims("google:999", "bob@example.com"));
        assert_eq!(neither.matches(&grants), None);
    }
}
