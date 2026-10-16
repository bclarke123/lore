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
pub use lore_revision::access::PUBLIC_PRINCIPAL;
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
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),
}

/// The identities a caller may be granted under: the canonical user id
/// (`<idp>:<subject>`) plus the email alias admins may have typed.
#[derive(Debug, Clone)]
pub struct Principals(Vec<String>);

impl Principals {
    pub fn from_claims(claims: &AuthorizationToken) -> Self {
        let mut principals = vec![claims.user_id.clone()];
        if let Some(preferred_username) = claims.preferred_username.as_deref()
            && !preferred_username.is_empty()
            && preferred_username != claims.user_id
        {
            principals.push(preferred_username.to_string());
        }
        Self(principals)
    }

    #[lore_macro::test_pub]
    fn matches(&self, grants: &AccessGrants) -> Option<AccessRole> {
        self.0
            .iter()
            .filter_map(|principal| grants.get(principal))
            // A public grant applies to every caller; an explicit stronger
            // grant still wins via `max`.
            .chain(grants.get(PUBLIC_PRINCIPAL))
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

    /// Whether the repository carries the public (`*`) read grant.
    pub async fn is_public(&self, repository: RepositoryId) -> Result<bool, AccessError> {
        Ok(self
            .grants(repository)
            .await?
            .contains_key(PUBLIC_PRINCIPAL))
    }

    pub async fn grant(
        &self,
        repository: RepositoryId,
        principal: &str,
        role: AccessRole,
    ) -> Result<(), AccessError> {
        if principal == PUBLIC_PRINCIPAL {
            if role != AccessRole::Read {
                return Err(AccessError::InvalidGrant(format!(
                    "the public principal '{PUBLIC_PRINCIPAL}' may only hold the read role"
                )));
            }
            if repository == RepositoryId::default() {
                return Err(AccessError::InvalidGrant(format!(
                    "the public principal '{PUBLIC_PRINCIPAL}' cannot hold a server-level grant"
                )));
            }
        }
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

    /// Authorization check requiring server-administrator standing
    /// (repository creation, alias management — operations reserved for the
    /// hub / trusted control plane).
    pub async fn check_server_admin(
        &self,
        authorization: Option<&str>,
    ) -> Result<AuthorizationToken, tonic::Status> {
        let claims = self.claims_from_header(authorization).await?;
        let principals = Principals::from_claims(&claims);
        match self.is_server_admin(&principals).await {
            Ok(true) => Ok(claims),
            Ok(false) => Err(tonic::Status::permission_denied(
                "Server administrator role required",
            )),
            Err(e) => Err(tonic::Status::internal(format!("Access check failed: {e}"))),
        }
    }
}
