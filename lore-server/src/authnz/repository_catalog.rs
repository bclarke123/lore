// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use anyhow::anyhow;
use async_trait::async_trait;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use lore_proto::auth::LookupUserPermissionsRequest;
use lore_proto::auth::LookupUserPermissionsResponse;
use lore_revision::lore_debug;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use tokio_stream::StreamExt;
use tonic::Code;
use tonic::Status;
use tracing::info;
use tracing::warn;

use super::auth::grpc_get_auth_client;
use super::common::create_request_with_authorization;
use super::repository_authorizer::VerifiedToken;
use super::repository_authorizer::bearer_header;
use super::repository_authorizer::select_repository_authorizer;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::ServerResultExt;
use crate::settings::AuthSettings;
use crate::settings::BaselineAccess;
use crate::settings::RepositoryCatalogMode;

/// Which partitions a caller may see. Enumeration needs to do a search over the
/// grant store. The information is not available in the tokens, and this is not
/// a standard OIDC feature. Therefore this functionality lives off the
/// authorization path on this optional trait.
#[async_trait]
pub trait RepositoryCatalog: Send + Sync {
    /// The partitions `token` may see, paginated. Returns a list of repository IDs,
    /// and an `Option<String>` continuation token (`None`, if this was the last
    /// page). `page_size` of `None` or zero means no limit.
    async fn list_repositories(
        &self,
        token: Option<&VerifiedToken<'_>>,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<(Vec<RepositoryId>, Option<String>), Status>;
}

impl dyn RepositoryCatalog {
    /// Every partition the caller may see, following continuation tokens
    /// until the catalog returns none, within `budget` for the whole walk.
    /// The v1 list handler streams and so runs under no request timeout, so
    /// this is what bounds an upstream that never stops issuing tokens; a
    /// token seen before is refused at once rather than paid for in time.
    pub async fn list_all(
        &self,
        token: Option<&VerifiedToken<'_>>,
        budget: Duration,
    ) -> Result<Vec<RepositoryId>, Status> {
        let deadline = Instant::now() + budget;
        let mut repositories = Vec::new();
        let mut page_token: Option<String> = None;
        let mut seen = HashSet::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(Status::deadline_exceeded(
                    "Repository catalog listing exceeded the request deadline",
                ));
            }
            let (page, next) = tokio::time::timeout(
                remaining,
                self.list_repositories(token, None, page_token.as_deref()),
            )
            .await
            .map_err(|_elapsed| {
                Status::deadline_exceeded(
                    "Repository catalog listing exceeded the request deadline",
                )
            })??;
            repositories.extend(page);
            match next {
                Some(next) => {
                    if !seen.insert(next.clone()) {
                        return Err(Status::internal(
                            "Repository catalog repeated a page token; the listing does not progress",
                        ));
                    }
                    page_token = Some(next);
                }
                None => return Ok(repositories),
            }
        }
    }
}

/// The default catalog, driven by `baseline_access`: `Denied` lists
/// nothing, `Reachable` lists every partition the server holds, enumerated
/// from the mutable store.
pub struct BaselineRepositoryCatalog {
    baseline: BaselineAccess,
    immutable_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
}

impl BaselineRepositoryCatalog {
    pub fn new(
        baseline: BaselineAccess,
        immutable_store: Arc<dyn ImmutableStore>,
        mutable_store: Arc<dyn MutableStore>,
    ) -> Self {
        Self {
            baseline,
            immutable_store,
            mutable_store,
        }
    }

    async fn list_held(&self) -> Result<Vec<RepositoryId>, Status> {
        let repository = Arc::new(RepositoryContext::new_server_context(
            self.immutable_store.clone(),
            self.mutable_store.clone(),
            Context::default().into(),
        ));
        let mut stream = repository::list_local(repository)
            .await
            .filter_slow_down()?
            .warn_map_err(|err| Status::internal(format!("Failed to list repositories: {err}")))?;
        let mut held = Vec::new();
        while let Some(id) = stream.next().await {
            held.push(id.into());
        }
        Ok(held)
    }
}

#[async_trait]
impl RepositoryCatalog for BaselineRepositoryCatalog {
    async fn list_repositories(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<(Vec<RepositoryId>, Option<String>), Status> {
        match self.baseline {
            BaselineAccess::Denied => Ok((Vec::new(), None)),
            BaselineAccess::Reachable => page(self.list_held().await?, page_size, page_token),
        }
    }
}

/// One page of a full listing, in identifier order. The continuation token
/// is the last identifier on the page, so a partition created between two
/// pages lands at its position in the order and nothing already listed
/// repeats.
#[lore_macro::test_pub]
fn page(
    mut held: Vec<RepositoryId>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<(Vec<RepositoryId>, Option<String>), Status> {
    held.sort_unstable();
    held.dedup();
    if let Some(token) = page_token {
        let after = RepositoryId::from_str(token)
            .map_err(|err| Status::invalid_argument(format!("Malformed page token: {err}")))?;
        held.drain(..held.partition_point(|id| *id <= after));
    }
    let limit = page_size.map(|size| size as usize).filter(|size| *size > 0);
    let next = match limit {
        Some(limit) if held.len() > limit => {
            held.truncate(limit);
            held.last().map(ToString::to_string)
        }
        _ => None,
    };
    Ok((held, next))
}

/// A `RepositoryCatalog` implementation using`UrcAuthApi`.
/// Calls `LookupUserPermissions`.
pub struct AuthClientRepositoryCatalog {
    auth_url: String,
}

impl AuthClientRepositoryCatalog {
    pub fn new(auth_url: String) -> Self {
        Self { auth_url }
    }
}

#[async_trait]
impl RepositoryCatalog for AuthClientRepositoryCatalog {
    async fn list_repositories(
        &self,
        token: Option<&VerifiedToken<'_>>,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> Result<(Vec<RepositoryId>, Option<String>), Status> {
        lore_debug!("Repository fetch authorized repositories");

        let mut client = grpc_get_auth_client(self.auth_url.clone()).await?;
        let request = lookup_request(bearer_header(token), page_size, page_token)?;

        let permissions = client
            .lookup_user_permissions(request)
            .await
            .warn_map_err(|err| {
                if err.code() == Code::PermissionDenied {
                    return Status::permission_denied("List resources denied");
                } else if err.code() == Code::Unauthenticated {
                    return Status::unauthenticated("list resource failed - unauthenticated");
                }
                Status::internal(format!(
                    "Failed to call auth lookup_user_permissions: {err}"
                ))
            })?;

        Ok(repositories_from_response(permissions.into_inner()))
    }
}

#[lore_macro::test_pub]
fn lookup_request(
    authorization: Option<String>,
    page_size: Option<u32>,
    page_token: Option<&str>,
) -> Result<tonic::Request<LookupUserPermissionsRequest>, Status> {
    create_request_with_authorization(
        LookupUserPermissionsRequest {
            resource_filter: "urc".to_string(),
            context_filter: None,
            page_size: page_size.map(|size| i32::try_from(size).unwrap_or(i32::MAX)),
            page_token: page_token.map(ToString::to_string),
        },
        authorization,
    )
}

/// The partitions a `LookupUserPermissions` response names. Entries outside
/// the `urc-{id}` shape are not partitions and are skipped. An empty
/// continuation token is the end of the listing.
#[lore_macro::test_pub]
fn repositories_from_response(
    response: LookupUserPermissionsResponse,
) -> (Vec<RepositoryId>, Option<String>) {
    let repositories = response
        .resource_permission
        .iter()
        .filter_map(|permission| {
            permission
                .resource_id
                .strip_prefix("urc-")
                .and_then(|repository_id| Context::from_str(repository_id).ok())
                .map(RepositoryId::from)
        })
        .collect();
    let next_page_token = response.next_page_token.filter(|token| !token.is_empty());
    (repositories, next_page_token)
}

/// Lists the repositories the server-local grant store lets the caller see:
/// every repository for a server admin, the granted ones otherwise. The
/// catalog half of [`super::repository_authorizer::GrantStoreRepositoryAuthorizer`].
///
/// A caller with no token, or the [`crate::auth::anonymous`] sentinel, is
/// refused rather than listed public repositories: listing needs an identity.
pub struct GrantStoreRepositoryCatalog {
    access: Arc<crate::access::AccessControl>,
}

impl GrantStoreRepositoryCatalog {
    pub fn new(access: Arc<crate::access::AccessControl>) -> Self {
        Self { access }
    }
}

#[async_trait]
impl RepositoryCatalog for GrantStoreRepositoryCatalog {
    async fn list_repositories(
        &self,
        token: Option<&VerifiedToken<'_>>,
        _page_size: Option<u32>,
        _page_token: Option<&str>,
    ) -> Result<(Vec<RepositoryId>, Option<String>), Status> {
        let claims = match token {
            Some(token) if !crate::auth::anonymous::is_anonymous(token.claims) => token.claims,
            _ => return Err(Status::unauthenticated("missing bearer token")),
        };
        let principals = crate::access::Principals::from_claims(claims);
        let repositories = self
            .access
            .authorized_repositories(&principals)
            .await
            .map_err(|err| Status::internal(format!("Access lookup failed: {err}")))?;
        Ok((repositories, None))
    }
}

/// Which implementation [`repository_catalog`] selects for a
/// configuration, named in the startup log beside the authorizer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CatalogSelection {
    /// Answers per `baseline_access` from the server's own store. A server
    /// with no `[server.auth]` gets `Reachable` and lists everything it holds.
    Baseline(BaselineAccess),
    /// `LookupUserPermissions` at this `UrcAuthApi` endpoint, forwarding the
    /// caller's token.
    AuthClient(String),
}

impl fmt::Display for CatalogSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Baseline(BaselineAccess::Denied) => {
                f.write_str("BaselineRepositoryCatalog(denied)")
            }
            Self::Baseline(BaselineAccess::Reachable) => {
                f.write_str("BaselineRepositoryCatalog(reachable)")
            }
            Self::AuthClient(url) => write!(f, "AuthClientRepositoryCatalog({url})"),
        }
    }
}

/// Selects the `RepositoryCatalog` implementation. The rules:
/// - `repository_catalog` config can be used to select the mode
/// - if unset, uses `AuthService` if `auth_url` is defined,
///   `Baseline` otherwise
/// - if using `AuthService` catalog, the gRPC server url is
///   read primarily from `repository_catalog_url`, or from
///   `auth_url` if unset
pub fn select_repository_catalog(
    auth: Option<&AuthSettings>,
    auth_url: Option<&str>,
) -> anyhow::Result<CatalogSelection> {
    select_repository_authorizer(auth, auth_url)?;
    let Some(auth) = auth else {
        return Ok(CatalogSelection::Baseline(BaselineAccess::Reachable));
    };
    let mode = auth.repository_catalog.unwrap_or(if auth_url.is_some() {
        RepositoryCatalogMode::AuthService
    } else {
        RepositoryCatalogMode::Baseline
    });
    Ok(match mode {
        RepositoryCatalogMode::Baseline => CatalogSelection::Baseline(auth.baseline_access),
        RepositoryCatalogMode::AuthService => {
            let url = auth
                .repository_catalog_url
                .as_deref()
                .or(auth_url)
                .ok_or_else(|| {
                    anyhow!(
                        "[server.auth] repository_catalog = \"auth_service\" needs an endpoint to \
                         ask: set repository_catalog_url, or [environment.endpoint] auth_url."
                    )
                })?;
            CatalogSelection::AuthClient(url.to_string())
        }
    })
}

/// Creates the catalog [`select_repository_catalog`] picks for this
/// configuration. Built once at startup beside the authorizer.
pub fn repository_catalog(
    auth: Option<&AuthSettings>,
    auth_url: Option<&str>,
    immutable_store: Arc<dyn ImmutableStore>,
    mutable_store: Arc<dyn MutableStore>,
) -> anyhow::Result<Arc<dyn RepositoryCatalog>> {
    // The server-local grant store, when installed, answers the listing the
    // same way it answers the authorizer.
    if let Some(access) = crate::access::installed() {
        info!("Repository catalog: GrantStoreRepositoryCatalog");
        return Ok(Arc::new(GrantStoreRepositoryCatalog::new(access)));
    }
    let selection = select_repository_catalog(auth, auth_url)?;
    info!("Repository catalog: {selection}");
    Ok(match selection {
        CatalogSelection::Baseline(baseline) => Arc::new(BaselineRepositoryCatalog::new(
            baseline,
            immutable_store,
            mutable_store,
        )),
        CatalogSelection::AuthClient(url) => {
            if auth.is_some_and(|auth| auth.baseline_access == BaselineAccess::Reachable) {
                warn!("[server.auth] baseline_access is not consulted by the auth_service catalog");
            }
            Arc::new(AuthClientRepositoryCatalog::new(url))
        }
    })
}
