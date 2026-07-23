// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Anonymous read access to public repositories.
//!
//! A repository carrying the public (`*`) read grant is readable without
//! any credentials. Requests with no `authorization` header are normally
//! rejected by the JWT interceptors; the [`AnonymousReadLayer`] runs ahead
//! of them and, for read-only methods on public repositories, injects a
//! synthesized read-scoped [`AuthorizationToken`] as a request extension.
//! The interceptors honor that extension in place of a bearer token. The
//! extension is created server-side only — clients cannot forge it.
//!
//! Because token verb enforcement is presence-only today, the read-only
//! method allowlist below is the boundary keeping anonymous callers from
//! mutating public repositories. Extend it with care.

use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use lore_revision::lore::RepositoryId;
use tonic::metadata::MetadataMap;
use tower::Layer;
use tower::Service;

use crate::access::AccessControl;
use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;

/// The principal recorded for unauthenticated callers reading public
/// repositories. Canonical user ids are `<idp>:<subject>`, so this cannot
/// collide with a real identity.
pub const ANONYMOUS_USER: &str = "anonymous";

/// A synthesized read-only authorization for an unauthenticated caller on a
/// public repository. Never minted as a JWT — it exists only as a request
/// extension / connection attribute inside the server process.
pub fn anonymous_token(repository: RepositoryId) -> AuthorizationToken {
    AuthorizationToken {
        user_id: ANONYMOUS_USER.to_string(),
        name: ANONYMOUS_USER.to_string(),
        preferred_username: ANONYMOUS_USER.to_string(),
        resources: Some(vec![ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: vec!["read".to_string()],
        }]),
        ..AuthorizationToken::default()
    }
}

pub fn is_anonymous(authorization: &AuthorizationToken) -> bool {
    authorization.user_id == ANONYMOUS_USER
}

/// Sentinel `authorization` value handlers pass in place of a real bearer
/// header for admitted anonymous requests. Distinguishes "external
/// anonymous caller" (must be a public repository) from "internal call with
/// no authorization" (trusted). A client sending this literal header value
/// only grants itself anonymous standing, so it is safe to accept on the
/// wire.
pub const ANONYMOUS_AUTHORIZATION: &str = "anonymous";

/// The effective `authorization` for a repository-lookup handler: the raw
/// bearer header when present, otherwise the anonymous sentinel when the
/// `AnonymousReadLayer` admitted the request.
pub fn effective_authorization(
    header: Option<String>,
    extensions: &tonic::Extensions,
) -> Option<String> {
    header.or_else(|| {
        extensions
            .get::<AuthorizationToken>()
            .filter(|authorization| is_anonymous(authorization))
            .map(|_| ANONYMOUS_AUTHORIZATION.to_string())
    })
}

/// Repository-scoped gRPC methods that only read repository state. Requests
/// to these methods carry the repository id in metadata, so public-ness is
/// decided before the request reaches the service.
const READ_ONLY_METHODS: &[&str] = &[
    // Legacy urc.rpc data plane (the stock client).
    "/urc.rpc.StorageService/Get",
    "/urc.rpc.StorageService/Ping",
    "/urc.rpc.StorageService/Query",
    "/urc.rpc.StorageService/MutableLoad",
    "/urc.rpc.RevisionService/BranchQuery",
    "/urc.rpc.RevisionService/BranchGet",
    "/urc.rpc.RevisionService/BranchList",
    "/urc.rpc.RevisionService/BranchDiff",
    "/urc.rpc.RevisionService/BranchRevisionList",
    "/urc.rpc.RevisionService/BranchMetadataGet",
    "/urc.rpc.RevisionService/RevisionDescribe",
    "/urc.rpc.RevisionService/RevisionDiff",
    "/urc.rpc.RevisionService/RevisionStateHistory",
    "/urc.rpc.RevisionService/RevisionTree",
    "/urc.rpc.RevisionService/RevisionList",
    // v1 data plane.
    "/lore.storage.v1.StorageService/Get",
    "/lore.storage.v1.StorageService/GetMetadata",
    "/lore.storage.v1.StorageService/Query",
    "/lore.storage.v1.StorageService/MutableLoad",
    "/lore.revision.v1.RevisionService/BranchGet",
    "/lore.revision.v1.RevisionService/BranchList",
    "/lore.revision.v1.RevisionService/BranchMetadataGet",
    "/lore.revision.v1.RevisionService/RevisionList",
    // Thin-client reads (web hubs).
    "/lore.thin_client.v1.ThinClientService/ContentDiff",
    "/lore.thin_client.v1.ThinClientService/RevisionInfo",
    "/lore.thin_client.v1.ThinClientService/RevisionDiff",
    "/lore.thin_client.v1.ThinClientService/RevisionTree",
    "/lore.thin_client.v1.ThinClientService/ReadContent",
];

/// Repository-lookup methods that resolve a name to a repository before the
/// repository id is known. Anonymous requests are let through with a
/// synthesized token carrying no resources; the repository-query handler
/// itself requires the resolved repository to be public.
const LOOKUP_METHODS: &[&str] = &[
    "/urc.rpc.RepositoryService/RepositoryQuery",
    "/lore.repository.v1.RepositoryService/RepositoryGet",
];

pub fn read_only_grpc_method(path: &str) -> bool {
    READ_ONLY_METHODS.contains(&path)
}

pub fn lookup_grpc_method(path: &str) -> bool {
    LOOKUP_METHODS.contains(&path)
}

/// A token for lookup methods: authenticated as `anonymous` with no
/// resources. Passes the authn-only interceptor; the handlers decide
/// per-repository.
pub fn anonymous_lookup_token() -> AuthorizationToken {
    AuthorizationToken {
        user_id: ANONYMOUS_USER.to_string(),
        name: ANONYMOUS_USER.to_string(),
        preferred_username: ANONYMOUS_USER.to_string(),
        resources: Some(vec![]),
        ..AuthorizationToken::default()
    }
}

/// Tower layer granting anonymous read access to public repositories. Runs
/// before the per-service JWT interceptors; requests with an
/// `authorization` header pass through untouched.
#[derive(Clone, Default)]
pub struct AnonymousReadLayer;

impl<S> Layer<S> for AnonymousReadLayer {
    type Service = AnonymousRead<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AnonymousRead { inner }
    }
}

#[derive(Clone)]
pub struct AnonymousRead<S> {
    inner: S,
}

impl<S, B> Service<http::Request<B>> for AnonymousRead<S>
where
    S: Service<http::Request<B>> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures::future::BoxFuture<'static, Result<S::Response, S::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        // Tower requires the service moved into the future to be the one
        // that reported readiness; the clone swap is the standard pattern.
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            if request.headers().get(http::header::AUTHORIZATION).is_none()
                && let Some(access) = crate::access::installed()
            {
                let path = request.uri().path().to_string();
                if lookup_grpc_method(&path) {
                    request.extensions_mut().insert(anonymous_lookup_token());
                } else if read_only_grpc_method(&path)
                    && let Some(repository) = repository_from_headers(request.headers())
                    && matches!(public(&access, repository).await, Some(true))
                {
                    request.extensions_mut().insert(anonymous_token(repository));
                }
            }
            inner.call(request).await
        })
    }
}

async fn public(access: &Arc<AccessControl>, repository: RepositoryId) -> Option<bool> {
    match access.is_public(repository).await {
        Ok(public) => Some(public),
        Err(err) => {
            tracing::warn!(%repository, error = %err, "Anonymous public check failed");
            None
        }
    }
}

fn repository_from_headers(headers: &http::HeaderMap) -> Option<RepositoryId> {
    let metadata = MetadataMap::from_headers(headers.clone());
    crate::grpc::get_repository(&metadata).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_contains_no_mutating_methods() {
        for method in READ_ONLY_METHODS.iter().chain(LOOKUP_METHODS) {
            for verb in [
                "Put",
                "Copy",
                "Verify",
                "MutableStore",
                "MutableCompareAndSwap",
                "Create",
                "Delete",
                "Push",
                "Set",
                "Protect",
                "Obliterate",
            ] {
                assert!(
                    !method.contains(verb),
                    "{method} looks like a mutating method"
                );
            }
        }
    }

    #[test]
    fn anonymous_token_is_read_scoped() {
        let repository = RepositoryId::default();
        let token = anonymous_token(repository);
        assert!(is_anonymous(&token));
        let resources = token.resources.expect("resources");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].permission, vec!["read"]);

        // The lookup token authenticates but authorizes nothing.
        let lookup = anonymous_lookup_token();
        assert!(is_anonymous(&lookup));
        assert_eq!(lookup.resources, Some(vec![]));
    }
}
