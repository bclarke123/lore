// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::types::RepositoryId;
use lore_proto::auth::CheckUserPermissionRequest;
use tonic::Code;
use tonic::Status;

use super::auth::grpc_get_auth_client;
use super::common::create_request_with_authorization;
use crate::grpc::ServerResultExt;

#[async_trait]
pub trait RepositoryAuthorizer: Send + Sync {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status>;
}

/// Always allows access. Used when no auth URL is configured.
pub struct AllowAllRepositoryAuthorizer;

#[async_trait]
impl RepositoryAuthorizer for AllowAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        _authorization: Option<String>,
        _repository_id: RepositoryId,
    ) -> Result<(), Status> {
        Ok(())
    }
}

/// Checks repository access against the Lore auth service.
pub struct AuthClientAuthorizer {
    auth_url: String,
}

impl AuthClientAuthorizer {
    pub fn new(auth_url: String) -> Self {
        Self { auth_url }
    }
}

#[async_trait]
impl RepositoryAuthorizer for AuthClientAuthorizer {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status> {
        let mut client = grpc_get_auth_client(self.auth_url.clone()).await?;
        let resource_id = format!("urc-{repository_id}");
        let request = create_request_with_authorization(
            CheckUserPermissionRequest {
                resource_id: vec![resource_id.clone()],
                target_user: None,
            },
            authorization,
        )?;

        let permissions = client
            .check_user_permission(request)
            .await
            .warn_map_err(|err| {
                if err.code() == Code::PermissionDenied {
                    return Status::permission_denied("Query resource denied");
                } else if err.code() == Code::Unauthenticated {
                    return Status::unauthenticated("Query resource failed - unauthenticated");
                }
                Status::internal(format!("Failed to call auth check_user_permission: {err}"))
            })?;

        if permissions
            .into_inner()
            .allowed_resource_permission
            .first()
            .ok_or(Status::internal("No permissions for resource"))?
            .resource_id
            == resource_id
        {
            Ok(())
        } else {
            Err(Status::internal("Unexpected resource_id"))
        }
    }
}

/// Answers repository-access questions from the server-local grant store.
///
/// This is the fork's access model expressed behind the upstream
/// `RepositoryAuthorizer` seam, which the upstream OIDC proposal (D8/D9)
/// rewires every enforcement point onto: when that lands, this
/// implementation plugs in unchanged. Anonymous callers — no authorization,
/// or the [`crate::auth::anonymous`] sentinel — get read-level visibility
/// on public repositories, the same rule the anonymous tower layer applies
/// at the interceptor seam.
pub struct GrantStoreRepositoryAuthorizer {
    access: Arc<crate::access::AccessControl>,
}

impl GrantStoreRepositoryAuthorizer {
    pub fn new(access: Arc<crate::access::AccessControl>) -> Self {
        Self { access }
    }
}

#[async_trait]
impl RepositoryAuthorizer for GrantStoreRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        authorization: Option<String>,
        repository_id: RepositoryId,
    ) -> Result<(), Status> {
        let anonymous = match authorization.as_deref() {
            None => true,
            Some(value) => value == crate::auth::anonymous::ANONYMOUS_AUTHORIZATION,
        };
        if anonymous {
            return match self.access.is_public(repository_id).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(Status::permission_denied(
                    "Not authorized for this repository",
                )),
                Err(e) => Err(Status::internal(format!("Access check failed: {e}"))),
            };
        }
        self.access
            .check_visibility(authorization.as_deref(), repository_id)
            .await
    }
}

/// Creates the appropriate authorizer. The server-local grant store, when
/// installed, outranks delegation to an external auth service — the
/// decision is the same one `CheckUserPermission` would answer from, minus
/// the loopback RPC. Returns `AllowAllRepositoryAuthorizer` when neither
/// is configured.
pub fn repository_authorizer(auth_url: Option<String>) -> Arc<dyn RepositoryAuthorizer> {
    if let Some(access) = crate::access::installed() {
        return Arc::new(GrantStoreRepositoryAuthorizer::new(access));
    }
    match auth_url {
        Some(url) => Arc::new(AuthClientAuthorizer::new(url)),
        None => Arc::new(AllowAllRepositoryAuthorizer),
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use lore_base::runtime::LORE_CONTEXT;

    use super::*;
    use crate::access::AccessControl;
    use crate::access::AccessRole;
    use crate::access::PUBLIC_PRINCIPAL;
    use crate::auth::local_auth::LocalAuth;
    use crate::store::test_store_create;

    #[tokio::test]
    async fn grant_store_authorizer_answers_from_grants() {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
        let auth = LocalAuth::from_settings(Some(&settings))
            .expect("build")
            .expect("enabled");
        let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
        let access = Arc::new(AccessControl::new(
            immutable,
            mutable,
            auth.verifier.clone(),
            Vec::new(),
        ));
        let authorizer = GrantStoreRepositoryAuthorizer::new(access.clone());

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let project = RepositoryId::from_str("0194b726b34e72b0b45550b88a967076").expect("id");
            let minted = auth
                .minter
                .mint_user_token(&crate::auth::provider::ExternalIdentity {
                    subject: "alice".to_string(),
                    email: Some("alice@example.com".to_string()),
                    display_name: Some("Alice".to_string()),
                    idp: "static".to_string(),
                })
                .expect("mint");
            let bearer = Some(format!("Bearer {}", minted.token));

            // Deny-by-default for authenticated and anonymous callers.
            let denied = authorizer
                .check_repository_access(bearer.clone(), project)
                .await
                .expect_err("no grant");
            assert_eq!(denied.code(), Code::PermissionDenied);
            let denied = authorizer
                .check_repository_access(None, project)
                .await
                .expect_err("anonymous on private");
            assert_eq!(denied.code(), Code::PermissionDenied);

            // A grant admits the bearer.
            access
                .grant(project, "static:alice", AccessRole::Read)
                .await
                .expect("grant");
            authorizer
                .check_repository_access(bearer, project)
                .await
                .expect("granted");

            // The public grant admits anonymous callers, plain and via the
            // admitted-anonymous sentinel.
            access
                .grant(project, PUBLIC_PRINCIPAL, AccessRole::Read)
                .await
                .expect("public grant");
            authorizer
                .check_repository_access(None, project)
                .await
                .expect("anonymous on public");
            authorizer
                .check_repository_access(
                    Some(crate::auth::anonymous::ANONYMOUS_AUTHORIZATION.to_string()),
                    project,
                )
                .await
                .expect("sentinel on public");

            // Garbage credentials stay unauthenticated even on a public
            // repository: a bearer was presented, so it must verify.
            let garbage = authorizer
                .check_repository_access(Some("Bearer garbage".to_string()), project)
                .await
                .expect_err("bad token");
            assert_eq!(garbage.code(), Code::Unauthenticated);
        }))
        .await;
    }
}
