// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Server-local implementation of the `UrcAuthApi` and `RebacApi` gRPC
//! services.
//!
//! When a local auth provider is configured, `loreserver` serves the same
//! auth-session protocol the client already speaks (`lore auth login` →
//! `StartAuthSession` → browser → `GetAuthSession` polling), minting its
//! own tokens instead of delegating to an external auth service. The
//! environment's `auth_url` then points back at this server
//! (`ucs-auth://<host>:<grpc-port>`).
//!
//! Authorization note: until the per-repository access store lands,
//! `ExchangeUserTokenForMultiresourceToken` grants every *authenticated*
//! user `read`/`write` on any requested resource, and the permission-check
//! RPCs answer permissively. This upgrades an auth-less deployment to
//! "must be logged in" without yet distinguishing per-repository roles.
//! `RebacApi` resource registration is a no-op for the same reason.

use std::sync::Arc;

use lore_proto::auth::urc_auth_api_server::UrcAuthApi;
use lore_proto::rebac::rebac_api_server::RebacApi;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::instrument;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;
use crate::auth::jwt_interceptor::extract_bearer_token;
use crate::auth::local_auth::LocalAuth;
use crate::auth::session::SessionError;

/// Permissions granted to any authenticated user until the per-repository
/// access store provides real grants.
const DEFAULT_PERMISSIONS: [&str; 2] = ["read", "write"];

fn default_permissions() -> Vec<String> {
    DEFAULT_PERMISSIONS
        .iter()
        .map(ToString::to_string)
        .collect()
}

pub struct LoreAuthService {
    auth: Arc<LocalAuth>,
}

impl LoreAuthService {
    pub fn new(auth: Arc<LocalAuth>) -> Self {
        Self { auth }
    }

    /// Verify the bearer token on a request's metadata.
    async fn verify_caller<T>(&self, request: &Request<T>) -> Result<AuthorizationToken, Status> {
        let token = extract_bearer_token(request.metadata())
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;
        self.auth
            .verifier
            .verify_token(&token)
            .await
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))
    }
}

fn user_token_proto(minted: crate::auth::session::MintedLogin) -> lore_proto::auth::UserToken {
    lore_proto::auth::UserToken {
        user_token: minted.token,
        // The client interprets `expires_at` as milliseconds since the UNIX
        // epoch (Lore's wire-wide timestamp convention).
        expires_at: minted.expires_at_ms,
        user_id: minted.user_id,
        user_name: minted.user_name,
    }
}

#[tonic::async_trait]
impl UrcAuthApi for LoreAuthService {
    #[instrument(name = "UrcAuthApi::HealthCheck", skip_all)]
    async fn health_check(
        &self,
        _request: Request<lore_proto::auth::HealthCheckRequest>,
    ) -> Result<Response<lore_proto::auth::HealthCheckResponse>, Status> {
        Ok(Response::new(lore_proto::auth::HealthCheckResponse {
            status: "ok".to_string(),
        }))
    }

    #[instrument(name = "UrcAuthApi::StartAuthSession", skip_all)]
    async fn start_auth_session(
        &self,
        request: Request<lore_proto::auth::StartAuthSessionRequest>,
    ) -> Result<Response<lore_proto::auth::StartAuthSessionResponse>, Status> {
        let client_state = request.into_inner().client_state;
        if client_state.is_empty() {
            return Err(Status::invalid_argument("client_state must not be empty"));
        }

        let session = self
            .auth
            .sessions
            .create(&client_state)
            .map_err(|e| match e {
                SessionError::Exhausted => Status::resource_exhausted(e.to_string()),
                other => Status::internal(other.to_string()),
            })?;
        let login_url = self
            .auth
            .provider
            .begin_login(&session)
            .await
            .map_err(|e| Status::internal(format!("failed to begin login: {e}")))?;

        debug!(session_code = session.session_code, "Started auth session");
        Ok(Response::new(lore_proto::auth::StartAuthSessionResponse {
            session_code: session.session_code,
            login_url: login_url.to_string(),
        }))
    }

    #[instrument(name = "UrcAuthApi::GetAuthSession", skip_all)]
    async fn get_auth_session(
        &self,
        request: Request<lore_proto::auth::GetAuthSessionRequest>,
    ) -> Result<Response<lore_proto::auth::GetAuthSessionResponse>, Status> {
        let request = request.into_inner();
        match self
            .auth
            .sessions
            .take_if_ready(&request.session_code, &request.client_state)
        {
            Ok(minted) => Ok(Response::new(lore_proto::auth::GetAuthSessionResponse {
                user_token: minted.map(user_token_proto),
            })),
            Err(SessionError::NotFound) => {
                Err(Status::not_found("unknown or expired login session"))
            }
            Err(SessionError::ClientStateMismatch) => {
                Err(Status::permission_denied("login session mismatch"))
            }
            Err(SessionError::LoginFailed(reason)) => Err(Status::permission_denied(reason)),
            Err(other) => Err(Status::internal(other.to_string())),
        }
    }

    #[instrument(name = "UrcAuthApi::RefreshAuthSession", skip_all)]
    async fn refresh_auth_session(
        &self,
        _request: Request<lore_proto::auth::RefreshAuthSessionRequest>,
    ) -> Result<Response<lore_proto::auth::RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented("refresh is not supported yet"))
    }

    #[instrument(name = "UrcAuthApi::VerifyUser", skip_all)]
    async fn verify_user(
        &self,
        _request: Request<lore_proto::auth::VerifyUserRequest>,
    ) -> Result<Response<lore_proto::auth::VerifyUserResponse>, Status> {
        Err(Status::unimplemented(
            "user verification is not supported by server-local auth",
        ))
    }

    #[instrument(name = "UrcAuthApi::ExchangeExternalTokenForUserToken", skip_all)]
    async fn exchange_external_token_for_user_token(
        &self,
        _request: Request<lore_proto::auth::ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<lore_proto::auth::ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "external token exchange is not supported by server-local auth; use `lore auth login`",
        ))
    }

    #[instrument(name = "UrcAuthApi::ExchangeAPIKeyForUserToken", skip_all)]
    async fn exchange_api_key_for_user_token(
        &self,
        _request: Request<lore_proto::auth::ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<lore_proto::auth::ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "API key exchange is not supported by server-local auth",
        ))
    }

    #[instrument(name = "UrcAuthApi::ExchangeUserTokenForMultiresourceToken", skip_all)]
    async fn exchange_user_token_for_multiresource_token(
        &self,
        request: Request<lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<lore_proto::auth::ExchangeUserTokenForMultiresourceTokenResponse>, Status>
    {
        let user_claims = self.verify_caller(&request).await?;
        let resource_ids = request.into_inner().resource_id;
        if resource_ids.is_empty() {
            return Err(Status::invalid_argument("no resource ids requested"));
        }

        let resources = resource_ids
            .into_iter()
            .map(|resource_id| ResourcePermission {
                resource_id,
                permission: default_permissions(),
            })
            .collect();

        let minted = self
            .auth
            .minter
            .mint_authz_token(&user_claims, resources)
            .map_err(|e| Status::internal(format!("failed to mint token: {e}")))?;

        Ok(Response::new(
            lore_proto::auth::ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(user_token_proto(minted)),
            },
        ))
    }

    #[instrument(name = "UrcAuthApi::CheckUserPermission", skip_all)]
    async fn check_user_permission(
        &self,
        request: Request<lore_proto::auth::CheckUserPermissionRequest>,
    ) -> Result<Response<lore_proto::auth::CheckUserPermissionResponse>, Status> {
        self.verify_caller(&request).await?;
        let resource_ids = request.into_inner().resource_id;
        let allowed = resource_ids
            .into_iter()
            .map(|resource_id| lore_proto::auth::ResourcePermission {
                resource_id,
                permission: default_permissions(),
            })
            .collect();
        Ok(Response::new(
            lore_proto::auth::CheckUserPermissionResponse {
                allowed_resource_permission: allowed,
                denied_resource_permission: Vec::new(),
            },
        ))
    }

    #[instrument(name = "UrcAuthApi::LookupUserPermissions", skip_all)]
    async fn lookup_user_permissions(
        &self,
        request: Request<lore_proto::auth::LookupUserPermissionsRequest>,
    ) -> Result<Response<lore_proto::auth::LookupUserPermissionsResponse>, Status> {
        self.verify_caller(&request).await?;
        // Until the access store lands there is no per-user grant list to
        // enumerate; answer with a wildcard so repository listing shows
        // every repository to any authenticated user.
        let filter = request.into_inner().resource_filter;
        Ok(Response::new(
            lore_proto::auth::LookupUserPermissionsResponse {
                resource_permission: vec![lore_proto::auth::ResourcePermission {
                    resource_id: format!("{filter}-*"),
                    permission: default_permissions(),
                }],
                next_page_token: None,
            },
        ))
    }

    #[instrument(name = "UrcAuthApi::GetUserInfo", skip_all)]
    async fn get_user_info(
        &self,
        request: Request<lore_proto::auth::GetUserInfoRequest>,
    ) -> Result<Response<lore_proto::auth::GetUserInfoResponse>, Status> {
        let caller = self.verify_caller(&request).await?;
        // There is no user directory; resolve the caller's own id to the
        // display name from their token and echo other ids back unchanged.
        let user_info = request
            .into_inner()
            .user_id
            .into_iter()
            .map(|user_id| {
                let display_name = if user_id == caller.user_id {
                    caller.name.clone()
                } else {
                    user_id.clone()
                };
                lore_proto::auth::UserInfo {
                    user_id,
                    display_name,
                }
            })
            .collect();
        Ok(Response::new(lore_proto::auth::GetUserInfoResponse {
            user_info,
        }))
    }

    #[instrument(name = "UrcAuthApi::GetUserId", skip_all)]
    async fn get_user_id(
        &self,
        _request: Request<lore_proto::auth::GetUserIdRequest>,
    ) -> Result<Response<lore_proto::auth::GetUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "display-name lookup is not supported by server-local auth",
        ))
    }

    #[instrument(name = "UrcAuthApi::GetProviderUserId", skip_all)]
    async fn get_provider_user_id(
        &self,
        _request: Request<lore_proto::auth::GetProviderUserIdRequest>,
    ) -> Result<Response<lore_proto::auth::GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented(
            "provider user id lookup is not supported by server-local auth",
        ))
    }
}

/// No-op `RebacApi`: repository create/delete register auth resources when
/// an `auth_url` is configured; with server-local auth those registrations
/// become meaningful once the access store lands.
pub struct LoreRebacService {
    auth: Arc<LocalAuth>,
}

impl LoreRebacService {
    pub fn new(auth: Arc<LocalAuth>) -> Self {
        Self { auth }
    }

    async fn verify_caller<T>(&self, request: &Request<T>) -> Result<AuthorizationToken, Status> {
        let token = extract_bearer_token(request.metadata())
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;
        self.auth
            .verifier
            .verify_token(&token)
            .await
            .map_err(|e| Status::unauthenticated(format!("invalid token: {e}")))
    }
}

#[tonic::async_trait]
impl RebacApi for LoreRebacService {
    #[instrument(name = "RebacApi::CreateResource", skip_all)]
    async fn create_resource(
        &self,
        request: Request<lore_proto::rebac::CreateResourceRequest>,
    ) -> Result<Response<lore_proto::rebac::CreateResourceResponse>, Status> {
        self.verify_caller(&request).await?;
        Ok(Response::new(lore_proto::rebac::CreateResourceResponse {}))
    }

    #[instrument(name = "RebacApi::DeleteResource", skip_all)]
    async fn delete_resource(
        &self,
        request: Request<lore_proto::rebac::DeleteResourceRequest>,
    ) -> Result<Response<lore_proto::rebac::DeleteResourceResponse>, Status> {
        self.verify_caller(&request).await?;
        Ok(Response::new(lore_proto::rebac::DeleteResourceResponse {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::CallbackParams;

    async fn service() -> (LoreAuthService, Arc<LocalAuth>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
        let auth = Arc::new(
            LocalAuth::from_settings(Some(&settings))
                .expect("build")
                .expect("enabled"),
        );
        (LoreAuthService::new(auth.clone()), auth, dir)
    }

    fn callback(pairs: &[(&str, &str)]) -> CallbackParams {
        CallbackParams {
            params: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    async fn login(service: &LoreAuthService, auth: &LocalAuth) -> lore_proto::auth::UserToken {
        let started = service
            .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
                client_state: "client-1".to_string(),
            }))
            .await
            .expect("start")
            .into_inner();

        // Simulate the browser flow.
        let session = auth
            .sessions
            .for_callback_state(
                url::Url::parse(&started.login_url)
                    .expect("login url")
                    .query_pairs()
                    .find(|(k, _)| k == "state")
                    .map(|(_, v)| v.to_string())
                    .expect("state param")
                    .as_str(),
            )
            .expect("session");
        auth.complete_login(callback(&[
            ("state", &session.csrf_state),
            ("user", "alice"),
            ("secret", "s3cret"),
        ]))
        .await
        .expect("complete");

        service
            .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
                session_code: started.session_code,
                client_state: "client-1".to_string(),
            }))
            .await
            .expect("poll")
            .into_inner()
            .user_token
            .expect("token ready")
    }

    fn authed_request<T>(payload: T, token: &str) -> Request<T> {
        let mut request = Request::new(payload);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}").parse().expect("metadata"),
        );
        request
    }

    #[tokio::test]
    async fn start_and_poll_full_flow() {
        let (service, auth, _dir) = service().await;
        let token = login(&service, &auth).await;
        assert_eq!(token.user_id, "static:alice");
        assert_eq!(token.user_name, "Alice");
        assert!(!token.user_token.is_empty());
        assert!(token.expires_at > 0);
    }

    #[tokio::test]
    async fn start_rejects_empty_client_state() {
        let (service, _auth, _dir) = service().await;
        let err = service
            .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
                client_state: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn poll_pending_session_returns_empty() {
        let (service, _auth, _dir) = service().await;
        let started = service
            .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
                client_state: "client-1".to_string(),
            }))
            .await
            .expect("start")
            .into_inner();
        let polled = service
            .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
                session_code: started.session_code,
                client_state: "client-1".to_string(),
            }))
            .await
            .expect("poll")
            .into_inner();
        assert!(polled.user_token.is_none());
    }

    #[tokio::test]
    async fn poll_unknown_session_is_not_found() {
        let (service, _auth, _dir) = service().await;
        let err = service
            .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
                session_code: "bogus".to_string(),
                client_state: "client-1".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn poll_with_wrong_client_state_is_denied() {
        let (service, _auth, _dir) = service().await;
        let started = service
            .start_auth_session(Request::new(lore_proto::auth::StartAuthSessionRequest {
                client_state: "client-1".to_string(),
            }))
            .await
            .expect("start")
            .into_inner();
        let err = service
            .get_auth_session(Request::new(lore_proto::auth::GetAuthSessionRequest {
                session_code: started.session_code,
                client_state: "other".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn exchange_requires_valid_token() {
        let (service, _auth, _dir) = service().await;
        let payload = lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec!["urc-00000000000000000000000000000000".to_string()],
        };

        let err = service
            .exchange_user_token_for_multiresource_token(Request::new(payload.clone()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let err = service
            .exchange_user_token_for_multiresource_token(authed_request(payload, "garbage"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn exchange_mints_verifiable_authz_token() {
        let (service, auth, _dir) = service().await;
        let user_token = login(&service, &auth).await;

        let resource = "urc-00000000000000000000000000000000".to_string();
        let exchanged = service
            .exchange_user_token_for_multiresource_token(authed_request(
                lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
                    resource_id: vec![resource.clone()],
                },
                &user_token.user_token,
            ))
            .await
            .expect("exchange")
            .into_inner()
            .token
            .expect("token");

        let claims = auth
            .verifier
            .verify_token(&exchanged.user_token)
            .await
            .expect("verify");
        crate::auth::jwt::verify_authorization(
            &claims,
            lore_revision::lore::RepositoryId::default(),
        )
        .expect("authorized");
        let resources = claims.resources.expect("resources claim");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].resource_id, resource);
        assert_eq!(resources[0].permission, vec!["read", "write"]);
    }

    #[tokio::test]
    async fn exchange_rejects_empty_resource_list() {
        let (service, auth, _dir) = service().await;
        let user_token = login(&service, &auth).await;
        let err = service
            .exchange_user_token_for_multiresource_token(authed_request(
                lore_proto::auth::ExchangeUserTokenForMultiresourceTokenRequest {
                    resource_id: vec![],
                },
                &user_token.user_token,
            ))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn permission_checks_answer_permissively_for_authenticated_users() {
        let (service, auth, _dir) = service().await;
        let user_token = login(&service, &auth).await;

        let checked = service
            .check_user_permission(authed_request(
                lore_proto::auth::CheckUserPermissionRequest {
                    resource_id: vec!["urc-abc".to_string()],
                    target_user: None,
                },
                &user_token.user_token,
            ))
            .await
            .expect("check")
            .into_inner();
        assert_eq!(checked.allowed_resource_permission.len(), 1);
        assert!(checked.denied_resource_permission.is_empty());

        let lookup = service
            .lookup_user_permissions(authed_request(
                lore_proto::auth::LookupUserPermissionsRequest {
                    resource_filter: "urc".to_string(),
                    context_filter: None,
                    page_size: None,
                    page_token: None,
                },
                &user_token.user_token,
            ))
            .await
            .expect("lookup")
            .into_inner();
        assert_eq!(lookup.resource_permission[0].resource_id, "urc-*");

        // Unauthenticated callers are refused.
        let err = service
            .check_user_permission(Request::new(lore_proto::auth::CheckUserPermissionRequest {
                resource_id: vec!["urc-abc".to_string()],
                target_user: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }

    #[tokio::test]
    async fn get_user_info_resolves_caller_display_name() {
        let (service, auth, _dir) = service().await;
        let user_token = login(&service, &auth).await;

        let info = service
            .get_user_info(authed_request(
                lore_proto::auth::GetUserInfoRequest {
                    resource_id: "urc-abc".to_string(),
                    user_id: vec!["static:alice".to_string(), "static:bob".to_string()],
                },
                &user_token.user_token,
            ))
            .await
            .expect("info")
            .into_inner();
        assert_eq!(info.user_info[0].display_name, "Alice");
        assert_eq!(info.user_info[1].display_name, "static:bob");
    }

    #[tokio::test]
    async fn rebac_noop_requires_authentication() {
        let (service, auth, _dir) = service().await;
        let user_token = login(&service, &auth).await;
        let rebac = LoreRebacService::new(auth.clone());

        rebac
            .create_resource(authed_request(
                lore_proto::rebac::CreateResourceRequest {
                    resource_id: "urc-abc".to_string(),
                    resource_name: "repo".to_string(),
                },
                &user_token.user_token,
            ))
            .await
            .expect("create");

        let err = rebac
            .delete_resource(Request::new(lore_proto::rebac::DeleteResourceRequest {
                resource_id: "urc-abc".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);
    }
}
