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
//! Authorization: when per-repository access control is installed (always
//! the case with server-local auth), `ExchangeUserTokenForMultiresourceToken`
//! resolves the caller's granted role per repository — deny-by-default —
//! and embeds the role's permission verbs in the minted authorization
//! token. The permission-check RPCs and `RebacApi` registration answer
//! from the same grants.

use std::sync::Arc;

use lore_proto::auth::urc_auth_api_server::UrcAuthApi;
use lore_proto::rebac::rebac_api_server::RebacApi;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::instrument;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt_interceptor::extract_bearer_token;
use crate::auth::local_auth::LocalAuth;
use crate::auth::resource_exchange::ResourceRequest;
use crate::auth::resource_exchange::default_permissions;
use crate::auth::resource_exchange::parse_repository_resource;
use crate::auth::resource_exchange::resolve_resource_permissions;
use crate::auth::session::SessionError;

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
        refresh_token: minted.refresh_token,
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

    /// Redeem a refresh token (presented as the bearer credential) for a
    /// fresh user token plus a rotated successor refresh token.
    #[instrument(name = "UrcAuthApi::RefreshAuthSession", skip_all)]
    async fn refresh_auth_session(
        &self,
        request: Request<lore_proto::auth::RefreshAuthSessionRequest>,
    ) -> Result<Response<lore_proto::auth::RefreshAuthSessionResponse>, Status> {
        let Some(refresh) = crate::auth::refresh::installed() else {
            return Err(Status::unimplemented("refresh is not supported"));
        };
        let token = extract_bearer_token(request.metadata())
            .ok_or_else(|| Status::unauthenticated("missing refresh token"))?;

        let (identity, successor) = refresh.refresh(&token).await.map_err(|error| match error {
            crate::auth::refresh::RefreshError::Store(message) => Status::internal(message),
            denied => Status::unauthenticated(denied.to_string()),
        })?;
        let mut minted = self
            .auth
            .minter
            .mint_user_token(&identity)
            .map_err(|e| Status::internal(format!("failed to mint token: {e}")))?;
        minted.refresh_token = Some(successor);
        Ok(Response::new(
            lore_proto::auth::RefreshAuthSessionResponse {
                user_token: Some(user_token_proto(minted)),
            },
        ))
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

    /// Exchange an externally obtained OIDC ID token (e.g. from a web hub
    /// running its own OAuth flow against the same identity provider) for a
    /// Lore user token. The provider validates signature/issuer/expiry and
    /// requires the token's `aud` to be explicitly configured in
    /// `trusted_external_audiences`; providers without OIDC backing (the
    /// static dev provider) answer Unimplemented.
    #[instrument(name = "UrcAuthApi::ExchangeExternalTokenForUserToken", skip_all)]
    async fn exchange_external_token_for_user_token(
        &self,
        request: Request<lore_proto::auth::ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<lore_proto::auth::ExchangeExternalTokenForUserTokenResponse>, Status> {
        let req = request.into_inner();
        match req.token_type.as_str() {
            "google-id-token" | "oidc-id-token" => {}
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported token_type '{other}' (expected google-id-token or oidc-id-token)"
                )));
            }
        }
        if req.external_token.is_empty() {
            return Err(Status::invalid_argument("external_token must not be empty"));
        }

        let identity = self
            .auth
            .provider
            .verify_external_id_token(&req.external_token)
            .await
            .map_err(|error| {
                use crate::auth::provider::AuthProviderError;
                match error {
                    AuthProviderError::Unsupported(message) => Status::unimplemented(message),
                    AuthProviderError::Denied(message) => Status::unauthenticated(message),
                    AuthProviderError::Upstream(message) => Status::unavailable(message),
                    other => Status::internal(other.to_string()),
                }
            })?;

        let mut minted = self
            .auth
            .minter
            .mint_user_token(&identity)
            .map_err(|e| Status::internal(format!("failed to mint token: {e}")))?;
        if let Some(refresh) = crate::auth::refresh::installed() {
            match refresh.issue(&identity).await {
                Ok(token) => minted.refresh_token = Some(token),
                Err(error) => {
                    debug!(%error, "Failed to issue refresh token on exchange; continuing");
                }
            }
        }
        info!(user_id = minted.user_id, "External token exchanged");
        Ok(Response::new(
            lore_proto::auth::ExchangeExternalTokenForUserTokenResponse {
                user_token: Some(user_token_proto(minted)),
            },
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

        let requests = resource_ids
            .into_iter()
            .map(|resource_id| ResourceRequest {
                repository: parse_repository_resource(&resource_id),
                resource_id,
            })
            .collect();
        let resources = resolve_resource_permissions(&user_claims, requests).await?;

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
        let claims = self.verify_caller(&request).await?;
        let resource_ids = request.into_inner().resource_id;

        let Some(access) = crate::access::installed() else {
            let allowed = resource_ids
                .into_iter()
                .map(|resource_id| lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: default_permissions(),
                })
                .collect();
            return Ok(Response::new(
                lore_proto::auth::CheckUserPermissionResponse {
                    allowed_resource_permission: allowed,
                    denied_resource_permission: Vec::new(),
                },
            ));
        };

        let principals = crate::access::Principals::from_claims(&claims);
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for resource_id in resource_ids {
            let role = match parse_repository_resource(&resource_id) {
                Some(repository) => access
                    .role_for(&principals, repository)
                    .await
                    .map_err(|e| Status::internal(format!("Access lookup failed: {e}")))?,
                None => None,
            };
            match role {
                Some(role) => allowed.push(lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: role.verbs().iter().map(ToString::to_string).collect(),
                }),
                None => denied.push(lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: Vec::new(),
                }),
            }
        }
        Ok(Response::new(
            lore_proto::auth::CheckUserPermissionResponse {
                allowed_resource_permission: allowed,
                denied_resource_permission: denied,
            },
        ))
    }

    #[instrument(name = "UrcAuthApi::LookupUserPermissions", skip_all)]
    async fn lookup_user_permissions(
        &self,
        request: Request<lore_proto::auth::LookupUserPermissionsRequest>,
    ) -> Result<Response<lore_proto::auth::LookupUserPermissionsResponse>, Status> {
        let claims = self.verify_caller(&request).await?;
        let filter = request.into_inner().resource_filter;

        let Some(access) = crate::access::installed() else {
            // No access store: answer with a wildcard so repository listing
            // shows every repository to any authenticated user.
            return Ok(Response::new(
                lore_proto::auth::LookupUserPermissionsResponse {
                    resource_permission: vec![lore_proto::auth::ResourcePermission {
                        resource_id: format!("{filter}-*"),
                        permission: default_permissions(),
                    }],
                    next_page_token: None,
                },
            ));
        };

        let principals = crate::access::Principals::from_claims(&claims);
        let mut resource_permission = Vec::new();
        for repository in access
            .authorized_repositories(&principals)
            .await
            .map_err(|e| Status::internal(format!("Access lookup failed: {e}")))?
        {
            let role = access
                .role_for(&principals, repository)
                .await
                .map_err(|e| Status::internal(format!("Access lookup failed: {e}")))?;
            if let Some(role) = role {
                resource_permission.push(lore_proto::auth::ResourcePermission {
                    resource_id: format!("urc-{repository}"),
                    permission: role.verbs().iter().map(ToString::to_string).collect(),
                });
            }
        }
        Ok(Response::new(
            lore_proto::auth::LookupUserPermissionsResponse {
                resource_permission,
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
                    caller.name.clone().unwrap_or_else(|| user_id.clone())
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

/// `RebacApi` backed by the access store: repository creation grants the
/// caller the admin role, deletion clears the repository's grants. Falls
/// back to a no-op when no access control is installed.
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
        let claims = self.verify_caller(&request).await?;
        if let Some(access) = crate::access::installed()
            && let Some(repository) = parse_repository_resource(&request.get_ref().resource_id)
        {
            access
                .on_repository_created(repository, &claims.user_id)
                .await
                .map_err(|e| Status::internal(format!("Failed to record creator grant: {e}")))?;
        }
        Ok(Response::new(lore_proto::rebac::CreateResourceResponse {}))
    }

    #[instrument(name = "RebacApi::DeleteResource", skip_all)]
    async fn delete_resource(
        &self,
        request: Request<lore_proto::rebac::DeleteResourceRequest>,
    ) -> Result<Response<lore_proto::rebac::DeleteResourceResponse>, Status> {
        let claims = self.verify_caller(&request).await?;
        if let Some(access) = crate::access::installed()
            && let Some(repository) = parse_repository_resource(&request.get_ref().resource_id)
        {
            let principals = crate::access::Principals::from_claims(&claims);
            match access.role_for(&principals, repository).await {
                Ok(Some(crate::access::AccessRole::Admin)) => {}
                Ok(_) => {
                    return Err(Status::permission_denied(
                        "Repository administrator role required",
                    ));
                }
                Err(e) => return Err(Status::internal(format!("Access lookup failed: {e}"))),
            }
            access
                .on_repository_deleted(repository)
                .await
                .map_err(|e| Status::internal(format!("Failed to clear grants: {e}")))?;
        }
        Ok(Response::new(lore_proto::rebac::DeleteResourceResponse {}))
    }
}
