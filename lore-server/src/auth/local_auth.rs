// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Composition root for server-local authentication.
//!
//! [`LocalAuth`] bundles the configured [`AuthProvider`], the
//! [`TokenMinter`], the pending-login [`SessionManager`], and the
//! [`JwtVerifier`] that trusts the local signing key. It is built once at
//! server startup (when `[server.auth]` configures a provider and token
//! minting) and shared by the auth gRPC service and the HTTP login
//! callback routes.

use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::JwtVerifier;
use crate::auth::local_jwk::LocalJwkService;
use crate::auth::minting::MintingError;
use crate::auth::minting::TokenMinter;
use crate::auth::provider::AuthProvider;
use crate::auth::provider::AuthProviderError;
use crate::auth::provider::CallbackParams;
use crate::auth::provider::static_provider::StaticProvider;
use crate::auth::provider::static_provider::StaticProviderError;
use crate::auth::provider::static_provider::StaticProviderSettings;
use crate::auth::session::SessionError;
use crate::auth::session::SessionManager;
use crate::settings::AuthSettings;

#[derive(Clone, Debug, Deserialize)]
pub struct AuthProviderSettings {
    /// Which provider to use: `static` (development/CI). Further providers
    /// (`google`, `cognito`, `oidc`) are added by follow-up work.
    pub mode: String,
    /// Externally reachable base URL of the server's HTTP endpoint; login
    /// callback URLs are built under it, e.g.
    /// `https://lore.example.com` → `https://lore.example.com/auth/callback`.
    pub callback_base_url: String,
    #[serde(rename = "static")]
    pub static_provider: Option<StaticProviderSettings>,
}

#[derive(Debug, Error)]
pub enum LocalAuthError {
    #[error("auth.provider requires auth.token (token minting) to be configured")]
    MissingTokenSettings,
    #[error("auth.token requires auth.provider to be configured")]
    MissingProviderSettings,
    #[error("auth.jwk (external JWKS) and auth.token (local minting) are mutually exclusive")]
    AmbiguousVerifier,
    #[error("Unknown auth provider mode '{0}'")]
    UnknownProvider(String),
    #[error("auth.provider.mode = 'static' requires an [auth.provider.static] section")]
    MissingStaticSettings,
    #[error(transparent)]
    StaticProvider(#[from] StaticProviderError),
    #[error(transparent)]
    Minting(#[from] MintingError),
}

/// Server-local authentication: provider, minter, sessions, verifier.
pub struct LocalAuth {
    pub provider: Arc<dyn AuthProvider>,
    pub minter: Arc<TokenMinter>,
    pub sessions: Arc<SessionManager>,
    pub verifier: JwtVerifier,
}

impl LocalAuth {
    /// Build from `[server.auth]` settings. Returns `Ok(None)` when no local
    /// provider is configured (external-JWKS or auth-off deployments).
    pub fn from_settings(auth: Option<&AuthSettings>) -> Result<Option<Self>, LocalAuthError> {
        let Some(auth) = auth else { return Ok(None) };

        match (auth.provider.as_ref(), auth.token.as_ref()) {
            (None, None) => return Ok(None),
            (Some(_), None) => return Err(LocalAuthError::MissingTokenSettings),
            (None, Some(_)) => return Err(LocalAuthError::MissingProviderSettings),
            (Some(_), Some(_)) => {}
        }
        if auth.jwk.is_some() {
            return Err(LocalAuthError::AmbiguousVerifier);
        }

        let provider_settings = auth.provider.as_ref().expect("checked above");
        let token_settings = auth.token.as_ref().expect("checked above");

        let provider = Self::build_provider(provider_settings)?;
        let minter = TokenMinter::from_settings(token_settings)?;
        let verifier = JwtVerifier {
            jwk_service: Arc::new(LocalJwkService::new(&minter)),
            // Explicit issuer/audience settings override the minting values,
            // matching the external-JWKS configuration surface.
            jwt_issuer: auth
                .jwt_issuer
                .clone()
                .or_else(|| Some(token_settings.issuer.clone())),
            jwt_audience: auth
                .jwt_audience
                .clone()
                .or_else(|| Some(token_settings.audience.clone())),
        };

        info!(
            provider = provider.name(),
            issuer = token_settings.issuer,
            "Server-local authentication enabled"
        );
        if provider_settings.mode == "static" {
            warn!(
                "The static auth provider is for development only; \
                 secrets travel through the login callback"
            );
        }

        Ok(Some(Self {
            provider,
            minter: Arc::new(minter),
            sessions: Arc::new(SessionManager::new()),
            verifier,
        }))
    }

    fn build_provider(
        settings: &AuthProviderSettings,
    ) -> Result<Arc<dyn AuthProvider>, LocalAuthError> {
        match settings.mode.as_str() {
            "static" => {
                let static_settings = settings
                    .static_provider
                    .as_ref()
                    .ok_or(LocalAuthError::MissingStaticSettings)?;
                Ok(Arc::new(StaticProvider::new(
                    static_settings,
                    &settings.callback_base_url,
                )?))
            }
            other => Err(LocalAuthError::UnknownProvider(other.to_string())),
        }
    }

    /// Complete a browser login: resolve the pending session for the
    /// callback's `state`, verify the identity with the provider, mint a
    /// user token, and record the outcome for the polling client.
    ///
    /// Provider denials are recorded on the session (so the polling CLI
    /// reports the failure) and returned as an error for the HTTP page.
    pub async fn complete_login(&self, params: CallbackParams) -> Result<(), CompleteLoginError> {
        let state = params
            .get("state")
            .ok_or_else(|| CompleteLoginError::BadRequest("missing 'state' parameter".into()))?
            .to_string();
        let session = self.sessions.for_callback_state(&state)?;

        match self.provider.complete_login(&session, &params).await {
            Ok(identity) => {
                let minted = self.minter.mint_user_token(&identity)?;
                info!(user_id = minted.user_id, "Login completed");
                self.sessions.complete_by_state(&state, Ok(minted))?;
                Ok(())
            }
            Err(provider_error) => {
                warn!(error = %provider_error, "Login attempt failed");
                // Record the failure for the polling client; parameter
                // errors leave the session pending so the user can retry
                // the form.
                if !matches!(provider_error, AuthProviderError::Invalid(_)) {
                    let _ = self
                        .sessions
                        .complete_by_state(&state, Err(provider_error.to_string()));
                }
                Err(CompleteLoginError::Provider(provider_error))
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum CompleteLoginError {
    #[error("{0}")]
    BadRequest(String),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    Provider(#[from] AuthProviderError),
    #[error(transparent)]
    Minting(#[from] MintingError),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::auth::minting::TokenMintingSettings;
    use crate::auth::provider::static_provider::StaticUserSettings;

    pub(crate) fn test_auth_settings(dir: &std::path::Path) -> AuthSettings {
        AuthSettings {
            jwk: None,
            jwt_audience: None,
            jwt_issuer: None,
            token: Some(TokenMintingSettings {
                signing_key_path: Some(dir.join("key.pem").to_string_lossy().to_string()),
                generate_signing_key: true,
                issuer: "https://lore.example.com".to_string(),
                audience: vec!["lore.example.com".to_string()],
                user_token_ttl_seconds: 3600,
                authz_token_ttl_seconds: 900,
                env: "test".to_string(),
            }),
            provider: Some(AuthProviderSettings {
                mode: "static".to_string(),
                callback_base_url: "http://localhost:8080".to_string(),
                static_provider: Some(StaticProviderSettings {
                    allow_insecure_dev_login: true,
                    users: vec![StaticUserSettings {
                        user: "alice".to_string(),
                        secret: "s3cret".to_string(),
                        name: Some("Alice".to_string()),
                        email: Some("alice@example.com".to_string()),
                    }],
                }),
            }),
        }
    }

    fn callback(pairs: &[(&str, &str)]) -> CallbackParams {
        CallbackParams {
            params: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn absent_settings_disable_local_auth() {
        assert!(LocalAuth::from_settings(None).expect("none").is_none());
        let bare = AuthSettings {
            jwk: None,
            jwt_audience: None,
            jwt_issuer: None,
            token: None,
            provider: None,
        };
        assert!(
            LocalAuth::from_settings(Some(&bare))
                .expect("bare")
                .is_none()
        );
    }

    #[test]
    fn partial_settings_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let full = test_auth_settings(dir.path());

        let mut no_token = full.clone();
        no_token.token = None;
        assert!(matches!(
            LocalAuth::from_settings(Some(&no_token)),
            Err(LocalAuthError::MissingTokenSettings)
        ));

        let mut no_provider = full.clone();
        no_provider.provider = None;
        assert!(matches!(
            LocalAuth::from_settings(Some(&no_provider)),
            Err(LocalAuthError::MissingProviderSettings)
        ));

        let mut both_verifiers = full.clone();
        both_verifiers.jwk = Some(crate::auth::jwk::JWKServiceSettings {
            endpoint: "https://idp.example.com/jwks".to_string(),
        });
        assert!(matches!(
            LocalAuth::from_settings(Some(&both_verifiers)),
            Err(LocalAuthError::AmbiguousVerifier)
        ));

        let mut bad_mode = full.clone();
        bad_mode.provider.as_mut().expect("provider").mode = "carrier-pigeon".to_string();
        assert!(matches!(
            LocalAuth::from_settings(Some(&bad_mode)),
            Err(LocalAuthError::UnknownProvider(_))
        ));

        let mut no_static = full;
        no_static
            .provider
            .as_mut()
            .expect("provider")
            .static_provider = None;
        assert!(matches!(
            LocalAuth::from_settings(Some(&no_static)),
            Err(LocalAuthError::MissingStaticSettings)
        ));
    }

    #[tokio::test]
    async fn end_to_end_login_flow() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = LocalAuth::from_settings(Some(&test_auth_settings(dir.path())))
            .expect("build")
            .expect("enabled");

        // StartAuthSession
        let session = auth.sessions.create("client-1").expect("create");
        let login_url = auth.provider.begin_login(&session).await.expect("begin");
        assert!(login_url.query().unwrap_or_default().contains("state="));

        // Browser callback
        auth.complete_login(callback(&[
            ("state", &session.csrf_state),
            ("user", "alice"),
            ("secret", "s3cret"),
        ]))
        .await
        .expect("complete");

        // GetAuthSession poll
        let minted = auth
            .sessions
            .take_if_ready(&session.session_code, "client-1")
            .expect("poll")
            .expect("ready");
        assert_eq!(minted.user_id, "static:alice");

        // The minted token verifies against the bundled verifier.
        let claims = auth
            .verifier
            .verify_token(&minted.token)
            .await
            .expect("verify");
        assert_eq!(claims.user_id, "static:alice");
    }

    #[tokio::test]
    async fn denied_login_is_reported_to_poller() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = LocalAuth::from_settings(Some(&test_auth_settings(dir.path())))
            .expect("build")
            .expect("enabled");
        let session = auth.sessions.create("client-1").expect("create");

        let err = auth
            .complete_login(callback(&[
                ("state", &session.csrf_state),
                ("user", "alice"),
                ("secret", "wrong"),
            ]))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CompleteLoginError::Provider(AuthProviderError::Denied(_))
        ));

        assert!(matches!(
            auth.sessions
                .take_if_ready(&session.session_code, "client-1"),
            Err(SessionError::LoginFailed(_))
        ));
    }

    #[tokio::test]
    async fn missing_credentials_leave_session_pending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = LocalAuth::from_settings(Some(&test_auth_settings(dir.path())))
            .expect("build")
            .expect("enabled");
        let session = auth.sessions.create("client-1").expect("create");

        // A form load / incomplete submission must not burn the session.
        let err = auth
            .complete_login(callback(&[("state", &session.csrf_state)]))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CompleteLoginError::Provider(AuthProviderError::Invalid(_))
        ));
        assert_eq!(
            auth.sessions
                .take_if_ready(&session.session_code, "client-1")
                .expect("still pending"),
            None
        );

        // Retry with credentials succeeds.
        auth.complete_login(callback(&[
            ("state", &session.csrf_state),
            ("user", "alice"),
            ("secret", "s3cret"),
        ]))
        .await
        .expect("retry");
    }

    #[tokio::test]
    async fn unknown_state_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = LocalAuth::from_settings(Some(&test_auth_settings(dir.path())))
            .expect("build")
            .expect("enabled");
        let err = auth
            .complete_login(callback(&[
                ("state", "bogus"),
                ("user", "a"),
                ("secret", "b"),
            ]))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CompleteLoginError::Session(SessionError::NotFound)
        ));

        let err = auth
            .complete_login(callback(&[("user", "a"), ("secret", "b")]))
            .await
            .unwrap_err();
        assert!(matches!(err, CompleteLoginError::BadRequest(_)));
    }
}
