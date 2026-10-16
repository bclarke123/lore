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
use crate::auth::provider::ExternalIdentity;
use crate::auth::provider::google::OidcProviderSettings;
use crate::auth::provider::google::OidcSettingsError;
use crate::auth::provider::google::generic_oidc_provider;
use crate::auth::provider::google::google_provider;
use crate::auth::provider::oidc::ReqwestOidcBackend;
use crate::auth::provider::static_provider::StaticProvider;
use crate::auth::provider::static_provider::StaticProviderError;
use crate::auth::provider::static_provider::StaticProviderSettings;
use crate::auth::session::SessionError;
use crate::auth::session::SessionManager;
use crate::settings::AuthSettings;

#[derive(Clone, Debug, Deserialize)]
pub struct AuthProviderSettings {
    /// Which provider to use: `google`, `cognito`, `oidc` (generic), or
    /// `static` (development/CI).
    pub mode: String,
    /// Externally reachable base URL of the server's HTTP endpoint; login
    /// callback URLs are built under it, e.g.
    /// `https://lore.example.com` → `https://lore.example.com/auth/callback`.
    pub callback_base_url: String,
    #[serde(rename = "static")]
    pub static_provider: Option<StaticProviderSettings>,
    /// OIDC settings for the `google` and `oidc` modes.
    pub oidc: Option<OidcProviderSettings>,
}

/// One machine identity for the OAuth 2.0 `client_credentials` grant.
#[derive(Clone, Debug, Deserialize)]
pub struct ClientCredentialSettings {
    /// The `client_id` the machine presents; it authenticates as the
    /// principal `client:<client_id>`, which grants are assigned to like
    /// any other principal.
    pub client_id: String,
    /// Path to a file holding the client secret (preferred in production;
    /// keep the file private).
    pub secret_path: Option<String>,
    /// Inline client secret, for development and tests.
    pub secret: Option<String>,
    /// Optional display name recorded as the token's `name` claim.
    pub name: Option<String>,
}

/// A resolved machine credential: settings with the secret loaded.
#[derive(Clone)]
struct ClientCredential {
    client_id: String,
    secret: String,
    name: Option<String>,
}

/// The `idp` component of machine principals (`client:<client_id>`).
pub const CLIENT_IDP: &str = "client";

#[derive(Debug, Error)]
pub enum LocalAuthError {
    #[error("auth.provider requires auth.token (token minting) to be configured")]
    MissingTokenSettings,
    #[error("auth.clients requires auth.token (token minting) to be configured")]
    ClientsRequireTokenSettings,
    #[error("Invalid [server.auth.clients] entry: {0}")]
    InvalidClientCredential(String),
    #[error("auth.token requires auth.provider to be configured")]
    MissingProviderSettings,
    #[error("auth.jwk (external JWKS) and auth.token (local minting) are mutually exclusive")]
    AmbiguousVerifier,
    #[error("Unknown auth provider mode '{0}'")]
    UnknownProvider(String),
    #[error("auth.provider.mode = 'static' requires an [auth.provider.static] section")]
    MissingStaticSettings,
    #[error("auth.provider.mode = '{0}' requires an [auth.provider.oidc] section")]
    MissingOidcSettings(String),
    #[error("Invalid callback base URL: {0}")]
    InvalidCallbackBase(String),
    #[error(transparent)]
    StaticProvider(#[from] StaticProviderError),
    #[error(transparent)]
    OidcSettings(#[from] OidcSettingsError),
    #[error(transparent)]
    Minting(#[from] MintingError),
}

/// Server-local authentication: provider, minter, sessions, verifier.
pub struct LocalAuth {
    pub provider: Arc<dyn AuthProvider>,
    pub minter: Arc<TokenMinter>,
    pub sessions: Arc<SessionManager>,
    pub verifier: JwtVerifier,
    /// Machine credentials for the `client_credentials` grant.
    clients: Vec<ClientCredential>,
}

impl LocalAuth {
    /// Build from `[server.auth]` settings. Returns `Ok(None)` when no local
    /// provider is configured (external-JWKS or auth-off deployments).
    pub fn from_settings(auth: Option<&AuthSettings>) -> Result<Option<Self>, LocalAuthError> {
        let Some(auth) = auth else { return Ok(None) };

        match (auth.provider.as_ref(), auth.token.as_ref()) {
            (None, None) if auth.clients.is_empty() => return Ok(None),
            (None, None) => return Err(LocalAuthError::ClientsRequireTokenSettings),
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
                .or_else(|| Some(vec![token_settings.issuer.clone()])),
            jwt_audience: auth
                .jwt_audience
                .clone()
                .or_else(|| Some(token_settings.audience.clone())),
            // Unset by default: tokens minted before the `at+jwt` header
            // carry `JWT` and must keep verifying until they expire.
            jwt_typ: auth.jwt_typ.clone(),
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
            clients: Self::resolve_clients(&auth.clients)?,
        }))
    }

    /// The OIDC provider the environment service advertises when this
    /// server is its own issuer: built from the local settings rather than
    /// a fetched discovery document, which at startup would ask this server
    /// before it listens. `None` without `[server.auth.oidc]`, or when the
    /// minted issuer is not an HTTP(S) URL (the OAuth routes are off then).
    ///
    /// As for an external provider, OIDC is preferred when configured so or
    /// when no `auth_url` offers the gRPC path. Stock clients cannot yet
    /// exchange an OIDC token for repository access, so keep `preferred`
    /// off while `auth_url` serves them.
    pub fn advertised_oidc(
        &self,
        auth: &AuthSettings,
        auth_url: Option<&str>,
    ) -> Option<lore_transport::Oidc> {
        let oidc = auth.oidc.as_ref()?;
        let issuer = self.minter.issuer().trim_end_matches('/').to_string();
        if !url::Url::parse(&issuer).is_ok_and(|url| matches!(url.scheme(), "http" | "https")) {
            warn!(
                issuer,
                "[server.auth.oidc] is set but auth.token.issuer is not an HTTP(S) URL; \
                 not advertising an OIDC provider"
            );
            return None;
        }
        info!(
            issuer,
            "Advertising this server as the OIDC provider to clients"
        );
        let non_empty = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
        let resource_template = non_empty(&oidc.resource_template);
        let scope_template = non_empty(&oidc.scope_template);
        let is_tier_2 = resource_template.is_some() || scope_template.is_some();
        let token_exchange_issuer = is_tier_2
            .then(|| non_empty(&oidc.token_exchange_issuer).unwrap_or_else(|| issuer.clone()));
        Some(lore_transport::Oidc {
            issuer,
            client_id: oidc.client_id.clone(),
            scopes: oidc.scopes.clone(),
            preferred: oidc.preferred || auth_url.is_none(),
            resource_template,
            scope_template,
            token_exchange_issuer,
        })
    }

    fn resolve_clients(
        settings: &[ClientCredentialSettings],
    ) -> Result<Vec<ClientCredential>, LocalAuthError> {
        let mut clients: Vec<ClientCredential> = Vec::with_capacity(settings.len());
        for entry in settings {
            if entry.client_id.is_empty() {
                return Err(LocalAuthError::InvalidClientCredential(
                    "client_id must not be empty".to_string(),
                ));
            }
            if clients.iter().any(|c| c.client_id == entry.client_id) {
                return Err(LocalAuthError::InvalidClientCredential(format!(
                    "duplicate client_id '{}'",
                    entry.client_id
                )));
            }
            let secret = match (entry.secret_path.as_deref(), entry.secret.as_deref()) {
                (Some(path), None) => std::fs::read_to_string(path)
                    .map_err(|e| {
                        LocalAuthError::InvalidClientCredential(format!(
                            "client '{}': failed to read secret_path {path}: {e}",
                            entry.client_id
                        ))
                    })?
                    .trim()
                    .to_string(),
                (None, Some(secret)) => secret.to_string(),
                _ => {
                    return Err(LocalAuthError::InvalidClientCredential(format!(
                        "client '{}': set exactly one of secret_path and secret",
                        entry.client_id
                    )));
                }
            };
            if secret.is_empty() {
                return Err(LocalAuthError::InvalidClientCredential(format!(
                    "client '{}': secret is empty",
                    entry.client_id
                )));
            }
            clients.push(ClientCredential {
                client_id: entry.client_id.clone(),
                secret,
                name: entry.name.clone(),
            });
        }
        Ok(clients)
    }

    /// Verify a `client_credentials` grant. Returns the machine identity
    /// (`client:<client_id>`) on a matching id and secret, `None`
    /// otherwise — the caller must not distinguish an unknown client from
    /// a wrong secret.
    pub fn verify_client(&self, client_id: &str, client_secret: &str) -> Option<ExternalIdentity> {
        let client = self.clients.iter().find(|c| c.client_id == client_id)?;
        // Compare digests rather than the secrets themselves: a plain
        // comparison's early exit would leak the matching prefix length,
        // while digest bytes are unpredictable to the caller.
        let digest = |value: &str| ring::digest::digest(&ring::digest::SHA256, value.as_bytes());
        if digest(&client.secret).as_ref() != digest(client_secret).as_ref() {
            return None;
        }
        Some(ExternalIdentity {
            subject: client.client_id.clone(),
            email: None,
            display_name: client.name.clone(),
            idp: CLIENT_IDP.to_string(),
        })
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
            mode @ ("google" | "oidc" | "cognito") => {
                let oidc_settings = settings
                    .oidc
                    .as_ref()
                    .ok_or_else(|| LocalAuthError::MissingOidcSettings(mode.to_string()))?;
                let callback_url = Self::callback_url(&settings.callback_base_url)?;
                let backend = Arc::new(ReqwestOidcBackend);
                let provider = match mode {
                    "google" => google_provider(oidc_settings, &callback_url, backend)?,
                    "cognito" => crate::auth::provider::cognito::cognito_provider(
                        oidc_settings,
                        &callback_url,
                        backend,
                    )?,
                    _ => generic_oidc_provider(oidc_settings, &callback_url, backend)?,
                };
                Ok(Arc::new(provider))
            }
            other => Err(LocalAuthError::UnknownProvider(other.to_string())),
        }
    }

    /// `<callback_base_url>/auth/callback` — the redirect URI registered
    /// with the identity provider.
    fn callback_url(callback_base_url: &str) -> Result<String, LocalAuthError> {
        let base = url::Url::parse(callback_base_url)
            .map_err(|e| LocalAuthError::InvalidCallbackBase(e.to_string()))?;
        let callback = base
            .join("/auth/callback")
            .map_err(|e| LocalAuthError::InvalidCallbackBase(e.to_string()))?;
        Ok(callback.to_string())
    }

    /// Rebuild with a different identity provider, sharing everything
    /// else. For tests that swap in a mock provider backend.
    pub fn with_provider(&self, provider: Arc<dyn AuthProvider>) -> Self {
        Self {
            provider,
            minter: self.minter.clone(),
            sessions: self.sessions.clone(),
            verifier: self.verifier.clone(),
            clients: self.clients.clone(),
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
                let mut minted = self.minter.mint_user_token(&identity)?;
                // Long-lived sessions: hand out a rotating refresh token
                // alongside the short-lived user token.
                if let Some(refresh) = crate::auth::refresh::installed() {
                    match refresh.issue(&identity).await {
                        Ok(token) => minted.refresh_token = Some(token),
                        Err(error) => {
                            warn!(%error, "Failed to issue refresh token; continuing without");
                        }
                    }
                }
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
