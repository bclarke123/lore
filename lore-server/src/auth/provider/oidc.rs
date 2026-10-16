// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Generic `OpenID` Connect identity provider.
//!
//! Implements the Authorization Code flow with PKCE (RFC 7636): the login
//! URL sends the browser to the provider's authorization endpoint, and the
//! callback exchanges the returned code at the token endpoint (the client
//! secret never leaves the server), then validates the ID token — signature
//! via the provider's JWKS, plus issuer, audience, expiry, and nonce.
//!
//! Provider presets ([`google`](super::google), and Cognito in follow-up
//! work) are thin configuration layers over this type.

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use serde::Deserialize;
use tokio::sync::OnceCell;
use url::Url;

use super::AuthProvider;
use super::AuthProviderError;
use super::CallbackParams;
use super::ExternalIdentity;
use crate::auth::jwk::JWKService;
use crate::auth::session::PendingSession;

/// The subset of the OIDC discovery document this provider uses.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct DiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// The subset of the token-endpoint response this provider uses.
#[derive(Clone, Debug, Deserialize)]
pub struct TokenResponse {
    pub id_token: String,
}

/// Network operations behind the OIDC flow, separated so unit tests can
/// run the full provider logic without a live identity provider.
#[async_trait]
pub trait OidcBackend: Send + Sync {
    async fn fetch_discovery(&self, url: &str) -> Result<DiscoveryDocument, AuthProviderError>;

    /// POST the authorization-code exchange to the token endpoint.
    async fn exchange_code(
        &self,
        token_endpoint: &str,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse, AuthProviderError>;

    /// Key resolution for ID-token signature validation.
    fn jwk_service(&self, jwks_uri: &str) -> Arc<dyn JWKService>;
}

/// Production backend: reqwest for HTTP, [`JwkServiceImpl`] for JWKS.
pub struct ReqwestOidcBackend;

#[async_trait]
impl OidcBackend for ReqwestOidcBackend {
    async fn fetch_discovery(&self, url: &str) -> Result<DiscoveryDocument, AuthProviderError> {
        let client = reqwest::Client::builder()
            .user_agent(lore_transport::user_agent())
            .build()
            .map_err(|e| AuthProviderError::Internal(format!("http client: {e}")))?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| AuthProviderError::Upstream(format!("discovery fetch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(AuthProviderError::Upstream(format!(
                "discovery fetch returned {}",
                response.status()
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| AuthProviderError::Upstream(format!("discovery read failed: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| AuthProviderError::Upstream(format!("invalid discovery document: {e}")))
    }

    async fn exchange_code(
        &self,
        token_endpoint: &str,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse, AuthProviderError> {
        let client = reqwest::Client::builder()
            .user_agent(lore_transport::user_agent())
            .build()
            .map_err(|e| AuthProviderError::Internal(format!("http client: {e}")))?;
        let response = client
            .post(token_endpoint)
            .form(form)
            .send()
            .await
            .map_err(|e| AuthProviderError::Upstream(format!("code exchange failed: {e}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AuthProviderError::Upstream(format!(
                "code exchange returned {status}: {body}"
            )));
        }
        let body = response
            .text()
            .await
            .map_err(|e| AuthProviderError::Upstream(format!("token response read failed: {e}")))?;
        serde_json::from_str(&body)
            .map_err(|e| AuthProviderError::Upstream(format!("invalid token response: {e}")))
    }

    fn jwk_service(&self, jwks_uri: &str) -> Arc<dyn JWKService> {
        Arc::new(crate::auth::jwk::JwkServiceImpl::new(
            crate::auth::jwk::JWKServiceSettings {
                endpoint: Some(jwks_uri.to_string()),
            },
        ))
    }
}

/// Static configuration for an OIDC provider instance.
#[derive(Clone, Debug)]
pub struct OidcConfig {
    /// Provider name recorded as the `idp` of authenticated identities.
    pub idp: &'static str,
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Full redirect URI registered with the provider
    /// (`<callback_base_url>/auth/callback`).
    pub redirect_uri: String,
    /// OAuth scopes; `openid` is required by OIDC.
    pub scopes: Vec<String>,
    /// Extra query parameters for the authorization URL (e.g. Google `hd`).
    pub extra_auth_params: Vec<(String, String)>,
    /// Refuse identities whose `email_verified` claim is not `true`.
    pub require_verified_email: bool,
    /// Refuse identities whose `hd` (hosted domain) claim differs.
    pub hosted_domain: Option<String>,
    /// Additional `aud` values accepted on *externally obtained* ID tokens
    /// presented to `ExchangeExternalTokenForUserToken` (e.g. a web hub's
    /// own OAuth client id). Empty = external exchange disabled.
    pub trusted_external_audiences: Vec<String>,
}

/// ID-token claims this provider validates or maps to [`ExternalIdentity`].
#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    hd: Option<String>,
}

pub struct OidcProvider {
    config: OidcConfig,
    backend: Arc<dyn OidcBackend>,
    /// Discovery document and JWKS handle, fetched lazily on first use.
    discovery: OnceCell<(DiscoveryDocument, Arc<dyn JWKService>)>,
}

/// PKCE S256 code challenge: BASE64URL(SHA256(verifier)), unpadded.
#[lore_macro::test_pub]
fn pkce_challenge_s256(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest.as_ref())
}

impl OidcProvider {
    pub fn new(config: OidcConfig, backend: Arc<dyn OidcBackend>) -> Self {
        Self {
            config,
            backend,
            discovery: OnceCell::new(),
        }
    }

    async fn discovery(
        &self,
    ) -> Result<&(DiscoveryDocument, Arc<dyn JWKService>), AuthProviderError> {
        self.discovery
            .get_or_try_init(|| async {
                let document = self
                    .backend
                    .fetch_discovery(&self.config.discovery_url)
                    .await?;
                let jwks = self.backend.jwk_service(&document.jwks_uri);
                Ok((document, jwks))
            })
            .await
    }

    /// Decode an ID token and validate signature (via JWKS), `iss`, `exp`,
    /// and membership of `aud` in `audiences`. Nonce handling is the
    /// caller's concern.
    async fn decode_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        jwks: &Arc<dyn JWKService>,
        audiences: &[&str],
    ) -> Result<IdTokenClaims, AuthProviderError> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| AuthProviderError::Denied(format!("invalid ID token header: {e}")))?;
        let kid = header
            .kid
            .ok_or_else(|| AuthProviderError::Denied("ID token has no key id".to_string()))?;
        let (key, algorithm) = jwks
            .get_key(&kid)
            .await
            .map_err(|e| AuthProviderError::Upstream(format!("JWKS key lookup failed: {e}")))?;

        let mut validation = jsonwebtoken::Validation::new(algorithm);
        validation.set_issuer(&[issuer]);
        validation.set_audience(audiences);
        validation.validate_exp = true;

        let token = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| AuthProviderError::Denied(format!("ID token validation failed: {e}")))?;
        Ok(token.claims)
    }

    /// Validate the ID token: signature (via JWKS), `iss`, `aud`, `exp`,
    /// and the session `nonce`.
    async fn validate_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        jwks: &Arc<dyn JWKService>,
        session: &PendingSession,
    ) -> Result<IdTokenClaims, AuthProviderError> {
        let claims = self
            .decode_id_token(id_token, issuer, jwks, &[self.config.client_id.as_str()])
            .await?;

        // Replay protection: the token must carry the nonce minted for this
        // login session.
        if claims.nonce.as_deref() != Some(session.nonce.as_str()) {
            return Err(AuthProviderError::Denied(
                "ID token nonce does not match the login session".to_string(),
            ));
        }
        Ok(claims)
    }

    fn check_identity_policy(&self, claims: &IdTokenClaims) -> Result<(), AuthProviderError> {
        if self.config.require_verified_email && claims.email_verified != Some(true) {
            return Err(AuthProviderError::Denied(
                "account email is not verified".to_string(),
            ));
        }
        if let Some(required) = self.config.hosted_domain.as_deref()
            && claims.hd.as_deref() != Some(required)
        {
            return Err(AuthProviderError::Denied(format!(
                "account is not in the required domain '{required}'"
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl AuthProvider for OidcProvider {
    fn name(&self) -> &'static str {
        self.config.idp
    }

    async fn begin_login(&self, session: &PendingSession) -> Result<Url, AuthProviderError> {
        let (discovery, _) = self.discovery().await?;
        let mut url = Url::parse(&discovery.authorization_endpoint).map_err(|e| {
            AuthProviderError::Upstream(format!("invalid authorization endpoint: {e}"))
        })?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.config.client_id)
            .append_pair("redirect_uri", &self.config.redirect_uri)
            .append_pair("scope", &self.config.scopes.join(" "))
            .append_pair("state", &session.csrf_state)
            .append_pair("nonce", &session.nonce)
            .append_pair(
                "code_challenge",
                &pkce_challenge_s256(&session.pkce_verifier),
            )
            .append_pair("code_challenge_method", "S256");
        for (key, value) in &self.config.extra_auth_params {
            url.query_pairs_mut().append_pair(key, value);
        }
        Ok(url)
    }

    async fn complete_login(
        &self,
        session: &PendingSession,
        params: &CallbackParams,
    ) -> Result<ExternalIdentity, AuthProviderError> {
        // The provider signals user-facing failures (declined consent,
        // policy) via an `error` parameter instead of a code.
        if let Some(error) = params.get("error") {
            let description = params.get("error_description").unwrap_or(error);
            return Err(AuthProviderError::Denied(description.to_string()));
        }
        let code = params
            .get("code")
            .ok_or_else(|| AuthProviderError::Invalid("missing 'code' parameter".to_string()))?;

        let (discovery, jwks) = self.discovery().await?;
        let response = self
            .backend
            .exchange_code(
                &discovery.token_endpoint,
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", &self.config.client_id),
                    ("client_secret", &self.config.client_secret),
                    ("redirect_uri", &self.config.redirect_uri),
                    ("code_verifier", &session.pkce_verifier),
                ],
            )
            .await?;

        let claims = self
            .validate_id_token(&response.id_token, &discovery.issuer, jwks, session)
            .await?;
        self.check_identity_policy(&claims)?;

        Ok(ExternalIdentity {
            subject: claims.sub,
            email: claims.email,
            display_name: claims.name,
            idp: self.config.idp.to_string(),
        })
    }

    /// Verify an *externally obtained* ID token (no login session, so no
    /// nonce): signature via the provider's JWKS, `iss`, `exp`, and `aud`
    /// restricted to the explicitly trusted external audiences. Disabled
    /// (Unsupported) unless `trusted_external_audiences` is configured.
    async fn verify_external_id_token(
        &self,
        id_token: &str,
    ) -> Result<ExternalIdentity, AuthProviderError> {
        if self.config.trusted_external_audiences.is_empty() {
            return Err(AuthProviderError::Unsupported(
                "no trusted external audiences configured".to_string(),
            ));
        }
        let (discovery, jwks) = self.discovery().await?;
        let audiences: Vec<&str> = self
            .config
            .trusted_external_audiences
            .iter()
            .map(String::as_str)
            .collect();
        let claims = self
            .decode_id_token(id_token, &discovery.issuer, jwks, &audiences)
            .await?;
        self.check_identity_policy(&claims)?;

        Ok(ExternalIdentity {
            subject: claims.sub,
            email: claims.email,
            display_name: claims.name,
            idp: self.config.idp.to_string(),
        })
    }
}
