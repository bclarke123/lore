// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Generic OpenID Connect identity provider.
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
            .user_agent(lore_transport::grpc::user_agent())
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
            .user_agent(lore_transport::grpc::user_agent())
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
                endpoint: jwks_uri.to_string(),
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

    /// Validate the ID token: signature (via JWKS), `iss`, `aud`, `exp`,
    /// and the session `nonce`.
    async fn validate_id_token(
        &self,
        id_token: &str,
        issuer: &str,
        jwks: &Arc<dyn JWKService>,
        session: &PendingSession,
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
        validation.set_audience(&[&self.config.client_id]);
        validation.validate_exp = true;

        let token = jsonwebtoken::decode::<IdTokenClaims>(id_token, &key, &validation)
            .map_err(|e| AuthProviderError::Denied(format!("ID token validation failed: {e}")))?;

        // Replay protection: the token must carry the nonce minted for this
        // login session.
        if token.claims.nonce.as_deref() != Some(session.nonce.as_str()) {
            return Err(AuthProviderError::Denied(
                "ID token nonce does not match the login session".to_string(),
            ));
        }
        Ok(token.claims)
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
}

/// Test support: an in-memory OIDC backend with an HS256-signed token
/// factory, shared by the oidc/google/cognito provider tests.
#[cfg(test)]
pub(crate) mod test_support {
    use jsonwebtoken::DecodingKey;
    use parking_lot::Mutex;

    use super::*;
    use crate::auth::jwk::JWKServiceError;

    pub const SIGNING_SECRET: &str = "oidc-test-secret";
    pub const KID: &str = "test-kid";
    pub const ISSUER: &str = "https://idp.example.com";
    pub const CLIENT_ID: &str = "lore-client-id";

    pub fn discovery() -> DiscoveryDocument {
        DiscoveryDocument {
            issuer: ISSUER.to_string(),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            jwks_uri: format!("{ISSUER}/jwks"),
        }
    }

    pub struct StaticJwkService;

    #[async_trait]
    impl JWKService for StaticJwkService {
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
            if kid != KID {
                return Err(JWKServiceError::NotFound);
            }
            Ok((
                DecodingKey::from_secret(SIGNING_SECRET.as_ref()),
                jsonwebtoken::Algorithm::HS256,
            ))
        }
    }

    /// Signs an ID token with the test secret.
    pub fn id_token(claims: &serde_json::Value) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        jsonwebtoken::encode(
            &header,
            claims,
            &jsonwebtoken::EncodingKey::from_secret(SIGNING_SECRET.as_ref()),
        )
        .expect("encode test token")
    }

    pub fn valid_claims(nonce: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "google-subject-1",
            "exp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs() + 300,
            "nonce": nonce,
            "email": "alice@example.com",
            "email_verified": true,
            "name": "Alice Example",
            "hd": "example.com",
        })
    }

    /// Backend returning canned discovery + token responses and recording
    /// the exchange form for assertions.
    pub struct MockBackend {
        pub id_token: Mutex<Option<String>>,
        pub last_exchange_form: Mutex<Option<Vec<(String, String)>>>,
        pub fail_exchange: bool,
    }

    impl MockBackend {
        pub fn new() -> Self {
            Self {
                id_token: Mutex::new(None),
                last_exchange_form: Mutex::new(None),
                fail_exchange: false,
            }
        }
    }

    #[async_trait]
    impl OidcBackend for MockBackend {
        async fn fetch_discovery(
            &self,
            _url: &str,
        ) -> Result<DiscoveryDocument, AuthProviderError> {
            Ok(discovery())
        }

        async fn exchange_code(
            &self,
            _token_endpoint: &str,
            form: &[(&str, &str)],
        ) -> Result<TokenResponse, AuthProviderError> {
            if self.fail_exchange {
                return Err(AuthProviderError::Upstream("exchange refused".to_string()));
            }
            *self.last_exchange_form.lock() = Some(
                form.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            );
            let id_token = self
                .id_token
                .lock()
                .clone()
                .expect("test set an id_token before exchanging");
            Ok(TokenResponse { id_token })
        }

        fn jwk_service(&self, _jwks_uri: &str) -> Arc<dyn JWKService> {
            Arc::new(StaticJwkService)
        }
    }

    pub fn config() -> OidcConfig {
        OidcConfig {
            idp: "test-oidc",
            discovery_url: format!("{ISSUER}/.well-known/openid-configuration"),
            client_id: CLIENT_ID.to_string(),
            client_secret: "the-client-secret".to_string(),
            redirect_uri: "http://localhost:8080/auth/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            extra_auth_params: vec![],
            require_verified_email: true,
            hosted_domain: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::auth::session::SessionManager;

    fn session() -> PendingSession {
        SessionManager::new()
            .create("client-state")
            .expect("create")
    }

    fn params(pairs: &[(&str, &str)]) -> CallbackParams {
        CallbackParams {
            params: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn provider_with(backend: Arc<MockBackend>, config: OidcConfig) -> OidcProvider {
        OidcProvider::new(config, backend)
    }

    #[tokio::test]
    async fn begin_login_builds_authorization_url() {
        let provider = provider_with(Arc::new(MockBackend::new()), config());
        let session = session();
        let url = provider.begin_login(&session).await.expect("begin");

        assert!(url.as_str().starts_with(&format!("{ISSUER}/authorize?")));
        let query: std::collections::HashMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["redirect_uri"], "http://localhost:8080/auth/callback");
        assert_eq!(query["scope"], "openid email profile");
        assert_eq!(query["state"], session.csrf_state);
        assert_eq!(query["nonce"], session.nonce);
        assert_eq!(query["code_challenge_method"], "S256");
        assert_eq!(
            query["code_challenge"],
            pkce_challenge_s256(&session.pkce_verifier)
        );
    }

    #[tokio::test]
    async fn extra_auth_params_are_appended() {
        let mut config = config();
        config
            .extra_auth_params
            .push(("hd".to_string(), "example.com".to_string()));
        let provider = provider_with(Arc::new(MockBackend::new()), config);
        let url = provider.begin_login(&session()).await.expect("begin");
        assert!(url.query().unwrap_or_default().contains("hd=example.com"));
    }

    #[tokio::test]
    async fn complete_login_happy_path() {
        let backend = Arc::new(MockBackend::new());
        let provider = provider_with(backend.clone(), config());
        let session = session();
        *backend.id_token.lock() = Some(id_token(&valid_claims(&session.nonce)));

        let identity = provider
            .complete_login(&session, &params(&[("code", "auth-code-1")]))
            .await
            .expect("login");
        assert_eq!(identity.subject, "google-subject-1");
        assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
        assert_eq!(identity.display_name.as_deref(), Some("Alice Example"));
        assert_eq!(identity.idp, "test-oidc");

        // The exchange carried the code, secret, and PKCE verifier.
        let form = backend.last_exchange_form.lock().clone().expect("form");
        let get = |key: &str| {
            form.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        assert_eq!(get("grant_type"), "authorization_code");
        assert_eq!(get("code"), "auth-code-1");
        assert_eq!(get("client_secret"), "the-client-secret");
        assert_eq!(get("code_verifier"), session.pkce_verifier);
    }

    #[tokio::test]
    async fn provider_error_param_is_denied() {
        let provider = provider_with(Arc::new(MockBackend::new()), config());
        let err = provider
            .complete_login(
                &session(),
                &params(&[("error", "access_denied"), ("error_description", "nope")]),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(message) if message == "nope"));
    }

    #[tokio::test]
    async fn missing_code_is_invalid() {
        let provider = provider_with(Arc::new(MockBackend::new()), config());
        let err = provider
            .complete_login(&session(), &params(&[]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Invalid(_)));
    }

    #[tokio::test]
    async fn exchange_failure_is_upstream() {
        let backend = Arc::new(MockBackend {
            fail_exchange: true,
            ..MockBackend::new()
        });
        let provider = provider_with(backend, config());
        let err = provider
            .complete_login(&session(), &params(&[("code", "c")]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Upstream(_)));
    }

    async fn expect_denied(mutate: impl FnOnce(&mut serde_json::Value)) {
        let backend = Arc::new(MockBackend::new());
        let provider = provider_with(backend.clone(), config());
        let session = session();
        let mut claims = valid_claims(&session.nonce);
        mutate(&mut claims);
        *backend.id_token.lock() = Some(id_token(&claims));

        let err = provider
            .complete_login(&session, &params(&[("code", "c")]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn wrong_nonce_is_denied() {
        expect_denied(|claims| claims["nonce"] = "other-nonce".into()).await;
    }

    #[tokio::test]
    async fn missing_nonce_is_denied() {
        expect_denied(|claims| {
            claims.as_object_mut().expect("object").remove("nonce");
        })
        .await;
    }

    #[tokio::test]
    async fn wrong_issuer_audience_or_expired_is_denied() {
        expect_denied(|claims| claims["iss"] = "https://evil.example.com".into()).await;
        expect_denied(|claims| claims["aud"] = "other-client".into()).await;
        expect_denied(|claims| claims["exp"] = 1000.into()).await;
    }

    #[tokio::test]
    async fn unverified_email_is_denied() {
        expect_denied(|claims| claims["email_verified"] = false.into()).await;
        expect_denied(|claims| {
            claims
                .as_object_mut()
                .expect("object")
                .remove("email_verified");
        })
        .await;
    }

    #[tokio::test]
    async fn hosted_domain_mismatch_is_denied() {
        let backend = Arc::new(MockBackend::new());
        let mut config = config();
        config.hosted_domain = Some("corp.example.com".to_string());
        let provider = provider_with(backend.clone(), config);
        let session = session();
        // Claims carry hd = example.com.
        *backend.id_token.lock() = Some(id_token(&valid_claims(&session.nonce)));

        let err = provider
            .complete_login(&session, &params(&[("code", "c")]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)));
    }

    #[tokio::test]
    async fn token_signed_by_unknown_key_is_refused() {
        let backend = Arc::new(MockBackend::new());
        let provider = provider_with(backend.clone(), config());
        let session = session();

        // Sign with a different kid so JWKS lookup fails.
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("unknown-kid".to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &valid_claims(&session.nonce),
            &jsonwebtoken::EncodingKey::from_secret(b"attacker-secret"),
        )
        .expect("encode");
        *backend.id_token.lock() = Some(forged);

        let err = provider
            .complete_login(&session, &params(&[("code", "c")]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Upstream(_)));
    }

    #[tokio::test]
    async fn token_with_bad_signature_is_denied() {
        let backend = Arc::new(MockBackend::new());
        let provider = provider_with(backend.clone(), config());
        let session = session();

        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &valid_claims(&session.nonce),
            &jsonwebtoken::EncodingKey::from_secret(b"attacker-secret"),
        )
        .expect("encode");
        *backend.id_token.lock() = Some(forged);

        let err = provider
            .complete_login(&session, &params(&[("code", "c")]))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)));
    }

    #[test]
    fn pkce_challenge_matches_rfc_7636_appendix_b() {
        // RFC 7636 Appendix B test vector.
        assert_eq!(
            pkce_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn pkce_verifier_length_meets_rfc_7636() {
        let session = session();
        assert!((43..=128).contains(&session.pkce_verifier.len()));
    }
}
