// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::provider::AuthProvider;
use lore_server::auth::provider::AuthProviderError;
use lore_server::auth::provider::CallbackParams;
use lore_server::auth::provider::oidc::*;
use lore_server::auth::session::PendingSession;
use lore_server::auth::session::SessionManager;
use test_support::*;

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

mod external_id_token {
    use super::*;

    const HUB_CLIENT_ID: &str = "lorehub-client-id";

    fn provider_trusting_hub() -> OidcProvider {
        let mut config = config();
        config.trusted_external_audiences = vec![HUB_CLIENT_ID.to_string()];
        provider_with(Arc::new(MockBackend::new()), config)
    }

    /// Claims as a hub-obtained Google ID token would carry: the hub's
    /// client id as `aud`, and no nonce.
    fn hub_claims() -> serde_json::Value {
        let mut claims = valid_claims("unused-nonce");
        claims["aud"] = HUB_CLIENT_ID.into();
        claims.as_object_mut().expect("object").remove("nonce");
        claims
    }

    #[tokio::test]
    async fn trusted_audience_token_yields_identity() {
        let provider = provider_trusting_hub();
        let identity = provider
            .verify_external_id_token(&id_token(&hub_claims()))
            .await
            .expect("verify");
        assert_eq!(identity.subject, "google-subject-1");
        assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
        assert_eq!(identity.idp, "test-oidc");
    }

    #[tokio::test]
    async fn disabled_without_trusted_audiences() {
        let provider = provider_with(Arc::new(MockBackend::new()), config());
        let err = provider
            .verify_external_id_token(&id_token(&hub_claims()))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Unsupported(_)));
    }

    #[tokio::test]
    async fn untrusted_audience_is_denied() {
        let provider = provider_trusting_hub();
        let mut claims = hub_claims();
        claims["aud"] = "some-other-app".into();
        let err = provider
            .verify_external_id_token(&id_token(&claims))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)));

        // The provider's own login client id is NOT implicitly trusted
        // for external exchange.
        let mut own = hub_claims();
        own["aud"] = CLIENT_ID.into();
        let err = provider
            .verify_external_id_token(&id_token(&own))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthProviderError::Denied(_)));
    }

    #[tokio::test]
    async fn expired_or_wrong_issuer_is_denied() {
        let provider = provider_trusting_hub();
        let mut expired = hub_claims();
        expired["exp"] = 1000.into();
        assert!(matches!(
            provider
                .verify_external_id_token(&id_token(&expired))
                .await
                .unwrap_err(),
            AuthProviderError::Denied(_)
        ));

        let mut wrong_iss = hub_claims();
        wrong_iss["iss"] = "https://evil.example.com".into();
        assert!(matches!(
            provider
                .verify_external_id_token(&id_token(&wrong_iss))
                .await
                .unwrap_err(),
            AuthProviderError::Denied(_)
        ));
    }

    #[tokio::test]
    async fn bad_signature_is_denied() {
        let provider = provider_trusting_hub();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let forged = jsonwebtoken::encode(
            &header,
            &hub_claims(),
            &jsonwebtoken::EncodingKey::from_secret(b"attacker-secret"),
        )
        .expect("encode");
        assert!(matches!(
            provider
                .verify_external_id_token(&forged)
                .await
                .unwrap_err(),
            AuthProviderError::Denied(_)
        ));
    }

    #[tokio::test]
    async fn identity_policy_still_applies() {
        let provider = provider_trusting_hub();
        let mut unverified = hub_claims();
        unverified["email_verified"] = false.into();
        assert!(matches!(
            provider
                .verify_external_id_token(&id_token(&unverified))
                .await
                .unwrap_err(),
            AuthProviderError::Denied(_)
        ));
    }
}

/// Test support: an in-memory OIDC backend with an HS256-signed token
/// factory, shared by the oidc/google/cognito provider tests.
pub(crate) mod test_support {
    use jsonwebtoken::DecodingKey;
    use lore_server::auth::jwk::JWKServiceError;
    use parking_lot::Mutex;

    use super::*;

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
            self.get_cached_key(kid).ok_or(JWKServiceError::NotFound)
        }

        fn get_cached_key(&self, kid: &str) -> Option<(DecodingKey, jsonwebtoken::Algorithm)> {
            (kid == KID).then(|| {
                (
                    DecodingKey::from_secret(SIGNING_SECRET.as_ref()),
                    jsonwebtoken::Algorithm::HS256,
                )
            })
        }

        // The static test key never rotates; a refresh can only answer
        // "unchanged".
        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError> {
            Ok(None)
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
            trusted_external_audiences: vec![],
        }
    }
}
