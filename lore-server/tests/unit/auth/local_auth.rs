// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::auth::local_auth::*;
use lore_server::auth::minting::TokenMintingSettings;
use lore_server::auth::provider::AuthProviderError;
use lore_server::auth::provider::CallbackParams;
use lore_server::auth::provider::static_provider::StaticProviderSettings;
use lore_server::auth::provider::static_provider::StaticUserSettings;
use lore_server::auth::session::SessionError;
use lore_server::settings::AuthSettings;
use lore_server::settings::OidcSettings;

pub(crate) fn test_auth_settings(dir: &std::path::Path) -> AuthSettings {
    AuthSettings {
        jwk: None,
        jwt_audience: None,
        jwt_issuer: None,
        jwt_typ: None,
        token: Some(TokenMintingSettings {
            signing_key_path: Some(dir.join("key.pem").to_string_lossy().to_string()),
            generate_signing_key: true,
            issuer: "https://lore.example.com".to_string(),
            audience: vec!["lore.example.com".to_string()],
            user_token_ttl_seconds: 3600,
            authz_token_ttl_seconds: 900,
            refresh_token_ttl_seconds: 3600,
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
            oidc: None,
        }),
        server_admins: Vec::new(),
        clients: Vec::new(),
        permission_claim: None,
        resource_claim: None,
        resource_id_template: AuthSettings::default_resource_id_template(),
        resource_id_claim: AuthSettings::default_resource_id_claim(),
        resource_wildcard: AuthSettings::default_resource_wildcard(),
        baseline_access: lore_server::settings::BaselineAccess::default(),
        repository_catalog: None,
        repository_catalog_url: None,
        oidc: None,
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
        jwt_typ: None,
        token: None,
        provider: None,
        server_admins: Vec::new(),
        clients: Vec::new(),
        permission_claim: None,
        resource_claim: None,
        resource_id_template: AuthSettings::default_resource_id_template(),
        resource_id_claim: AuthSettings::default_resource_id_claim(),
        resource_wildcard: AuthSettings::default_resource_wildcard(),
        baseline_access: lore_server::settings::BaselineAccess::default(),
        repository_catalog: None,
        repository_catalog_url: None,
        oidc: None,
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
    both_verifiers.jwk = Some(lore_server::auth::jwk::JWKServiceSettings {
        endpoint: Some("https://idp.example.com/jwks".to_string()),
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

    let mut no_static = full.clone();
    no_static
        .provider
        .as_mut()
        .expect("provider")
        .static_provider = None;
    assert!(matches!(
        LocalAuth::from_settings(Some(&no_static)),
        Err(LocalAuthError::MissingStaticSettings)
    ));

    let mut google_without_oidc = full;
    google_without_oidc
        .provider
        .as_mut()
        .expect("provider")
        .mode = "google".to_string();
    assert!(matches!(
        LocalAuth::from_settings(Some(&google_without_oidc)),
        Err(LocalAuthError::MissingOidcSettings(_))
    ));
}

#[test]
fn google_mode_builds_with_oidc_settings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let secret_path = dir.path().join("client-secret");
    std::fs::write(&secret_path, "secret").expect("write");

    let mut settings = test_auth_settings(dir.path());
    let provider = settings.provider.as_mut().expect("provider");
    provider.mode = "google".to_string();
    provider.static_provider = None;
    provider.oidc = Some(lore_server::auth::provider::google::OidcProviderSettings {
        client_id: "client-id".to_string(),
        client_secret_path: secret_path.to_string_lossy().to_string(),
        discovery_url: None,
        extra_scopes: vec![],
        hosted_domain: None,
        trusted_external_audiences: vec![],
        region: None,
        user_pool_id: None,
    });

    let auth = LocalAuth::from_settings(Some(&settings))
        .expect("build")
        .expect("enabled");
    assert_eq!(auth.provider.name(), "google");
}

fn client(id: &str, secret: Option<&str>, secret_path: Option<&str>) -> ClientCredentialSettings {
    ClientCredentialSettings {
        client_id: id.to_string(),
        secret_path: secret_path.map(str::to_string),
        secret: secret.map(str::to_string),
        name: Some("CI".to_string()),
    }
}

#[test]
fn client_credentials_verify_and_validation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut settings = test_auth_settings(dir.path());
    let secret_file = dir.path().join("ci-secret");
    std::fs::write(&secret_file, "from-file\n").expect("write");
    settings.clients = vec![
        client("ci-inline", Some("s3cret"), None),
        client("ci-file", None, Some(&secret_file.to_string_lossy())),
    ];
    let auth = LocalAuth::from_settings(Some(&settings))
        .expect("build")
        .expect("enabled");

    let identity = auth.verify_client("ci-inline", "s3cret").expect("verify");
    assert_eq!(identity.user_id(), "client:ci-inline");
    assert_eq!(identity.idp, CLIENT_IDP);
    // File secrets are trimmed of the trailing newline.
    assert!(auth.verify_client("ci-file", "from-file").is_some());

    assert!(auth.verify_client("ci-inline", "wrong").is_none());
    assert!(auth.verify_client("unknown", "s3cret").is_none());

    // Validation failures.
    let reject = |clients: Vec<ClientCredentialSettings>| {
        let mut bad = test_auth_settings(dir.path());
        bad.clients = clients;
        assert!(matches!(
            LocalAuth::from_settings(Some(&bad)),
            Err(LocalAuthError::InvalidClientCredential(_))
        ));
    };
    reject(vec![client("ci", None, None)]);
    reject(vec![client(
        "ci",
        Some("both"),
        Some(&secret_file.to_string_lossy()),
    )]);
    reject(vec![client("", Some("s3cret"), None)]);
    reject(vec![client("ci", Some(""), None)]);
    reject(vec![
        client("ci", Some("a"), None),
        client("ci", Some("b"), None),
    ]);

    // Clients without token minting is a startup error, not a no-op.
    let mut clients_only = test_auth_settings(dir.path());
    clients_only.token = None;
    clients_only.provider = None;
    clients_only.clients = vec![client("ci", Some("s3cret"), None)];
    assert!(matches!(
        LocalAuth::from_settings(Some(&clients_only)),
        Err(LocalAuthError::ClientsRequireTokenSettings)
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

fn oidc_settings() -> OidcSettings {
    OidcSettings {
        client_id: "lore-cli".to_string(),
        scopes: vec!["openid".to_string()],
        preferred: false,
        resource_template: None,
        scope_template: None,
        token_exchange_issuer: None,
    }
}

fn self_issuer(
    dir: &std::path::Path,
    issuer: &str,
    oidc: Option<OidcSettings>,
) -> (LocalAuth, AuthSettings) {
    let mut settings = test_auth_settings(dir);
    if let Some(token) = settings.token.as_mut() {
        token.issuer = issuer.to_string();
    }
    settings.oidc = oidc;
    let auth = LocalAuth::from_settings(Some(&settings))
        .expect("build")
        .expect("enabled");
    (auth, settings)
}

/// Without `[server.auth.oidc]` the server advertises no OIDC provider, so
/// clients keep the gRPC login.
#[test]
fn self_issuer_advertises_nothing_without_oidc_block() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (auth, settings) = self_issuer(dir.path(), "https://lore.example.com", None);
    assert!(
        auth.advertised_oidc(&settings, Some("ucs-auth://lore.example.com:41337"))
            .is_none()
    );
}

/// The advertised issuer is the one `/.well-known/openid-configuration`
/// reports (no trailing slash), and stays non-preferred while `auth_url`
/// serves stock clients.
#[test]
fn self_issuer_advertises_its_own_issuer_without_preference() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (auth, settings) = self_issuer(
        dir.path(),
        "https://lore.example.com/",
        Some(oidc_settings()),
    );
    let oidc = auth
        .advertised_oidc(&settings, Some("ucs-auth://lore.example.com:41337"))
        .expect("advertised");
    assert_eq!(oidc.issuer, "https://lore.example.com");
    assert_eq!(oidc.client_id, "lore-cli");
    assert_eq!(oidc.scopes, vec!["openid".to_string()]);
    assert!(!oidc.preferred);
    assert!(oidc.token_exchange_issuer.is_none());
}

#[test]
fn self_issuer_is_preferred_without_auth_url() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (auth, settings) = self_issuer(
        dir.path(),
        "https://lore.example.com",
        Some(oidc_settings()),
    );
    let oidc = auth.advertised_oidc(&settings, None).expect("advertised");
    assert!(oidc.preferred);
}

/// Tier 2 points token exchange at this server unless told otherwise.
#[test]
fn self_issuer_tier_2_exchanges_with_itself() {
    let dir = tempfile::tempdir().expect("tempdir");
    let oidc = OidcSettings {
        resource_template: Some("urc-{id}".to_string()),
        ..oidc_settings()
    };
    let (auth, settings) = self_issuer(dir.path(), "https://lore.example.com", Some(oidc));
    let oidc = auth
        .advertised_oidc(&settings, Some("ucs-auth://lore.example.com:41337"))
        .expect("advertised");
    assert_eq!(
        oidc.token_exchange_issuer.as_deref(),
        Some("https://lore.example.com")
    );
}

/// An issuer clients cannot fetch discovery from is not advertised.
#[test]
fn self_issuer_with_non_http_issuer_is_not_advertised() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (auth, settings) = self_issuer(dir.path(), "lore-local", Some(oidc_settings()));
    assert!(auth.advertised_oidc(&settings, None).is_none());
}
