// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::Response;
use lore_server::auth::local_auth::LocalAuth;
use lore_server::http::oauth::*;
use tower::ServiceExt;

/// The OAuth router merged with the login-door routes, as the server
/// mounts them, so the device flow can complete end to end.
fn router() -> (Arc<LocalAuth>, axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = crate::auth::local_auth::test_auth_settings(dir.path());
    let auth = Arc::new(
        LocalAuth::from_settings(Some(&settings))
            .expect("build")
            .expect("enabled"),
    );
    let router = lore_server::http::auth_login::create_router(auth.clone())
        .merge(create_router(auth.clone()).expect("oauth router"));
    (auth, router, dir)
}

async fn get(router: &axum::Router, uri: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .body(Body::empty())
                .expect("req"),
        )
        .await
        .expect("response");
    read(response).await
}

async fn post_form(router: &axum::Router, uri: &str, body: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body.to_string()))
                .expect("req"),
        )
        .await
        .expect("response");
    read(response).await
}

async fn read(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

fn json(body: &str) -> serde_json::Value {
    serde_json::from_str(body).expect("json")
}

#[tokio::test]
async fn discovery_document_names_the_endpoints() {
    let (_auth, router, _dir) = router();
    for path in [
        "/.well-known/openid-configuration",
        "/auth/.well-known/openid-configuration",
    ] {
        let (status, body) = get(&router, path).await;
        assert_eq!(status, StatusCode::OK);
        let doc = json(&body);
        assert_eq!(doc["issuer"], "https://lore.example.com");
        assert_eq!(doc["token_endpoint"], "https://lore.example.com/auth/token");
        assert_eq!(
            doc["device_authorization_endpoint"],
            "https://lore.example.com/auth/device_authorization"
        );
        assert_eq!(
            doc["jwks_uri"],
            "https://lore.example.com/auth/.well-known/jwks.json"
        );
        assert!(
            doc["grant_types_supported"]
                .as_array()
                .expect("grants")
                .iter()
                .any(|g| g == GRANT_TYPE_DEVICE_CODE)
        );
    }
}

#[tokio::test]
async fn device_flow_end_to_end() {
    let (auth, router, _dir) = router();

    // Device authorization.
    let (status, body) =
        post_form(&router, "/auth/device_authorization", "client_id=lore-cli").await;
    assert_eq!(status, StatusCode::OK);
    let response = json(&body);
    let device_code = response["device_code"].as_str().expect("device_code");
    let user_code = response["user_code"].as_str().expect("user_code");
    assert_eq!(response["interval"], 5);
    assert_eq!(
        response["verification_uri"],
        "https://lore.example.com/auth/device"
    );
    assert!(
        response["verification_uri_complete"]
            .as_str()
            .expect("uri")
            .contains("state=")
    );

    // Polling before approval: authorization_pending.
    let poll =
        format!("grant_type={GRANT_TYPE_DEVICE_CODE}&device_code={device_code}&client_id=lore-cli");
    let (status, body) = post_form(&router, "/auth/token", &poll).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "authorization_pending");

    // A mismatched client_id is rejected without consuming the session.
    let (status, body) = post_form(
        &router,
        "/auth/token",
        &format!("grant_type={GRANT_TYPE_DEVICE_CODE}&device_code={device_code}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_grant");

    // The verification page resolves the user code to the provider.
    let (status, _) = get(&router, &format!("/auth/device?user_code={user_code}")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);

    // The user approves in the browser (static provider form).
    let session = auth.sessions.for_user_code(user_code).expect("session");
    let (status, _) = get(
        &router,
        &format!(
            "/auth/callback?state={}&user=alice&secret=s3cret",
            session.csrf_state
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Polling now yields the token.
    let (status, body) = post_form(&router, "/auth/token", &poll).await;
    assert_eq!(status, StatusCode::OK);
    let response = json(&body);
    assert_eq!(response["token_type"], "Bearer");
    assert!(response["expires_in"].as_u64().expect("expires_in") > 0);
    let access_token = response["access_token"].as_str().expect("access_token");
    let claims = auth
        .verifier
        .verify_token(access_token)
        .await
        .expect("verify");
    assert_eq!(claims.user_id, "static:alice");

    // The code is one-shot.
    let (status, body) = post_form(&router, "/auth/token", &poll).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "expired_token");
}

#[tokio::test]
async fn device_page_renders_form_and_rejects_unknown_codes() {
    let (_auth, router, _dir) = router();
    let (status, body) = get(&router, "/auth/device").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("user_code"));

    let (status, body) = get(&router, "/auth/device?user_code=XXXX-XXXX").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("unknown or has expired"));
}

#[tokio::test]
async fn client_credentials_grant_mints_a_machine_token() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut settings = crate::auth::local_auth::test_auth_settings(dir.path());
    settings
        .clients
        .push(lore_server::auth::local_auth::ClientCredentialSettings {
            client_id: "ci-builder".to_string(),
            secret_path: None,
            secret: Some("machine-s3cret".to_string()),
            name: Some("CI Builder".to_string()),
        });
    let auth = Arc::new(
        LocalAuth::from_settings(Some(&settings))
            .expect("build")
            .expect("enabled"),
    );
    let router = create_router(auth.clone()).expect("oauth router");

    let (status, body) = post_form(
        &router,
        "/auth/token",
        "grant_type=client_credentials&client_id=ci-builder&client_secret=machine-s3cret",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let response = json(&body);
    assert_eq!(response["token_type"], "Bearer");
    // No refresh token: the client re-authenticates with its secret.
    assert!(response.get("refresh_token").is_none());
    let claims = auth
        .verifier
        .verify_token(response["access_token"].as_str().expect("token"))
        .await
        .expect("verify");
    assert_eq!(claims.user_id, "client:ci-builder");
    assert_eq!(claims.name.as_deref(), Some("CI Builder"));

    // Wrong secret and unknown client answer identically.
    for form in [
        "grant_type=client_credentials&client_id=ci-builder&client_secret=wrong",
        "grant_type=client_credentials&client_id=nobody&client_secret=machine-s3cret",
    ] {
        let (status, body) = post_form(&router, "/auth/token", form).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json(&body)["error"], "invalid_client");
    }

    // Missing credentials are a malformed request.
    let (status, body) = post_form(&router, "/auth/token", "grant_type=client_credentials").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_request");

    // Discovery advertises the grant.
    let (_, body) = get(&router, "/.well-known/openid-configuration").await;
    assert!(
        json(&body)["grant_types_supported"]
            .as_array()
            .expect("grants")
            .iter()
            .any(|g| g == GRANT_TYPE_CLIENT_CREDENTIALS)
    );
}

#[tokio::test]
async fn token_endpoint_rejects_unknown_grants() {
    let (_auth, router, _dir) = router();
    let (status, body) = post_form(&router, "/auth/token", "grant_type=password").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "unsupported_grant_type");

    let (status, body) = post_form(&router, "/auth/token", "").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&body)["error"], "invalid_request");
}

#[tokio::test]
async fn resource_exchange_narrows_a_user_token() {
    let (auth, router, _dir) = router();
    let minted = auth
        .minter
        .mint_user_token(&lore_server::auth::provider::ExternalIdentity {
            subject: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
            idp: "static".to_string(),
        })
        .expect("mint");

    let hex = "0194b726b34e72b0b45550b88a967076";
    let body = format!(
        "grant_type={GRANT_TYPE_TOKEN_EXCHANGE}\
         &subject_token={}\
         &subject_token_type={TOKEN_TYPE_ACCESS_TOKEN}\
         &resource=https%3A%2F%2Flore.example.com%2Fpartitions%2F{hex}",
        minted.token
    );
    let (status, response) = post_form(&router, "/auth/token", &body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let response = json(&response);
    assert_eq!(response["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);

    let claims = auth
        .verifier
        .verify_token(response["access_token"].as_str().expect("token"))
        .await
        .expect("verify");
    let resources = claims.resources.expect("resources");
    assert_eq!(resources.len(), 1);
    // No access store installed in unit tests: the default permissions
    // apply, keyed by the canonical legacy resource id.
    assert_eq!(resources[0].resource_id, format!("urc-{hex}"));
    assert!(resources[0].permission.contains(&"read".to_string()));

    // An unusable resource indicator is invalid_target.
    let body = format!(
        "grant_type={GRANT_TYPE_TOKEN_EXCHANGE}\
         &subject_token={}\
         &subject_token_type={TOKEN_TYPE_ACCESS_TOKEN}\
         &resource=not-a-repository",
        minted.token
    );
    let (status, response) = post_form(&router, "/auth/token", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&response)["error"], "invalid_target");

    // A garbage subject token is invalid_grant.
    let body = format!(
        "grant_type={GRANT_TYPE_TOKEN_EXCHANGE}\
         &subject_token=garbage\
         &subject_token_type={TOKEN_TYPE_ACCESS_TOKEN}\
         &resource=urc-{hex}"
    );
    let (status, response) = post_form(&router, "/auth/token", &body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json(&response)["error"], "invalid_grant");
}

#[tokio::test]
async fn non_url_issuer_disables_the_oauth_router() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut settings = crate::auth::local_auth::test_auth_settings(dir.path());
    settings.token.as_mut().expect("token").issuer = "URC".to_string();
    let auth = Arc::new(
        LocalAuth::from_settings(Some(&settings))
            .expect("build")
            .expect("enabled"),
    );
    assert!(create_router(auth).is_none());
}
