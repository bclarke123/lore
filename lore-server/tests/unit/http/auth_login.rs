// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use axum::http::StatusCode;
use lore_server::auth::local_auth::LocalAuth;
use lore_server::http::auth_login::*;
use tower::ServiceExt;

fn auth() -> (Arc<LocalAuth>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = crate::auth::local_auth::test_auth_settings(dir.path());
    (
        Arc::new(
            LocalAuth::from_settings(Some(&settings))
                .expect("build")
                .expect("enabled"),
        ),
        dir,
    )
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
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&bytes).to_string())
}

#[tokio::test]
async fn dev_login_renders_form_with_state() {
    let (auth, _dir) = auth();
    let router = create_router(auth);
    let (status, body) = get(&router, "/auth/dev-login?state=abc123").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("value=\"abc123\""));
    assert!(body.contains("/auth/callback"));

    let (status, _) = get(&router, "/auth/dev-login").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dev_login_escapes_state() {
    let (auth, _dir) = auth();
    let router = create_router(auth);
    let (status, body) = get(
        &router,
        "/auth/dev-login?state=%22%3E%3Cscript%3Ex%3C/script%3E",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("<script>"));
}

#[tokio::test]
async fn callback_completes_login_end_to_end() {
    let (auth, _dir) = auth();
    let router = create_router(auth.clone());
    let session = auth.sessions.create("client-1").expect("create");

    let (status, body) = get(
        &router,
        &format!(
            "/auth/callback?state={}&user=alice&secret=s3cret",
            session.csrf_state
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("Login complete"));

    let minted = auth
        .sessions
        .take_if_ready(&session.session_code, "client-1")
        .expect("poll")
        .expect("ready");
    assert_eq!(minted.user_id, "static:alice");
}

#[tokio::test]
async fn callback_rejects_bad_requests() {
    let (auth, _dir) = auth();
    let router = create_router(auth.clone());

    // No state.
    let (status, _) = get(&router, "/auth/callback?user=a&secret=b").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Unknown state.
    let (status, _) = get(&router, "/auth/callback?state=bogus&user=a&secret=b").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Wrong secret.
    let session = auth.sessions.create("client-1").expect("create");
    let (status, _) = get(
        &router,
        &format!(
            "/auth/callback?state={}&user=alice&secret=wrong",
            session.csrf_state
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn jwks_endpoint_serves_the_signing_key() {
    let (auth, _dir) = auth();
    let router = create_router(auth.clone());
    let (status, body) = get(&router, "/auth/.well-known/jwks.json").await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("json");
    let key = &parsed["keys"][0];
    assert_eq!(key["kty"], "OKP");
    assert_eq!(key["crv"], "Ed25519");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["kid"], auth.minter.kid());
    assert!(!key["x"].as_str().unwrap_or_default().is_empty());
}

#[tokio::test]
async fn callback_link_is_single_use() {
    let (auth, _dir) = auth();
    let router = create_router(auth.clone());
    let session = auth.sessions.create("client-1").expect("create");
    let uri = format!(
        "/auth/callback?state={}&user=alice&secret=s3cret",
        session.csrf_state
    );

    let (status, _) = get(&router, &uri).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = get(&router, &uri).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("already used"));
}
