// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! HTTP endpoints for the server-local browser login flow.
//!
//! `GET /auth/callback` completes a pending login session: identity
//! providers redirect the user's browser here (OIDC `code`/`state`, or the
//! dev-login form submission for the static provider). `GET /auth/dev-login`
//! renders the static provider's credential form.
//!
//! Both routes are unauthenticated by design — they are the login door.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Response;
use tracing::debug;

use crate::auth::local_auth::CompleteLoginError;
use crate::auth::local_auth::LocalAuth;
use crate::auth::provider::AuthProviderError;
use crate::auth::provider::CallbackParams;
use crate::auth::session::SessionError;

/// Minimal HTML page shell.
fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
         <title>{title}</title></head>\
         <body style=\"font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 30rem;\">\
         {body}</body></html>"
    ))
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// `GET /auth/callback` — complete a pending login session.
pub async fn callback(
    State(auth): State<Arc<LocalAuth>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    match auth.complete_login(CallbackParams { params }).await {
        Ok(()) => page(
            "Login complete",
            "<h1>Login complete</h1>\
             <p>You are signed in. Return to your terminal — you can close this tab.</p>",
        )
        .into_response(),
        Err(error) => {
            debug!(error = %error, "Login callback failed");
            let (status, message) = match &error {
                CompleteLoginError::BadRequest(message) => {
                    (StatusCode::BAD_REQUEST, escape_html(message))
                }
                CompleteLoginError::Session(SessionError::NotFound) => (
                    StatusCode::BAD_REQUEST,
                    "This login link is unknown or has expired. \
                     Run <code>lore auth login</code> again."
                        .to_string(),
                ),
                CompleteLoginError::Session(SessionError::AlreadyCompleted) => (
                    StatusCode::BAD_REQUEST,
                    "This login link was already used. \
                     Run <code>lore auth login</code> again."
                        .to_string(),
                ),
                CompleteLoginError::Provider(AuthProviderError::Invalid(message)) => {
                    (StatusCode::BAD_REQUEST, escape_html(message))
                }
                CompleteLoginError::Provider(AuthProviderError::Denied(_)) => (
                    StatusCode::FORBIDDEN,
                    "Login was denied. Return to your terminal for details.".to_string(),
                ),
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Login failed. Return to your terminal for details.".to_string(),
                ),
            };
            (
                status,
                page(
                    "Login failed",
                    &format!("<h1>Login failed</h1><p>{message}</p>"),
                ),
            )
                .into_response()
        }
    }
}

/// `GET /auth/dev-login` — the static provider's credential form. Submits to
/// `/auth/callback` via GET so a smoke test can complete a login with a
/// single request.
pub async fn dev_login(Query(params): Query<HashMap<String, String>>) -> Response {
    let Some(state) = params.get("state") else {
        return (
            StatusCode::BAD_REQUEST,
            page("Login failed", "<h1>Login failed</h1><p>Missing state.</p>"),
        )
            .into_response();
    };
    let state = escape_html(state);
    page(
        "Lore development login",
        &format!(
            "<h1>Lore development login</h1>\
             <p>This server uses the insecure <em>static</em> auth provider \
             (development only).</p>\
             <form action=\"/auth/callback\" method=\"get\">\
             <input type=\"hidden\" name=\"state\" value=\"{state}\">\
             <p><label>User <input type=\"text\" name=\"user\" autofocus></label></p>\
             <p><label>Secret <input type=\"password\" name=\"secret\"></label></p>\
             <p><button type=\"submit\">Sign in</button></p>\
             </form>"
        ),
    )
    .into_response()
}

/// Router for the unauthenticated login endpoints.
pub fn create_router(auth: Arc<LocalAuth>) -> axum::Router {
    axum::Router::new()
        .route("/auth/callback", axum::routing::get(callback))
        .route("/auth/dev-login", axum::routing::get(dev_login))
        .with_state(auth)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    async fn auth() -> (Arc<LocalAuth>, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
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
        let (auth, _dir) = auth().await;
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
        let (auth, _dir) = auth().await;
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
        let (auth, _dir) = auth().await;
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
        let (auth, _dir) = auth().await;
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
    async fn callback_link_is_single_use() {
        let (auth, _dir) = auth().await;
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
}
