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
                CompleteLoginError::BadRequest(message)
                | CompleteLoginError::Provider(AuthProviderError::Invalid(message)) => {
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

/// `GET /auth/.well-known/jwks.json` — the server's token-verification
/// keys, for external services validating Lore-minted tokens.
pub async fn jwks(State(auth): State<Arc<LocalAuth>>) -> Response {
    let body = serde_json::json!({ "keys": [auth.minter.public_jwk()] });
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body.to_string(),
    )
        .into_response()
}

/// Router for the unauthenticated login endpoints.
pub fn create_router(auth: Arc<LocalAuth>) -> axum::Router {
    axum::Router::new()
        .route("/auth/callback", axum::routing::get(callback))
        .route("/auth/dev-login", axum::routing::get(dev_login))
        .route("/auth/.well-known/jwks.json", axum::routing::get(jwks))
        .with_state(auth)
}
