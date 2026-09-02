// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Standard OAuth 2.0 / OIDC endpoints in front of server-local auth.
//!
//! These routes serve the same login, refresh and exchange flows as the
//! `UrcAuthApi` gRPC service, in the shapes the upstream OIDC proposal
//! (`docs/proposals/2026-08-20-oidc-oauth2-authentication.md`) migrates
//! clients onto, so the server qualifies as that design's "custom issuer":
//!
//! - `GET /.well-known/openid-configuration` — OIDC discovery, also served
//!   under `/auth` for issuers configured with that path.
//! - `POST /auth/device_authorization` — RFC 8628 device authorization,
//!   fronting the pending-session flow `StartAuthSession` uses.
//! - `GET /auth/device` — the verification page where a user enters the
//!   device `user_code` (linked flows skip it via
//!   `verification_uri_complete`).
//! - `POST /auth/token` — the token endpoint: the device-code grant
//!   (`GetAuthSession` polling), the `refresh_token` grant, and RFC 8693
//!   token exchange for both partition scoping
//!   (`ExchangeUserTokenForMultiresourceToken`) and external ID tokens
//!   (`ExchangeExternalTokenForUserToken`).
//!
//! Both interfaces run side by side; existing gRPC clients are untouched.
//! Standard OAuth tooling can drive these endpoints end to end, which is
//! the guard against the issuer drifting back into a Lore-only dialect.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::extract::Query;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::Html;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::response::Response;
use tonic::Code;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::auth::local_auth::LocalAuth;
use crate::auth::provider::AuthProviderError;
use crate::auth::resource_exchange::ResourceRequest;
use crate::auth::resource_exchange::parse_resource_indicator;
use crate::auth::resource_exchange::resolve_resource_permissions;
use crate::auth::session::MintedLogin;
use crate::auth::session::SESSION_TTL;
use crate::auth::session::SessionError;

const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const GRANT_TYPE_CLIENT_CREDENTIALS: &str = "client_credentials";
const GRANT_TYPE_REFRESH_TOKEN: &str = "refresh_token";
const GRANT_TYPE_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Client state recorded for sessions started without a `client_id`; the
/// token request's `client_id` must match what device authorization used,
/// both defaulting to this.
const DEFAULT_CLIENT_ID: &str = "device";

/// Advertised device-flow polling cadence, matching the interval the
/// existing gRPC clients hardcode.
const DEVICE_POLL_INTERVAL_SECONDS: u64 = 5;

/// Shared state for the OAuth routes: the local auth stack plus the
/// absolute endpoint URLs advertised by discovery.
#[derive(Clone)]
pub struct OAuthState {
    auth: Arc<LocalAuth>,
    issuer: String,
    token_endpoint: String,
    device_authorization_endpoint: String,
    verification_uri: String,
    jwks_uri: String,
}

/// Router for the standard OAuth endpoints. `None` (with a warning) when
/// the configured issuer is not an HTTP(S) URL, since discovery cannot be
/// served for an issuer the document's URLs cannot be derived from.
pub fn create_router(auth: Arc<LocalAuth>) -> Option<axum::Router> {
    let issuer = auth.minter.issuer().trim_end_matches('/').to_string();
    let base = match url::Url::parse(&issuer) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => {
            if !matches!(url.path(), "" | "/") {
                warn!(
                    issuer,
                    "auth.token.issuer carries a path; OIDC discovery is served at \
                     /.well-known/openid-configuration relative to the server root, so \
                     prefer an origin-only issuer URL"
                );
            }
            url.origin().ascii_serialization()
        }
        _ => {
            warn!(
                issuer = auth.minter.issuer(),
                "auth.token.issuer is not an HTTP(S) URL; the standard OAuth endpoints \
                 (OIDC discovery, device authorization, token endpoint) are disabled. \
                 Set the issuer to the server's externally reachable base URL to enable \
                 them"
            );
            return None;
        }
    };

    let state = OAuthState {
        auth,
        issuer,
        token_endpoint: format!("{base}/auth/token"),
        device_authorization_endpoint: format!("{base}/auth/device_authorization"),
        verification_uri: format!("{base}/auth/device"),
        jwks_uri: format!("{base}/auth/.well-known/jwks.json"),
    };
    info!(
        issuer = state.issuer,
        "Serving standard OAuth endpoints for server-local auth"
    );

    Some(
        axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(discovery),
            )
            .route(
                "/auth/.well-known/openid-configuration",
                axum::routing::get(discovery),
            )
            .route(
                "/auth/device_authorization",
                axum::routing::post(device_authorization),
            )
            .route("/auth/device", axum::routing::get(device_page))
            .route("/auth/token", axum::routing::post(token))
            .with_state(state),
    )
}

/// `GET /.well-known/openid-configuration`.
async fn discovery(State(state): State<OAuthState>) -> Response {
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "issuer": state.issuer,
            "token_endpoint": state.token_endpoint,
            "device_authorization_endpoint": state.device_authorization_endpoint,
            "jwks_uri": state.jwks_uri,
            "grant_types_supported": [
                GRANT_TYPE_DEVICE_CODE,
                GRANT_TYPE_CLIENT_CREDENTIALS,
                GRANT_TYPE_REFRESH_TOKEN,
                GRANT_TYPE_TOKEN_EXCHANGE,
            ],
            "response_types_supported": [],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["EdDSA"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["openid", "email", "profile", "offline_access"],
        }),
    )
}

/// `POST /auth/device_authorization` — RFC 8628 §3.2.
async fn device_authorization(
    State(state): State<OAuthState>,
    body: axum::body::Bytes,
) -> Response {
    let form = parse_form(&body);
    let client_id = single(&form, "client_id").unwrap_or(DEFAULT_CLIENT_ID);

    let session = match state.auth.sessions.create(client_id) {
        Ok(session) => session,
        Err(SessionError::Exhausted) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "too many pending login sessions",
            );
        }
        Err(other) => return internal_error(&other),
    };
    let login_url = match state.auth.provider.begin_login(&session).await {
        Ok(url) => url,
        Err(error) => return internal_error(&error),
    };

    debug!(
        session_code = session.session_code,
        "Started device authorization"
    );
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "device_code": session.session_code,
            "user_code": session.user_code,
            "verification_uri": state.verification_uri,
            "verification_uri_complete": login_url.to_string(),
            "expires_in": SESSION_TTL.as_secs(),
            "interval": DEVICE_POLL_INTERVAL_SECONDS,
        }),
    )
}

/// `GET /auth/device` — RFC 8628 verification page: enter the user code,
/// get redirected to the identity provider.
async fn device_page(
    State(state): State<OAuthState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let Some(user_code) = params.get("user_code").filter(|code| !code.is_empty()) else {
        return device_form(None);
    };
    let session = match state.auth.sessions.for_user_code(user_code) {
        Ok(session) => session,
        Err(SessionError::NotFound) => {
            return device_form(Some("That code is unknown or has expired."));
        }
        Err(SessionError::AlreadyCompleted) => {
            return device_form(Some("That code was already used."));
        }
        Err(other) => return internal_error(&other),
    };
    match state.auth.provider.begin_login(&session).await {
        Ok(login_url) => Redirect::to(login_url.as_str()).into_response(),
        Err(error) => internal_error(&error),
    }
}

fn device_form(error: Option<&str>) -> Response {
    let notice = error
        .map(|message| format!("<p><strong>{message}</strong></p>"))
        .unwrap_or_default();
    Html(format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">\
         <title>Connect a device</title></head>\
         <body style=\"font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 30rem;\">\
         <h1>Connect a device</h1>{notice}\
         <p>Enter the code shown by the device you are signing in.</p>\
         <form action=\"/auth/device\" method=\"get\">\
         <p><label>Code <input type=\"text\" name=\"user_code\" autofocus \
         autocomplete=\"off\" spellcheck=\"false\" placeholder=\"XXXX-XXXX\"></label></p>\
         <p><button type=\"submit\">Continue</button></p>\
         </form></body></html>"
    ))
    .into_response()
}

/// `POST /auth/token` — the token endpoint, dispatching on `grant_type`.
async fn token(State(state): State<OAuthState>, body: axum::body::Bytes) -> Response {
    let form = parse_form(&body);
    match single(&form, "grant_type") {
        Some(GRANT_TYPE_DEVICE_CODE) => device_code_grant(&state, &form).await,
        Some(GRANT_TYPE_CLIENT_CREDENTIALS) => client_credentials_grant(&state, &form),
        Some(GRANT_TYPE_REFRESH_TOKEN) => refresh_grant(&state, &form).await,
        Some(GRANT_TYPE_TOKEN_EXCHANGE) => token_exchange_grant(&state, &form).await,
        Some(other) => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("unsupported grant_type '{other}'"),
        ),
        None => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "grant_type is required",
        ),
    }
}

/// RFC 8628 §3.4–3.5: poll for the outcome of a device authorization.
async fn device_code_grant(state: &OAuthState, form: &Form) -> Response {
    let Some(device_code) = single(form, "device_code") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "device_code is required",
        );
    };
    let client_id = single(form, "client_id").unwrap_or(DEFAULT_CLIENT_ID);

    match state.auth.sessions.take_if_ready(device_code, client_id) {
        Ok(Some(minted)) => {
            info!(user_id = minted.user_id, "Device grant completed");
            token_response(minted, None)
        }
        Ok(None) => oauth_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "the user has not yet completed authorization",
        ),
        Err(SessionError::NotFound) => oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device_code is unknown or has expired",
        ),
        Err(SessionError::ClientStateMismatch) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match the device authorization request",
        ),
        Err(SessionError::LoginFailed(reason)) => {
            oauth_error(StatusCode::BAD_REQUEST, "access_denied", &reason)
        }
        Err(other) => internal_error(&other),
    }
}

/// RFC 6749 §4.4: a registered machine identity authenticates as itself.
/// No user, no session, and no refresh token — the client re-requests
/// with its credentials whenever the short-lived token expires. Grants are
/// held by the `client:<client_id>` principal like any other.
fn client_credentials_grant(state: &OAuthState, form: &Form) -> Response {
    let (Some(client_id), Some(client_secret)) =
        (single(form, "client_id"), single(form, "client_secret"))
    else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "client_id and client_secret are required",
        );
    };
    let Some(identity) = state.auth.verify_client(client_id, client_secret) else {
        // One message for unknown client and wrong secret alike.
        return oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
    };
    match state.auth.minter.mint_user_token(&identity) {
        Ok(minted) => {
            info!(user_id = minted.user_id, "Client credentials grant");
            token_response(minted, None)
        }
        Err(error) => internal_error(&error),
    }
}

/// RFC 6749 §6: redeem a rotating refresh token.
async fn refresh_grant(state: &OAuthState, form: &Form) -> Response {
    let Some(refresh) = crate::auth::refresh::installed() else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "refresh tokens are not enabled on this server",
        );
    };
    let Some(token) = single(form, "refresh_token") else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "refresh_token is required",
        );
    };

    let (identity, successor) = match refresh.refresh(token).await {
        Ok(result) => result,
        Err(crate::auth::refresh::RefreshError::Store(message)) => {
            return internal_error(&message);
        }
        Err(denied) => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                &denied.to_string(),
            );
        }
    };
    match state.auth.minter.mint_user_token(&identity) {
        Ok(mut minted) => {
            minted.refresh_token = Some(successor);
            token_response(minted, None)
        }
        Err(error) => internal_error(&error),
    }
}

/// RFC 8693: exchange an access token for a partition-scoped one (the
/// `resource` carrier), or an external OIDC ID token for a user token.
async fn token_exchange_grant(state: &OAuthState, form: &Form) -> Response {
    let Some(subject_token) = single(form, "subject_token").filter(|t| !t.is_empty()) else {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token is required",
        );
    };
    match single(form, "subject_token_type") {
        Some(TOKEN_TYPE_ACCESS_TOKEN) => {
            resource_exchange(state, subject_token, form.get("resource")).await
        }
        Some(TOKEN_TYPE_ID_TOKEN) => external_token_exchange(state, subject_token).await,
        Some(other) => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            &format!(
                "unsupported subject_token_type '{other}' \
                 (expected {TOKEN_TYPE_ACCESS_TOKEN} or {TOKEN_TYPE_ID_TOKEN})"
            ),
        ),
        None => oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token_type is required",
        ),
    }
}

/// Narrow a Lore user token to the requested resources, embedding the
/// caller's granted permission verbs — the standard-shaped equivalent of
/// `ExchangeUserTokenForMultiresourceToken`.
async fn resource_exchange(
    state: &OAuthState,
    subject_token: &str,
    resources: Option<&Vec<String>>,
) -> Response {
    let user_claims = match state.auth.verifier.verify_token(subject_token).await {
        Ok(claims) => claims,
        Err(error) => {
            debug!(%error, "Token exchange subject_token rejected");
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "subject_token is not a valid access token",
            );
        }
    };

    let indicators = resources.map(Vec::as_slice).unwrap_or_default();
    if indicators.is_empty() {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "at least one resource indicator is required",
        );
    }
    let mut requests = Vec::with_capacity(indicators.len());
    for indicator in indicators {
        let Some(repository) = parse_resource_indicator(indicator) else {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_target",
                &format!("'{indicator}' does not name a repository"),
            );
        };
        requests.push(ResourceRequest {
            // The claim keeps the legacy resource-id form the server's
            // enforcement points match against.
            resource_id: format!("urc-{repository}"),
            repository: Some(repository),
        });
    }

    let granted = match resolve_resource_permissions(&user_claims, requests).await {
        Ok(granted) => granted,
        Err(status) if status.code() == Code::PermissionDenied => {
            return oauth_error(StatusCode::FORBIDDEN, "access_denied", status.message());
        }
        Err(status) => return internal_error(&status),
    };

    match state.auth.minter.mint_authz_token(&user_claims, granted) {
        Ok(minted) => token_response(minted, Some(TOKEN_TYPE_ACCESS_TOKEN)),
        Err(error) => internal_error(&error),
    }
}

/// Exchange a trusted external OIDC ID token for a Lore user token — the
/// standard-shaped equivalent of `ExchangeExternalTokenForUserToken`.
async fn external_token_exchange(state: &OAuthState, subject_token: &str) -> Response {
    let identity = match state
        .auth
        .provider
        .verify_external_id_token(subject_token)
        .await
    {
        Ok(identity) => identity,
        Err(AuthProviderError::Unsupported(message)) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &message);
        }
        Err(AuthProviderError::Denied(message)) => {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", &message);
        }
        Err(AuthProviderError::Upstream(message)) => {
            return oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                &message,
            );
        }
        Err(other) => return internal_error(&other),
    };

    let mut minted = match state.auth.minter.mint_user_token(&identity) {
        Ok(minted) => minted,
        Err(error) => return internal_error(&error),
    };
    if let Some(refresh) = crate::auth::refresh::installed() {
        match refresh.issue(&identity).await {
            Ok(token) => minted.refresh_token = Some(token),
            Err(error) => {
                debug!(%error, "Failed to issue refresh token on exchange; continuing")
            }
        }
    }
    info!(user_id = minted.user_id, "External token exchanged");
    token_response(minted, Some(TOKEN_TYPE_ACCESS_TOKEN))
}

type Form = HashMap<String, Vec<String>>;

/// Parse an `application/x-www-form-urlencoded` body, preserving repeated
/// keys (RFC 8707 allows several `resource` parameters).
fn parse_form(body: &[u8]) -> Form {
    let mut form: Form = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(body) {
        form.entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }
    form
}

fn single<'f>(form: &'f Form, key: &str) -> Option<&'f str> {
    form.get(key)?.first().map(String::as_str)
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// RFC 6749 §5.1 success response.
fn token_response(minted: MintedLogin, issued_token_type: Option<&str>) -> Response {
    let expires_in =
        (minted.expires_at_ms.max(0) as u64 / 1000).saturating_sub(now_epoch_seconds());
    let mut body = serde_json::json!({
        "access_token": minted.token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    });
    if let Some(refresh_token) = minted.refresh_token {
        body["refresh_token"] = serde_json::Value::String(refresh_token);
    }
    if let Some(issued_token_type) = issued_token_type {
        body["issued_token_type"] = serde_json::Value::String(issued_token_type.to_string());
    }
    json_response(StatusCode::OK, body)
}

/// RFC 6749 §5.2 error response.
fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    json_response(
        status,
        serde_json::json!({ "error": error, "error_description": description }),
    )
}

fn internal_error(error: &impl std::fmt::Display) -> Response {
    // Deliberately unspecific on the wire; the detail goes to the log.
    warn!(%error, "OAuth endpoint internal error");
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "the request could not be processed",
    )
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            // Token and discovery responses must not be cached (RFC 6749
            // §5.1); no-store everywhere here is simplest and safe.
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;

    /// The OAuth router merged with the login-door routes, as the server
    /// mounts them, so the device flow can complete end to end.
    async fn router() -> (Arc<LocalAuth>, axum::Router, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
        let auth = Arc::new(
            LocalAuth::from_settings(Some(&settings))
                .expect("build")
                .expect("enabled"),
        );
        let router = crate::http::auth_login::create_router(auth.clone())
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
        let (_auth, router, _dir) = router().await;
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
        let (auth, router, _dir) = router().await;

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
        let poll = format!(
            "grant_type={GRANT_TYPE_DEVICE_CODE}&device_code={device_code}&client_id=lore-cli"
        );
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
        let (_auth, router, _dir) = router().await;
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
        let mut settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
        settings
            .clients
            .push(crate::auth::local_auth::ClientCredentialSettings {
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
        assert_eq!(claims.name, "CI Builder");

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
        let (status, body) =
            post_form(&router, "/auth/token", "grant_type=client_credentials").await;
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
        let (_auth, router, _dir) = router().await;
        let (status, body) = post_form(&router, "/auth/token", "grant_type=password").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"], "unsupported_grant_type");

        let (status, body) = post_form(&router, "/auth/token", "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json(&body)["error"], "invalid_request");
    }

    #[tokio::test]
    async fn resource_exchange_narrows_a_user_token() {
        let (auth, router, _dir) = router().await;
        let minted = auth
            .minter
            .mint_user_token(&crate::auth::provider::ExternalIdentity {
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
        let mut settings = crate::auth::local_auth::tests::test_auth_settings(dir.path());
        settings.token.as_mut().expect("token").issuer = "URC".to_string();
        let auth = Arc::new(
            LocalAuth::from_settings(Some(&settings))
                .expect("build")
                .expect("enabled"),
        );
        assert!(create_router(auth).is_none());
    }
}
