// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use anyhow::Result;
use lore_base::runtime::runtime;
use lore_telemetry::tracing::fields::USER_ID;
use tokio::task;
use tonic::service::Interceptor;
use tracing::Span;
use tracing::debug;

use super::jwt::JwtVerifier;
use crate::auth::jwt::AuthorizationToken;
use crate::authnz::repository_authorizer::RawToken;

fn add_auth_fields_to_current_span(auth: &AuthorizationToken) {
    let span = Span::current();
    span.record(USER_ID, auth.identity().to_string());
}

/// Resolve the bearer token to an [`AuthorizationToken`]. The cached signing key serves the
/// hot path synchronously; the blocking fallback runs only when the cache cannot answer —
/// no key for the id, or a key that rejected the signature and may therefore have been
/// rotated out. A token that fails on its own claims is refused without blocking. That is
/// what lets this run inside tonic's synchronous [`Interceptor::call`].
fn authorize(verifier: &JwtVerifier, token: &str) -> Result<AuthorizationToken, tonic::Status> {
    match verifier.try_verify_token_cached(token) {
        Ok(Some(authorization)) => Ok(authorization),
        // Reached only when the cache cannot answer, so the core handed off here is one the
        // hot path never gives up.
        #[allow(clippy::disallowed_methods)]
        Ok(None) => task::block_in_place(|| runtime().block_on(verifier.verify_token(token))),
        Err(e) => Err(e),
    }
    .map_err(|e| {
        // The reason stays in the log. Told apart, "the signature is wrong", "the token
        // expired", "no such key id" and "the JWKS endpoint is unwell" are an oracle for a
        // caller who has not authenticated — and not one of them is something that caller
        // could act on.
        debug!(error = ?e, "Rejecting request: token verification failed");
        tonic::Status::permission_denied("Not allowed")
    })
}

/// Authentication only: verifies the signature, parses the bearer token claims, and hands
/// the verified halves to the handler as extensions ([`RawToken`] for the raw token
/// string, and [`AuthorizationToken`] for the parsed claims).
///
/// With no verifier (no `[server.auth]`), every request passes through untouched: no
/// bearer token is required, one that is present is not read, and no extension is
/// inserted.
#[derive(Clone)]
pub struct JWTInterceptor {
    jwt_verifier: Option<JwtVerifier>,
}

impl JWTInterceptor {
    pub fn new(jwt_verifier: Option<&JwtVerifier>) -> Self {
        Self {
            jwt_verifier: jwt_verifier.cloned(),
        }
    }
}

impl Interceptor for JWTInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let Some(jwt_verifier) = &self.jwt_verifier else {
            return Ok(request);
        };

        let (authorization, raw_token) = match extract_bearer_token(request.metadata()) {
            Some(token) => (authorize(jwt_verifier, &token)?, Some(token)),
            // No bearer: accept only a server-injected anonymous
            // authorization (public repository, read-only method) from the
            // `AnonymousReadLayer`. Clients cannot forge request extensions.
            // There is no raw token to record, so `get_verified_token`
            // answers `None` and the authorizer sees an anonymous caller.
            None => (
                anonymous_authorization(request.extensions()).ok_or(
                    tonic::Status::unauthenticated("authorization header required"),
                )?,
                None,
            ),
        };
        add_auth_fields_to_current_span(&authorization);

        if let Some(token) = raw_token {
            request.extensions_mut().insert(RawToken(token));
        }
        request.extensions_mut().insert(authorization);

        Ok(request)
    }
}

/// A server-injected anonymous authorization, if the `AnonymousReadLayer`
/// admitted this request.
fn anonymous_authorization(extensions: &tonic::Extensions) -> Option<AuthorizationToken> {
    extensions
        .get::<AuthorizationToken>()
        .filter(|authorization| crate::auth::anonymous::is_anonymous(authorization))
        .cloned()
}

pub(crate) fn extract_bearer_token(metadata: &tonic::metadata::MetadataMap) -> Option<String> {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|header| {
            if header.starts_with("Bearer ") {
                Some(header.trim_start_matches("Bearer ").to_string())
            } else {
                None
            }
        })
}
