// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Pluggable identity providers for server-local authentication.
//!
//! An [`AuthProvider`] verifies *who the user is* against an external
//! identity provider (or a static user list for development). Everything
//! downstream of [`ExternalIdentity`] — token minting, claims, authorization —
//! is provider-independent, so adding an identity provider never requires
//! protocol or client changes.

pub mod static_provider;

use std::collections::HashMap;

use async_trait::async_trait;
use thiserror::Error;
use url::Url;

use crate::auth::session::PendingSession;

#[derive(Debug, Error)]
pub enum AuthProviderError {
    /// The user's identity could not be verified (bad credentials,
    /// unverified email, policy restriction).
    #[error("Authentication denied: {0}")]
    Denied(String),
    /// The callback request was malformed or missing required parameters.
    #[error("Invalid callback: {0}")]
    Invalid(String),
    /// The upstream identity provider could not be reached or returned
    /// an unexpected response.
    #[error("Identity provider error: {0}")]
    Upstream(String),
    #[error("Internal auth provider error: {0}")]
    Internal(String),
}

/// A verified identity returned by a provider after a successful login.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalIdentity {
    /// The provider's stable subject identifier (`sub`).
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    /// Provider name, e.g. `static` or `google`.
    pub idp: String,
}

impl ExternalIdentity {
    /// The canonical Lore user id: `<idp>:<subject>`.
    ///
    /// Stable across email changes at the identity provider.
    pub fn user_id(&self) -> String {
        format!("{}:{}", self.idp, self.subject)
    }
}

/// Query parameters delivered to the auth callback endpoint.
///
/// Providers extract what they need (`code` for OIDC, `user`/`secret` for
/// the static provider) so the HTTP handler stays provider-agnostic.
#[derive(Debug, Default, Clone)]
pub struct CallbackParams {
    pub params: HashMap<String, String>,
}

impl CallbackParams {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(String::as_str)
    }
}

/// A pluggable identity provider.
///
/// Implementations verify a user's identity via a browser-based login flow:
/// [`begin_login`](AuthProvider::begin_login) builds the URL the user's
/// browser is sent to, and [`complete_login`](AuthProvider::complete_login)
/// handles the redirect back and returns the verified identity.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Build the URL the user's browser is sent to for this pending session.
    async fn begin_login(&self, session: &PendingSession) -> Result<Url, AuthProviderError>;

    /// Handle the redirect back from the provider and return the verified
    /// identity. `session` is the pending session resolved from the
    /// callback's `state` parameter.
    async fn complete_login(
        &self,
        session: &PendingSession,
        params: &CallbackParams,
    ) -> Result<ExternalIdentity, AuthProviderError>;
}
