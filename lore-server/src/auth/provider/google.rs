// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Google identity provider: a preset over the generic [`OidcProvider`].
//!
//! Uses Google's OIDC discovery document, requires a verified email, and
//! optionally restricts sign-in to a Google Workspace hosted domain (`hd`).

use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;

use super::oidc::OidcBackend;
use super::oidc::OidcConfig;
use super::oidc::OidcProvider;

pub const GOOGLE_PROVIDER_NAME: &str = "google";
const GOOGLE_DISCOVERY_URL: &str = "https://accounts.google.com/.well-known/openid-configuration";

#[derive(Clone, Debug, Deserialize)]
pub struct OidcProviderSettings {
    pub client_id: String,
    /// Path to a file holding the OAuth client secret (kept out of the
    /// config file so configuration can be committed).
    pub client_secret_path: String,
    /// Discovery document URL. Preset for `google`; required for a generic
    /// `oidc` provider.
    pub discovery_url: Option<String>,
    /// Additional scopes beyond `openid email profile`.
    #[serde(default)]
    pub extra_scopes: Vec<String>,
    /// Google Workspace hosted domain restriction (`hd`).
    pub hosted_domain: Option<String>,
    /// `aud` values trusted on externally obtained ID tokens presented to
    /// `ExchangeExternalTokenForUserToken` (e.g. a web hub's own OAuth
    /// client id). Empty = external exchange disabled.
    #[serde(default)]
    pub trusted_external_audiences: Vec<String>,
    /// AWS region of the Cognito user pool (mode `cognito`).
    pub region: Option<String>,
    /// Cognito user pool id (mode `cognito`).
    pub user_pool_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum OidcSettingsError {
    #[error("Failed to read client secret {path}: {source}")]
    ReadSecret {
        path: String,
        source: std::io::Error,
    },
    #[error("Client secret file {0} is empty")]
    EmptySecret(String),
    #[error("auth.provider.oidc.discovery_url is required for mode 'oidc'")]
    MissingDiscoveryUrl,
    #[error(
        "auth.provider.oidc.region and user_pool_id (or discovery_url) are required for mode 'cognito'"
    )]
    MissingCognitoPool,
}

pub(super) fn read_client_secret(path: &str) -> Result<String, OidcSettingsError> {
    let secret = std::fs::read_to_string(path)
        .map_err(|source| OidcSettingsError::ReadSecret {
            path: path.to_string(),
            source,
        })?
        .trim()
        .to_string();
    if secret.is_empty() {
        return Err(OidcSettingsError::EmptySecret(path.to_string()));
    }
    Ok(secret)
}

#[lore_macro::test_pub]
pub(super) fn scopes(settings: &OidcProviderSettings) -> Vec<String> {
    let mut scopes = vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
    ];
    for extra in &settings.extra_scopes {
        if !scopes.contains(extra) {
            scopes.push(extra.clone());
        }
    }
    scopes
}

/// Build the Google provider.
pub fn google_provider(
    settings: &OidcProviderSettings,
    callback_url: &str,
    backend: Arc<dyn OidcBackend>,
) -> Result<OidcProvider, OidcSettingsError> {
    let mut extra_auth_params = Vec::new();
    if let Some(domain) = settings.hosted_domain.as_deref() {
        // Pre-filters the account chooser; the ID token `hd` claim is still
        // enforced server-side after login.
        extra_auth_params.push(("hd".to_string(), domain.to_string()));
    }
    Ok(OidcProvider::new(
        OidcConfig {
            idp: GOOGLE_PROVIDER_NAME,
            discovery_url: settings
                .discovery_url
                .clone()
                .unwrap_or_else(|| GOOGLE_DISCOVERY_URL.to_string()),
            client_id: settings.client_id.clone(),
            client_secret: read_client_secret(&settings.client_secret_path)?,
            redirect_uri: callback_url.to_string(),
            scopes: scopes(settings),
            extra_auth_params,
            require_verified_email: true,
            hosted_domain: settings.hosted_domain.clone(),
            trusted_external_audiences: settings.trusted_external_audiences.clone(),
        },
        backend,
    ))
}

/// Build a generic OIDC provider (explicit discovery URL, no Google policy).
pub fn generic_oidc_provider(
    settings: &OidcProviderSettings,
    callback_url: &str,
    backend: Arc<dyn OidcBackend>,
) -> Result<OidcProvider, OidcSettingsError> {
    Ok(OidcProvider::new(
        OidcConfig {
            idp: "oidc",
            discovery_url: settings
                .discovery_url
                .clone()
                .ok_or(OidcSettingsError::MissingDiscoveryUrl)?,
            client_id: settings.client_id.clone(),
            client_secret: read_client_secret(&settings.client_secret_path)?,
            redirect_uri: callback_url.to_string(),
            scopes: scopes(settings),
            extra_auth_params: Vec::new(),
            require_verified_email: false,
            hosted_domain: None,
            trusted_external_audiences: settings.trusted_external_audiences.clone(),
        },
        backend,
    ))
}
