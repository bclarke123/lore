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
}

fn read_client_secret(path: &str) -> Result<String, OidcSettingsError> {
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

fn scopes(settings: &OidcProviderSettings) -> Vec<String> {
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
        },
        backend,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::provider::AuthProvider;
    use crate::auth::provider::oidc::test_support::MockBackend;

    fn settings(dir: &std::path::Path) -> OidcProviderSettings {
        let secret_path = dir.join("client-secret");
        std::fs::write(&secret_path, "shhh-google-secret\n").expect("write secret");
        OidcProviderSettings {
            client_id: "google-client-id".to_string(),
            client_secret_path: secret_path.to_string_lossy().to_string(),
            discovery_url: None,
            extra_scopes: vec![],
            hosted_domain: None,
        }
    }

    #[test]
    fn google_preset_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let provider = google_provider(
            &settings(dir.path()),
            "https://lore.example.com/auth/callback",
            Arc::new(MockBackend::new()),
        )
        .expect("provider");
        assert_eq!(provider.name(), "google");
    }

    #[test]
    fn missing_or_empty_secret_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut bad = settings(dir.path());
        bad.client_secret_path = dir.path().join("nope").to_string_lossy().to_string();
        assert!(matches!(
            google_provider(&bad, "http://x/auth/callback", Arc::new(MockBackend::new())),
            Err(OidcSettingsError::ReadSecret { .. })
        ));

        let empty_path = dir.path().join("empty");
        std::fs::write(&empty_path, "  \n").expect("write");
        let mut empty = settings(dir.path());
        empty.client_secret_path = empty_path.to_string_lossy().to_string();
        assert!(matches!(
            google_provider(
                &empty,
                "http://x/auth/callback",
                Arc::new(MockBackend::new())
            ),
            Err(OidcSettingsError::EmptySecret(_))
        ));
    }

    #[test]
    fn generic_oidc_requires_discovery_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            generic_oidc_provider(
                &settings(dir.path()),
                "http://x/auth/callback",
                Arc::new(MockBackend::new())
            ),
            Err(OidcSettingsError::MissingDiscoveryUrl)
        ));
    }

    #[test]
    fn extra_scopes_are_deduplicated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut with_scopes = settings(dir.path());
        with_scopes.extra_scopes = vec!["email".to_string(), "groups".to_string()];
        assert_eq!(
            scopes(&with_scopes),
            vec!["openid", "email", "profile", "groups"]
        );
    }

    #[tokio::test]
    async fn hosted_domain_flows_into_auth_url_and_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut restricted = settings(dir.path());
        restricted.hosted_domain = Some("example.com".to_string());
        let provider = google_provider(
            &restricted,
            "http://localhost/auth/callback",
            Arc::new(MockBackend::new()),
        )
        .expect("provider");

        let session = crate::auth::session::SessionManager::new()
            .create("cs")
            .expect("session");
        let url = provider.begin_login(&session).await.expect("begin");
        assert!(url.query().unwrap_or_default().contains("hd=example.com"));
    }
}
