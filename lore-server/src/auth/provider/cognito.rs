// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Amazon Cognito identity provider: a preset over the generic
//! [`OidcProvider`].
//!
//! Uses the user pool's OIDC discovery document
//! (`https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/openid-configuration`).
//! Cognito ID tokens carry `aud` = app client id and standard OIDC claims,
//! which the generic core already validates.

use std::sync::Arc;

use super::google::OidcProviderSettings;
use super::google::OidcSettingsError;
use super::google::read_client_secret;
use super::google::scopes;
use super::oidc::OidcBackend;
use super::oidc::OidcConfig;
use super::oidc::OidcProvider;

pub const COGNITO_PROVIDER_NAME: &str = "cognito";

fn discovery_url(settings: &OidcProviderSettings) -> Result<String, OidcSettingsError> {
    if let Some(url) = settings.discovery_url.clone() {
        return Ok(url);
    }
    match (settings.region.as_deref(), settings.user_pool_id.as_deref()) {
        (Some(region), Some(pool)) => Ok(format!(
            "https://cognito-idp.{region}.amazonaws.com/{pool}/.well-known/openid-configuration"
        )),
        _ => Err(OidcSettingsError::MissingCognitoPool),
    }
}

/// Build the Cognito provider.
pub fn cognito_provider(
    settings: &OidcProviderSettings,
    callback_url: &str,
    backend: Arc<dyn OidcBackend>,
) -> Result<OidcProvider, OidcSettingsError> {
    Ok(OidcProvider::new(
        OidcConfig {
            idp: COGNITO_PROVIDER_NAME,
            discovery_url: discovery_url(settings)?,
            client_id: settings.client_id.clone(),
            client_secret: read_client_secret(&settings.client_secret_path)?,
            redirect_uri: callback_url.to_string(),
            scopes: scopes(settings),
            extra_auth_params: Vec::new(),
            // Cognito sets `email_verified` on verified pool accounts.
            require_verified_email: true,
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
        std::fs::write(&secret_path, "cognito-secret").expect("write secret");
        OidcProviderSettings {
            client_id: "cognito-app-client".to_string(),
            client_secret_path: secret_path.to_string_lossy().to_string(),
            discovery_url: None,
            extra_scopes: vec![],
            hosted_domain: None,
            region: Some("us-east-1".to_string()),
            user_pool_id: Some("us-east-1_AbCdEfGhI".to_string()),
        }
    }

    #[test]
    fn pool_settings_derive_the_discovery_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            discovery_url(&settings(dir.path())).expect("url"),
            "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI/.well-known/openid-configuration"
        );
    }

    #[test]
    fn explicit_discovery_url_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut with_url = settings(dir.path());
        with_url.discovery_url = Some("https://idp.example.com/.well-known".to_string());
        assert_eq!(
            discovery_url(&with_url).expect("url"),
            "https://idp.example.com/.well-known"
        );
    }

    #[test]
    fn missing_pool_settings_are_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut incomplete = settings(dir.path());
        incomplete.user_pool_id = None;
        assert!(matches!(
            cognito_provider(
                &incomplete,
                "https://lore.example.com/auth/callback",
                Arc::new(MockBackend::new())
            ),
            Err(OidcSettingsError::MissingCognitoPool)
        ));
    }

    #[test]
    fn cognito_preset_builds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let provider = cognito_provider(
            &settings(dir.path()),
            "https://lore.example.com/auth/callback",
            Arc::new(MockBackend::new()),
        )
        .expect("provider");
        assert_eq!(provider.name(), "cognito");
    }
}
