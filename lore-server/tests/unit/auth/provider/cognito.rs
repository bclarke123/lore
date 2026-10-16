// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_server::auth::provider::AuthProvider;
use lore_server::auth::provider::cognito::*;
use lore_server::auth::provider::google::OidcProviderSettings;
use lore_server::auth::provider::google::OidcSettingsError;

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
        trusted_external_audiences: vec![],
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
