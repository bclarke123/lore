// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_server::auth::provider::AuthProvider;
use lore_server::auth::provider::google::*;

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
        trusted_external_audiences: vec![],
        region: None,
        user_pool_id: None,
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

    let session = lore_server::auth::session::SessionManager::new()
        .create("cs")
        .expect("session");
    let url = provider.begin_login(&session).await.expect("begin");
    assert!(url.query().unwrap_or_default().contains("hd=example.com"));
}
