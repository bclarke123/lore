// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::auth::local_jwk::*;
use lore_server::auth::minting::TokenMinter;
use lore_server::auth::minting::TokenMintingSettings;
use lore_server::auth::provider::ExternalIdentity;

fn minter(dir: &std::path::Path) -> TokenMinter {
    let settings = TokenMintingSettings {
        signing_key_path: Some(dir.join("key.pem").to_string_lossy().to_string()),
        generate_signing_key: true,
        issuer: "https://lore.example.com".to_string(),
        audience: vec!["lore.example.com".to_string()],
        user_token_ttl_seconds: 3600,
        authz_token_ttl_seconds: 900,
        refresh_token_ttl_seconds: 3600,
        env: "test".to_string(),
    };
    TokenMinter::from_settings(&settings).expect("minter")
}

fn identity() -> ExternalIdentity {
    ExternalIdentity {
        subject: "alice".to_string(),
        email: Some("alice@example.com".to_string()),
        display_name: Some("Alice".to_string()),
        idp: "static".to_string(),
    }
}

fn verifier(minter: &TokenMinter) -> JwtVerifier {
    JwtVerifier {
        jwk_service: Arc::new(LocalJwkService::new(minter)),
        jwt_issuer: Some(vec![minter.issuer().to_string()]),
        jwt_audience: Some(minter.audience().to_vec()),
        jwt_typ: None,
    }
}

#[tokio::test]
async fn unknown_kid_is_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let service = LocalJwkService::new(&minter(dir.path()));
    assert!(matches!(
        service.get_key("unknown").await,
        Err(JWKServiceError::NotFound)
    ));
}

#[tokio::test]
async fn mint_verify_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let minter = minter(dir.path());
    let minted = minter.mint_user_token(&identity()).expect("mint");

    let claims = verifier(&minter)
        .verify_token(&minted.token)
        .await
        .expect("verify");
    assert_eq!(claims.user_id, "static:alice");
    assert_eq!(claims.idp.as_deref(), Some("static"));
    assert_eq!(claims.resources, None);
}

#[tokio::test]
async fn authz_token_roundtrip_carries_resources() {
    use lore_server::auth::jwt::ResourcePermission;

    let dir = tempfile::tempdir().expect("tempdir");
    let minter = minter(dir.path());
    let user = minter.mint_user_token(&identity()).expect("mint user");
    let verifier = verifier(&minter);
    let user_claims = verifier.verify_token(&user.token).await.expect("verify");

    let repo_id = lore_revision::lore::RepositoryId::default();
    let resource = ResourcePermission {
        resource_id: format!("urc-{repo_id}"),
        permission: vec!["read".to_string(), "write".to_string()],
    };
    let authz = minter
        .mint_authz_token(&user_claims, vec![resource])
        .expect("mint authz");

    let authz_claims = verifier.verify_token(&authz.token).await.expect("verify");
    let resources = authz_claims.resources.as_deref().expect("resources claim");
    assert!(
        lore_server::auth::jwt::ResourceMatcher::default().any_match(resources, repo_id),
        "authorized for granted repo"
    );
    assert_eq!(authz_claims.user_id, "static:alice");
}

#[tokio::test]
async fn rejects_token_from_another_key() {
    let dir_a = tempfile::tempdir().expect("tempdir");
    let dir_b = tempfile::tempdir().expect("tempdir");
    let minter_a = minter(dir_a.path());
    let minter_b = minter(dir_b.path());

    let minted_by_b = minter_b.mint_user_token(&identity()).expect("mint");
    // Verifier only trusts A's key; B's kid is unknown.
    let err = verifier(&minter_a)
        .verify_token(&minted_by_b.token)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        lore_server::auth::jwt::JwtVerifierError::KeyNotFound(_)
    ));
}

#[tokio::test]
async fn rejects_wrong_issuer_and_audience() {
    let dir = tempfile::tempdir().expect("tempdir");
    let minter = minter(dir.path());
    let minted = minter.mint_user_token(&identity()).expect("mint");

    for bad in [
        JwtVerifier {
            jwk_service: Arc::new(LocalJwkService::new(&minter)),
            jwt_issuer: Some(vec!["https://other.example.com".to_string()]),
            jwt_audience: None,
            jwt_typ: None,
        },
        JwtVerifier {
            jwk_service: Arc::new(LocalJwkService::new(&minter)),
            jwt_issuer: None,
            jwt_audience: Some(vec!["other.example.com".to_string()]),
            jwt_typ: None,
        },
    ] {
        let err = bad.verify_token(&minted.token).await.unwrap_err();
        assert!(matches!(
            err,
            lore_server::auth::jwt::JwtVerifierError::ValidationFailed(_)
        ));
    }
}

#[tokio::test]
async fn minted_tokens_pass_client_side_domain_check() {
    // The client refuses to present a token to a remote whose domain is
    // not covered by the token's iss/aud root domains (the "check token
    // recipient" rule in lore-credential). Minted tokens must satisfy it
    // for the server's own domain, including host:port and localhost
    // remotes.
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = TokenMintingSettings {
        signing_key_path: Some(dir.path().join("key.pem").to_string_lossy().to_string()),
        generate_signing_key: true,
        issuer: "https://lore.example.com".to_string(),
        audience: vec!["lore.example.com".to_string(), "localhost".to_string()],
        user_token_ttl_seconds: 3600,
        authz_token_ttl_seconds: 900,
        refresh_token_ttl_seconds: 3600,
        env: "test".to_string(),
    };
    let minter = TokenMinter::from_settings(&settings).expect("minter");
    let minted = minter.mint_user_token(&identity()).expect("mint");

    let decoded = lore_credential::insecure_decode_token(&minted.token).expect("decode");
    lore_credential::verify_jwt_usage_for_remote(&decoded.claims, "lore.example.com")
        .expect("server domain accepted");
    lore_credential::verify_jwt_usage_for_remote(&decoded.claims, "localhost")
        .expect("localhost accepted");
    lore_credential::verify_jwt_usage_for_remote(&decoded.claims, "evil.example.org")
        .expect_err("unrelated domain refused");
}
