// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::Path;

use jsonwebtoken::Algorithm;
use lore_server::auth::minting::*;
use lore_server::auth::provider::ExternalIdentity;

pub(crate) fn test_settings(dir: &Path) -> TokenMintingSettings {
    TokenMintingSettings {
        signing_key_path: Some(dir.join("signing-key.pem").to_string_lossy().to_string()),
        generate_signing_key: true,
        issuer: "https://lore.example.com".to_string(),
        audience: vec!["lore.example.com".to_string()],
        user_token_ttl_seconds: 3600,
        authz_token_ttl_seconds: 900,
        refresh_token_ttl_seconds: 3600,
        env: "test".to_string(),
    }
}

fn identity() -> ExternalIdentity {
    ExternalIdentity {
        subject: "alice".to_string(),
        email: Some("alice@example.com".to_string()),
        display_name: Some("Alice Example".to_string()),
        idp: "static".to_string(),
    }
}

#[test]
fn generates_and_reloads_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let settings = test_settings(dir.path());

    let first = TokenMinter::from_settings(&settings).expect("generate");
    // A second construction reloads the persisted key rather than
    // generating a new one.
    let second = TokenMinter::from_settings(&settings).expect("reload");
    assert_eq!(first.kid(), second.kid());
}

#[test]
fn refuses_without_key_or_generation() {
    let settings = TokenMintingSettings {
        signing_key_path: None,
        generate_signing_key: false,
        ..test_settings(Path::new("/nonexistent"))
    };
    assert!(matches!(
        TokenMinter::from_settings(&settings),
        Err(MintingError::NoSigningKey)
    ));
}

#[test]
fn rejects_invalid_key_material() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.pem");
    std::fs::write(&path, der_to_pem(b"not a key")).expect("write");
    let settings = TokenMintingSettings {
        signing_key_path: Some(path.to_string_lossy().to_string()),
        ..test_settings(dir.path())
    };
    assert!(matches!(
        TokenMinter::from_settings(&settings),
        Err(MintingError::InvalidKey(_))
    ));
}

#[test]
fn user_token_claims_are_complete() {
    let dir = tempfile::tempdir().expect("tempdir");
    let minter = TokenMinter::from_settings(&test_settings(dir.path())).expect("minter");
    let minted = minter.mint_user_token(&identity()).expect("mint");

    assert_eq!(minted.user_id, "static:alice");
    assert_eq!(minted.user_name, "Alice Example");

    // Decode without verification to inspect claims.
    let decoded = lore_credential::insecure_decode_token(&minted.token).expect("decode");
    assert_eq!(decoded.claims.user_id, "static:alice");
    assert_eq!(decoded.claims.issuer, "https://lore.example.com");
    assert_eq!(decoded.claims.audience, vec!["lore.example.com"]);
    assert_eq!(decoded.claims.expires * 1000, minted.expires_at_ms as u64);
    let header = jsonwebtoken::decode_header(&minted.token).expect("header");
    assert_eq!(header.kid.as_deref(), Some(minter.kid()));
    assert_eq!(header.alg, Algorithm::EdDSA);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
}

#[test]
fn identity_fallbacks_without_name_or_email() {
    let dir = tempfile::tempdir().expect("tempdir");
    let minter = TokenMinter::from_settings(&test_settings(dir.path())).expect("minter");
    let minted = minter
        .mint_user_token(&ExternalIdentity {
            subject: "bob".to_string(),
            email: None,
            display_name: None,
            idp: "static".to_string(),
        })
        .expect("mint");
    assert_eq!(minted.user_name, "bob");
}

#[test]
fn pem_roundtrip() {
    let der = b"arbitrary bytes for the envelope".to_vec();
    assert_eq!(pem_to_der(der_to_pem(&der).as_bytes()).expect("parse"), der);
    // Raw DER passes through.
    assert_eq!(pem_to_der(&der).expect("raw"), der);
}
