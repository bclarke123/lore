// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! [`JWKService`] over the server's own signing keys.
//!
//! Lets the standard [`JwtVerifier`](crate::auth::jwt::JwtVerifier) verify
//! self-minted tokens without a remote JWKS endpoint. Holds an accept-list
//! of key ids so signing-key rotation can keep a previous key verifiable.

use async_trait::async_trait;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;

use crate::auth::jwk::JWKService;
use crate::auth::jwk::JWKServiceError;
use crate::auth::minting::TokenMinter;

pub struct LocalJwkService {
    keys: Vec<(String, DecodingKey, Algorithm)>,
}

impl LocalJwkService {
    pub fn new(minter: &TokenMinter) -> Self {
        Self {
            keys: vec![(
                minter.kid().to_string(),
                minter.decoding_key(),
                minter.algorithm(),
            )],
        }
    }
}

#[async_trait]
impl JWKService for LocalJwkService {
    async fn get_key(&self, kid: &str) -> Result<(DecodingKey, Algorithm), JWKServiceError> {
        self.get_cached_key(kid).ok_or(JWKServiceError::NotFound)
    }

    // The whole accept-list lives in memory, so the synchronous hot path
    // can always answer for a known kid.
    fn get_cached_key(&self, kid: &str) -> Option<(DecodingKey, Algorithm)> {
        self.keys
            .iter()
            .find(|(key_id, _, _)| key_id == kid)
            .map(|(_, key, alg)| (key.clone(), *alg))
    }

    /// Local keys live for the process; there is never fresher material to
    /// fetch, so a rotation suspicion can only answer "unchanged".
    async fn refresh_key(
        &self,
        _kid: &str,
    ) -> Result<Option<(DecodingKey, Algorithm)>, JWKServiceError> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::auth::jwt::JwtVerifier;
    use crate::auth::minting::TokenMintingSettings;
    use crate::auth::provider::ExternalIdentity;

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
            jwt_issuer: Some(minter.issuer().to_string()),
            jwt_audience: Some(minter.audience().to_vec()),
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
        assert_eq!(claims.idp, "static");
        assert_eq!(claims.resources, None);
    }

    #[tokio::test]
    async fn authz_token_roundtrip_carries_resources() {
        use crate::auth::jwt::ResourcePermission;
        use crate::auth::jwt::verify_authorization;

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
        verify_authorization(&authz_claims, repo_id).expect("authorized for granted repo");
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
            crate::auth::jwt::JwtVerifierError::KeyNotFound(_)
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
                jwt_issuer: Some("https://other.example.com".to_string()),
                jwt_audience: None,
            },
            JwtVerifier {
                jwk_service: Arc::new(LocalJwkService::new(&minter)),
                jwt_issuer: None,
                jwt_audience: Some(vec!["other.example.com".to_string()]),
            },
        ] {
            let err = bad.verify_token(&minted.token).await.unwrap_err();
            assert!(matches!(
                err,
                crate::auth::jwt::JwtVerifierError::ValidationFailed(_)
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
}
