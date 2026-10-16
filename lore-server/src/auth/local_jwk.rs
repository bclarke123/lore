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
