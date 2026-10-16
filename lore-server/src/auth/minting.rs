// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Server-local JWT minting.
//!
//! When a local auth provider is configured, `loreserver` mints its own
//! short-lived tokens instead of relying on an external auth service:
//! a *user token* (authentication, no `resources` claim) at login, and
//! per-repository *authorization tokens* (with `resources` claims) at
//! token-exchange time. Tokens are signed with a server-local Ed25519 key
//! and verified through the standard [`JwtVerifier`](crate::auth::jwt)
//! machinery via [`LocalJwkService`](crate::auth::local_jwk).

use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use ring::signature::Ed25519KeyPair;
use ring::signature::KeyPair;
use serde::Deserialize;
use thiserror::Error;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;
use crate::auth::provider::ExternalIdentity;
use crate::auth::session::MintedLogin;

fn default_user_token_ttl() -> u64 {
    3600
}

fn default_authz_token_ttl() -> u64 {
    900
}

fn default_refresh_token_ttl() -> u64 {
    30 * 24 * 3600
}

fn default_env() -> String {
    "lore".to_string()
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenMintingSettings {
    /// Path to a PKCS#8 PEM Ed25519 private key used to sign minted tokens.
    pub signing_key_path: Option<String>,
    /// Generate (and persist to `signing_key_path`, when set) a signing key
    /// if none exists. Intended for development and tests.
    #[serde(default)]
    pub generate_signing_key: bool,
    /// `iss` claim of minted tokens.
    pub issuer: String,
    /// `aud` claim of minted tokens. Entries double as the root domains the
    /// client will trust the token to (the client-side "check token
    /// recipient" rule matches the remote host against these), so they
    /// should be the server's domain, e.g. `lore.example.com`.
    pub audience: Vec<String>,
    #[serde(default = "default_user_token_ttl")]
    pub user_token_ttl_seconds: u64,
    #[serde(default = "default_authz_token_ttl")]
    pub authz_token_ttl_seconds: u64,
    /// Lifetime of refresh tokens (rotated on every use).
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl_seconds: u64,
    /// `env` claim of minted tokens.
    #[serde(default = "default_env")]
    pub env: String,
}

#[derive(Debug, Error)]
pub enum MintingError {
    #[error("No signing key: set auth.token.signing_key_path or generate_signing_key = true")]
    NoSigningKey,
    #[error("Failed to read signing key {path}: {source}")]
    ReadKey {
        path: String,
        source: std::io::Error,
    },
    #[error("Failed to write generated signing key {path}: {source}")]
    WriteKey {
        path: String,
        source: std::io::Error,
    },
    #[error("Invalid signing key: {0}")]
    InvalidKey(String),
    #[error("Failed to generate signing key")]
    Generate,
    #[error("Failed to sign token: {0}")]
    Sign(#[from] jsonwebtoken::errors::Error),
    #[error("System clock is before the UNIX epoch")]
    Clock,
}

const PEM_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
const PEM_FOOTER: &str = "-----END PRIVATE KEY-----";

/// Wrap PKCS#8 DER bytes in a PEM envelope.
#[lore_macro::test_pub]
fn der_to_pem(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from(PEM_HEADER);
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push('\n');
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    pem.push('\n');
    pem.push_str(PEM_FOOTER);
    pem.push('\n');
    pem
}

/// Extract PKCS#8 DER bytes from a PEM envelope (or pass DER through).
#[lore_macro::test_pub]
fn pem_to_der(contents: &[u8]) -> Result<Vec<u8>, MintingError> {
    let text = match std::str::from_utf8(contents) {
        Ok(text) if text.contains(PEM_HEADER) => text,
        // Not PEM; assume raw PKCS#8 DER.
        _ => return Ok(contents.to_vec()),
    };
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| MintingError::InvalidKey(format!("invalid PEM base64: {e}")))
}

/// Mints Lore-issued JWTs from a server-local Ed25519 signing key.
pub struct TokenMinter {
    encoding_key: EncodingKey,
    /// Raw Ed25519 public key bytes for verification and JWKS publication.
    public_key: Vec<u8>,
    kid: String,
    issuer: String,
    audience: Vec<String>,
    env: String,
    user_token_ttl_seconds: u64,
    authz_token_ttl_seconds: u64,
}

fn now_epoch_seconds() -> Result<u64, MintingError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_err| MintingError::Clock)
}

impl TokenMinter {
    pub fn from_settings(settings: &TokenMintingSettings) -> Result<Self, MintingError> {
        let der = Self::load_or_generate_key(settings)?;
        Self::from_pkcs8_der(&der, settings)
    }

    fn load_or_generate_key(settings: &TokenMintingSettings) -> Result<Vec<u8>, MintingError> {
        if let Some(path) = settings.signing_key_path.as_deref()
            && Path::new(path).exists()
        {
            let contents = std::fs::read(path).map_err(|source| MintingError::ReadKey {
                path: path.to_string(),
                source,
            })?;
            return pem_to_der(&contents);
        }

        if !settings.generate_signing_key {
            return Err(MintingError::NoSigningKey);
        }

        let rng = ring::rand::SystemRandom::new();
        let document =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_err| MintingError::Generate)?;
        let der = document.as_ref().to_vec();

        if let Some(path) = settings.signing_key_path.as_deref() {
            std::fs::write(path, der_to_pem(&der)).map_err(|source| MintingError::WriteKey {
                path: path.to_string(),
                source,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
        }
        Ok(der)
    }

    fn from_pkcs8_der(der: &[u8], settings: &TokenMintingSettings) -> Result<Self, MintingError> {
        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map_err(|e| MintingError::InvalidKey(format!("not an Ed25519 PKCS#8 key: {e}")))?;
        let public_key = key_pair.public_key().as_ref().to_vec();

        // Stable key id derived from the public key, for JWT headers and
        // JWKS publication.
        let digest = ring::digest::digest(&ring::digest::SHA256, &public_key);
        let kid = hex::encode(&digest.as_ref()[..8]);

        Ok(Self {
            encoding_key: EncodingKey::from_ed_der(der),
            public_key,
            kid,
            issuer: settings.issuer.clone(),
            audience: settings.audience.clone(),
            env: settings.env.clone(),
            user_token_ttl_seconds: settings.user_token_ttl_seconds,
            authz_token_ttl_seconds: settings.authz_token_ttl_seconds,
        })
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &[String] {
        &self.audience
    }

    /// Verification key for [`LocalJwkService`](crate::auth::local_jwk).
    pub fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ed_der(&self.public_key)
    }

    /// The public signing key as a JWK (RFC 8037 Ed25519 OKP), for
    /// publication at `/auth/.well-known/jwks.json` so external services
    /// can verify Lore-minted tokens.
    pub fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.public_key),
            "kid": self.kid,
            "alg": "EdDSA",
            "use": "sig",
        })
    }

    fn sign(&self, claims: &AuthorizationToken) -> Result<String, MintingError> {
        let mut header = Header::new(Algorithm::EdDSA);
        // RFC 9068 access tokens, so a verifier configured with
        // `jwt_typ = "at+jwt"` accepts what this server mints.
        header.typ = Some("at+jwt".to_string());
        header.kid = Some(self.kid.clone());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding_key)?)
    }

    /// Mint an authentication (user) token for a verified identity. Carries
    /// no `resources` claim; per-repository access comes from the exchange
    /// endpoint via [`mint_authz_token`](Self::mint_authz_token).
    pub fn mint_user_token(
        &self,
        identity: &ExternalIdentity,
    ) -> Result<MintedLogin, MintingError> {
        let now = now_epoch_seconds()?;
        let user_id = identity.user_id();
        let name = identity
            .display_name
            .clone()
            .or_else(|| identity.email.clone())
            .unwrap_or_else(|| identity.subject.clone());
        let preferred_username = identity
            .email
            .clone()
            .unwrap_or_else(|| identity.subject.clone());

        let claims = AuthorizationToken {
            user_id: user_id.clone(),
            identity: None,
            issuer: self.issuer.clone(),
            issued_at: now,
            expires: now + self.user_token_ttl_seconds,
            audience: self.audience.clone(),
            env: Some(self.env.clone()),
            name: Some(name.clone()),
            preferred_username: Some(preferred_username),
            client_id: None,
            resources: None,
            groups: None,
            is_service_account: Some(false),
            idp: Some(identity.idp.clone()),
            // The audience entries are the server's domain(s); advertising
            // them under the dedicated claim as well keeps the client-side
            // send-check working if `aud` ever becomes a URI (upstream D5).
            root_domains: Some(self.audience.clone()),
            extra: Default::default(),
        };

        Ok(MintedLogin {
            token: self.sign(&claims)?,
            user_id,
            user_name: name,
            expires_at_ms: (claims.expires as i64).saturating_mul(1000),
            refresh_token: None,
        })
    }

    /// Mint an authorization token for a verified user token, embedding the
    /// resolved per-resource permissions.
    pub fn mint_authz_token(
        &self,
        user_claims: &AuthorizationToken,
        resources: Vec<ResourcePermission>,
    ) -> Result<MintedLogin, MintingError> {
        let now = now_epoch_seconds()?;
        let claims = AuthorizationToken {
            issued_at: now,
            expires: now + self.authz_token_ttl_seconds,
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            env: Some(self.env.clone()),
            resources: Some(resources),
            ..user_claims.clone()
        };

        Ok(MintedLogin {
            token: self.sign(&claims)?,
            user_id: claims.user_id.clone(),
            user_name: claims
                .name
                .clone()
                .unwrap_or_else(|| claims.user_id.clone()),
            expires_at_ms: (claims.expires as i64).saturating_mul(1000),
            refresh_token: None,
        })
    }
}
