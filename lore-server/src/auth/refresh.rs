// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Server-side refresh tokens for server-local authentication.
//!
//! Refresh tokens are opaque 256-bit values handed out at login and on
//! every refresh. The server stores only a hash of each token, mapping to a
//! record blob (identity, family, expiry) via the mutable/immutable store
//! pattern. Tokens rotate on use: refreshing marks the presented token
//! `rotated` and issues a successor in the same *family*.
//!
//! Reuse of a rotated token has two interpretations. Within a short grace
//! window it is a *racing legitimate client* — several processes sharing
//! one credential store (CLI + desktop app + editor plugin) can present
//! the same token concurrently — and the replay idempotently returns the
//! same successor so all racers converge on one token. After the window
//! it is treated as theft: the family's active token is revoked so
//! neither party can continue.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::Metadata;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tracing::info;
use tracing::warn;

use crate::auth::provider::ExternalIdentity;

/// Key-derivation function names.
const TOKEN_FUNCTION: &str = "refresh-token";
const FAMILY_FUNCTION: &str = "refresh-family";
/// Metadata field holding the serialized record.
const RECORD_FIELD: &str = "record";

static INSTALLED: OnceLock<Arc<RefreshTokenStore>> = OnceLock::new();

/// Install the process-global refresh token store (server-local auth only).
pub fn install(store: Arc<RefreshTokenStore>) {
    if INSTALLED.set(store).is_err() {
        warn!("Refresh token store was already installed; ignoring duplicate");
    }
}

pub fn installed() -> Option<Arc<RefreshTokenStore>> {
    INSTALLED.get().cloned()
}

#[derive(Debug, Error)]
pub enum RefreshError {
    #[error("Unknown or expired refresh token")]
    Unknown,
    #[error("Refresh token reuse detected; session revoked")]
    ReuseDetected,
    #[error("Refresh store operation failed: {0}")]
    Store(String),
}

/// The persisted record behind a refresh token hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RefreshRecord {
    subject: String,
    email: Option<String>,
    display_name: Option<String>,
    idp: String,
    /// Rotation family; shared by every successor of one login.
    family: String,
    /// Milliseconds since the UNIX epoch.
    expires_ms: u64,
    /// Set when this token has been rotated away; presenting it again is
    /// reuse.
    rotated: bool,
    /// When the rotation happened (ms since epoch; 0 = never). Old records
    /// deserialize to 0, which reads as "grace long expired" — safe.
    #[serde(default)]
    rotated_at_ms: u64,
    /// The successor issued at rotation, returned verbatim to replays
    /// inside the grace window. A stored raw token, but a short-lived one:
    /// it is itself rotated away on first use, so a store read leaks at
    /// most one already-spent generation.
    #[serde(default)]
    successor: Option<String>,
}

impl RefreshRecord {
    fn identity(&self) -> ExternalIdentity {
        ExternalIdentity {
            subject: self.subject.clone(),
            email: self.email.clone(),
            display_name: self.display_name.clone(),
            idp: self.idp.clone(),
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Random URL-safe 256-bit value.
fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// How long a rotated token keeps answering with its successor before
/// reuse reads as theft. Long enough to cover a slow racing client's
/// round trip, short enough that a genuinely stolen token is useless
/// minutes later.
const REUSE_GRACE_MS: u64 = 60_000;

pub struct RefreshTokenStore {
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    ttl_ms: u64,
    reuse_grace_ms: u64,
}

impl RefreshTokenStore {
    pub fn new(
        immutable_store: Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: Arc<dyn lore_storage::MutableStore>,
        ttl_seconds: u64,
    ) -> Self {
        Self {
            immutable_store,
            mutable_store,
            ttl_ms: ttl_seconds.saturating_mul(1000),
            reuse_grace_ms: REUSE_GRACE_MS,
        }
    }

    #[cfg(test)]
    fn with_reuse_grace_ms(mut self, grace_ms: u64) -> Self {
        self.reuse_grace_ms = grace_ms;
        self
    }

    fn context(&self) -> Arc<lore_revision::repository::RepositoryContext> {
        lore_revision::access::server_context(
            self.immutable_store.clone(),
            self.mutable_store.clone(),
            RepositoryId::default(),
        )
    }

    /// The storage layer requires a `LORE_CONTEXT`.
    async fn scoped<T>(future: impl Future<Output = T>) -> T {
        let execution =
            crate::util::setup_execution(module_path!(), String::default(), String::default());
        lore_base::runtime::LORE_CONTEXT
            .scope(execution, future)
            .await
    }

    /// Only token hashes touch storage; the raw value never does.
    fn token_key(&self, token: &str) -> Hash {
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        lore_storage::hash::hash_function_arg_slice(b"lore", TOKEN_FUNCTION, digest.as_ref())
    }

    fn family_key(&self, family: &str) -> Hash {
        lore_storage::hash::hash_function_arg(b"lore", FAMILY_FUNCTION, family)
    }

    async fn load_record(&self, key: Hash) -> Result<Option<RefreshRecord>, RefreshError> {
        let context = self.context();
        let pointer = match Self::scoped(context.read_mutable_store().load(
            RepositoryId::default(),
            key,
            KeyType::Untyped,
        ))
        .await
        {
            Ok(pointer) if pointer != Hash::default() => pointer,
            Ok(_) => return Ok(None),
            Err(lore_storage::StoreError::AddressNotFound(_)) => return Ok(None),
            Err(err) => return Err(RefreshError::Store(err.to_string())),
        };
        let metadata = Self::scoped(Metadata::deserialize(context, pointer))
            .await
            .map_err(|e| RefreshError::Store(e.to_string()))?;
        let serialized = metadata
            .get_string(RECORD_FIELD)
            .map_err(|e| RefreshError::Store(e.to_string()))?;
        serde_json::from_str(serialized)
            .map(Some)
            .map_err(|e| RefreshError::Store(e.to_string()))
    }

    async fn store_value(&self, key: Hash, value: Hash) -> Result<(), RefreshError> {
        let context = self.context();
        let handle = context
            .try_write_mutable_store()
            .ok_or_else(|| RefreshError::Store("write access required".to_string()))?;
        Self::scoped(handle.store(RepositoryId::default(), key, value, KeyType::Untyped))
            .await
            .map_err(|e| RefreshError::Store(e.to_string()))
    }

    async fn store_record(&self, key: Hash, record: &RefreshRecord) -> Result<(), RefreshError> {
        let context = self.context();
        let serialized =
            serde_json::to_string(record).map_err(|e| RefreshError::Store(e.to_string()))?;
        let mut metadata = Metadata::new();
        metadata
            .set_string(RECORD_FIELD, serialized.as_str())
            .map_err(|e| RefreshError::Store(e.to_string()))?;
        let pointer = Self::scoped(metadata.serialize(context))
            .await
            .map_err(|e| RefreshError::Store(e.to_string()))?;
        self.store_value(key, pointer).await
    }

    /// Issue a fresh token (new family) for a verified login.
    pub async fn issue(&self, identity: &ExternalIdentity) -> Result<String, RefreshError> {
        let token = random_token();
        let family = random_token();
        let record = RefreshRecord {
            subject: identity.subject.clone(),
            email: identity.email.clone(),
            display_name: identity.display_name.clone(),
            idp: identity.idp.clone(),
            family: family.clone(),
            expires_ms: now_ms() + self.ttl_ms,
            rotated: false,
            rotated_at_ms: 0,
            successor: None,
        };
        let key = self.token_key(&token);
        self.store_record(key, &record).await?;
        self.store_value(self.family_key(&family), key).await?;
        Ok(token)
    }

    /// Redeem a refresh token: returns the identity plus a successor token.
    /// The presented token is rotated away; presenting it again revokes the
    /// whole family.
    pub async fn refresh(&self, token: &str) -> Result<(ExternalIdentity, String), RefreshError> {
        let key = self.token_key(token);
        let Some(mut record) = self.load_record(key).await? else {
            return Err(RefreshError::Unknown);
        };

        if record.rotated {
            // Within the grace window this is a racing legitimate client
            // (several processes share one credential store); replaying
            // idempotently returns the same successor so everyone
            // converges on one token instead of killing the session.
            if now_ms() < record.rotated_at_ms.saturating_add(self.reuse_grace_ms)
                && let Some(successor) = record.successor.clone()
            {
                info!(
                    idp = record.idp,
                    "Rotated refresh token replayed within grace; returning successor"
                );
                return Ok((record.identity(), successor));
            }
            // Past the grace window someone replayed an old value.
            // Revoke the family's active token so the session dies for
            // everyone holding pieces of it.
            warn!(
                idp = record.idp,
                "Refresh token reuse detected; revoking family"
            );
            let family_key = self.family_key(&record.family);
            let context = self.context();
            if let Some(handle) = context.try_write_mutable_store() {
                // Load the family's active token key and tombstone it.
                if let Ok(active_key) = Self::scoped(context.read_mutable_store().load(
                    RepositoryId::default(),
                    family_key,
                    KeyType::Untyped,
                ))
                .await
                {
                    let _ = Self::scoped(handle.store(
                        RepositoryId::default(),
                        active_key,
                        Hash::default(),
                        KeyType::Untyped,
                    ))
                    .await;
                }
                let _ = Self::scoped(handle.store(
                    RepositoryId::default(),
                    family_key,
                    Hash::default(),
                    KeyType::Untyped,
                ))
                .await;
            }
            return Err(RefreshError::ReuseDetected);
        }

        if record.expires_ms <= now_ms() {
            self.store_value(key, Hash::default()).await?;
            return Err(RefreshError::Unknown);
        }

        // Rotate: mark the presented token used, issue a successor in the
        // same family.
        let successor = random_token();
        let successor_key = self.token_key(&successor);
        let successor_record = RefreshRecord {
            rotated: false,
            rotated_at_ms: 0,
            successor: None,
            expires_ms: now_ms() + self.ttl_ms,
            ..record.clone()
        };
        self.store_record(successor_key, &successor_record).await?;
        self.store_value(self.family_key(&record.family), successor_key)
            .await?;
        let identity = record.identity();
        record.rotated = true;
        record.rotated_at_ms = now_ms();
        record.successor = Some(successor.clone());
        self.store_record(key, &record).await?;

        info!(idp = identity.idp, "Refresh token rotated");
        Ok((identity, successor))
    }
}

#[cfg(test)]
mod tests {
    use lore_base::runtime::LORE_CONTEXT;

    use super::*;
    use crate::store::test_store_create;

    fn identity() -> ExternalIdentity {
        ExternalIdentity {
            subject: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            display_name: Some("Alice".to_string()),
            idp: "static".to_string(),
        }
    }

    async fn store(
        ttl_seconds: u64,
    ) -> (
        RefreshTokenStore,
        Arc<lore_revision::interface::ExecutionContext>,
    ) {
        let (immutable, mutable, execution) = test_store_create().await.expect("test stores");
        (
            RefreshTokenStore::new(immutable, mutable, ttl_seconds),
            execution,
        )
    }

    #[tokio::test]
    async fn issue_then_refresh_rotates() {
        let (store, execution) = store(3600).await;
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let token = store.issue(&identity()).await.expect("issue");

            let (refreshed_identity, successor) = store.refresh(&token).await.expect("refresh");
            assert_eq!(refreshed_identity, identity());
            assert_ne!(successor, token);

            // The successor works too.
            let (_, third) = store.refresh(&successor).await.expect("second refresh");
            assert_ne!(third, successor);
        }))
        .await;
    }

    #[tokio::test]
    async fn unknown_token_is_refused() {
        let (store, execution) = store(3600).await;
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            assert!(matches!(
                store.refresh("never-issued").await,
                Err(RefreshError::Unknown)
            ));
        }))
        .await;
    }

    #[tokio::test]
    async fn expired_token_is_refused() {
        let (store, execution) = store(0).await;
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let token = store.issue(&identity()).await.expect("issue");
            assert!(matches!(
                store.refresh(&token).await,
                Err(RefreshError::Unknown)
            ));
        }))
        .await;
    }

    #[tokio::test]
    async fn concurrent_replay_within_grace_converges_on_one_successor() {
        let (store, execution) = store(3600).await;
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let token = store.issue(&identity()).await.expect("issue");
            let (_, successor) = store.refresh(&token).await.expect("refresh");

            // A racing process replays the same token: same successor, no
            // revocation — both processes now hold the same live token.
            let (_, replayed) = store.refresh(&token).await.expect("replay in grace");
            assert_eq!(replayed, successor);
            store
                .refresh(&successor)
                .await
                .expect("family survives the race");
        }))
        .await;
    }

    #[tokio::test]
    async fn reuse_revokes_the_family() {
        // Grace 0 = every replay is past the window (the theft path).
        let (store, execution) = store(3600).await;
        let store = store.with_reuse_grace_ms(0);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let token = store.issue(&identity()).await.expect("issue");
            let (_, successor) = store.refresh(&token).await.expect("refresh");

            // Replaying the rotated token is reuse...
            assert!(matches!(
                store.refresh(&token).await,
                Err(RefreshError::ReuseDetected)
            ));
            // ...which revokes the active successor as well.
            assert!(matches!(
                store.refresh(&successor).await,
                Err(RefreshError::Unknown)
            ));
        }))
        .await;
    }

    #[tokio::test]
    async fn families_are_independent() {
        let (store, execution) = store(3600).await;
        let store = store.with_reuse_grace_ms(0);
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let first_login = store.issue(&identity()).await.expect("issue");
            let second_login = store.issue(&identity()).await.expect("issue");

            // Killing the first family leaves the second alone.
            let (_, successor) = store.refresh(&first_login).await.expect("refresh");
            let _ = store.refresh(&first_login).await;
            assert!(matches!(
                store.refresh(&successor).await,
                Err(RefreshError::Unknown)
            ));

            store
                .refresh(&second_login)
                .await
                .expect("second family lives");
        }))
        .await;
    }
}
