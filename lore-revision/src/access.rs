// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Per-repository access-control grants.
//!
//! Grants follow the repository-metadata storage pattern: the grant set
//! serializes into a [`Metadata`] blob in the content-addressed immutable
//! store, with a pointer in the mutable store under
//! [`KeyType::AccessControl`], updated via compare-and-swap so concurrent
//! grant changes never lose writes. Server-level grants use the default
//! repository id (the default partition), like repository name mappings.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;

use lore_base::error::WriteRequired;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_error_set::prelude::*;
use serde::Deserialize;
use serde::Serialize;

use crate::hash;
use crate::lore::RepositoryId;
use crate::metadata::Metadata;
use crate::repository::RepositoryContext;
use crate::repository::RepositoryError;

/// Key-derivation function name for the grants pointer.
const GRANTS_FUNCTION: &str = "access-grants";
/// Metadata field holding the serialized grant set.
const GRANTS_FIELD: &str = "grants";
/// Attempts before giving up on a compare-and-swap race.
const CAS_ATTEMPTS: usize = 8;

/// Reserved principal marking a repository as public: any caller —
/// authenticated or anonymous — receives at least this grant's role. Public
/// grants are restricted to [`AccessRole::Read`] and are not permitted on
/// the server-level (default) repository id; enforcement lives in the
/// server's `AccessControl`.
pub const PUBLIC_PRINCIPAL: &str = "*";

/// A role granted to a principal on a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessRole {
    /// Clone/sync/read.
    Read,
    /// Read plus push/branch/lock.
    Write,
    /// Write plus grant management, repository settings, obliterate.
    Admin,
}

impl AccessRole {
    /// The permission verbs embedded in minted authorization tokens,
    /// matching the verbs the enforcement helpers check.
    pub fn verbs(self) -> &'static [&'static str] {
        match self {
            AccessRole::Read => &["read"],
            AccessRole::Write => &["read", "write"],
            AccessRole::Admin => &["read", "write", "admin", "owner", "obliterate", "migrate"],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            AccessRole::Read => "read",
            AccessRole::Write => "write",
            AccessRole::Admin => "admin",
        }
    }
}

impl FromStr for AccessRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(AccessRole::Read),
            "write" => Ok(AccessRole::Write),
            "admin" => Ok(AccessRole::Admin),
            other => Err(format!(
                "unknown role '{other}' (expected read, write, or admin)"
            )),
        }
    }
}

/// Principal → role. Principals are canonical user ids (`<idp>:<subject>`)
/// or admin-entered email aliases; matching against both is the caller's
/// concern.
pub type AccessGrants = BTreeMap<String, AccessRole>;

fn grants_key(repository: &RepositoryContext) -> (Hash, KeyType) {
    let key = hash::hash_function_arg(
        repository.salt(),
        GRANTS_FUNCTION,
        hex::encode(repository.id.data()).as_str(),
    );
    (key, KeyType::AccessControl)
}

/// The discriminant [`KeyType::AccessControl`] held before the 0.9.1 upstream
/// merge renumbered it to 8 (upstream took 7 for `Resolve`). The mutable
/// store stamps the discriminant into the row key, so grant pointers written
/// by a pre-merge server live at this slot. Reading it as a fallback cannot
/// collide with real `Resolve` rows: the key hash is derived from
/// [`GRANTS_FUNCTION`], and nothing but grant pointers was ever written
/// under it.
const LEGACY_GRANTS_KEY_TYPE: KeyType = KeyType::Resolve;

/// The grants pointer plus which key slot held it.
struct GrantsPointer {
    hash: Hash,
    /// Found under [`LEGACY_GRANTS_KEY_TYPE`]; the current key holds nothing,
    /// so a compare-and-swap on it must expect the default hash, and a write
    /// through the current key permanently shadows the legacy row.
    legacy: bool,
}

/// Load the current grants pointer, mapping "never written" to the default
/// hash. A miss at the current key falls back to the pre-0.9.1 key slot so
/// grants written before the `KeyType` renumbering stay readable.
async fn load_pointer(
    repository: &Arc<RepositoryContext>,
) -> Result<GrantsPointer, RepositoryError> {
    let (key, key_type) = grants_key(repository);
    for (key_type, legacy) in [(key_type, false), (LEGACY_GRANTS_KEY_TYPE, true)] {
        match repository
            .read_mutable_store()
            .load(repository.id, key, key_type)
            .await
        {
            // Found. A default hash is a tombstone — "cleared here", an
            // explicit state that must not fall through to the legacy slot
            // and resurrect old grants.
            Ok(hash) => return Ok(GrantsPointer { hash, legacy }),
            // Never written at this slot: try the next one.
            Err(lore_storage::StoreError::AddressNotFound(_)) => {}
            Err(err) => {
                return Err(err)
                    .forward::<RepositoryError>("Failed to load access-control grants pointer");
            }
        }
    }
    Ok(GrantsPointer {
        hash: Hash::default(),
        legacy: false,
    })
}

async fn load_blob(
    repository: &Arc<RepositoryContext>,
    pointer: Hash,
) -> Result<AccessGrants, RepositoryError> {
    if pointer == Hash::default() {
        return Ok(AccessGrants::new());
    }
    let metadata = Metadata::deserialize(repository.clone(), pointer)
        .await
        .forward::<RepositoryError>("Failed to load access-control grants")?;
    let serialized = metadata
        .get_string(GRANTS_FIELD)
        .forward::<RepositoryError>("Failed to read access-control grants")?;
    serde_json::from_str(serialized).map_err(|err| {
        RepositoryError::internal(format!("Failed to parse access-control grants: {err}"))
    })
}

async fn store_blob(
    repository: &Arc<RepositoryContext>,
    grants: &AccessGrants,
) -> Result<Hash, RepositoryError> {
    let serialized = serde_json::to_string(grants).map_err(|err| {
        RepositoryError::internal(format!("Failed to serialize access-control grants: {err}"))
    })?;
    let mut metadata = Metadata::new();
    metadata
        .set_string(GRANTS_FIELD, serialized.as_str())
        .forward::<RepositoryError>("Failed to serialize access-control grants")?;
    metadata
        .serialize(repository.clone())
        .await
        .forward::<RepositoryError>("Failed to store access-control grants")
}

/// Load the grant set for the context's repository. A repository with no
/// grants yet yields an empty set.
///
/// Grants found under the legacy key slot are re-registered under the
/// current one when the context can write, so the fallback read is paid
/// once per repository rather than on every load.
pub async fn load_grants(
    repository: Arc<RepositoryContext>,
) -> Result<AccessGrants, RepositoryError> {
    let pointer = load_pointer(&repository).await?;
    if pointer.legacy
        && let Some(handle) = repository.try_write_mutable_store()
    {
        let (key, key_type) = grants_key(&repository);
        // Best-effort: expect "never written" at the current slot; a racing
        // writer that got there first wins and this copy is a no-op.
        let _ = handle
            .compare_and_swap(repository.id, key, Hash::default(), pointer.hash, key_type)
            .await
            .inspect_err(|err| {
                lore_base::lore_debug!("Failed to upgrade legacy access-control grants: {err}");
            });
    }
    load_blob(&repository, pointer.hash).await
}

/// Apply `mutate` to the grant set under a compare-and-swap loop and return
/// the stored result. Concurrent modifications retry rather than losing
/// writes.
pub async fn modify_grants(
    repository: Arc<RepositoryContext>,
    mut mutate: impl FnMut(&mut AccessGrants),
) -> Result<AccessGrants, RepositoryError> {
    let (key, key_type) = grants_key(&repository);
    for _attempt in 0..CAS_ATTEMPTS {
        let pointer = load_pointer(&repository).await?;
        // A legacy-slot pointer means the current key holds nothing: the
        // swap below expects the default hash there, and its success
        // permanently shadows the legacy row.
        let expected = if pointer.legacy {
            Hash::default()
        } else {
            pointer.hash
        };
        let mut grants = load_blob(&repository, pointer.hash).await?;
        mutate(&mut grants);
        let updated = store_blob(&repository, &grants).await?;
        if updated == pointer.hash {
            // No change; nothing to swap.
            return Ok(grants);
        }

        let handle = repository
            .try_write_mutable_store()
            .ok_or_else(|| RepositoryError::from(WriteRequired))?;
        let previous = handle
            .compare_and_swap(repository.id, key, expected, updated, key_type)
            .await
            .forward::<RepositoryError>("Failed to swap access-control grants pointer")?;
        if previous == expected {
            return Ok(grants);
        }
        // Lost the race; reload and retry.
    }
    Err(RepositoryError::internal(
        "Failed to update access-control grants after repeated conflicts",
    ))
}

/// Remove every grant for the context's repository (repository deletion).
pub async fn clear_grants(repository: Arc<RepositoryContext>) -> Result<(), RepositoryError> {
    modify_grants(repository, BTreeMap::clear).await.map(|_| ())
}

/// The grants pointer key plus its current and legacy key slots, exposed for
/// the legacy-upgrade tests and nothing else.
#[doc(hidden)]
pub fn grants_slots(repository: &RepositoryContext) -> (Hash, KeyType, KeyType) {
    let (key, current) = grants_key(repository);
    (key, current, LEGACY_GRANTS_KEY_TYPE)
}

/// Convenience: a server context for grant operations against `repository`.
pub fn server_context(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    repository: RepositoryId,
) -> Arc<RepositoryContext> {
    Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_verbs_are_ordered_supersets() {
        assert_eq!(AccessRole::Read.verbs(), ["read"]);
        assert_eq!(AccessRole::Write.verbs(), ["read", "write"]);
        for verb in AccessRole::Write.verbs() {
            assert!(AccessRole::Admin.verbs().contains(verb));
        }
        assert!(AccessRole::Admin.verbs().contains(&"owner"));
        assert!(AccessRole::Admin.verbs().contains(&"obliterate"));
    }

    #[test]
    fn role_parsing_round_trips() {
        for role in [AccessRole::Read, AccessRole::Write, AccessRole::Admin] {
            assert_eq!(AccessRole::from_str(role.as_str()).unwrap(), role);
        }
        assert!(AccessRole::from_str("owner").is_err());
    }

    #[test]
    fn grants_serialize_stably() {
        let mut grants = AccessGrants::new();
        grants.insert("google:123".to_string(), AccessRole::Admin);
        grants.insert("static:alice".to_string(), AccessRole::Read);
        let json = serde_json::to_string(&grants).unwrap();
        assert_eq!(json, r#"{"google:123":"admin","static:alice":"read"}"#);
        let parsed: AccessGrants = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, grants);
    }
}
