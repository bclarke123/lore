// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! `put_resolved`: `put` + `mutable_store` performed server-side, saving the caller one round
//! trip. The write side of [`super::get_resolved`], and the only thing that makes a key readable
//! by it.
//!
//! The fragment is stored through [`handle_put`] rather than a parallel implementation, so it
//! inherits `put`'s hash and fragment validation exactly. Only once that succeeds is the
//! `KeyType::Resolve` mapping published, so a key never names content the server does not hold —
//! the ordering the revision layer uses for branch pointers, and the one `read_resolved`'s
//! write-back already follows on the client.
//!
//! A request whose content address is the zero hash **deletes** the mapping instead: there is no
//! fragment to store, and storing the zero value is how the mutable store removes a key. That
//! makes publish and delete the same operation with different content, and it is what
//! `read_resolved` already expects — it reports a zero resolved value as a miss.
use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_storage::StoreError;
use tracing::debug;
use tracing::warn;

use crate::protocol::storage::messages::LoreResponse;
use crate::protocol::storage::messages::Message;
use crate::protocol::storage::messages::MessageHandleError;
use crate::protocol::storage::messages::MessageParseError;
use crate::protocol::storage::messages::Response;
use crate::protocol::storage::put::Put;
use crate::protocol::storage::put::UnvalidatedPut;
use crate::protocol::storage::put::handle_put;
use crate::util::setup_execution;

/// Wire request: key `Hash` (32) ++ `Address` (48) ++ `Fragment` (16) ++ payload.
#[derive(Clone, Debug, PartialEq)]
pub struct PutResolved {
    /// Mutable key to publish the stored hash under.
    pub key: Hash,
    /// Content address of the fragment; `address.hash` is what `key` will resolve to. A zero hash
    /// deletes the mapping instead. Held alongside `put` because `Put` does not expose it.
    pub address: Address,
    put: Option<Put>,
}

impl PutResolved {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError> {
        const KEY: usize = size_of::<Hash>();
        if bytes.len() < KEY + size_of::<Address>() + size_of::<Fragment>() {
            return Err(MessageParseError::InvalidFieldLength);
        }

        let mut bytes = bytes;
        let key = Hash::from(&bytes.split_to(KEY)[..]);
        if key.is_zero() {
            return Err(MessageParseError::ParseFailure(
                "put_resolved: key must be non-zero",
            ));
        }

        let address: Address = bytes.split_to(size_of::<Address>()).into();
        let fragment: Fragment = bytes.split_to(size_of::<Fragment>()).into();
        let payload = if bytes.is_empty() { None } else { Some(bytes) };

        let put = if address.hash.is_zero() {
            None
        } else {
            if payload.is_none() {
                return Err(MessageParseError::ParseFailure(
                    "put_resolved: publishing requires a payload",
                ));
            }
            Some(
                UnvalidatedPut {
                    address,
                    fragment,
                    payload,
                }
                .validate()?,
            )
        };

        Ok(Self { key, address, put })
    }

    /// The validated fragment write this request carries, or `None` when it is a deletion.
    pub fn put(&self) -> Option<&Put> {
        self.put.as_ref()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_put_resolved(
    key: Hash,
    put: Option<&Put>,
    address: Address,
    repository: RepositoryId,
    correlation_id: String,
    user_id: String,
    mutable_store: Arc<dyn MutableStore>,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<LoreResponse, MessageHandleError> {
    if let Some(put) = put {
        handle_put(
            put,
            repository,
            correlation_id.clone(),
            user_id.clone(),
            immutable_store,
        )
        .await?;
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    LORE_CONTEXT
        .scope(execution, async move {
            match mutable_store
                .store(repository, key, address.hash, KeyType::Resolve)
                .await
            {
                Ok(()) => {
                    if address.hash.is_zero() {
                        debug!("put_resolved: removed key {} in repository {}", key, repository);
                    } else {
                        debug!(
                            "put_resolved: key {} -> {} in repository {}",
                            key, address.hash, repository
                        );
                    }
                    Ok(LoreResponse::PutResolved(PutResolvedResponse::default()))
                }
                Err(StoreError::SlowDown(_)) => Err(MessageHandleError::SlowDown),
                Err(err) => {
                    warn!(error = ?err, "put_resolved: stored {} but failed to map key {}", address.hash, key);
                    Err(MessageHandleError::StoreFailure)
                }
            }
        })
        .await
}

/// Dispatched from the v4 path: the defaults return `NotImplemented`, since v0 supplies only one
/// store and this needs both.
impl Message for PutResolved {}

#[derive(Debug, Default, PartialEq)]
pub struct PutResolvedResponse {}

impl Response for PutResolvedResponse {
    fn data(&self) -> Vec<Bytes> {
        vec![]
    }
}
