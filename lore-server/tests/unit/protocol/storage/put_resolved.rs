// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::protocol::storage::put_resolved::*;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

fn request_bytes(key: Hash, address: Address, fragment: Fragment, payload: &[u8]) -> Bytes {
    let mut bytes = bytes::BytesMut::new();
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(address.as_bytes());
    bytes.extend_from_slice(fragment.as_bytes());
    bytes.extend_from_slice(payload);
    bytes.freeze()
}

fn fragment_for(payload: &[u8]) -> (Address, Fragment) {
    let hash = lore_storage::hash_slice(payload);
    (
        Address {
            hash,
            context: Default::default(),
        },
        Fragment {
            flags: FragmentFlags::PayloadStoredLocal.bits(),
            size_payload: payload.len() as u32,
            size_content: payload.len() as u64,
        },
    )
}

#[test]
fn test_parse_round_trips_key_address_and_payload() {
    let payload = b"put-resolved-parse".as_slice();
    let (address, fragment) = fragment_for(payload);
    let key = Hash::hash_buffer(b"parse-key");
    let parsed = PutResolved::parse(request_bytes(key, address, fragment, payload)).unwrap();
    assert_eq!(parsed.key, key);
    assert_eq!(parsed.address, address);
}

#[test]
fn test_parse_rejects_zero_key() {
    let payload = b"put-resolved-zero-key".as_slice();
    let (address, fragment) = fragment_for(payload);
    assert!(matches!(
        PutResolved::parse(request_bytes(Hash::default(), address, fragment, payload)),
        Err(MessageParseError::ParseFailure(_))
    ));
}

/// A publish with no payload would store metadata only and still map the key to it — the
/// dangling mapping this command exists to prevent.
#[test]
fn test_parse_rejects_publish_without_payload() {
    let payload = b"put-resolved-no-payload".as_slice();
    let (address, fragment) = fragment_for(payload);
    let key = Hash::hash_buffer(b"no-payload-key");
    assert!(matches!(
        PutResolved::parse(request_bytes(key, address, fragment, &[])),
        Err(MessageParseError::ParseFailure(_))
    ));
}

#[test]
fn test_parse_invalid_length() {
    let bytes = Bytes::from(vec![0u8; size_of::<Hash>() + size_of::<Address>()]);
    assert_eq!(
        PutResolved::parse(bytes),
        Err(MessageParseError::InvalidFieldLength)
    );
}

/// The mapping must be readable straight after the call, and must name the stored content.
#[tokio::test]
async fn test_stores_fragment_then_publishes_mapping() {
    let repository = random::<RepositoryId>();
    let payload = b"put-resolved-round-trip".as_slice();
    let (address, fragment) = fragment_for(payload);
    let key = Hash::hash_buffer(b"publish-key");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let parsed = PutResolved::parse(request_bytes(key, address, fragment, payload)).expect("parse");

    LORE_CONTEXT
        .scope(execution, async move {
            handle_put_resolved(
                parsed.key,
                parsed.put(),
                parsed.address,
                repository,
                String::new(),
                String::new(),
                mutable_store.clone(),
                immutable_store.clone(),
            )
            .await
            .expect("put_resolved must succeed");

            let mapped = mutable_store
                .load(repository, key, KeyType::Resolve)
                .await
                .expect("mapping must exist after put_resolved");
            assert_eq!(mapped, address.hash, "key must resolve to the stored hash");

            let stored = immutable_store
                .get(repository, address)
                .await
                .expect("fragment must be stored")
                .payload
                .expect("stored fragment must carry its payload");
            assert_eq!(stored.as_ref(), payload);
        })
        .await;
}

/// A zero content hash removes the mapping rather than publishing one, and does so without
/// requiring a valid fragment — there is nothing to store.
#[tokio::test]
async fn test_zero_hash_removes_the_mapping() {
    let repository = random::<RepositoryId>();
    let payload = b"put-resolved-then-delete".as_slice();
    let (address, fragment) = fragment_for(payload);
    let key = Hash::hash_buffer(b"delete-key");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let publish =
        PutResolved::parse(request_bytes(key, address, fragment, payload)).expect("parse");
    let zero_address = Address {
        hash: Hash::default(),
        context: Default::default(),
    };
    let delete = PutResolved::parse(request_bytes(key, zero_address, Fragment::default(), &[]))
        .expect("a zero content hash needs no valid fragment");
    assert!(
        delete.put().is_none(),
        "a deletion carries no fragment to store"
    );

    LORE_CONTEXT
        .scope(execution, async move {
            handle_put_resolved(
                publish.key,
                publish.put(),
                publish.address,
                repository,
                String::new(),
                String::new(),
                mutable_store.clone(),
                immutable_store.clone(),
            )
            .await
            .expect("publish");
            assert!(
                mutable_store
                    .clone()
                    .load(repository, key, KeyType::Resolve)
                    .await
                    .is_ok(),
                "sanity: the key is published before the delete"
            );

            handle_put_resolved(
                delete.key,
                delete.put(),
                delete.address,
                repository,
                String::new(),
                String::new(),
                mutable_store.clone(),
                immutable_store.clone(),
            )
            .await
            .expect("delete");

            assert!(
                mutable_store
                    .load(repository, key, KeyType::Resolve)
                    .await
                    .is_err(),
                "a zero content hash must remove the mapping"
            );
        })
        .await;
}

/// A payload that does not hash to the advertised address must be refused, and must leave no
/// mapping behind — otherwise a rejected write would still publish the key.
#[tokio::test]
async fn test_hash_mismatch_leaves_no_mapping() {
    let repository = random::<RepositoryId>();
    let payload = b"put-resolved-mismatch".as_slice();
    let (_, fragment) = fragment_for(payload);
    let wrong_address = Address {
        hash: Hash::hash_buffer(b"not-the-payload-hash"),
        context: Default::default(),
    };
    let key = Hash::hash_buffer(b"mismatch-key");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let parsed = PutResolved::parse(request_bytes(key, wrong_address, fragment, payload))
        .expect("parse accepts it; the hash check happens in the handler");

    LORE_CONTEXT
        .scope(execution, async move {
            let result = handle_put_resolved(
                parsed.key,
                parsed.put(),
                parsed.address,
                repository,
                String::new(),
                String::new(),
                mutable_store.clone(),
                immutable_store,
            )
            .await;

            assert!(matches!(result, Err(MessageHandleError::HashMismatch)));
            assert!(
                mutable_store
                    .load(repository, key, KeyType::Resolve)
                    .await
                    .is_err(),
                "a rejected fragment must not publish its key"
            );
        })
        .await;
}
