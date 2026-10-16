// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_server::protocol::storage::get_resolved::*;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::messages::MessageParseError;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

fn request_bytes(key: Hash, context: Context, flags: u32) -> Bytes {
    let mut bytes =
        bytes::BytesMut::with_capacity(size_of::<Hash>() + size_of::<Context>() + FLAGS_WIRE_SIZE);
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(context.as_bytes());
    bytes.extend_from_slice(&flags.to_le_bytes());
    bytes.freeze()
}

#[test]
fn test_request_is_four_byte_aligned() {
    let len = request_bytes(Hash::default(), Context::default(), 0).len();
    assert_eq!(len, 52);
    assert_eq!(len % 4, 0, "request should stay a multiple of 4 bytes");
}

#[test]
fn test_parse() {
    let key = Hash::hash_buffer(b"test-key");
    let context = Context::default();
    let parsed = GetResolved::parse(request_bytes(key, context, 0)).unwrap();
    assert_eq!(parsed.key, key);
    assert_eq!(parsed.context, context);
    assert_eq!(parsed.flags, 0);
}

#[test]
fn test_parse_preserves_all_flag_bits() {
    let key = Hash::hash_buffer(b"test-key");
    for flags in [1u32, 0x80, 0xFF_FF, 0x00FF_FFFF, u32::MAX] {
        let parsed = GetResolved::parse(request_bytes(key, Context::default(), flags)).unwrap();
        assert_eq!(parsed.flags, flags, "flags {flags:#x} did not round trip");
    }
}

#[test]
fn test_parse_invalid_length() {
    let bytes = Bytes::from(vec![
        0u8;
        size_of::<Hash>()
            + size_of::<Context>()
            + FLAGS_WIRE_SIZE
            - 1
    ]);
    assert_eq!(
        GetResolved::parse(bytes),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[tokio::test]
async fn test_missing_key_is_mutable_not_found() {
    let repository = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"missing-key");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let result = LORE_CONTEXT
        .scope(execution, async move {
            handle_get_resolved(
                key,
                Context::default(),
                0,
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await;

    assert!(matches!(
        result,
        Err(MessageHandleError::MutableDataNotFound(_))
    ));
}

#[tokio::test]
async fn test_dangling_pointer_is_fragment_not_found() {
    let repository = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"dangling-key");
    let value = Hash::hash_buffer(b"never-stored");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let result = LORE_CONTEXT
        .scope(execution, async move {
            mutable_store
                .clone()
                .store(repository, key, value, KeyType::Resolve)
                .await
                .unwrap();
            handle_get_resolved(
                key,
                Context::default(),
                0,
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await;

    assert!(matches!(result, Err(MessageHandleError::FragmentNotFound)));
}

#[tokio::test]
async fn test_unknown_flag_rejected() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let result = LORE_CONTEXT
        .scope(execution, async move {
            handle_get_resolved(
                Hash::hash_buffer(b"any-key"),
                Context::default(),
                1, // no bits are defined yet, so any bit must be refused
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await;

    assert!(matches!(result, Err(MessageHandleError::NotImplemented)));
}
