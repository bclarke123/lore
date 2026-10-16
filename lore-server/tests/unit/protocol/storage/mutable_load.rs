// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::LoreResponse;
use lore_server::protocol::storage::messages::Message;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::protocol::storage::mutable_load::*;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

#[test]
fn test_parse() {
    let key = Hash::hash_buffer(b"test-key");
    let mut bytes = bytes::BytesMut::with_capacity(size_of::<Hash>() + 1);
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&[KeyType::BranchMetadata as u8]);
    let result = MutableLoad::parse(bytes.freeze()).unwrap();
    assert_eq!(result.key, key);
    assert_eq!(result.key_type, KeyType::BranchMetadata);
}

#[test]
fn test_parse_invalid_length() {
    let bytes = Bytes::from_static(&[0u8; 16]);
    assert_eq!(
        MutableLoad::parse(bytes),
        Err(MessageParseError::InvalidFieldLength)
    );
}

#[tokio::test]
async fn test_handle_not_found() {
    let repository = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"missing-key");

    let context = Arc::new(AttributeMap::default());
    context.insert(repository);

    let (_immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let message = MutableLoad {
        key,
        key_type: KeyType::Untyped,
    };
    let result = LORE_CONTEXT
        .scope(execution, async move {
            message.handle_mutable(context, mutable_store).await
        })
        .await;

    assert!(matches!(
        result,
        Err(MessageHandleError::MutableDataNotFound(_))
    ));
}

#[tokio::test]
async fn test_handle_round_trip() {
    let repository = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"test-key");
    let value = Hash::hash_buffer(b"test-value");

    let context = Arc::new(AttributeMap::default());
    context.insert(repository);

    let (_immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    LORE_CONTEXT
        .scope(execution, async move {
            mutable_store
                .clone()
                .store(repository, key, value, KeyType::Untyped)
                .await
                .unwrap();

            let message = MutableLoad {
                key,
                key_type: KeyType::Untyped,
            };
            let result = message
                .handle_mutable(context, mutable_store)
                .await
                .unwrap();

            assert_eq!(
                result,
                LoreResponse::MutableLoad(MutableLoadResponse { value })
            );
        })
        .await;
}

#[tokio::test]
async fn test_handle_load_after_overwrite() {
    let repository = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"overwrite-load-key");
    let first_value = Hash::hash_buffer(b"first");
    let second_value = Hash::hash_buffer(b"second");

    let context = Arc::new(AttributeMap::default());
    context.insert(repository);

    let (_immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    LORE_CONTEXT
        .scope(execution, async move {
            mutable_store
                .clone()
                .store(repository, key, first_value, KeyType::Untyped)
                .await
                .unwrap();
            mutable_store
                .clone()
                .store(repository, key, second_value, KeyType::Untyped)
                .await
                .unwrap();

            let message = MutableLoad {
                key,
                key_type: KeyType::Untyped,
            };
            let result = message
                .handle_mutable(context, mutable_store)
                .await
                .unwrap();

            assert_eq!(
                result,
                LoreResponse::MutableLoad(MutableLoadResponse {
                    value: second_value
                })
            );
        })
        .await;
}

#[tokio::test]
async fn test_handle_load_independent_repositories() {
    let repo_a = random::<RepositoryId>();
    let repo_b = random::<RepositoryId>();
    let key = Hash::hash_buffer(b"shared-key");
    let value_a = Hash::hash_buffer(b"value-a");
    let value_b = Hash::hash_buffer(b"value-b");

    let (_immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    LORE_CONTEXT
        .scope(execution, async move {
            mutable_store
                .clone()
                .store(repo_a, key, value_a, KeyType::Untyped)
                .await
                .unwrap();
            mutable_store
                .clone()
                .store(repo_b, key, value_b, KeyType::Untyped)
                .await
                .unwrap();

            // Load from repo_a
            let context_a = Arc::new(AttributeMap::default());
            context_a.insert(repo_a);
            let msg_a = MutableLoad {
                key,
                key_type: KeyType::Untyped,
            };
            let result_a = msg_a
                .handle_mutable(context_a, mutable_store.clone())
                .await
                .unwrap();
            assert_eq!(
                result_a,
                LoreResponse::MutableLoad(MutableLoadResponse { value: value_a })
            );

            // Load from repo_b
            let context_b = Arc::new(AttributeMap::default());
            context_b.insert(repo_b);
            let msg_b = MutableLoad {
                key,
                key_type: KeyType::Untyped,
            };
            let result_b = msg_b
                .handle_mutable(context_b, mutable_store)
                .await
                .unwrap();
            assert_eq!(
                result_b,
                LoreResponse::MutableLoad(MutableLoadResponse { value: value_b })
            );
        })
        .await;
}
