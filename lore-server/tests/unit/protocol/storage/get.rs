// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::Hash;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::get::*;
use lore_server::protocol::storage::messages::LoreResponse;
use lore_server::protocol::storage::messages::Message;
use lore_server::protocol::storage::messages::MessageHandleError;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

fn allow_all() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer)
}

fn get_bytes(value: &Get) -> Vec<u8> {
    value.address.as_bytes().to_vec()
}

#[test]
fn test_parse() {
    let payload = random::<[u8; 32]>().to_vec();
    let hash = Hash::hash_buffer(payload.as_slice());
    let context = random::<Context>();

    let message = Get {
        address: Address { hash, context },
    };
    let message_bytes: Vec<u8> = get_bytes(&message);

    assert_eq!(
        Get::parse(Bytes::copy_from_slice(message_bytes.as_slice())),
        Ok(message)
    );
}

#[tokio::test]
async fn test_handle() {
    let repository = random::<RepositoryId>();

    let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
    let hash = Hash::hash_buffer(payload.as_ref());
    let context = random::<Context>();

    let address = Address { hash, context };
    let message = Get { address };

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            immutable_store
                .clone()
                .put(
                    repository,
                    address,
                    Fragment {
                        flags: FragmentFlags::PayloadStoredLocal.bits(),
                        size_payload: payload.len() as u32,
                        size_content: payload.len() as u64,
                    },
                    Some(payload.clone()),
                    false,
                )
                .await
                .expect("Failed to put immutable data in store");

            assert_eq!(
                LoreResponse::Get(GetResponse {
                    fragment: Fragment {
                        flags: FragmentFlags::PayloadStoredDurable.bits(),
                        size_payload: payload.len() as u32,
                        size_content: payload.len() as u64
                    },
                    payload: payload.clone(),
                }),
                message
                    .handle(context_map, immutable_store, allow_all())
                    .await
                    .unwrap()
            );
        })
        .await;
}

#[tokio::test]
async fn test_get_metadata_handle_returns_fragment_without_payload() {
    let repository = random::<RepositoryId>();

    let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
    let hash = Hash::hash_buffer(payload.as_ref());
    let context = random::<Context>();

    let address = Address { hash, context };
    let message = GetMetadata { address };

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            immutable_store
                .clone()
                .put(
                    repository,
                    address,
                    Fragment {
                        flags: FragmentFlags::PayloadStoredLocal.bits(),
                        size_payload: payload.len() as u32,
                        size_content: payload.len() as u64,
                    },
                    Some(payload.clone()),
                    false,
                )
                .await
                .expect("Failed to put immutable data in store");

            let response = message
                .handle(context_map, immutable_store, allow_all())
                .await
                .unwrap();
            let LoreResponse::Get(GetResponse { fragment, payload }) = response else {
                panic!("Expected GetResponse variant");
            };
            // Fragment carries the same shape as a regular Get…
            assert_eq!(fragment.size_payload, 32);
            assert_eq!(fragment.size_content, 32);
            assert_eq!(fragment.flags, FragmentFlags::PayloadStoredDurable.bits());
            // …but the payload is empty, which is the whole point of GetMetadata.
            assert!(payload.is_empty(), "payload must be empty");
        })
        .await;
}

#[tokio::test]
async fn test_get_metadata_handle_address_not_found() {
    let repository = random::<RepositoryId>();

    let address = Address {
        hash: Hash::hash_buffer(b"nonexistent"),
        context: random::<Context>(),
    };
    let message = GetMetadata { address };

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let response = message
                .handle(context_map, immutable_store, allow_all())
                .await;
            assert!(matches!(
                response,
                Err(MessageHandleError::FragmentNotFound)
            ));
        })
        .await;
}
