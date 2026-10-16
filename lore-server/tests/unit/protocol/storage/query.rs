// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::LoreResponse;
use lore_server::protocol::storage::messages::Message;
use lore_server::protocol::storage::query::*;
use lore_storage::StoreMatch;
use lore_transport::quic::storage_service::QueryStatus;
use rand::Rng;
use rand::random;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

fn allow_all() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer)
}
use crate::util::test_support::address_with_random_context;

#[tokio::test]
async fn test_not_found() {
    let hash = Hash::hash_buffer(b"some fragment hash");
    let context = random::<Context>();

    let repository = random::<RepositoryId>();

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            assert_eq!(
                LoreResponse::Query(QueryResponse {
                    results: Bytes::copy_from_slice(&[QueryStatus::NotFound as u8])
                }),
                Query {
                    address: Bytes::copy_from_slice(Address { hash, context }.as_bytes()),
                }
                .handle(context_map, immutable_store, allow_all())
                .await
                .unwrap()
            );
        })
        .await;
}

#[tokio::test]
async fn test_found() {
    let repository = random::<RepositoryId>();

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
            let hash = Hash::hash_buffer(payload.as_ref());
            let context = random::<Context>();

            let fragment = Fragment {
                flags: 0,
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            };

            let address = Address { hash, context };

            immutable_store
                .clone()
                .put(repository, address, fragment, Some(payload), false)
                .await
                .expect("Failed to write fragment");

            assert_eq!(
                LoreResponse::Query(QueryResponse {
                    results: Bytes::copy_from_slice(&[QueryStatus::ExistPartitionMatch as u8])
                }),
                Query {
                    address: Bytes::copy_from_slice(
                        address_with_random_context(address).as_bytes()
                    )
                }
                .handle(context_map, immutable_store, allow_all())
                .await
                .unwrap()
            );
        })
        .await;
}

/// The collapse rule, which is the reason this mapping exists in one place.
///
/// Content stored by another partition resolves to a hash match in a store that does not
/// isolate, and reporting that back would tell this caller a hash it has no claim to exists
/// somewhere. It has to arrive as absence, indistinguishable from content nobody stored.
#[tokio::test]
async fn a_hash_held_only_by_another_partition_reports_absence() {
    let stored_under = random::<RepositoryId>();
    let asked_under = random::<RepositoryId>();

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(asked_under);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
            let hash = Hash::hash_buffer(payload.as_ref());
            let address = Address {
                hash,
                context: random::<Context>(),
            };

            let fragment = Fragment {
                flags: 0,
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            };

            immutable_store
                .clone()
                .put(stored_under, address, fragment, Some(payload), false)
                .await
                .expect("Failed to write fragment");

            // Without this the assertion below would pass on a store that simply found
            // nothing, and would stop testing the collapse the day resolution changed.
            let resolved =
                lore_storage::immutable_store::query_one(&immutable_store, asked_under, address)
                    .await
                    .expect("resolve should work");
            assert_eq!(resolved.match_made, StoreMatch::MatchHash);

            assert_eq!(
                LoreResponse::Query(QueryResponse {
                    results: Bytes::copy_from_slice(&[QueryStatus::NotFound as u8])
                }),
                Query {
                    address: Bytes::copy_from_slice(address.as_bytes())
                }
                .handle(context_map, immutable_store, allow_all())
                .await
                .unwrap()
            );
        })
        .await;
}

#[tokio::test]
async fn test_found_in_context() {
    let repository = random::<RepositoryId>();

    let context_map = Arc::new(AttributeMap::default());
    context_map.insert(repository);

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
            let hash = Hash::hash_buffer(payload.as_ref());
            let context = random::<Context>();

            let fragment = Fragment {
                flags: 0,
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            };

            let address = Address { hash, context };

            immutable_store
                .clone()
                .put(repository, address, fragment, Some(payload), false)
                .await
                .expect("Failed to write fragment");

            assert_eq!(
                LoreResponse::Query(QueryResponse {
                    results: Bytes::copy_from_slice(&[QueryStatus::ExistFullMatch as u8])
                }),
                Query {
                    address: Bytes::copy_from_slice(address.as_bytes())
                }
                .handle(context_map, immutable_store, allow_all())
                .await
                .unwrap()
            );
        })
        .await;
}

#[tokio::test]
async fn test_query_fragment_bulk() {
    let repository = random::<RepositoryId>();

    let context = random::<Context>();

    let (immutable_store, _mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let count = 10;

            // we use an IndexMap which lets you iterate values in insertion order, which will allow us
            // to later verify the results in the response are in the same order as the fragments in the
            // request.
            let mut results = indexmap::IndexMap::new();
            for _ in 0..count {
                let payload = Bytes::copy_from_slice(&random::<[u8; 32]>());
                let hash = Hash::hash_buffer(payload.as_ref());
                let fragment = Fragment {
                    flags: 0,
                    size_payload: payload.len() as u32,
                    size_content: payload.len() as u64,
                };

                let address = Address { hash, context };

                // QueryStatus does not exist for value 2 (which would be exist, but in another repository)
                // since client-server protocol cannot leak the existence in another repo. Avoid the value
                let result: u8 = loop {
                    let result = rand::rng().random_range(
                        QueryStatus::ExistFullMatch as u8..=QueryStatus::NotFound as u8,
                    );
                    if result != 2 {
                        break result;
                    }
                };
                results.insert(address, result);

                let state: QueryStatus = result.into();
                match state {
                    QueryStatus::ExistPartitionMatch => immutable_store
                        .clone()
                        .put(
                            repository,
                            address_with_random_context(address),
                            fragment,
                            Some(payload),
                            false,
                        )
                        .await
                        .expect("Failed to store item"),
                    QueryStatus::ExistFullMatch => immutable_store
                        .clone()
                        .put(repository, address, fragment, Some(payload), false)
                        .await
                        .expect("Failed to store item"),
                    QueryStatus::NotFound => {}
                }
            }

            let context_map = Arc::new(AttributeMap::default());
            context_map.insert(repository);

            let addresses: Vec<Address> = results.keys().cloned().collect();
            let message = Query {
                address: Bytes::copy_from_slice(addresses.as_bytes()),
            };

            let results_clone = results.clone();

            assert_eq!(
                LoreResponse::Query(QueryResponse {
                    results: results_clone.values().cloned().collect()
                }),
                message
                    .handle(context_map, immutable_store, allow_all())
                    .await
                    .unwrap()
            );
        })
        .await;
}
