// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use lore_server::grpc::storage_service::LoreStorageService;
use rand::random;
use zerocopy::IntoBytes;

use crate::grpc::storage::v1::test_utils::make_request_with_metadata;
use crate::store::test_support::test_store_create;

/// Round-trip test that exercises `MutableStore` → `MutableLoad` → `MutableCompareAndSwap` → `MutableLoad` against the gRPC v1 service.
#[tokio::test]
async fn test_v1_mutable_store_load_cas() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    let repository = random::<Context>();
    let key = random::<Hash>();
    let value = random::<Hash>();
    let new_value = random::<Hash>();

    lore_spawn!(LORE_CONTEXT.scope(execution, async move {
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        );

        let store_request = storage_v1::MutableStoreRequest {
            key: bytes::Bytes::copy_from_slice(key.as_bytes()),
            value: bytes::Bytes::copy_from_slice(value.as_bytes()),
            key_type: 0,
        };
        let request = make_request_with_metadata(store_request, repository, "test-mutable-corr");

        StorageServiceV1::mutable_store(&service, request)
            .await
            .expect("MutableStore should succeed");

        let load_request = storage_v1::MutableLoadRequest {
            key: bytes::Bytes::copy_from_slice(key.as_bytes()),
            key_type: 0,
        };
        let request = make_request_with_metadata(load_request, repository, "test-mutable-corr");

        let load_response = StorageServiceV1::mutable_load(&service, request)
            .await
            .expect("MutableLoad should succeed");

        let loaded_value = load_response.into_inner().value;
        assert_eq!(
            loaded_value.as_ref(),
            value.as_bytes(),
            "Loaded value should match stored value"
        );

        let cas_request = storage_v1::MutableCompareAndSwapRequest {
            key: bytes::Bytes::copy_from_slice(key.as_bytes()),
            expected: bytes::Bytes::copy_from_slice(value.as_bytes()),
            value: bytes::Bytes::copy_from_slice(new_value.as_bytes()),
            key_type: 0,
        };
        let request = make_request_with_metadata(cas_request, repository, "test-mutable-corr");

        let cas_response = StorageServiceV1::mutable_compare_and_swap(&service, request)
            .await
            .expect("MutableCas should succeed");

        let current = cas_response.into_inner().current_value;
        // CAS returns the value after the swap (the new value if it succeeded)
        // or the actual current value if the expected didn't match.
        // The specific behavior depends on the store implementation.
        // Just verify we get a valid 32-byte hash back.
        assert_eq!(current.len(), 32, "CAS should return a 32-byte hash");

        let load_request = storage_v1::MutableLoadRequest {
            key: bytes::Bytes::copy_from_slice(key.as_bytes()),
            key_type: 0,
        };
        let request = make_request_with_metadata(load_request, repository, "test-mutable-corr");

        let load_response = StorageServiceV1::mutable_load(&service, request)
            .await
            .expect("MutableLoad after CAS should succeed");

        let loaded_value = load_response.into_inner().value;
        assert_eq!(
            loaded_value.as_ref(),
            new_value.as_bytes(),
            "Value should be updated after CAS"
        );
    }))
    .await
    .expect("Test task failed");
}
