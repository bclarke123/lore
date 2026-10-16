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

#[tokio::test]
async fn test_v1_mutable_load_not_found() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    let repository = random::<Context>();
    let key = random::<Hash>();

    lore_spawn!(LORE_CONTEXT.scope(execution, async move {
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        );

        let load_request = storage_v1::MutableLoadRequest {
            key: bytes::Bytes::copy_from_slice(key.as_bytes()),
            key_type: 0,
        };
        let request = make_request_with_metadata(load_request, repository, "test-not-found");

        let result = StorageServiceV1::mutable_load(&service, request).await;
        assert!(result.is_err(), "Load of non-existent key should fail");
        assert_eq!(
            result.unwrap_err().code(),
            tonic::Code::NotFound,
            "Should return NotFound"
        );
    }))
    .await
    .expect("Test task failed");
}
