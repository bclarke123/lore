// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_proto::lore::storage::v1::storage_service_server::StorageService as StorageServiceV1;
use lore_revision::fragment::generate_random;
use lore_server::grpc::storage_service::LoreStorageService;
use rand::random;
use tonic::Request;

use crate::grpc::storage::v1::test_utils::make_request_with_metadata;
use crate::store::test_support::test_store_create;

#[tokio::test]
async fn test_v1_query_with_stored_and_missing_addresses() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    let (fragment, address, payload) = generate_random();
    let (_, other_address, _) = generate_random();

    let repository = random::<Context>();
    let correlation_id = "test-grpc-v1-correlation";

    lore_spawn!(LORE_CONTEXT.scope(execution, async move {
        immutable_store
            .clone()
            .put(
                repository.into(),
                address,
                fragment,
                Some(payload.clone()),
                false,
            )
            .await
            .expect("Direct put should succeed");

        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        );

        let v1_address: model_v1::Address = address.into();
        let other_v1_address: model_v1::Address = other_address.into();

        let query_request = storage_v1::QueryRequest {
            addresses: vec![v1_address, other_v1_address],
        };
        let request = make_request_with_metadata(query_request, repository, correlation_id);

        let query_response = StorageServiceV1::query(&service, request)
            .await
            .expect("Query should succeed");

        let results = query_response.into_inner().results;
        assert_eq!(results.len(), 2);
        // QueryStatus::ExistFullMatch = 0
        assert_eq!(results[0], 0, "Stored address should be ExistFullMatch");
        // QueryStatus::NotFound = 3
        assert_eq!(results[1], 3, "Missing address should be NotFound");
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn test_v1_query_missing_repository_metadata() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    lore_spawn!(LORE_CONTEXT.scope(execution, async move {
        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        );

        let query_request = storage_v1::QueryRequest { addresses: vec![] };
        let request = Request::new(query_request);

        let result = StorageServiceV1::query(&service, request).await;
        assert!(result.is_err(), "Query without repo metadata should fail");
        assert_eq!(
            result.unwrap_err().code(),
            tonic::Code::InvalidArgument,
            "Should return InvalidArgument for missing repository"
        );
    }))
    .await
    .expect("Test task failed");
}

#[tokio::test]
async fn test_v1_query_two_correlation_ids() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create store");

    let (fragment1, address1, payload1) = generate_random();
    let (fragment2, address2, payload2) = generate_random();
    let (_, missing_address, _) = generate_random();

    let repository = random::<Context>();

    lore_spawn!(LORE_CONTEXT.scope(execution, async move {
        immutable_store
            .clone()
            .put(
                repository.into(),
                address1,
                fragment1,
                Some(payload1),
                false,
            )
            .await
            .expect("Put fragment 1 should succeed");

        immutable_store
            .clone()
            .put(
                repository.into(),
                address2,
                fragment2,
                Some(payload2),
                false,
            )
            .await
            .expect("Put fragment 2 should succeed");

        let service = LoreStorageService::new(
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        );

        let v1_addr1: model_v1::Address = address1.into();
        let v1_addr2: model_v1::Address = address2.into();
        let v1_missing: model_v1::Address = missing_address.into();

        let query_request = storage_v1::QueryRequest {
            addresses: vec![v1_addr1.clone(), v1_addr2.clone(), v1_missing.clone()],
        };
        let request = make_request_with_metadata(query_request, repository, "corr-A");

        let response = StorageServiceV1::query(&service, request)
            .await
            .expect("Query with corr-A should succeed");
        let results_a = response.into_inner().results;

        let query_request = storage_v1::QueryRequest {
            addresses: vec![v1_addr1, v1_addr2, v1_missing],
        };
        let request = make_request_with_metadata(query_request, repository, "corr-B");

        let response = StorageServiceV1::query(&service, request)
            .await
            .expect("Query with corr-B should succeed");
        let results_b = response.into_inner().results;

        assert_eq!(
            results_a, results_b,
            "Results must be identical across correlation IDs"
        );
        assert_eq!(results_a.len(), 3);
        assert_eq!(results_a[0], 0, "Fragment 1 should be ExistFullMatch");
        assert_eq!(results_a[1], 0, "Fragment 2 should be ExistFullMatch");
        assert_eq!(results_a[2], 3, "Missing address should be NotFound");
    }))
    .await
    .expect("Test task failed");
}
