// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod stream_error_tests;

use std::sync::Arc;

use lore_base::types::Partition;
use lore_revision::fragment::generate_random;
use lore_server::store::grpc_replica::*;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use mockall::predicate::eq;

#[tokio::test]
async fn test_put() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| Ok(()));

    let store = GrpcReplica::new(client);

    Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn test_put_fails_with_slowdown() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| Err(ReplicationClientError::SlowDown));

    let store = GrpcReplica::new(client);

    let err = Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await
        .expect_err("should have failed");

    assert!(matches!(err, StoreError::SlowDown(_)));

    Ok(())
}

#[tokio::test]
async fn test_put_fails_with_other_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MockReplicationClientImpl::default();

    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();

    client
        .expect_put()
        .with(
            eq(repository),
            eq(address),
            eq(fragment),
            eq(Some(payload.clone())),
        )
        .return_once(|_, _, _, _| {
            Err(ReplicationClientError::RequestFailed(
                tonic::Status::internal("Oh noes"),
            ))
        });

    let store = GrpcReplica::new(client);

    let err = Arc::new(store)
        .put(
            repository,
            address,
            fragment,
            Some(payload),
            false, /* force */
        )
        .await
        .expect_err("should have failed");

    assert!(matches!(err, StoreError::Internal(_)));

    Ok(())
}
