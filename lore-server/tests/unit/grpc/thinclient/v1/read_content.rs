// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_proto::lore::thin_client::v1::ReadContentRequest;
use lore_server::grpc::thinclient::v1::read_content::*;
use lore_storage::WriteOptions;
use tonic::Request;
use tonic::Status;

use crate::store::test_support::test_store_create;

/// Store a blob and return its address, using the same write path the
/// server uses so reassembly/compression is exercised realistically.
async fn put_blob(
    store: &Arc<dyn lore_storage::ImmutableStore>,
    partition: Partition,
    content: &[u8],
) -> Address {
    lore_storage::write_content(
        store.clone(),
        partition,
        Context::default(),
        Bytes::copy_from_slice(content),
        WriteOptions::default().no_remote_write(),
        None,
        lore_storage::WriteContext::none(),
        None,
    )
    .await
    .expect("write blob")
    .address
}

async fn read_all(
    store: Arc<dyn lore_storage::ImmutableStore>,
    partition: Partition,
    address: Address,
    max_bytes: Option<u64>,
) -> Result<Vec<u8>, Status> {
    read_ranged(store, partition, address, max_bytes, None, None).await
}

async fn read_ranged(
    store: Arc<dyn lore_storage::ImmutableStore>,
    partition: Partition,
    address: Address,
    max_bytes: Option<u64>,
    offset: Option<u64>,
    length: Option<u64>,
) -> Result<Vec<u8>, Status> {
    let mut request = Request::new(ReadContentRequest {
        address: Some(lore_proto::lore::model::v1::Address {
            hash: address.hash.data().to_vec().into(),
            context: address.context.data().to_vec().into(),
        }),
        max_bytes,
        offset,
        length,
    });
    request.metadata_mut().insert_bin(
        lore_transport::grpc::REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(partition.data()),
    );
    let response = handler(request, store).await?;
    let mut out = Vec::new();
    let mut stream = response.into_inner();
    use tokio_stream::StreamExt;
    while let Some(item) = stream.next().await {
        out.extend_from_slice(&item?.chunk);
    }
    Ok(out)
}

#[tokio::test]
async fn reads_small_blob_roundtrip() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        let content = b"hello, lorehub\n";
        let address = put_blob(&store, partition, content).await;
        let got = read_all(store, partition, address, None)
            .await
            .expect("read");
        assert_eq!(got, content);
    }))
    .await;
}

#[tokio::test]
async fn reads_large_blob_roundtrip() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        // Larger than CHUNK_SIZE and likely fragmented/compressed.
        let content: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let address = put_blob(&store, partition, &content).await;
        let got = read_all(store, partition, address, None)
            .await
            .expect("read");
        assert_eq!(got, content);
    }))
    .await;
}

#[tokio::test]
async fn max_bytes_rejects_oversized() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        let content = vec![7u8; 10_000];
        let address = put_blob(&store, partition, &content).await;
        let err = read_all(store, partition, address, Some(1000))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }))
    .await;
}

#[tokio::test]
async fn ranged_read_reports_total_size() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        let content = vec![5u8; 40_000];
        let address = put_blob(&store, partition, &content).await;
        let mut request = Request::new(ReadContentRequest {
            address: Some(lore_proto::lore::model::v1::Address {
                hash: address.hash.data().to_vec().into(),
                context: address.context.data().to_vec().into(),
            }),
            max_bytes: None,
            offset: Some(100),
            length: Some(64),
        });
        request.metadata_mut().insert_bin(
            lore_transport::grpc::REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(partition.data()),
        );
        let response = handler(request, store).await.expect("handler");
        use tokio_stream::StreamExt;
        let first = response
            .into_inner()
            .next()
            .await
            .expect("first message")
            .expect("ok");
        assert_eq!(first.size_content, 64);
        assert_eq!(first.total_size_content, 40_000);
    }))
    .await;
}

#[tokio::test]
async fn ranged_read_returns_requested_slice() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        // Fragmented content so the range crosses fragment boundaries.
        let content: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
        let address = put_blob(&store, partition, &content).await;
        let got = read_ranged(store, partition, address, None, Some(65_000), Some(10_000))
            .await
            .expect("ranged read");
        assert_eq!(got, &content[65_000..75_000]);
    }))
    .await;
}

#[tokio::test]
async fn ranged_read_clamps_at_end_of_content() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        let content = vec![3u8; 10_000];
        let address = put_blob(&store, partition, &content).await;
        // Range extending past the end returns just the tail…
        let got = read_ranged(
            store.clone(),
            partition,
            address,
            None,
            Some(9_000),
            Some(5_000),
        )
        .await
        .expect("tail read");
        assert_eq!(got, &content[9_000..]);
        // …and a range starting past the end returns nothing.
        let got = read_ranged(store, partition, address, None, Some(50_000), Some(16))
            .await
            .expect("past-end read");
        assert!(got.is_empty());
    }))
    .await;
}

#[tokio::test]
async fn ranged_read_ignores_total_size_cap_but_caps_range() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = Partition::default();
        let content = vec![7u8; 10_000];
        let address = put_blob(&store, partition, &content).await;
        // Content exceeds max_bytes, but the bounded range fits: allowed.
        let got = read_ranged(
            store.clone(),
            partition,
            address,
            Some(1_000),
            Some(0),
            Some(64),
        )
        .await
        .expect("header read of oversized content");
        assert_eq!(got, &content[..64]);
        // A bounded range larger than max_bytes is rejected up front.
        let err = read_ranged(
            store.clone(),
            partition,
            address,
            Some(1_000),
            Some(0),
            Some(2_000),
        )
        .await
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        // An open-ended range whose tail exceeds max_bytes is rejected.
        let err = read_ranged(store, partition, address, Some(1_000), Some(4), None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }))
    .await;
}

#[tokio::test]
async fn unknown_address_is_not_found() {
    let (store, _mut, execution) = test_store_create().await.expect("stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let address = Address {
            hash: Hash::from([9u8; 32].as_ref()),
            context: Context::default(),
        };
        let err = read_all(store, Partition::default(), address, None)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }))
    .await;
}
