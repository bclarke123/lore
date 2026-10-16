// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_server::grpc::storage::v1::put_resolved::*;
use rand::random;
use tonic::Code;

use crate::store::test_support::test_store_create;

const TEST_REQUEST_ID: u64 = 11;

fn request_for(key: Hash, payload: &[u8]) -> storage_v1::PutResolvedRequest {
    let address = Address {
        hash: lore_storage::hash_slice(payload),
        context: Default::default(),
    };
    let fragment = Fragment {
        flags: FragmentFlags::PayloadStoredLocal.bits(),
        size_payload: payload.len() as u32,
        size_content: payload.len() as u64,
    };
    storage_v1::PutResolvedRequest {
        request_id: TEST_REQUEST_ID,
        key: bytes::Bytes::copy_from_slice(key.as_ref()),
        address: Some(address.into()),
        fragment: Some(fragment.into()),
        payload: bytes::Bytes::copy_from_slice(payload),
    }
}

#[test]
fn parse_request_rejects_zero_request_id_as_uncorrelatable() {
    let mut request = request_for(Hash::hash_buffer(b"k"), b"payload");
    request.request_id = 0;
    let Uncorrelatable(status) =
        parse_request(request).expect_err("a zero id has nowhere to send an in-band failure");
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[test]
fn parse_request_reports_zero_key_in_band() {
    let request = request_for(Hash::default(), b"payload");
    let (request_id, status) = parse_request(request)
        .expect("a zero key is correlatable, so not stream-fatal")
        .expect_err("a zero key is not storable");
    assert_eq!(request_id, TEST_REQUEST_ID);
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[test]
fn parse_request_reports_missing_address_in_band() {
    let mut request = request_for(Hash::hash_buffer(b"k"), b"payload");
    request.address = None;
    let (request_id, status) = parse_request(request)
        .expect("correlatable")
        .expect_err("an address is required");
    assert_eq!(request_id, TEST_REQUEST_ID);
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[test]
fn parse_request_reports_missing_payload_in_band() {
    let mut request = request_for(Hash::hash_buffer(b"k"), b"payload");
    request.payload = bytes::Bytes::new();
    let (request_id, status) = parse_request(request)
        .expect("correlatable")
        .expect_err("publishing without a payload would leave a dangling mapping");
    assert_eq!(request_id, TEST_REQUEST_ID);
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[tokio::test]
async fn store_item_publishes_the_key() {
    let repository = random::<lore_revision::lore::RepositoryId>();
    let payload = b"grpc-put-resolved".as_slice();
    let key = Hash::hash_buffer(b"grpc-publish-key");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let parsed = parse_request(request_for(key, payload))
        .expect("correlatable")
        .expect("well-formed");
    let expected_hash = parsed.address.hash;

    LORE_CONTEXT
        .scope(execution, async move {
            let response = store_item(
                parsed,
                repository,
                String::new(),
                String::new(),
                mutable_store.clone(),
                immutable_store,
            )
            .await
            .expect("put_resolved must succeed");

            assert_eq!(response.request_id, TEST_REQUEST_ID);
            assert!(
                response.status.is_none(),
                "a successful item carries no status"
            );

            let mapped = mutable_store
                .load(repository, key, KeyType::Resolve)
                .await
                .expect("the key must be published");
            assert_eq!(mapped, expected_hash);
        })
        .await;
}
