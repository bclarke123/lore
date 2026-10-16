// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_proto::lore::storage::v1 as storage_v1;
use lore_server::grpc::storage::v1::get_resolved::*;
use rand::random;
use tonic::Code;
use tonic::Status;
use zerocopy::IntoBytes;

use crate::store::test_support::test_store_create;

const TEST_REQUEST_ID: u64 = 7;

fn request_for(key_address: Address, flags: u32) -> storage_v1::GetResolvedRequest {
    storage_v1::GetResolvedRequest {
        request_id: TEST_REQUEST_ID,
        key: Some(key_address.into()),
        flags,
    }
}

/// A missing key is answered in-band against the request id, not with a stream error — a
/// stream error would discard every request queued behind it.
#[test]
fn parse_request_reports_missing_key_in_band() {
    let (request_id, status) = parse_request(storage_v1::GetResolvedRequest {
        request_id: TEST_REQUEST_ID,
        key: None,
        flags: 0,
    })
    .expect("a missing key is correlatable, so not stream-fatal")
    .expect_err("a request without a key address is malformed");
    assert_eq!(request_id, TEST_REQUEST_ID);
    assert_eq!(status.code(), Code::InvalidArgument);
}

/// A zero id is the one request that cannot be answered in-band, so it stays stream-fatal.
#[test]
fn parse_request_rejects_zero_request_id_as_uncorrelatable() {
    let Uncorrelatable(status) = parse_request(storage_v1::GetResolvedRequest {
        request_id: 0,
        key: Some(Address::default().into()),
        flags: 0,
    })
    .expect_err("a zero id has nowhere to send an in-band failure");
    assert_eq!(status.code(), Code::InvalidArgument);
}

#[test]
fn parse_request_decodes_id_key_context_and_flags() {
    let key_address = Address {
        hash: Hash::hash_buffer(b"grpc-resolve-key"),
        context: random::<Context>(),
    };
    let parsed = parse_request(request_for(key_address, 0x00AB_CDEF))
        .expect("well-formed")
        .expect("well-formed");
    assert_eq!(parsed.request_id, TEST_REQUEST_ID);
    assert_eq!(parsed.key_address, key_address);
    assert_eq!(parsed.flags, 0x00AB_CDEF);
}

#[tokio::test]
async fn resolve_item_missing_key_is_not_found() {
    let repository = random::<lore_revision::lore::RepositoryId>();
    let key_address = Address {
        hash: Hash::hash_buffer(b"grpc-missing-key"),
        context: random::<Context>(),
    };
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let status = LORE_CONTEXT
        .scope(execution, async move {
            resolve_item(
                ParsedRequest {
                    request_id: TEST_REQUEST_ID,
                    key_address,
                    flags: 0,
                },
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await
        .expect_err("nothing maps this key");

    assert_eq!(status.code(), Code::NotFound);
}

/// The failure a caller actually receives: an ordinary stream item carrying the id and a
/// non-OK status. If this were an `Err(Status)` item instead, tonic would send trailers and
/// every request queued behind it would go unanswered.
#[test]
fn error_response_is_an_in_band_item_carrying_the_request_id() {
    let response = error_response(TEST_REQUEST_ID, &Status::not_found("no such key"));
    assert_eq!(response.request_id, TEST_REQUEST_ID);
    let status = response.status.expect("a failed item carries a status");
    assert_eq!(Code::from_i32(status.code as i32), Code::NotFound);
    assert_eq!(status.message, "no such key");
    assert!(response.payload.is_empty());
    assert!(response.resolved.is_empty());
    assert!(response.fragment.is_none());
}

#[tokio::test]
async fn resolve_item_dangling_pointer_is_not_found() {
    let repository = random::<lore_revision::lore::RepositoryId>();
    let key_address = Address {
        hash: Hash::hash_buffer(b"grpc-dangling-key"),
        context: random::<Context>(),
    };
    let never_stored = Hash::hash_buffer(b"grpc-never-stored");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let status = LORE_CONTEXT
        .scope(execution, async move {
            mutable_store
                .clone()
                .store(repository, key_address.hash, never_stored, KeyType::Resolve)
                .await
                .expect("store resolve mapping");
            resolve_item(
                ParsedRequest {
                    request_id: TEST_REQUEST_ID,
                    key_address,
                    flags: 0,
                },
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await
        .expect_err("the mapping resolves but its blob was never stored");

    assert_eq!(status.code(), Code::NotFound);
}

#[tokio::test]
async fn resolve_item_echoes_request_identity_with_payload() {
    let repository = random::<lore_revision::lore::RepositoryId>();
    let context = random::<Context>();
    let payload = bytes::Bytes::from_static(b"resolved content over grpc");
    let resolved = Hash::hash_buffer(payload.as_ref());
    let key_address = Address {
        hash: Hash::hash_buffer(b"grpc-good-key"),
        context,
    };
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let expected_payload = payload.clone();
    let response = LORE_CONTEXT
        .scope(execution, async move {
            let fragment = Fragment {
                flags: FragmentFlags::PayloadStoredLocal.bits(),
                size_payload: payload.len() as u32,
                size_content: payload.len() as u64,
            };
            immutable_store
                .clone()
                .put(
                    repository,
                    Address {
                        hash: resolved,
                        context,
                    },
                    fragment,
                    Some(payload),
                    false,
                )
                .await
                .expect("store blob");
            debug_assert!(
                immutable_store
                    .clone()
                    .get(
                        repository,
                        Address {
                            hash: resolved,
                            context
                        }
                    )
                    .await
                    .is_ok()
            );
            mutable_store
                .clone()
                .store(repository, key_address.hash, resolved, KeyType::Resolve)
                .await
                .expect("store resolve mapping");
            resolve_item(
                ParsedRequest {
                    request_id: TEST_REQUEST_ID,
                    key_address,
                    flags: 0,
                },
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await
        .expect("mapping and blob are both present");

    assert_eq!(
        response.request_id, TEST_REQUEST_ID,
        "the response must echo the request id so the client can correlate it"
    );
    assert!(
        response.status.is_none(),
        "a successful item carries no status"
    );
    assert_eq!(response.resolved.as_ref(), resolved.as_bytes());
    assert_eq!(response.payload, expected_payload);
}

/// Unknown flag bits currently surface as `Internal`, because the shared handler reports them
/// as `MessageHandleError::NotImplemented`. Arguably they should be `InvalidArgument` — this
/// asserts today's behavior so a deliberate fix in the shared handler shows up here.
#[tokio::test]
async fn resolve_item_unknown_flags_are_rejected() {
    let repository = random::<lore_revision::lore::RepositoryId>();
    let key_address = Address {
        hash: Hash::hash_buffer(b"grpc-flagged-key"),
        context: random::<Context>(),
    };
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let status = LORE_CONTEXT
        .scope(execution, async move {
            resolve_item(
                ParsedRequest {
                    request_id: TEST_REQUEST_ID,
                    key_address,
                    flags: 1,
                },
                repository,
                String::new(),
                String::new(),
                mutable_store,
                immutable_store,
            )
            .await
        })
        .await
        .expect_err("no flag bits are defined yet");

    assert_eq!(status.code(), Code::Internal);
}
