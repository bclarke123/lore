// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Partition;
use lore_revision::fragment;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::protocol::replication_store::query::*;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::quic::replication_store_service::MAX_CHUNK_SIZE;
use lore_server::quic::replication_store_service::client::ReplicationStoreClientError;
use lore_server::quic::tests::collapse_bytes;
use lore_server::quic::tests::collapse_bytes_without_header;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_transport::quic::command_header::CommandHeader;
use rand::random;
use uuid::Uuid;

#[test]
fn is_under_max_chunk_size() {
    // 1 address is included in base request size, so pad with max addresses-1
    let max_request_size = BASE_REQUEST_SIZE + (size_of::<Address>() * (MAX_ADDRESSES - 1));
    let max_response_size = RESULT_WIRE_SIZE * MAX_ADDRESSES;
    // ensure both directions fit within the chunk size limit
    assert!(max_request_size + size_of::<CommandHeader>() < MAX_CHUNK_SIZE);
    assert!(max_response_size + size_of::<CommandHeader>() < MAX_CHUNK_SIZE);
}

mod request {
    use super::*;

    #[test]
    fn parsing_single_works() {
        let repository = random::<Context>();
        let (_, address, _) = fragment::generate_random();

        let input = Query {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            addresses: vec![address],
        };
        let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
        let output = Query::parse(input_bytes).expect("parse should work");

        assert_eq!(input, output);
    }

    #[test]
    fn parsing_with_multiple_addresses_works() {
        let repository = random::<Context>();
        let addresses: Vec<Address> = (0..99)
            .map(|_| {
                let (_, address, _) = fragment::generate_random();
                address
            })
            .collect();

        let input = Query {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            addresses,
        };
        let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
        let output = Query::parse(input_bytes).expect("parse should work");

        assert_eq!(input, output);
    }

    #[test]
    fn parsing_fails_if_too_big() {
        let repository = random::<Context>();
        let addresses: Vec<Address> = (0..101)
            .map(|_| {
                let (_, address, _) = fragment::generate_random();
                address
            })
            .collect();

        let input = Query {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            addresses,
        };
        let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
        let output = Query::parse(input_bytes).expect_err("parse should fail");

        assert_eq!(output, MessageParseError::InvalidFieldLength);
    }

    #[test]
    fn parsing_fails_if_too_small() {
        let repository = random::<Context>();

        let input = Query {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            addresses: vec![],
        };
        let input_bytes = collapse_bytes_without_header(&input.to_quic_chunks());
        let output = Query::parse(input_bytes).expect_err("parse should fail");

        assert_eq!(output, MessageParseError::InvalidFieldLength);
    }
}

mod response {
    use super::*;

    #[test]
    fn response_roundtrips() {
        let original = QueryResponse {
            results: vec![
                StoreMatchResult {
                    match_made: StoreMatch::MatchNone,
                    partition: random::<Partition>(),
                    context: random::<Context>(),
                    stored_local: false,
                    stored_durable: false,
                },
                StoreMatchResult {
                    match_made: StoreMatch::MatchHash,
                    partition: random::<Partition>(),
                    context: random::<Context>(),
                    stored_local: true,
                    stored_durable: false,
                },
                StoreMatchResult {
                    match_made: StoreMatch::MatchFull,
                    partition: random::<Partition>(),
                    context: random::<Context>(),
                    stored_local: true,
                    stored_durable: true,
                },
            ],
        };

        let bytes = original.clone().data();
        let reparsed = QueryResponse::parse(collapse_bytes(&bytes)).expect("parse should work");
        assert_eq!(reparsed, original);
    }

    #[test]
    fn parsing_fails_for_wrong_length() {
        let bytes = vec![Bytes::from(vec![0u8; RESULT_WIRE_SIZE - 1])];
        let error = QueryResponse::parse(collapse_bytes(&bytes)).expect_err("parse should fail");
        assert!(matches!(
            error,
            ReplicationStoreClientError::ResponseError(
                "QueryResponse length is not a multiple of entry size"
            )
        ));
    }

    #[test]
    fn parsing_fails_for_unknown_store_match() {
        let mut entry = vec![0u8; RESULT_WIRE_SIZE];
        entry[0] = 255; // invalid StoreMatch
        let bytes = vec![Bytes::from(entry)];
        let error = QueryResponse::parse(collapse_bytes(&bytes)).expect_err("parse should fail");
        assert!(matches!(
            error,
            ReplicationStoreClientError::ResponseError(
                "Failed to parse store match from QueryResponse"
            )
        ));
    }
}
