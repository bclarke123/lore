// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Context;
use lore_revision::fragment;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::protocol::replication_store::obliterate::*;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::quic::tests::collapse_bytes_without_header;
use rand::random;
use uuid::Uuid;

mod request {
    use super::*;
    #[test]
    fn parsing_works() {
        let repository = random::<Context>();
        let (_, address, _) = fragment::generate_random();

        let input = Obliterate {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            address,
        };
        let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
        let output = parse(input_bytes).expect("parse should work");

        assert_eq!(input, output);
    }

    #[test]
    fn parsing_fails_if_too_small() {
        let repository = random::<Context>();
        let (_, address, _) = fragment::generate_random();

        let input = Obliterate {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            address,
        };
        let input_bytes = collapse_bytes_without_header(&input.to_quic_chunks());
        let output =
            parse(input_bytes.slice(0..input_bytes.len() - 1)).expect_err("parse should fail");

        assert_eq!(output, MessageParseError::InvalidFieldLength);
    }
}

mod response {
    use lore_server::quic::tests::collapse_bytes;

    use super::*;

    #[test]
    fn response_to_bytes_works() {
        let original = ObliterateResponse {
            num_payloads: random(),
            num_fragments: random(),
        };

        let bytes = original.clone().data();

        let reparsed_response =
            ObliterateResponse::parse(collapse_bytes(&bytes)).expect("parse should work");
        assert_eq!(reparsed_response, original);
    }
}
