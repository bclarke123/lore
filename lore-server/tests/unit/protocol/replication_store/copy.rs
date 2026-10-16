// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Context;
use lore_base::types::Partition;
use lore_revision::fragment;
use lore_server::protocol::replication_store::copy::*;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::quic::tests::collapse_bytes_without_header;
use rand::random;
use uuid::Uuid;

mod request {
    use super::*;

    #[test]
    fn parsing_works() {
        let destination_repository = random::<Context>();
        let source_partition: Partition = random::<Context>().into();
        let (_, source_address, _) = fragment::generate_random();
        let destination_context = random::<Context>();

        // Each flag round trips on its own as well as alongside the other, so one sharing the
        // other's byte cannot stand in for it.
        for durable in [false, true] {
            for do_not_replicate in [false, true] {
                let input = ImmutableCopy {
                    header: ReplicationHeader {
                        correlation_id: Uuid::new_v4(),
                        repository: destination_repository,
                    },
                    source_partition,
                    source_address,
                    destination_context,
                    durable,
                    do_not_replicate,
                };
                let bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
                let output = parse(bytes).expect("parse should succeed");
                assert_eq!(input, output);
            }
        }
    }

    #[test]
    fn parsing_fails_if_too_small() {
        let input = ImmutableCopy {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository: random::<Context>(),
            },
            source_partition: random::<Context>().into(),
            source_address: fragment::generate_random().1,
            destination_context: random::<Context>(),
            durable: false,
            do_not_replicate: false,
        };
        let bytes = collapse_bytes_without_header(&input.to_quic_chunks());
        let output = parse(bytes.slice(0..bytes.len() - 1)).expect_err("parse should fail");
        assert_eq!(output, MessageParseError::InvalidFieldLength);
    }
}
