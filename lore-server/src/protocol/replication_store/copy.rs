// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Buf;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Partition;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::immutable_store::CopyBehavior;
use lore_telemetry::tracing::fields::ADDRESS;
use lore_telemetry::tracing::fields::CORRELATION_ID;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use tracing::Span;
use tracing::debug;
use tracing::info_span;
use zerocopy::IntoBytes as _;

use crate::protocol::replication_store::REPLICATION_SERVICE_USER_ID;
use crate::protocol::replication_store::header::ReplicationHeader;
use crate::protocol::storage::messages::MessageParseError;
use crate::quic::replication_store_service::server::ParsedReplicationStoreRequest;
use crate::quic::replication_store_service::server::RequestHandler;
use crate::util::setup_execution;

pub const BASE_REQUEST_SIZE: usize = size_of::<ReplicationHeader>()
    + size_of::<Partition>()
    + size_of::<Address>()
    + size_of::<Context>()
    + 1; // behavior flags

/// Positions of the behavior flags in the request's final byte. A peer that sets a bit this
/// build does not know is answered as though it were clear, since the opcode is what a peer
/// asking for behavior we cannot honour has to change.
const FLAG_DURABLE: u8 = 0b1;
const FLAG_DO_NOT_REPLICATE: u8 = 0b10;

/// `header.repository` carries the destination partition.
#[derive(Clone, Debug, PartialEq)]
pub struct ImmutableCopy {
    pub header: ReplicationHeader,
    pub source_partition: Partition,
    pub source_address: Address,
    pub destination_context: Context,
    pub durable: bool,
    pub do_not_replicate: bool,
}

impl ImmutableCopy {
    pub fn to_quic_chunks(self) -> [Bytes; 6] {
        let mut flags = 0;
        if self.durable {
            flags |= FLAG_DURABLE;
        }
        if self.do_not_replicate {
            flags |= FLAG_DO_NOT_REPLICATE;
        }
        [
            Bytes::default(), // command header placeholder
            Bytes::from_owner(self.header),
            Bytes::copy_from_slice(self.source_partition.as_bytes()),
            Bytes::from_owner(self.source_address),
            Bytes::copy_from_slice(self.destination_context.as_bytes()),
            Bytes::copy_from_slice(&[flags]),
        ]
    }
}

pub fn parse(mut bytes: Bytes) -> Result<ImmutableCopy, MessageParseError> {
    if bytes.len() < BASE_REQUEST_SIZE {
        return Err(MessageParseError::InvalidFieldLength);
    }

    let header: ReplicationHeader = bytes.split_to(size_of::<ReplicationHeader>()).into();
    let source_partition: Partition = Context::from(bytes.split_to(size_of::<Context>())).into();
    let source_address: Address = bytes.split_to(size_of::<Address>()).into();
    let destination_context: Context = bytes.split_to(size_of::<Context>()).into();
    let flags = {
        let flags = bytes[0];
        bytes.advance(1);
        flags
    };
    let durable = flags & FLAG_DURABLE != 0;
    let do_not_replicate = flags & FLAG_DO_NOT_REPLICATE != 0;

    Ok(ImmutableCopy {
        header,
        source_partition,
        source_address,
        destination_context,
        durable,
        do_not_replicate,
    })
}

pub fn create_handler(
    bytes: Bytes,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<ParsedReplicationStoreRequest, MessageParseError> {
    let request = parse(bytes)?;
    let handler = ImmutableCopyHandler {
        immutable_store,
        request,
    };
    Ok(ParsedReplicationStoreRequest::Copy(handler))
}

#[derive(Debug)]
pub struct ImmutableCopyHandler {
    immutable_store: Arc<dyn ImmutableStore>,
    pub request: ImmutableCopy,
}

#[async_trait::async_trait]
impl RequestHandler for ImmutableCopyHandler {
    fn span(&self) -> Span {
        info_span!("copy",
            {CORRELATION_ID} = %self.request.header.correlation_id.as_hyphenated(),
            {REPOSITORY_ID} = %self.request.header.repository)
    }

    async fn run(self) -> Result<Vec<Bytes>, StoreError> {
        debug!({ADDRESS} = %self.request.source_address, "copy request");

        let execution = setup_execution(
            module_path!(),
            self.request.header.correlation_id.to_string(),
            REPLICATION_SERVICE_USER_ID.to_string(),
        );

        LORE_CONTEXT
            .scope(execution, async move {
                self.immutable_store
                    .copy(
                        self.request.source_partition,
                        self.request.source_address,
                        self.request.header.repository.into(),
                        self.request.destination_context,
                        CopyBehavior {
                            durable: self.request.durable,
                            do_not_replicate: self.request.do_not_replicate,
                        },
                    )
                    .await
            })
            .await?;

        Ok(vec![])
    }
}
