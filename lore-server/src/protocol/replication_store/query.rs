// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Buf;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Partition;
use lore_base::types::TypedBytes;
use lore_base::types::VecBytes;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_telemetry::tracing::fields::CORRELATION_ID;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use tracing::Span;
use tracing::debug;
use tracing::info_span;
use tracing::warn;
use zerocopy::IntoBytes;

use crate::protocol::replication_store::REPLICATION_SERVICE_USER_ID;
use crate::protocol::replication_store::header::ReplicationHeader;
use crate::protocol::storage::messages::MessageParseError;
use crate::quic::replication_store_service::client::ReplicationStoreClientError;
use crate::quic::replication_store_service::server::ParsedReplicationStoreRequest;
use crate::quic::replication_store_service::server::RequestHandler;
use crate::util::setup_execution;

pub const MAX_ADDRESSES: usize = 100;

/// The `ReplicationHeader` and at least 1 `Address`
pub const BASE_REQUEST_SIZE: usize = size_of::<ReplicationHeader>() + size_of::<Address>();

/// Wire size of one serialised [`StoreMatchResult`]:
///   1 byte  — `match_made`
///  16 bytes — partition
///  16 bytes — context
///   1 byte  — flags: bit 0 = `stored_local`, bit 1 = `stored_durable`
#[lore_macro::test_pub]
const RESULT_WIRE_SIZE: usize = 1 + size_of::<Partition>() + size_of::<Context>() + 1;

#[derive(Clone, Debug, PartialEq)]
pub struct Query {
    pub header: ReplicationHeader,
    pub addresses: Vec<Address>,
}

impl Query {
    pub fn to_quic_chunks(self) -> [Bytes; 3] {
        [
            Bytes::default(), // command header
            Bytes::from_owner(self.header),
            Bytes::from_owner(VecBytes(self.addresses)),
        ]
    }

    pub fn parse(mut bytes: Bytes) -> Result<Query, MessageParseError> {
        if bytes.len() < BASE_REQUEST_SIZE {
            return Err(MessageParseError::InvalidFieldLength);
        };

        let header: ReplicationHeader = bytes.split_to(size_of::<ReplicationHeader>()).into();
        let addresses = bytes.as_type_slice::<Address>().to_vec();

        if addresses.len() > MAX_ADDRESSES {
            return Err(MessageParseError::InvalidFieldLength);
        }

        Ok(Query { header, addresses })
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct QueryResponse {
    pub results: Vec<StoreMatchResult>,
}

impl QueryResponse {
    #[lore_macro::test_pub]
    fn data(self) -> Vec<Bytes> {
        let mut buf = Vec::with_capacity(self.results.len() * RESULT_WIRE_SIZE);
        for r in self.results {
            buf.push(r.match_made.into());
            buf.extend_from_slice(r.partition.as_bytes());
            buf.extend_from_slice(r.context.as_bytes());
            buf.push((r.stored_local as u8) | ((r.stored_durable as u8) << 1));
        }
        vec![Bytes::from(buf)]
    }

    pub fn parse(mut bytes: Bytes) -> Result<Self, ReplicationStoreClientError> {
        if !bytes.len().is_multiple_of(RESULT_WIRE_SIZE) {
            return Err(ReplicationStoreClientError::ResponseError(
                "QueryResponse length is not a multiple of entry size",
            ));
        }

        let count = bytes.len() / RESULT_WIRE_SIZE;
        let mut results = Vec::with_capacity(count);

        for _ in 0..count {
            let match_made: StoreMatch = bytes[0].try_into().map_err(|error| {
                warn!(?error, "failed to parse store match");
                ReplicationStoreClientError::ResponseError(
                    "Failed to parse store match from QueryResponse",
                )
            })?;
            bytes.advance(1);

            let partition: Partition = bytes.split_to(size_of::<Partition>()).into();
            let context: Context = bytes.split_to(size_of::<Context>()).into();

            let flags = bytes[0];
            bytes.advance(1);
            let stored_local = flags & 0b01 != 0;
            let stored_durable = flags & 0b10 != 0;

            results.push(StoreMatchResult {
                match_made,
                partition,
                context,
                stored_local,
                stored_durable,
            });
        }

        Ok(QueryResponse { results })
    }
}

pub fn create_handler(
    bytes: Bytes,
    immutable_store: Arc<dyn ImmutableStore>,
    message_context: &'static str,
) -> Result<ParsedReplicationStoreRequest, MessageParseError> {
    let request = Query::parse(bytes)?;
    let handler = QueryHandler {
        immutable_store,
        request,
        message_context,
    };

    Ok(ParsedReplicationStoreRequest::Query(handler))
}

#[derive(Debug)]
pub struct QueryHandler {
    immutable_store: Arc<dyn ImmutableStore>,
    pub request: Query,
    message_context: &'static str,
}

#[async_trait::async_trait]
impl RequestHandler for QueryHandler {
    fn span(&self) -> Span {
        info_span!("query",
            {CORRELATION_ID} = %self.request.header.correlation_id.as_hyphenated(),
            {REPOSITORY_ID} = %self.request.header.repository,
            message_context = self.message_context)
    }

    async fn run(self) -> Result<Vec<Bytes>, StoreError> {
        debug!(num_items = self.request.addresses.len(), "query request");

        let execution = setup_execution(
            module_path!(),
            self.request.header.correlation_id.to_string(),
            REPLICATION_SERVICE_USER_ID.to_string(),
        );

        let results = LORE_CONTEXT
            .scope(execution, async move {
                let mut resolved = vec![StoreMatchResult::default(); self.request.addresses.len()];
                self.immutable_store
                    .query(
                        self.request.header.repository.into(),
                        &self.request.addresses,
                        &mut resolved,
                    )
                    .await
                    .map(|()| resolved)
            })
            .await?;

        let response = QueryResponse { results };
        Ok(response.data())
    }
}
