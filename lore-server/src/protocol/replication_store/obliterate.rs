// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreObliterateStats;
use lore_telemetry::tracing::fields::ADDRESS;
use lore_telemetry::tracing::fields::CORRELATION_ID;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use tracing::Span;
use tracing::debug;
use tracing::info_span;
use tracing::warn;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;

use crate::protocol::replication_store::REPLICATION_SERVICE_USER_ID;
use crate::protocol::replication_store::header::ReplicationHeader;
use crate::protocol::storage::messages::MessageParseError;
use crate::quic::replication_store_service::client::ReplicationStoreClientError;
use crate::quic::replication_store_service::server::ParsedReplicationStoreRequest;
use crate::quic::replication_store_service::server::RequestHandler;
use crate::util::setup_execution;

pub const BASE_REQUEST_SIZE: usize = size_of::<ReplicationHeader>() + size_of::<Address>();

#[derive(Clone, Debug, PartialEq)]
pub struct Obliterate {
    pub header: ReplicationHeader,
    pub address: Address,
}

impl Obliterate {
    pub fn to_quic_chunks(self) -> [Bytes; 3] {
        [
            Bytes::default(), // command header
            Bytes::from_owner(self.header),
            Bytes::from_owner(self.address),
        ]
    }
}

pub fn parse(mut bytes: Bytes) -> Result<Obliterate, MessageParseError> {
    if bytes.len() < BASE_REQUEST_SIZE {
        return Err(MessageParseError::InvalidFieldLength);
    };

    let header: ReplicationHeader = bytes.split_to(size_of::<ReplicationHeader>()).into();
    let address: Address = bytes.split_to(size_of::<Address>()).into();

    Ok(Obliterate { header, address })
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ObliterateResponse {
    pub num_fragments: u64,
    pub num_payloads: u64,
}

impl ObliterateResponse {
    #[lore_macro::test_pub]
    fn data(self) -> Vec<Bytes> {
        vec![
            Bytes::copy_from_slice(self.num_fragments.as_bytes()),
            Bytes::copy_from_slice(self.num_payloads.as_bytes()),
        ]
    }

    pub fn parse(mut bytes: Bytes) -> Result<Self, ReplicationStoreClientError> {
        let num_fragments = u64::read_from_prefix(&bytes.split_to(8))
            .map_err(|error| {
                warn!(?error, "failed to parse num_fragments");
                ReplicationStoreClientError::ResponseError("error parsing num_fragments'")
            })?
            .0;
        let num_payloads = u64::read_from_prefix(&bytes.split_to(8))
            .map_err(|error| {
                warn!(?error, "failed to parse num_payloads");
                ReplicationStoreClientError::ResponseError("error parsing num_payloads'")
            })?
            .0;

        Ok(ObliterateResponse {
            num_fragments,
            num_payloads,
        })
    }
}

pub fn create_handler(
    bytes: Bytes,
    immutable_store: Arc<dyn ImmutableStore>,
) -> Result<ParsedReplicationStoreRequest, MessageParseError> {
    let request = parse(bytes)?;
    let handler = ObliterateHandler {
        immutable_store,
        request,
    };

    Ok(ParsedReplicationStoreRequest::Obliterate(handler))
}

#[derive(Debug)]
pub struct ObliterateHandler {
    immutable_store: Arc<dyn ImmutableStore>,
    pub request: Obliterate,
}

#[async_trait::async_trait]
impl RequestHandler for ObliterateHandler {
    fn span(&self) -> Span {
        info_span!("obliterate",
            {CORRELATION_ID} = %self.request.header.correlation_id.as_hyphenated(),
            {REPOSITORY_ID} = %self.request.header.repository)
    }

    async fn run(self) -> Result<Vec<Bytes>, StoreError> {
        debug!({ADDRESS} = %self.request.address,
            "obliterate request");

        let execution = setup_execution(
            module_path!(),
            self.request.header.correlation_id.to_string(),
            REPLICATION_SERVICE_USER_ID.to_string(),
        );

        let stats = Arc::new(StoreObliterateStats::default());
        {
            let stats = stats.clone();
            LORE_CONTEXT
                .scope(execution, async move {
                    self.immutable_store
                        .obliterate(
                            self.request.header.repository.into(),
                            self.request.address,
                            stats,
                        )
                        .await
                })
                .await?;
        }

        let response = ObliterateResponse {
            num_fragments: stats.num_fragments.load(Ordering::Relaxed) as u64,
            num_payloads: stats.num_payloads.load(Ordering::Relaxed) as u64,
        };
        Ok(response.data())
    }
}
