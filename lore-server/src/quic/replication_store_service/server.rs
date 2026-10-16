// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use enum_dispatch::enum_dispatch;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_telemetry::tracing::fields::CONNECTION_ID;
use lore_telemetry::tracing::fields::CORRELATION_ID;
use lore_telemetry::tracing::fields::PROTOCOL;
use lore_telemetry::tracing::fields::QUIC_OPCODE;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use lore_telemetry::tracing::fields::SAMPLING_TIER_LOW;
use lore_telemetry::tracing::fields::TRANSPORT;
use lore_telemetry::tracing::fields::USER_AGENT;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::quic::QuicErrorStatus;
use lore_transport::quic::QuicOpCode;
use lore_transport::quic::command_header::CommandHeader;
use tracing::Instrument;
use tracing::Span;
use tracing::info_span;

use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::attribute_map::ConnectionId;
use crate::protocol::client_identify::ClientIdentify;
use crate::protocol::client_identify::UserAgentValue;
use crate::protocol::replication_store::copy;
use crate::protocol::replication_store::copy::ImmutableCopyHandler;
use crate::protocol::replication_store::get;
use crate::protocol::replication_store::get::GetHandler;
use crate::protocol::replication_store::get_metadata;
use crate::protocol::replication_store::get_metadata::GetMetadataHandler;
use crate::protocol::replication_store::obliterate;
use crate::protocol::replication_store::obliterate::ObliterateHandler;
use crate::protocol::replication_store::put;
use crate::protocol::replication_store::put::PutHandler;
use crate::protocol::replication_store::query;
use crate::protocol::replication_store::query::QueryHandler;
use crate::protocol::storage::messages::MessageParseError;
use crate::quic::NO_CONNECTION_ID;
use crate::quic::NO_USER_AGENT;
use crate::quic::ProtocolErrorInfo;
use crate::quic::QuicService;
use crate::quic::replication_store_service::Command;
use crate::quic::replication_store_service::MAX_CHUNK_SIZE;
use crate::quic::replication_store_service::ReplicationServiceErrorCode;
use crate::telemetry::StorageProtocol;
use crate::telemetry::Transport;

/// A trait to represent request handlers for the `ReplicationStoreService`,
/// this trait exists for convenience in reducing boilerplate in running
/// request handlers
#[async_trait::async_trait]
#[enum_dispatch]
pub trait RequestHandler {
    /// Creates a span that the `QuicService` will enter before running the handler
    fn span(&self) -> Span;

    /// Runs the request handler with its given configuration.
    /// If successful, the Ok result is the response bytes to send to the client.
    async fn run(self) -> Result<Vec<Bytes>, StoreError>;
}

/// Minimal handler wrapper for the `ClientIdentify` command.
/// The actual work (apply) is performed in `run_request_handler` before dispatch
/// so that the context is mutated before any subsequent span is built.
#[derive(Debug)]
pub struct ClientIdentifyHandler {
    pub message: ClientIdentify,
}

#[async_trait::async_trait]
impl RequestHandler for ClientIdentifyHandler {
    fn span(&self) -> Span {
        tracing::Span::none()
    }

    async fn run(self) -> Result<Vec<Bytes>, StoreError> {
        Ok(vec![])
    }
}

#[derive(Debug)]
#[enum_dispatch(RequestHandler)]
pub enum ParsedReplicationStoreRequest {
    Put(PutHandler),
    Get(GetHandler),
    Obliterate(ObliterateHandler),
    GetMetadata(GetMetadataHandler),
    Query(QueryHandler),
    Copy(ImmutableCopyHandler),
    ClientIdentify(ClientIdentifyHandler),
}

pub fn command_name(command: &Command) -> &'static str {
    match command {
        Command::ImmutableGet => "immutable_get",
        Command::ImmutablePut => "immutable_put",
        Command::ImmutableObliterate => "immutable_obliterate",
        Command::ImmutableGetMetadata => "immutable_get_metadata",
        Command::ImmutableLocalGet => "immutable_local_get",
        Command::ImmutableLocalPut => "immutable_local_put",
        Command::ImmutableLocalGetMetadata => "immutable_local_get_metadata",
        Command::ImmutableQuery => "immutable_query",
        Command::ImmutableLocalQuery => "immutable_local_query",
        Command::ImmutableCopy => "immutable_copy",
        Command::ClientIdentify => "client_identify",
    }
}

pub struct ReplicationStoreService {
    immutable_store: Arc<dyn ImmutableStore>,
    local_store: Arc<dyn ImmutableStore>,
    user_agent_filter: Arc<UserAgentFilter>,
}

impl ReplicationStoreService {
    pub fn new(
        immutable_store: Arc<dyn ImmutableStore>,
        local_store: Arc<dyn ImmutableStore>,
        user_agent_filter: Arc<UserAgentFilter>,
    ) -> Self {
        Self {
            immutable_store,
            local_store,
            user_agent_filter,
        }
    }
}

#[async_trait]
impl QuicService for ReplicationStoreService {
    type ParsedRequestType = ParsedReplicationStoreRequest;
    // MessageParseError is a convenient type that encapsulates most of the kind of errors
    // that we can encounter with message parsing as well. If the overlap changes too much we can
    // create our own type instead - it does not strictly need to be `MessageParseError`
    type RequestParseErrorType = MessageParseError;
    type RequestHandlerError = StoreError;

    fn get_service_name_label(&self) -> &'static str {
        StorageProtocol::Replication.as_str()
    }

    fn parse_request_bytes(
        &self,
        header: &lore_transport::quic::command_header::CommandHeader,
        bytes: Bytes,
    ) -> Result<Self::ParsedRequestType, Self::RequestParseErrorType> {
        let command: Command = header
            .cmd
            .try_into()
            .map_err(|_e| MessageParseError::UnknownOpcode(header.cmd))?;

        let handler = match command {
            Command::ImmutableGet => {
                get::create_handler(bytes, self.immutable_store.clone(), "get")?
            }
            Command::ImmutablePut => {
                put::create_handler(bytes, self.immutable_store.clone(), "put")?
            }
            Command::ImmutableObliterate => {
                obliterate::create_handler(bytes, self.immutable_store.clone())?
            }
            Command::ImmutableGetMetadata => {
                get_metadata::create_handler(bytes, self.immutable_store.clone(), "get_metadata")?
            }
            Command::ImmutableLocalGet => {
                get::create_handler(bytes, self.local_store.clone(), "local_get")?
            }
            Command::ImmutableLocalPut => {
                put::create_handler(bytes, self.local_store.clone(), "local_put")?
            }
            Command::ImmutableLocalGetMetadata => {
                get_metadata::create_handler(bytes, self.local_store.clone(), "local_get_metadata")?
            }
            Command::ImmutableQuery => {
                query::create_handler(bytes, self.immutable_store.clone(), "query")?
            }
            Command::ImmutableLocalQuery => {
                query::create_handler(bytes, self.local_store.clone(), "local_query")?
            }
            Command::ImmutableCopy => copy::create_handler(bytes, self.immutable_store.clone())?,
            Command::ClientIdentify => {
                return Ok(ParsedReplicationStoreRequest::ClientIdentify(
                    ClientIdentifyHandler {
                        message: ClientIdentify::parse(bytes, true)?,
                    },
                ));
            }
        };

        Ok(handler)
    }

    async fn run_request_handler(
        &self,
        context: Arc<AttributeMap>,
        request: Self::ParsedRequestType,
    ) -> Result<Vec<Bytes>, Self::RequestHandlerError> {
        if let ParsedReplicationStoreRequest::ClientIdentify(ref msg) = request {
            msg.message.apply(&context, &self.user_agent_filter);
            return Ok(vec![]);
        }
        let span = request.span();
        request.run().instrument(span).await
    }

    fn command_to_metrics_label(&self, opcode: QuicOpCode) -> &'static str {
        opcode.try_into().as_ref().map_or("unknown", command_name)
    }

    fn transform_protocol_error(&self, error: &Self::RequestHandlerError) -> ProtocolErrorInfo {
        let error_code: ReplicationServiceErrorCode = error.into();
        let is_appropriate_for_logging = match error_code {
            ReplicationServiceErrorCode::Internal | ReplicationServiceErrorCode::Oversized => true,
            ReplicationServiceErrorCode::AddressNotFound
            | ReplicationServiceErrorCode::SlowDown
            | ReplicationServiceErrorCode::PayloadNotFound => false,
        };
        let is_internal_error = match error_code {
            // if something has gone wrong, or we are failing to provide a good service, then treat
            // as internal like
            ReplicationServiceErrorCode::Internal | ReplicationServiceErrorCode::SlowDown => true,
            ReplicationServiceErrorCode::AddressNotFound
            | ReplicationServiceErrorCode::PayloadNotFound
            | ReplicationServiceErrorCode::Oversized => false,
        };

        ProtocolErrorInfo {
            response_error_code: error_code as QuicErrorStatus,
            message_handle_label: error_code_to_label(error_code),
            is_internal_error,
            is_appropriate_for_logging,
        }
    }

    fn max_chunk_size(&self) -> usize {
        MAX_CHUNK_SIZE
    }

    fn build_request_span(
        &self,
        header: &CommandHeader,
        message: &Self::ParsedRequestType,
        context: &Arc<AttributeMap>,
    ) -> Span {
        // ClientIdentify has no replication header; return a no-op span immediately.
        if let ParsedReplicationStoreRequest::ClientIdentify(_) = message {
            return Span::none();
        }

        let replication_header = match message {
            ParsedReplicationStoreRequest::Get(h) => &h.request.header,
            ParsedReplicationStoreRequest::Put(h) => &h.request.header,
            ParsedReplicationStoreRequest::Obliterate(h) => &h.request.header,
            ParsedReplicationStoreRequest::GetMetadata(h) => &h.request.header,
            ParsedReplicationStoreRequest::Query(h) => &h.request.header,
            ParsedReplicationStoreRequest::Copy(h) => &h.request.header,
            // Covered by the early return above; the compiler requires exhaustiveness.
            ParsedReplicationStoreRequest::ClientIdentify(_) => unreachable!(),
        };
        let repository_id = replication_header.repository.to_string();
        let correlation_id = replication_header
            .correlation_id
            .as_hyphenated()
            .to_string();

        let connection_id = context
            .get::<ConnectionId>()
            .map_or_else(|| NO_CONNECTION_ID.to_string(), |id| id.0.to_string());

        let user_agent_value = context.get::<UserAgentValue>();
        let user_agent = user_agent_value
            .as_ref()
            .map_or(NO_USER_AGENT, |v| v.0.as_ref());

        let command_parse = Command::try_from(header.cmd);
        let opcode_label = command_parse
            .as_ref()
            .map_or("", |command| command_name(command));

        match command_parse {
            Ok(Command::ImmutableGet) => info_span!(
                parent: None,
                "ReplicationGetTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutablePut) => info_span!(
                parent: None,
                "ReplicationPutTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableObliterate) => info_span!(
                parent: None,
                "ReplicationObliterateTask",
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableGetMetadata) => info_span!(
                parent: None,
                "ReplicationGetMetadataTask",
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableLocalGet) => info_span!(
                parent: None,
                "ReplicationLocalGetTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableLocalPut) => info_span!(
                parent: None,
                "ReplicationLocalPutTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableLocalGetMetadata) => info_span!(
                parent: None,
                "ReplicationLocalGetMetadataTask",
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableQuery) => info_span!(
                parent: None,
                "ReplicationQueryTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableLocalQuery) => info_span!(
                parent: None,
                "ReplicationLocalQueryTask",
                { SAMPLING_TIER_LOW } = true,
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            Ok(Command::ImmutableCopy) => info_span!(
                parent: None,
                "ReplicationCopyTask",
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { QUIC_OPCODE } = opcode_label,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
            // ClientIdentify is handled above with an early return; Err(_) is a truly unknown opcode.
            Ok(Command::ClientIdentify) | Err(_) => info_span!(
                parent: None,
                "ReplicationUnknownTask",
                { TRANSPORT } = %Transport::Quic,
                { PROTOCOL } = %StorageProtocol::Replication,
                { CONNECTION_ID } = connection_id,
                { REPOSITORY_ID } = repository_id,
                { CORRELATION_ID } = correlation_id,
                { USER_AGENT } = user_agent,
            ),
        }
    }
}

pub fn error_code_to_label(code: ReplicationServiceErrorCode) -> &'static str {
    match code {
        ReplicationServiceErrorCode::Internal => "Internal",
        ReplicationServiceErrorCode::AddressNotFound => "StoreNotFound",
        ReplicationServiceErrorCode::SlowDown => "StoreSlowDown",
        ReplicationServiceErrorCode::PayloadNotFound => "PayloadNotFound",
        ReplicationServiceErrorCode::Oversized => "Oversized",
    }
}
