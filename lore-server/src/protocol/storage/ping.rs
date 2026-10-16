// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_storage::ImmutableStore;
use tracing::warn;

use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::storage::messages::LoreResponse;
use crate::protocol::storage::messages::Message;
use crate::protocol::storage::messages::MessageHandleError;
use crate::protocol::storage::messages::MessageParseError;
use crate::protocol::storage::messages::Response;

#[derive(Debug, PartialEq)]
pub struct Ping {
    pub value: i64,
}

impl Ping {
    pub fn parse(bytes: Bytes) -> Result<Self, MessageParseError>
    where
        Self: Sized,
    {
        let bytes: [u8; std::mem::size_of::<i64>()] = bytes.as_ref().try_into().map_err(|e| {
            warn!("Could not parse ping value: {e}");
            MessageParseError::InvalidPingValue
        })?;

        Ok(Self {
            value: i64::from_le_bytes(bytes),
        })
    }
}

#[async_trait]
impl Message for Ping {
    #[tracing::instrument(name = "Ping::handle", skip_all)]
    async fn handle(
        &self,
        _context: Arc<AttributeMap>,
        _immutable_store: Arc<dyn ImmutableStore>,
        _repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    ) -> Result<LoreResponse, MessageHandleError> {
        Ok(LoreResponse::Ping(PingResponse { value: self.value }))
    }
}

#[derive(Debug, PartialEq)]
pub struct PingResponse {
    pub value: i64,
}

impl Response for PingResponse {
    fn data(&self) -> Vec<Bytes> {
        vec![Bytes::copy_from_slice(&self.value.to_le_bytes())]
    }
}
