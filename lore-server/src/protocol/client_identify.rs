// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_telemetry::user_agent_filter::NormalizeOutput;
use lore_telemetry::user_agent_filter::USER_AGENT_UNKNOWN;
use lore_telemetry::user_agent_filter::UserAgentFilter;

use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::storage::messages::MessageParseError;

pub struct UserAgentValue(pub Arc<str>);

/// Parsed representation of a `ClientIdentify` protocol message.
///
/// `user_agent` is `None` when the raw bytes were empty, exceeded the `USER_AGENT_MAX_BYTES`-byte
/// limit, or contained anything outside printable ASCII — all silently ignored so that
/// a malformed header never breaks the connection.
#[derive(Clone, Debug, PartialEq)]
pub struct ClientIdentify {
    pub user_agent: Option<String>,
    /// Whether this `ClientIdentity` can be trusted, or whether it should be
    /// put through the user agent filter
    pub is_trusted: bool,
}

#[lore_macro::test_pub]
const USER_AGENT_MAX_BYTES: usize = 256;

/// Returns `true` when every byte is printable ASCII (`0x20`–`0x7E`), so control characters,
/// `DEL` and any byte with the high bit set are rejected. Keeps the value safe to emit as a
/// telemetry attribute and log field.
fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| b.is_ascii_graphic() || *b == b' ')
}

impl ClientIdentify {
    /// Parses raw bytes from the wire into a `ClientIdentify`.
    ///
    /// Validation mirrors `Correlate::parse`: invalid input is silently
    /// discarded rather than surfaced as a protocol error.
    pub fn parse(bytes: Bytes, is_trusted: bool) -> Result<Self, MessageParseError> {
        let user_agent = if bytes.is_empty()
            || bytes.len() > USER_AGENT_MAX_BYTES
            || !is_printable_ascii(&bytes)
        {
            None
        } else {
            // SAFETY: is_printable_ascii guarantees every byte is in 0x20–0x7E,
            // which is valid UTF-8.
            Some(unsafe { String::from_utf8_unchecked(bytes.to_vec()) })
        };

        Ok(Self {
            user_agent,
            is_trusted,
        })
    }

    pub fn apply(&self, context: &Arc<AttributeMap>, filter: &UserAgentFilter) {
        let raw_agent = match self.user_agent.as_ref() {
            Some(v) => v,
            None => return,
        };

        let normalized: Arc<str> = {
            if !self.is_trusted {
                match filter.normalize(raw_agent) {
                    NormalizeOutput::KnownAgent(label) => label,
                    NormalizeOutput::Unknown => {
                        filter.sample_unknown_agent(raw_agent);
                        Arc::from(USER_AGENT_UNKNOWN)
                    }
                }
            } else {
                Arc::from(raw_agent.as_str())
            }
        };

        context.insert(UserAgentValue(normalized));
    }
}
