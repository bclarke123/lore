// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_storage::CompressionMode;
use lore_transport::Endpoint;
use lore_transport::Oidc;
use serde::Deserialize;

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct EnvironmentConfig {
    pub endpoint: Option<Endpoint>,
    pub config: Option<Config>,
    /// The OIDC provider info.
    #[serde(skip)]
    pub oidc: Option<Oidc>,
}

impl EnvironmentConfig {
    pub fn max_query_batch(&self) -> Option<usize> {
        self.config.as_ref().and_then(|c| c.max_query_batch)
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Config {
    pub max_query_batch: Option<usize>,
    pub compression_mode: Option<CompressionMode>,
}
