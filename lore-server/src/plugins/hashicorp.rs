// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Consul topology plugin factory.
//!
//! This module provides a plugin factory for Consul-based topology discovery:
//! - [`ConsulTopologyPluginFactory`] - Creates Consul-backed topology instances

use std::sync::Arc;
use std::time::Duration;

use lore_base::error::PluginConfigError;
use lore_hashicorp::consul::client;
use lore_hashicorp::consul::client::Consul;
use lore_hashicorp::consul::client::RsConsul;
use lore_hashicorp::consul::service_peer_discovery::ServicePeerDiscoveryBuilder;
use lore_hashicorp::telemetry::NomadResourceDetector;
use lore_revision::cluster::topology::Topology;
use opentelemetry_sdk::resource::ResourceDetector;
use serde::Deserialize;
use tracing::info;

use crate::plugins::PluginError;
use crate::plugins::PluginRegistry;
use crate::plugins::TopologyPluginFactory;

/// Configuration for the Consul topology plugin.
#[derive(Debug, Clone, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct ConsulTopologyPluginConfig {
    /// Optional Consul client config. Will read from environment if not set
    pub client_config: Option<client::Config>,

    /// Service name to discover peers for.
    pub service_name: String,

    /// Optional address to ignore (typically self) when discovering peers.
    #[serde(default)]
    pub ignore_address: Option<String>,

    /// Optional poll interval in seconds for refreshing the peer list.
    #[serde(default)]
    pub poll_interval_secs: Option<u64>,
}

/// Plugin factory for creating Consul-backed topology discovery.
pub struct ConsulTopologyPluginFactory;

impl TopologyPluginFactory for ConsulTopologyPluginFactory {
    fn name(&self) -> &'static str {
        "consul"
    }

    fn validate_config(&self, config: &toml::Value) -> Result<(), PluginError> {
        let plugin_name = self.name();

        let _plugin_config: ConsulTopologyPluginConfig =
            config.clone().try_into().map_err(|e| {
                PluginError::from(PluginConfigError {
                    plugin_name: plugin_name.to_string(),
                    message: format!("Failed to deserialize Consul topology config: {e}"),
                })
            })?;

        Ok(())
    }

    fn create(&self, config: &toml::Value) -> Result<Arc<dyn Topology + Send + Sync>, PluginError> {
        let plugin_name = self.name();

        let plugin_config: ConsulTopologyPluginConfig = config.clone().try_into().map_err(|e| {
            PluginError::from(PluginConfigError {
                plugin_name: plugin_name.to_string(),
                message: format!("Failed to deserialize Consul topology config: {e}"),
            })
        })?;

        info!(
            plugin_name = plugin_name,
            client_config = ?plugin_config.client_config.as_ref().map(|c| c.address.clone()),
            service_name = %plugin_config.service_name,
            ignore_address = ?plugin_config.ignore_address,
            poll_interval_secs = ?plugin_config.poll_interval_secs,
            "Creating Consul topology"
        );

        let consul_client_config = if let Some(config) = &plugin_config.client_config {
            config.clone()
        } else {
            client::Config::from_env()
        };

        let consul_client = Consul::new(consul_client_config);
        let rs_consul: RsConsul = consul_client.into();

        let mut builder =
            ServicePeerDiscoveryBuilder::new(Box::new(rs_consul), plugin_config.service_name);

        if let Some(addr) = plugin_config.ignore_address {
            builder = builder.with_ignore_address(addr);
        }

        if let Some(interval_secs) = plugin_config.poll_interval_secs {
            builder = builder.with_poll_interval(Duration::from_secs(interval_secs));
        }

        let discovery = builder.build();

        Ok(Arc::new(discovery))
    }
}

/// Registers the `HashiCorp` plugins and resource detector with the given
/// registry.
///
/// The Consul topology plugin and the Nomad resource detector are registered
/// independently: Consul service discovery and Nomad workload orchestration are
/// distinct concerns that merely share the `HashiCorp` module, so the detector
/// is not tied to the topology factory.
pub fn register(registry: &mut PluginRegistry) {
    registry.register_topology_plugin(Box::new(ConsulTopologyPluginFactory));
    registry.register_resource_detector(|_runtime_handle| {
        Box::new(NomadResourceDetector) as Box<dyn ResourceDetector>
    });
}
