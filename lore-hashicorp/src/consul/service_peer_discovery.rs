// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lore_revision::cluster::peer::Locality;
use lore_revision::cluster::peer::PeerInfo;
use lore_revision::cluster::topology::RefreshLoopError;
use lore_revision::cluster::topology::Topology;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::observe::ObserveResult;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;
use rs_consul::ConsulError;
use rs_consul::GetServiceNodesRequest;
use tokio::sync::Semaphore;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::Sender;
use tokio::time::MissedTickBehavior;
use tracing::debug;
use tracing::instrument;
use tracing::warn;
use urlencoding::encode;

use crate::consul::ConsulClient;

// The number of notifications a subscriber to peer changes can buffer
// before they become saturated. The assumption is that receivers will quickly
// or running behind the rate of peers being updated won't matter to the recipient
const PEERS_UPDATED_NOTIFICATION_BUFFER: usize = 10;

// If set to auto refresh, this is the fallback interval
const DEFAULT_POLL_INTERVAL_SECONDS: u64 = 60;

#[derive(Debug)]
struct PeerDiscoveryInstrumentProvider {
    metrics_attributes: Vec<KeyValue>,
}

impl InstrumentProvider for PeerDiscoveryInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "urc.hashicorp.service_peer_discovery"
    }

    fn labels(&self) -> &[KeyValue] {
        &self.metrics_attributes
    }
}

#[derive(Debug)]
struct PeerDiscoveryInstruments {
    provider: PeerDiscoveryInstrumentProvider,
    refresh_peers_loop_iteration_duration: Histogram<f64>,
}

pub struct ServicePeerDiscoveryBuilder {
    consul_client: Box<dyn ConsulClient + Send + Sync>,
    service_name: String,
    ignore_address: Option<String>,
    poll_interval: Option<Duration>,
}

impl ServicePeerDiscoveryBuilder {
    pub fn new(consul_client: Box<dyn ConsulClient + Send + Sync>, service_name: String) -> Self {
        Self {
            consul_client,
            service_name,
            ignore_address: None,
            poll_interval: None,
        }
    }

    pub fn build(self) -> ServicePeerDiscovery {
        let (peers_updated_broadcaster, _) =
            broadcast::channel::<HashSet<PeerInfo>>(PEERS_UPDATED_NOTIFICATION_BUFFER);

        let instrument_provider = PeerDiscoveryInstrumentProvider {
            metrics_attributes: vec![KeyValue::new(
                "consul_service_name",
                self.service_name.clone(),
            )],
        };

        let instruments = PeerDiscoveryInstruments {
            refresh_peers_loop_iteration_duration: instrument_provider
                .latency_histogram_ms("refresh_peers_loop.iteration.duration"),
            provider: instrument_provider,
        };

        ServicePeerDiscovery {
            instruments,
            consul_client: self.consul_client,
            service_name: self.service_name,
            address_filter: self.ignore_address.as_ref().map(|ignore_address| {
                encode(&format!("Node.Address != \"{ignore_address}\"")).into_owned()
            }),
            refresh_semaphore: Semaphore::new(1),
            peers_updated_broadcaster,
            poll_interval: self
                .poll_interval
                .unwrap_or(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECONDS)),
        }
    }

    pub fn with_ignore_address(mut self, address: String) -> Self {
        self.ignore_address = Some(address);
        self
    }

    pub fn with_poll_interval(mut self, poll_interval: Duration) -> Self {
        self.poll_interval = Some(poll_interval);
        self
    }
}

#[derive(Debug)]
pub struct ServicePeerDiscovery {
    instruments: PeerDiscoveryInstruments,

    consul_client: Box<dyn ConsulClient + Send + Sync>,
    service_name: String,
    address_filter: Option<String>,

    refresh_semaphore: Semaphore,
    peers_updated_broadcaster: Sender<HashSet<PeerInfo>>,
    poll_interval: Duration,
}

impl ServicePeerDiscovery {
    #[instrument(name = "ServicePeerDiscovery::RefreshPeers", skip_all, fields(service_name = self.service_name))]
    pub async fn refresh_peers(&self) -> Result<(), ConsulError> {
        // no point doing anything if no one is listening
        if self.peers_updated_broadcaster.receiver_count() == 0 {
            return Ok(());
        }

        let _permit = self.refresh_semaphore.acquire().await;

        let refreshed_infos: HashSet<PeerInfo> = {
            let request = GetServiceNodesRequest {
                service: &self.service_name,
                near: None,
                passing: true,
                filter: self.address_filter.as_deref(),
            };
            self.consul_client
                .get_service_nodes(request, None)
                .await?
                .response
                .drain(..)
                .map(|node| PeerInfo {
                    metric_id: format!("consul_node_{}", node.node.id),
                    id: node.node.id,
                    address: node.service.address,
                    port: node.service.port,
                    locality: Locality::SameRegion,
                })
                .collect()
        };

        if let Err(send_error) = self.peers_updated_broadcaster.send(refreshed_infos) {
            debug!(send_error = ?send_error, "failed to broadcast peer changes");
        }

        Ok(())
    }
}

#[async_trait]
impl Topology for ServicePeerDiscovery {
    #[instrument(name = "ServicePeerDiscovery::Auto_Refresh", skip_all)]
    async fn refresh_loop(self: Arc<Self>) -> Result<(), RefreshLoopError> {
        let mut interval = tokio::time::interval(self.poll_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;

            if let Err(error) = self
                .refresh_peers()
                .observe_result(
                    self.instruments
                        .refresh_peers_loop_iteration_duration
                        .clone(),
                    self.instruments.provider.labels().into(),
                )
                .await
                .output
            {
                warn!(error = ?error, "refresh peers error");
                // todo(plockhart) we may want to bail out of the task with repeated failures
            }
        }
    }

    fn subscribe_to_peer_refreshes(self: Arc<Self>) -> Receiver<HashSet<PeerInfo>> {
        self.peers_updated_broadcaster.subscribe()
    }
}
