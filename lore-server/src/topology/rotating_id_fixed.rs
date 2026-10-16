// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Rotating-ID fixed topology for cross-region connection cycling.
//!
//! [`RotatingIdFixedTopology`] wraps a static peer list but periodically
//! regenerates each peer's ID with a random suffix. Downstream consumers
//! that key connections on peer ID will tear down and re-establish
//! connections on each rotation, distributing load across remote endpoints.
//!
//! The peer addresses and ports remain constant — only the IDs change.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use lore_revision::cluster::peer::PeerInfo;
use lore_revision::cluster::topology::RefreshLoopError;
use lore_revision::cluster::topology::Topology;
use rand::Rng;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::time::MissedTickBehavior;
use tracing::info;
use tracing::warn;

use crate::topology::RotatingIdFixedTopologySettings;

/// Buffer capacity for peer update notifications.
const PEERS_UPDATED_NOTIFICATION_BUFFER_CAPACITY: usize = 10;

/// A fixed-peer topology that rotates peer IDs on a configurable interval.
///
/// Each tick of the refresh loop broadcasts the same set of peers with
/// freshly generated random IDs
#[derive(Debug)]
pub struct RotatingIdFixedTopology {
    /// The set of configured peers.
    peers: HashSet<PeerInfo>,

    /// How often the ID of Peers is rotated
    pub rotation_interval: Duration,

    peers_updated_broadcaster: broadcast::Sender<HashSet<PeerInfo>>,
}

impl RotatingIdFixedTopology {
    /// Creates a new topology from configuration.
    pub fn from_settings(config: &RotatingIdFixedTopologySettings) -> Arc<Self> {
        info!(
            peer_count = config.peers.len(),
            rotation_interval_seconds = config.rotation_interval_seconds,
            "Creating rotating id fixed topology"
        );

        let (peers_updated_broadcaster, _) =
            broadcast::channel::<HashSet<PeerInfo>>(PEERS_UPDATED_NOTIFICATION_BUFFER_CAPACITY);

        let peers: HashSet<PeerInfo> = config
            .peers
            .iter()
            .map(|peer| PeerInfo {
                // will get rotated upon read
                id: "".into(),
                address: peer.address.clone(),
                port: peer.port,
                locality: peer.locality,
                // peer list is static, so address is safe to use as a metric label
                metric_id: peer.address.clone(),
            })
            .collect();

        Arc::new(RotatingIdFixedTopology {
            peers,
            rotation_interval: Duration::from_secs(config.rotation_interval_seconds),
            peers_updated_broadcaster,
        })
    }
}

fn rotated_peer(peer: &PeerInfo) -> PeerInfo {
    let rand_identifier: String = rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(4)
        .map(char::from)
        .collect();

    let mut new_peer = peer.clone();
    new_peer.id = format!("RotatingPeer_'{rand_identifier}'");
    new_peer
}

#[async_trait]
impl Topology for RotatingIdFixedTopology {
    fn supports_refresh_loop(&self) -> bool {
        true
    }

    async fn refresh_loop(self: Arc<Self>) -> Result<(), RefreshLoopError> {
        let mut interval = tokio::time::interval(self.rotation_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;

            let peers = self.peers.iter().map(rotated_peer).collect();

            if let Err(error) = self.peers_updated_broadcaster.send(peers) {
                warn!(error = ?error, "failed to send Rotated ID peers to subscriber");
                // todo(plockhart) we may want to bail out of the task with repeated failures
            }
        }
    }

    fn subscribe_to_peer_refreshes(self: Arc<Self>) -> Receiver<HashSet<PeerInfo>> {
        self.peers_updated_broadcaster.subscribe()
    }
}
