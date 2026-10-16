// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::lore_spawn;
use lore_revision::cluster::peer::PeerInfo;
use lore_revision::cluster::topology::RefreshLoopError;
use lore_revision::cluster::topology::Topology;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::info;
use tracing::warn;

/// Buffer capacity for peer update notifications.
const PEERS_UPDATED_NOTIFICATION_BUFFER_CAPACITY: usize = 10;

/// A single topology source within a [`CompositeTopology`].
///
/// Each source wraps an inner [`Topology`] and maintains a cached snapshot
/// of the peers most recently reported by that topology. The cache is
/// updated whenever the inner topology broadcasts a change, allowing the
/// composite to re-merge all sources without polling.
#[derive(Debug)]
struct CompositeSource {
    /// The inner topology that provides peer updates.
    topology: Arc<dyn Topology + Send + Sync>,

    /// Most recent peer set received from this source.
    ///
    /// Written by the per-source subscription task and read when any source
    /// emits an update so the composite can union all cached sets.
    cached_peer_infos: RwLock<HashSet<PeerInfo>>,
}

/// A topology that merges peers from multiple underlying topology sources.
///
/// `CompositeTopology` subscribes to each source topology's peer updates,
/// caches the latest peer set per source, and broadcasts the union of all
/// cached sets whenever any source changes.
#[derive(Debug)]
pub struct CompositeTopology {
    /// The set of topology sources whose peers are merged.
    composite_sources: Vec<Arc<CompositeSource>>,

    /// Broadcaster for the merged peer set.
    ///
    /// Subscribers receive the full union of all source peer sets each time
    /// any individual source reports a change.
    peers_updated_broadcaster: broadcast::Sender<HashSet<PeerInfo>>,
}

impl CompositeTopology {
    pub fn from_sources(sources: Vec<Arc<dyn Topology + Send + Sync>>) -> Arc<Self> {
        info!(num_sources = sources.len(), "Creating Composite Topology");

        let mut composite_sources: Vec<Arc<CompositeSource>> = Vec::with_capacity(sources.len());

        for source in sources {
            let composite_source: Arc<_> = CompositeSource {
                topology: source.clone(),
                cached_peer_infos: HashSet::new().into(),
            }
            .into();

            composite_sources.push(composite_source);
        }

        let (peers_updated_broadcaster, _) =
            broadcast::channel::<HashSet<PeerInfo>>(PEERS_UPDATED_NOTIFICATION_BUFFER_CAPACITY);
        let composite_topology = CompositeTopology {
            composite_sources,
            peers_updated_broadcaster,
        };
        Arc::new(composite_topology)
    }
}

#[async_trait]
impl Topology for CompositeTopology {
    fn supports_refresh_loop(&self) -> bool {
        true
    }

    async fn refresh_loop(self: Arc<Self>) -> Result<(), RefreshLoopError> {
        let mut refresh_loops = JoinSet::new();

        let (source_updated_broadcaster, mut source_updated_receiver) =
            broadcast::channel::<()>(PEERS_UPDATED_NOTIFICATION_BUFFER_CAPACITY);

        // subscribe to source changes - caching the peers and then notify composite topology channel
        let mut subscriptions = Vec::with_capacity(self.composite_sources.len());
        for source in &self.composite_sources {
            let source_cloned = source.clone();
            let mut subscription = source_cloned.topology.clone().subscribe_to_peer_refreshes();
            let source_updated_broadcaster = source_updated_broadcaster.clone();
            let subscribe_task = AbortOnDropHandle::new(lore_spawn!(async move {
                loop {
                    let change_event = match subscription.recv().await {
                        Ok(change_event) => change_event,
                        Err(error) => {
                            info!("composite topology source receive error {error:?}");
                            match error {
                                RecvError::Closed => {
                                    info!("stopping composite source topology subscription");
                                    break;
                                }
                                RecvError::Lagged(_) => {
                                    continue;
                                }
                            };
                        }
                    };
                    let mut write = source_cloned.cached_peer_infos.write().await;
                    *write = change_event;
                    // notify the composite topology that something has changed
                    if let Err(error) = source_updated_broadcaster.send(()) {
                        warn!(error = ?error, "failed to send updated peers to composite");
                    }
                }
            }));
            subscriptions.push(subscribe_task);

            // run the refresh loop for this topology so we get subsequent updates
            if source.topology.supports_refresh_loop() {
                let source_cloned = source.clone();
                lore_spawn!(refresh_loops, async move {
                    let topology = source_cloned.topology.clone();
                    topology.refresh_loop().await.map_err(anyhow::Error::from)
                });
            }
        }

        loop {
            match source_updated_receiver.recv().await {
                Ok(change_event) => change_event,
                Err(error) => {
                    info!("composite topology sources receive error {error:?}");
                    match error {
                        RecvError::Closed => {
                            info!("stopping composite topology sources subscription");
                            return Ok(());
                        }
                        RecvError::Lagged(_) => {
                            continue;
                        }
                    };
                }
            };

            let mut total_peers = HashSet::new();
            for source in &self.composite_sources {
                let peers = source.cached_peer_infos.read().await;
                total_peers.extend(peers.clone());
            }

            if let Err(error) = self.peers_updated_broadcaster.send(total_peers) {
                warn!(error = ?error, "failed to send updated peers from composite");
            }
        }
    }

    fn subscribe_to_peer_refreshes(self: Arc<Self>) -> Receiver<HashSet<PeerInfo>> {
        self.peers_updated_broadcaster.subscribe()
    }
}
