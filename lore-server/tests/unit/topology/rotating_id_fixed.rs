// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::time::Duration;

use lore_base::lore_spawn;
use lore_revision::cluster::peer::Locality;
use lore_revision::cluster::topology::Topology;
use lore_server::topology::PeerSettings;
use lore_server::topology::RotatingIdFixedTopologySettings;
use lore_server::topology::rotating_id_fixed::*;

#[test]
fn empty_peers_succeeds() {
    let config = RotatingIdFixedTopologySettings {
        peers: vec![],
        rotation_interval_seconds: 10,
    };

    let _ = RotatingIdFixedTopology::from_settings(&config);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn topology_refresh_changes_id() {
    let peer_address = "example.com";
    let peer_port = 9090;
    let peer_locality = Locality::SameRegion;

    let config = RotatingIdFixedTopologySettings {
        peers: vec![PeerSettings {
            address: peer_address.to_string(),
            port: peer_port,
            locality: peer_locality,
        }],
        rotation_interval_seconds: 1,
    };
    let topology = RotatingIdFixedTopology::from_settings(&config);
    {
        let topology = topology.clone();
        let _task = lore_spawn!(async move {
            topology
                .refresh_loop()
                .await
                .expect("refresh should not fail");
        });
    }

    let mut receiver = topology.subscribe_to_peer_refreshes();

    let previous_id;
    {
        let result = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("Timeout waiting for peers (round 1)");
        match result {
            Ok(peers) => {
                assert_eq!(peers.len(), 1);
                let peer = peers.iter().next().expect("Should have one peer");

                previous_id = peer.id.clone();
                assert_eq!(peer.address, peer_address);
                assert_eq!(peer.port, peer_port);
                assert_eq!(peer.locality, peer_locality);
            }
            Err(e) => panic!("round 1 receive error: {e:?}"),
        }
    }
    {
        let result = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
            .await
            .expect("Timeout waiting for peers (round 2)");
        match result {
            Ok(peers) => {
                assert_eq!(peers.len(), 1);
                let peer = peers.iter().next().expect("Should have one peer");

                assert_ne!(peer.id, previous_id);
                assert_eq!(peer.address, peer_address);
                assert_eq!(peer.port, peer_port);
                assert_eq!(peer.locality, peer_locality);
            }
            Err(e) => panic!("round 2 receive error: {e:?}"),
        }
    }
}
