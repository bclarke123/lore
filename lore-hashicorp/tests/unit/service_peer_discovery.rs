// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use lore_hashicorp::consul::service_peer_discovery::ServicePeerDiscovery;
use lore_hashicorp::consul::service_peer_discovery::ServicePeerDiscoveryBuilder;
use lore_revision::cluster::peer::PeerInfo;
use lore_revision::cluster::topology::Topology;
use rand::random;
use rs_consul::ResponseMeta;
use rs_consul::ServiceNode;

use crate::factory::ServiceNodeFactory;
use crate::mocks::MockClient;

type TestResult = Result<(), Box<dyn Error>>;

fn assert_infos_match_source(mut infos: HashSet<PeerInfo>, mut source: Vec<ServiceNode>) {
    let mut infos_vec: Vec<PeerInfo> = infos.drain().collect();
    infos_vec.sort_by(|left: &PeerInfo, right: &PeerInfo| left.id.cmp(&right.id));
    source.sort_by(|left: &ServiceNode, right: &ServiceNode| left.node.id.cmp(&right.node.id));

    assert_eq!(infos_vec.len(), source.len());

    for (index, info) in infos_vec.iter().enumerate() {
        let source = &source[index];
        assert_eq!(info.id, source.node.id);
        assert_eq!(info.address, source.service.address);
        assert_eq!(info.port, source.service.port);
    }
}

#[tokio::test]
async fn can_refresh_peers_without_subscriber() -> TestResult {
    // no mocks required because nothing will be called
    let consul_client = MockClient::new();
    let discovery =
        ServicePeerDiscoveryBuilder::new(Box::new(consul_client), "some-service".into()).build();
    discovery.refresh_peers().await?;

    Ok(())
}

#[tokio::test]
async fn can_refresh_peers_with_subscriber() -> TestResult {
    let mut consul_client = MockClient::new();

    let nodes_in_datacenter: Vec<ServiceNode> = vec![
        random::<ServiceNodeFactory>().0,
        random::<ServiceNodeFactory>().0,
    ];
    {
        let service_nodes = nodes_in_datacenter.clone();
        consul_client
            .expect_get_service_nodes()
            .return_once(move |_, _| {
                Ok(ResponseMeta {
                    response: service_nodes.clone(),
                    index: 0,
                })
            });
    }

    let discovery: Arc<ServicePeerDiscovery> =
        ServicePeerDiscoveryBuilder::new(Box::new(consul_client), "some-service".into())
            .with_poll_interval(Duration::from_millis(100))
            .build()
            .into();
    let mut receiver = discovery.clone().subscribe_to_peer_refreshes();
    let _task = lore_base::lore_spawn!(async move {
        discovery
            .refresh_loop()
            .await
            .expect("refresh should not fail");
    });

    let peers_from_receive = receiver.recv().await.expect("receive should work");
    assert_infos_match_source(peers_from_receive, nodes_in_datacenter.clone());

    Ok(())
}
