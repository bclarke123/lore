// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use rand::Rng;
use rand::distr::Distribution;
use rand::distr::StandardUniform;
use rand::random;
use rs_consul::Node;
use rs_consul::Service;
use rs_consul::ServiceNode;
use uuid::Uuid;

fn random_ip_address<R: Rng + ?Sized>(rng: &mut R) -> String {
    let one = rng.random_range(1..255);
    let two = rng.random_range(1..255);
    let three = rng.random_range(1..255);
    let four = rng.random_range(1..255);

    [
        one.to_string(),
        two.to_string(),
        three.to_string(),
        four.to_string(),
    ]
    .join(".")
}

pub struct NodeFactory(pub Node);

impl Distribution<NodeFactory> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> NodeFactory {
        let id = Uuid::new_v4().to_string();
        let address = random_ip_address(rng);
        let datacenter = "us-east-2".to_string();
        let node = format!("{address}.{datacenter}.local.example.com");

        NodeFactory(Node {
            id,
            node,
            address,
            datacenter,
        })
    }
}

pub struct ServiceFactory(pub Service);

impl Distribution<ServiceFactory> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ServiceFactory {
        let random_suffix = rng.random_range(1..100);
        let id = format!("example_service-{random_suffix}");
        let service = "example_service".to_string();
        let address = random_ip_address(rng);
        let port = rng.random_range(1..30000);

        ServiceFactory(Service {
            id,
            service,
            address,
            port,
            tags: vec![],
        })
    }
}

pub struct ServiceNodeFactory(pub ServiceNode);

impl Distribution<ServiceNodeFactory> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, _rng: &mut R) -> ServiceNodeFactory {
        let service: ServiceFactory = random();
        let node: NodeFactory = random();

        ServiceNodeFactory(ServiceNode {
            node: node.0,
            service: service.0,
        })
    }
}
