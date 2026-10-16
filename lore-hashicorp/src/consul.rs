// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use rs_consul::ConsulError;
use rs_consul::GetServiceNodesRequest;
use rs_consul::QueryOptions;
pub use rs_consul::ResponseMeta;
pub use rs_consul::ServiceNode;

pub mod client;
pub mod service_peer_discovery;

/// A wrapper around the Consul HTTP API, for easy of mocking
/// and for switching out the underlying client. Based off the well typed
/// rs-consul module
#[async_trait]
pub trait ConsulClient: std::fmt::Debug {
    // Catalog api routes
    // https://developer.hashicorp.com/consul/api-docs/catalog

    /// Gets all the `ServiceNode`s running the given `service_name` in the cluster
    async fn get_service_nodes<'a>(
        &self,
        request: GetServiceNodesRequest<'a>,
        query_opts: Option<QueryOptions>,
    ) -> Result<ResponseMeta<Vec<ServiceNode>>, ConsulError>;
}
