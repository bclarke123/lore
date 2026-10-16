// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use async_trait::async_trait;
use lore_hashicorp::consul::ConsulClient;
use rs_consul::ConsulError;
use rs_consul::GetServiceNodesRequest;
use rs_consul::QueryOptions;
use rs_consul::ResponseMeta;
use rs_consul::ServiceNode;

mockall::mock! {

    #[derive(Debug)]
    pub Client { }

    #[async_trait]
    impl ConsulClient for Client {
        async fn get_service_nodes<'a>(
            &self,
            request: GetServiceNodesRequest<'a>,
            query_opts: Option<QueryOptions>,
        ) -> Result<ResponseMeta<Vec<ServiceNode>>, ConsulError>;
    }
}
