// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::thin_client::v1::thin_client_service_server::ThinClientServiceServer;
use lore_server::grpc::thinclient::v1::service::*;

/// Compile-time check that `LoreThinClientV1Service` fully implements
/// the generated `ThinClientService` trait — wrapping it in
/// `ThinClientServiceServer` requires the trait bound to hold.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreThinClientV1Service,
) -> ThinClientServiceServer<LoreThinClientV1Service> {
    ThinClientServiceServer::new(service)
}
