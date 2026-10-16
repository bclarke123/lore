// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::repository::v1::repository_service_server::RepositoryServiceServer;
use lore_server::grpc::repository::v1::service::*;

/// Compile-time check that `LoreRepositoryV1Service` fully implements
/// the generated `RepositoryService` trait — wrapping it in
/// `RepositoryServiceServer` requires the trait bound to hold.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreRepositoryV1Service,
) -> RepositoryServiceServer<LoreRepositoryV1Service> {
    RepositoryServiceServer::new(service)
}
