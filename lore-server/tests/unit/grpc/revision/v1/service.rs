// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::revision::v1::revision_service_server::RevisionServiceServer;
use lore_server::grpc::revision::v1::service::*;

/// Compile-time check that `LoreRevisionV1Service` fully implements
/// the generated `RevisionService` trait — wrapping it in
/// `RevisionServiceServer` requires the trait bound to hold.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreRevisionV1Service,
) -> RevisionServiceServer<LoreRevisionV1Service> {
    RevisionServiceServer::new(service)
}
