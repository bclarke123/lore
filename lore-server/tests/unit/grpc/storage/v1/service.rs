// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_proto::lore::storage::v1::storage_service_server::StorageServiceServer;
use lore_server::grpc::storage_service::LoreStorageService;

/// Compile-time check that `LoreStorageService` fully implements the generated
/// `StorageService` trait — wrapping it in `StorageServiceServer` requires the
/// trait bound to hold. Per-handler behavior is tested in each handler module.
#[allow(dead_code)]
fn assert_implements_trait(
    service: LoreStorageService,
) -> StorageServiceServer<LoreStorageService> {
    StorageServiceServer::new(service)
}
