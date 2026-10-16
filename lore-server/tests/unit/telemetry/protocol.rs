// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::telemetry::protocol::*;

#[test]
fn wire_strings() {
    assert_eq!(StorageProtocol::StorageV0.as_str(), "storage.v0");
    assert_eq!(StorageProtocol::StorageV1.as_str(), "storage.v1");
    assert_eq!(StorageProtocol::StorageV4.as_str(), "storage.v4");
    assert_eq!(StorageProtocol::Replication.as_str(), "replication");
    assert_eq!(Transport::Grpc.as_str(), "grpc");
    assert_eq!(Transport::Quic.as_str(), "quic");
}

#[test]
fn display_matches_as_str() {
    assert_eq!(format!("{}", StorageProtocol::StorageV0), "storage.v0");
    assert_eq!(format!("{}", StorageProtocol::Replication), "replication");
    assert_eq!(format!("{}", Transport::Grpc), "grpc");
    assert_eq!(format!("{}", Transport::Quic), "quic");
}
