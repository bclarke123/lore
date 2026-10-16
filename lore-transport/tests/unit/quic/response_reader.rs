// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_transport::quic::QuicClientError;
use lore_transport::quic::QuicServiceError;
use lore_transport::quic::response_reader::*;

#[test]
fn maps_known_service_errors_to_typed_variants() {
    assert!(matches!(
        handle_error(QuicServiceError::NotAuthorized as u32),
        QuicClientError::NotAuthorized
    ));
    assert!(matches!(
        handle_error(QuicServiceError::SlowDown as u32),
        QuicClientError::SlowDown
    ));
    assert!(matches!(
        handle_error(QuicServiceError::NotFound as u32),
        QuicClientError::NotFound
    ));
    assert!(matches!(
        handle_error(QuicServiceError::Oversized as u32),
        QuicClientError::Oversized
    ));
}

#[test]
fn unknown_status_falls_back_to_server_error() {
    assert!(matches!(handle_error(42), QuicClientError::ServerError(42)));
}
