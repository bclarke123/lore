// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_server::correlation::CorrelationId;

#[test]
fn test_default_correlation_id() {
    let correlation_id = CorrelationId::default();

    uuid::Uuid::try_parse(&correlation_id.0).expect("Inner correlation id should be a valid UUID");
}
