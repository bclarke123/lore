// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Context;
use lore_server::grpc::tower::tracing::*;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::metadata::MetadataMap;

#[test]
fn can_extract_repository_id() {
    let repository = random::<Context>();
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );

    let string_from_helper = repository_id_field(&metadata);
    let expected_string = repository.to_string();
    assert_eq!(string_from_helper, expected_string);
}

#[test]
fn handles_no_repository_id() {
    let metadata = MetadataMap::new();

    let string_from_helper = repository_id_field(&metadata);
    assert_eq!(string_from_helper, "<no_repo_id>".to_string());
}
