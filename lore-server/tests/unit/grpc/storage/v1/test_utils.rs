// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;

use lore_base::types::Context;
use lore_transport::grpc::CORRELATION_ID_HEADER;
use lore_transport::grpc::PARTITION_ID_KEY;
use tonic::Request;
use tonic::metadata::MetadataValue;

pub(crate) fn make_request_with_metadata<T>(
    inner: T,
    repository: Context,
    correlation_id: &str,
) -> Request<T> {
    let mut request = Request::new(inner);
    request.metadata_mut().insert_bin(
        PARTITION_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    if !correlation_id.is_empty() {
        request.metadata_mut().insert(
            CORRELATION_ID_HEADER,
            MetadataValue::from_str(correlation_id).unwrap(),
        );
    }
    request
}
