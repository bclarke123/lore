// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use tonic::Request;
use tonic::Status;

use crate::grpc::ServerResultExt;

// TODO: if no authorization string is passed, do not add a metadata for 'authorization'.
// See test can_create_request_without_authorization
fn grpc_set_authorization_metadata<F>(
    request: &mut Request<F>,
    authorization: Option<String>,
) -> Result<(), Status> {
    let auth_header: tonic::metadata::MetadataValue<_> = authorization
        .unwrap_or_default()
        .parse()
        .warn_map_err(|err| Status::internal(format!("Failed to create metadata: {err}")))?;
    request.metadata_mut().append("authorization", auth_header);
    Ok(())
}

pub fn create_request_with_authorization<T>(
    payload: T,
    authorization: Option<String>,
) -> Result<Request<T>, Status> {
    let mut request = tonic::Request::new(payload);
    grpc_set_authorization_metadata(&mut request, authorization)?;
    Ok(request)
}
