// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_proto::lore::revision::v1::BranchGetRequest;
use lore_proto::lore::revision::v1::BranchGetResponse;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::grpc::forwarded_requests::CallerContext;
use crate::grpc::revision::v1::branch_get::branch_get_implementation;

/// Handler that takes a `BranchGet` request forwarded on from peer's `RevisionService`
/// and executes it, returning the result to the other server for forwarding on to its
/// client
#[tracing::instrument(name = "ForwardedRevision::v1::BranchGet::Handler", skip_all)]
pub async fn handler(
    request: Request<BranchGetRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<BranchGetResponse>, Status> {
    let caller_context = CallerContext::from_forwarded_request(&request)?;

    branch_get_implementation(
        request.into_inner(),
        caller_context,
        immutable_store,
        mutable_store,
    )
    .await
}
