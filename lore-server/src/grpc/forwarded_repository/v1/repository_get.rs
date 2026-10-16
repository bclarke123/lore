// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_proto::lore::repository::v1::RepositoryGetRequest;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;

use crate::auth::jwt::JwtVerifier;
use crate::authnz::repository_authorizer::RawToken;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::grpc::forwarded_requests::CallerContext;
use crate::grpc::repository::v1::repository_get::repository_get_implementation;

/// Handler that takes a `RepositoryGet` request forwarded on from peer's `RepositoryService`
/// and executes it, returning the result to the other server for forwarding on to its
/// client.
///
/// The internal endpoint runs no JWT interceptor, so this handler verifies the
/// forwarded end-user token itself and inserts the same extensions the public
/// interceptor would, letting the injected [`RepositoryAuthorizer`] answer the
/// access check. A token that is absent or fails verification does not get
/// inserted, and the authorizer then denies the checks. The caller sees
/// `RepositoryNotFound`.
#[tracing::instrument(name = "ForwardedRepository::v1::RepositoryGet::Handler", skip_all)]
pub async fn handler(
    request: Request<RepositoryGetRequest>,
    jwt_verifier: Option<JwtVerifier>,
    authorizer: Arc<dyn RepositoryAuthorizer>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryGetResponse>, Status> {
    let caller_context = CallerContext::from_forwarded_request(&request)?;
    let (_, mut extensions, req) = request.into_parts();

    if let Some(verifier) = &jwt_verifier
        && let Some(raw) = caller_context
            .authorization
            .as_deref()
            .and_then(|header| header.strip_prefix("Bearer "))
    {
        match verifier.verify_token(raw).await {
            Ok(claims) => {
                extensions.insert(RawToken(raw.to_string()));
                extensions.insert(claims);
            }
            Err(err) => {
                debug!(error = ?err, "Forwarded token failed verification");
            }
        }
    }

    repository_get_implementation(
        req,
        caller_context,
        authorizer,
        extensions,
        immutable_store,
        mutable_store,
    )
    .await
}
