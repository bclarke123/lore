// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::thin_client::v1 as thin_client_v1;
use lore_proto::lore::thin_client::v1::RevisionTreeRequest;
use lore_proto::lore::thin_client::v1::RevisionTreeResponse;
use lore_proto::lore::thin_client::v1::revision_tree_response::Payload;
use lore_revision::repository::RepositoryContext;
use lore_revision::revision::tree;
use lore_revision::util::path::RelativePath;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use lore_telemetry::tracing::fields::REVISION;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::Instrument;
use tracing::debug;
use tracing::warn;

use super::helpers::node_flags_to_node_type;
use super::helpers::resolve_to_identifier;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::link_read_authorizer;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

#[lore_macro::test_pub]
type RevisionTreeStream =
    Pin<Box<dyn Stream<Item = Result<RevisionTreeResponse, Status>> + Send + 'static>>;

/// `lore.thin_client.v1.ThinClientService.RevisionTree` handler.
///
/// Server-streams a `RevisionTreeHeader` first (echoing the resolved
/// revision identifier + signature), then one `TreeNode` per entry at
/// or under the optional `path_prefix`, bounded by `max_depth` when
/// set. The header is always emitted before the first node — failures
/// during resolution surface as a non-OK `Status` from the unary part
/// of the call, before the stream begins.
#[tracing::instrument(name = "RevisionTree::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RevisionTreeRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    repository_authorizer: Arc<dyn RepositoryAuthorizer>,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
) -> Result<Response<RevisionTreeStream>, Status> {
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let can_read = link_read_authorizer(&repository_authorizer, request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();

    let Some(query) = req.query else {
        return Err(Status::invalid_argument(
            "RevisionTreeRequest.query must be set (identifier or signature)",
        ));
    };

    let path = match req.path_prefix.as_deref() {
        Some(s) if !s.is_empty() => RelativePath::new_from_initial_path(s)
            .map_err(|err| Status::invalid_argument(format!("invalid path_prefix: {err}")))?,
        _ => RelativePath::new(),
    };
    let max_depth = req.max_depth.map_or(usize::MAX, |d| d as usize);

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            // Resolve up-front so the unary part of the call can surface
            // NotFound / Internal before the stream opens.
            let (signature, identifier) =
                resolve_to_identifier(&repository, query.into(), history_step_size, acceleration)
                    .await?;

            if signature.is_zero() {
                return Err(Status::invalid_argument(
                    "Cannot get the tree of a zeroed revision",
                ));
            }

            let (tx, rx) = mpsc::channel(64);
            let header = thin_client_v1::RevisionTreeHeader {
                identifier: Some(identifier),
                signature: signature.into(),
            };

            lore_spawn!(
                async move {
                    stream_tree(repository, signature, path, max_depth, can_read, header, tx).await;
                }
                .in_current_span()
            );

            let stream: RevisionTreeStream = Box::pin(ReceiverStream::from(rx));
            Ok(Response::new(stream))
        })
        .await
}

#[allow(clippy::too_many_arguments)]
async fn stream_tree(
    repository: Arc<RepositoryContext>,
    signature: Hash,
    path: RelativePath,
    max_depth: usize,
    can_read: lore_revision::state::CanReadRepository,
    header: thin_client_v1::RevisionTreeHeader,
    tx: mpsc::Sender<Result<RevisionTreeResponse, Status>>,
) {
    // Emit header first. If the client has already dropped, just bail.
    if tx
        .send(Ok(RevisionTreeResponse {
            payload: Some(Payload::Header(header)),
        }))
        .await
        .is_err()
    {
        debug!("RevisionTree receiver dropped before header");
        return;
    }

    let result = match tree(repository.clone(), signature, path, max_depth, can_read).await {
        Ok(result) => result,
        Err(err) => {
            let status = if err.is_slow_down() {
                Status::resource_exhausted(err.to_string())
            } else if err.is_invalid_path() {
                Status::invalid_argument("Cannot calculate tree for path that is not a directory")
            } else if err.is_node_not_found() {
                Status::not_found("A node in the tree could not be found")
            } else {
                warn!(
                    {REPOSITORY_ID} = %repository.id, {REVISION} = %signature, ?err,
                    "Failed to walk revision tree",
                );
                warn_error_to_status(&err, |e| Status::internal(e.to_string()))
            };
            let _ = tx.send(Err(status)).await;
            return;
        }
    };

    let mut emitted: u64 = 0;
    for tree_path in result.paths {
        let node = thin_client_v1::TreeNode {
            path: tree_path.path.to_string(),
            node_type: node_flags_to_node_type(tree_path.flags) as i32,
            address: tree_path.address.map(model_v1::Address::from),
            size: tree_path.size,
            mode: tree_path.mode,
            tracking: tree_path.tracking,
        };
        if tx
            .send(Ok(RevisionTreeResponse {
                payload: Some(Payload::Node(node)),
            }))
            .await
            .is_err()
        {
            debug!(emitted, "RevisionTree receiver dropped mid-stream");
            return;
        }
        emitted += 1;
    }

    debug!(emitted, "RevisionTree complete");
}
