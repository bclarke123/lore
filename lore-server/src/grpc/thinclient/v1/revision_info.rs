// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::thin_client::v1 as thin_client_v1;
use lore_proto::lore::thin_client::v1::RevisionInfoRequest;
use lore_proto::lore::thin_client::v1::RevisionInfoResponse;
use lore_revision::metadata;
use lore_revision::metadata::Metadata;
use lore_revision::metadata::MetadataType;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_telemetry::tracing::fields::METADATA;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use lore_telemetry::tracing::fields::REVISION;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::warn;

use super::helpers::resolve_signature;
use crate::grpc::FilterSlowDownExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::grpc::warn_error_to_status;
use crate::util::setup_execution;

/// `lore.thin_client.v1.ThinClientService.RevisionInfo` handler.
///
/// Resolves a revision by signature or `(branch, number)` identifier
/// (`number == 0` resolves to branch latest), then returns the full
/// `Revision` record — signature, resolved identifier, commit metadata,
/// and (when applicable) self / other parents with their resolved
/// identifiers.
#[tracing::instrument(name = "RevisionInfo::v1::handle", skip_all)]
pub async fn handler(
    request: Request<RevisionInfoRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    history_step_size: u64,
    acceleration: crate::grpc::server::RevisionListAcceleration,
) -> Result<Response<RevisionInfoResponse>, Status> {
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();

    let Some(query) = req.query else {
        return Err(Status::invalid_argument(
            "RevisionInfoRequest.query must be set (identifier or signature)",
        ));
    };

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            let signature =
                resolve_signature(&repository, query.into(), history_step_size, acceleration)
                    .await?;
            // Only the default branch can exist with no revisions; its
            // latest then resolves to the zero hash. That is not an error:
            // answer successfully with no revision to describe, rather than
            // proceeding into state/metadata loads that fail as Internal.
            if signature.is_zero() {
                return Ok(Response::new(RevisionInfoResponse { revision: None }));
            }
            debug!({REVISION} = %signature, "Loading revision info");

            let revision = load_revision(&repository, signature).await?;

            Ok(Response::new(RevisionInfoResponse {
                revision: Some(revision),
            }))
        })
        .await
}

async fn load_revision(
    repository: &Arc<RepositoryContext>,
    signature: Hash,
) -> Result<thin_client_v1::Revision, Status> {
    let state = State::deserialize(repository.clone(), signature)
        .await
        .filter_slow_down()?
        .map_err(|err| {
            if err.is_not_found() {
                Status::not_found(format!("Revision {signature} not found"))
            } else {
                warn!(
                    {REPOSITORY_ID} = %repository.id, {REVISION} = %signature, ?err,
                    "Failed to deserialize revision state",
                );
                warn_error_to_status(&err, |e| Status::internal(e.to_string()))
            }
        })?;

    // Once we have `state`, the current revision's metadata, the
    // `parent_self` lookup, and the `parent_other` lookup are all
    // independent — fan them out in parallel.
    let metadata_hash = state.metadata_hash();
    let metadata_fut = async {
        Metadata::deserialize(repository.clone(), metadata_hash)
            .await
            .filter_slow_down()?
            .map_err(|err| {
                warn!(
                    {REPOSITORY_ID} = %repository.id,
                    {REVISION} = %signature,
                    {METADATA} = %metadata_hash,
                    ?err,
                    "Failed to deserialize revision metadata",
                );
                warn_error_to_status(&err, |e| Status::internal(e.to_string()))
            })
    };
    let parent_self_fut = load_optional_parent(repository, state.parent_self());
    let parent_other_fut = load_optional_parent(repository, state.parent_other());
    let (metadata, parent_self, parent_other) =
        tokio::try_join!(metadata_fut, parent_self_fut, parent_other_fut)?;

    let branch_id = metadata.get_branch().map_err(|err| {
        warn!(
            {REPOSITORY_ID} = %repository.id,
            {REVISION} = %signature,
            {METADATA} = %metadata_hash,
            ?err,
            "Revision metadata missing branch field",
        );
        warn_error_to_status(&err, |e| Status::internal(e.to_string()))
    })?;
    let identifier = model_v1::RevisionIdentifier {
        branch_id: branch_id.into(),
        number: state.revision_number(),
    };

    let mut commit_message = String::default();
    let mut timestamp: u64 = 0;
    let mut created_by = String::default();
    let mut committed_by = String::default();
    let mut metadata_entries: Vec<thin_client_v1::Metadata> = Vec::new();

    metadata.walk(|key, value, value_type| {
        let key = match std::str::from_utf8(key) {
            Ok(k) => k,
            Err(_) => return,
        };
        match key {
            metadata::MESSAGE => {
                commit_message = std::str::from_utf8(value).unwrap_or_default().to_string();
            }
            metadata::TIMESTAMP => {
                if value.len() == std::mem::size_of::<u64>() {
                    timestamp = u64::from_le_bytes(value.try_into().unwrap());
                }
            }
            metadata::CREATED_BY => {
                if let Ok(value) = std::str::from_utf8(value) {
                    created_by = value.to_string();
                }
            }
            metadata::COMMITTED_BY => {
                if let Ok(value) = std::str::from_utf8(value) {
                    committed_by = value.to_string();
                }
            }
            // Branch is surfaced via `identifier.branch_id`; not echoed
            // again as a generic metadata entry.
            metadata::BRANCH => {}
            _ => {
                if let Some(entry) = encode_metadata_entry(key, value, value_type) {
                    metadata_entries.push(entry);
                }
            }
        }
    });

    Ok(thin_client_v1::Revision {
        signature: signature.into(),
        identifier: Some(identifier),
        commit_message,
        timestamp,
        created_by,
        committed_by,
        metadata: metadata_entries,
        parent_self,
        parent_other,
        number: state.revision_number(),
    })
}

/// Encode an internal metadata entry as the v1 thin-client `Metadata`
/// proto. Mirrors the urc `as_lore_proto_metadata` conversion but binds
/// to the v1 `MetadataType` enum.
fn encode_metadata_entry(
    key: &str,
    value: &[u8],
    value_type: MetadataType,
) -> Option<thin_client_v1::Metadata> {
    let metadata_type = match value_type {
        MetadataType::Address => thin_client_v1::MetadataType::Address,
        MetadataType::Boolean => thin_client_v1::MetadataType::Boolean,
        MetadataType::Context => thin_client_v1::MetadataType::Context,
        MetadataType::Hash => thin_client_v1::MetadataType::Hash,
        MetadataType::Numeric => thin_client_v1::MetadataType::Numeric,
        MetadataType::String => thin_client_v1::MetadataType::String,
        MetadataType::Binary => thin_client_v1::MetadataType::Binary,
    };
    let value = match value_type {
        MetadataType::Address => Metadata::to_address(value).ok().map(|v| format!("{v}"))?,
        MetadataType::Boolean => Metadata::to_bool(value).ok().map(|v| format!("{v}"))?,
        MetadataType::Context => Metadata::to_context(value).ok().map(|v| format!("{v}"))?,
        MetadataType::Hash => Metadata::to_hash(value).ok().map(|v| format!("{v}"))?,
        MetadataType::Numeric => Metadata::to_u64(value).ok().map(|v| format!("{v}"))?,
        MetadataType::String => Metadata::to_string(value).ok().map(|v| v.to_string())?,
        MetadataType::Binary => format!("<Binary, {} bytes>", value.len()),
    };
    Some(thin_client_v1::Metadata {
        key: key.to_string(),
        value,
        metadata_type: metadata_type.into(),
    })
}

/// Returns `None` when `signature` is the zero hash (no parent on this
/// side); otherwise loads the parent's state + metadata sequentially
/// (metadata depends on `state.metadata_hash()`).
async fn load_optional_parent(
    repository: &Arc<RepositoryContext>,
    signature: Hash,
) -> Result<Option<thin_client_v1::revision::Parent>, Status> {
    if signature.is_zero() {
        return Ok(None);
    }
    let state = State::deserialize(repository.clone(), signature)
        .await
        .filter_slow_down()?
        .map_err(|err| {
            warn!(
                {REPOSITORY_ID} = %repository.id, {REVISION} = %signature, ?err,
                "Failed to deserialize parent revision state",
            );
            warn_error_to_status(&err, |e| Status::internal(e.to_string()))
        })?;
    let metadata_hash = state.metadata_hash();
    let metadata = Metadata::deserialize(repository.clone(), metadata_hash)
        .await
        .filter_slow_down()?
        .map_err(|err| {
            warn!(
                {REPOSITORY_ID} = %repository.id,
                {REVISION} = %signature,
                {METADATA} = %metadata_hash,
                ?err,
                "Failed to deserialize parent revision metadata",
            );
            warn_error_to_status(&err, |e| Status::internal(e.to_string()))
        })?;
    let branch_id = metadata.get_branch().map_err(|err| {
        warn!(
            {REPOSITORY_ID} = %repository.id,
            {REVISION} = %signature,
            {METADATA} = %metadata_hash,
            ?err,
            "Parent revision metadata missing branch field",
        );
        warn_error_to_status(&err, |e| Status::internal(e.to_string()))
    })?;

    Ok(Some(thin_client_v1::revision::Parent {
        signature: signature.into(),
        identifier: Some(model_v1::RevisionIdentifier {
            branch_id: branch_id.into(),
            number: state.revision_number(),
        }),
    }))
}
