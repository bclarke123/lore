// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_proto::Conflict;
use lore_proto::Path;
use lore_proto::PathDiff;
use lore_proto::PathType;
use lore_revision::change::FileAction;
use lore_revision::change::NodeChange;
use lore_revision::link;
use lore_revision::link::LinkPinChange;
use lore_revision::lore::RepositoryId;
use lore_revision::node::NodeFlags;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use tonic::Status;
use tracing::warn;

use crate::grpc::FilterSlowDownExt;

pub fn node_flags_to_type(flags: NodeFlags) -> i32 {
    if flags.contains(NodeFlags::File) {
        PathType::File as i32
    } else if flags.contains(NodeFlags::Link) {
        PathType::Link as i32
    } else {
        PathType::Directory as i32
    }
}

/// The partition is empty when the change resolves under the request's own
/// repository, so a consumer can default to the request's repository id.
async fn link_partition_and_tracking(
    change: &NodeChange,
    parent_repository_id: RepositoryId,
) -> (Bytes, bool) {
    let target = change.content_repository_id();
    let link_partition = if target == parent_repository_id {
        Bytes::new()
    } else {
        Bytes::from(target)
    };
    (link_partition, change.is_tracking_link().await)
}

pub async fn map_to_path_diff(
    change: &NodeChange,
    parent_repository_id: RepositoryId,
) -> Option<PathDiff> {
    let (link_partition, tracking) =
        link_partition_and_tracking(change, parent_repository_id).await;
    match change.action {
        FileAction::Delete => Some(PathDiff {
            from: Some(Path {
                path: change.path().to_string(),
                address: change.from.address.into(),
                r#type: node_flags_to_type(change.from.flags),
                tracking,
            }),
            to: None,
            automerged: change.flags.is_conflict_automerged(),
            link_partition,
            tracking,
        }),
        FileAction::Add => Some(PathDiff {
            from: None,
            to: Some(Path {
                path: change.path().to_string(),
                address: change.to.address.into(),
                r#type: node_flags_to_type(change.to.flags),
                tracking,
            }),
            automerged: change.flags.is_conflict_automerged(),
            link_partition,
            tracking,
        }),
        FileAction::Keep => Some(PathDiff {
            from: Some(Path {
                path: change.path().to_string(),
                address: change.from.address.into(),
                r#type: node_flags_to_type(change.from.flags),
                tracking,
            }),
            to: Some(Path {
                path: change.path().to_string(),
                address: change.to.address.into(),
                r#type: node_flags_to_type(change.to.flags),
                tracking,
            }),
            automerged: change.flags.is_conflict_automerged(),
            link_partition,
            tracking,
        }),
        _ => {
            // TODO(mjansson): handle MOVE, for which we need to have 2 paths, so the existing NodeChange doesn't work
            // TODO(parroyo): do we want to handle Copy ?
            warn!("unhandled action {:?}", change.action);
            None
        }
    }
}

/// A link's content is the revision it is pinned to, so `address` carries that
/// revision under the linked repository's context.
pub fn link_pin_change_to_path_diff(
    pin_change: &LinkPinChange,
    parent_repository_id: RepositoryId,
) -> PathDiff {
    let side = |revision: Hash, tracking: bool| {
        Some(Path {
            path: pin_change.link_path.clone(),
            address: Address {
                hash: revision,
                context: pin_change.link_repository.into(),
            }
            .into(),
            r#type: PathType::Link as i32,
            tracking,
        })
    };

    PathDiff {
        from: side(pin_change.revision_from, pin_change.tracking_from),
        to: side(pin_change.revision_to, pin_change.tracking_to),
        automerged: false,
        link_partition: if pin_change.link_repository == parent_repository_id {
            Bytes::new()
        } else {
            Bytes::from(pin_change.link_repository)
        },
        tracking: pin_change.tracking_to,
    }
}

/// Entries to prepend to a diff response for every link whose pin moved
/// between the two states.
///
/// A failure here fails the diff. Reporting the content changes alone would
/// claim no pin moved, which is indistinguishable from a pin that genuinely
/// did not move, and the response has no way to say it is incomplete.
pub async fn link_pin_path_diffs(
    repository: &Arc<RepositoryContext>,
    state_from: &Arc<State>,
    state_to: &Arc<State>,
    parent_repository_id: RepositoryId,
) -> Result<Vec<PathDiff>, Status> {
    let pin_changes = link::diff_link_pins(repository.clone(), state_from, state_to)
        .await
        .filter_slow_down()?
        .map_err(|err| {
            warn!(
                {REPOSITORY_ID} = %repository.id, ?err,
                "Failed to compare link pins",
            );
            Status::internal(err.to_string())
        })?;
    Ok(pin_changes
        .iter()
        .map(|pin_change| link_pin_change_to_path_diff(pin_change, parent_repository_id))
        .collect())
}

pub async fn map_to_conflict(
    conflict: &(NodeChange, NodeChange),
    parent_repository_id: RepositoryId,
) -> Option<Conflict> {
    Some(Conflict {
        diff_base: map_to_path_diff(&conflict.0, parent_repository_id).await,
        diff_compare: map_to_path_diff(&conflict.1, parent_repository_id).await,
    })
}
