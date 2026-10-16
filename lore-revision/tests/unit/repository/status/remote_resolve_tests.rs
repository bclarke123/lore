// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::error::Disconnected;
use lore_revision::lore::BranchId;
use lore_revision::repository::RemoteState;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::create_client_memory_stores;
use lore_revision::repository::status::*;
use lore_transport::ProtocolError;

fn disconnected() -> ProtocolError {
    ProtocolError::from(Disconnected)
}

async fn context_with_state(state: RemoteState) -> Arc<RepositoryContext> {
    let (immutable, mutable) = create_client_memory_stores()
        .await
        .expect("in-memory stores should be creatable");
    Arc::new(RepositoryContext::new_with_state(
        None,
        immutable,
        mutable,
        lore_revision::lore::RepositoryId::default(),
        lore_revision::instance::InstanceId::default(),
        state,
        Arc::default(),
        None,
    ))
}

#[tokio::test]
async fn offline_remote_resolves_to_unavailable() {
    let ctx = context_with_state(RemoteState::Offline).await;

    let result = resolve_remote_latest(&ctx, BranchId::default()).await;

    assert_eq!(
        result,
        (None, false, false),
        "offline should degrade to unavailable"
    );
}

#[tokio::test]
async fn failed_remote_resolves_to_unavailable() {
    let ctx = context_with_state(RemoteState::Failed(disconnected())).await;

    let result = resolve_remote_latest(&ctx, BranchId::default()).await;

    assert_eq!(
        result,
        (None, false, false),
        "failed remote should degrade to unavailable"
    );
}
