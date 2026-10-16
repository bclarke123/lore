// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::revision_tree::handle::synth_repository_context;
use lore::storage::store::in_memory_for_tests;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_revision::repository::RemoteStatus;
use lore_revision::state::State;

#[tokio::test]
async fn synth_repository_context_round_trips_empty_state_via_zero_hash_deserialize() {
    let store = in_memory_for_tests("synth-context-test").await;
    let partition = Partition::from([0x77u8; 16]);

    let repo_context = synth_repository_context(&store, partition).await;

    State::deserialize(repo_context.clone(), Hash::default())
        .await
        .expect("zero hash must deserialize to an empty state");

    assert!(
        repo_context.paths.is_none(),
        "synthesized context must have no working-tree path"
    );
    assert_eq!(
        repo_context.id, partition,
        "synthesized context must carry the supplied partition"
    );
    assert!(
        matches!(repo_context.remote_status().await, RemoteStatus::Offline),
        "in-memory store has no remote, so the context must be Offline"
    );
}
