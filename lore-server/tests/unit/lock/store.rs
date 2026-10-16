// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::lock::LockQuery;
use lore_revision::lock::LockStore;
use lore_revision::lock::util::assemble_resource_for_path;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_server::lock::store::*;

#[tokio::test]
async fn locking_a_resource_held_by_another_owner_states_the_reason() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let resource = assemble_resource_for_path("Map.umap", BranchId::default());

    store
        .lock_resources("user_A", repository, std::slice::from_ref(&resource))
        .await
        .expect("the first owner acquires the lock");

    let error = store
        .lock_resources("user_B", repository, &[resource])
        .await
        .expect_err("a second owner is refused");

    assert_eq!(error.to_string(), "resource already locked");
}

#[tokio::test]
async fn a_refused_batch_keeps_none_of_the_locks_it_took() {
    let store = LocalLockStore::default();
    let repository = RepositoryId::default();
    let branch = BranchId::default();
    let contended = assemble_resource_for_path("Contended.umap", branch);
    let free = assemble_resource_for_path("Free.umap", branch);

    store
        .lock_resources("user_A", repository, std::slice::from_ref(&contended))
        .await
        .expect("the first owner acquires the contended lock");

    store
        .lock_resources("user_B", repository, &[free, contended])
        .await
        .expect_err("the batch is refused");

    let held = store
        .query_locks(LockQuery::Repository(repository))
        .await
        .expect("the held locks can be queried");

    assert_eq!(held.len(), 1, "the refused batch left a lock behind");
    assert_eq!(held[0].owner, "user_A");
}
