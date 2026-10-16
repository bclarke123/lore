// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

use lore::interface::LoreEventCallback;
use lore::interface::LoreGlobalArgs;
use lore::revision_tree::handle as tree_handle;
use lore::revision_tree::handle::LoreRevisionTree;
use lore::revision_tree::load::LoreRevisionTreeLoadArgs;
use lore::revision_tree::load::load;
use lore::storage::close::*;
use lore::storage::handle;
use lore::storage::handle::LoreStore;
use lore::storage::store::OpGuard;
use lore::storage::store::in_memory_for_tests;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_revision::event::LoreEvent;

/// Load a revision tree against an already-registered storage handle.
async fn load_revision_tree(store_handle: LoreStore, repository: Partition) -> LoreRevisionTree {
    let loaded: Arc<Mutex<Option<u64>>> = Arc::new(Mutex::new(None));
    let sink = loaded.clone();
    let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
        if let LoreEvent::RevisionTreeLoaded(data) = event {
            *sink.lock().unwrap() = Some(data.handle_id);
        }
    }));
    let status = load(
        LoreGlobalArgs::default(),
        LoreRevisionTreeLoadArgs {
            store: store_handle,
            repository,
            revision_hash: Hash::default(),
        },
        callback,
    )
    .await;
    assert_eq!(status, 0, "loading the revision tree fixture must succeed");
    let handle_id = loaded
        .lock()
        .unwrap()
        .expect("load must emit RevisionTreeLoaded");
    LoreRevisionTree { handle_id }
}

/// Close must block until the in-flight counter drains. An `OpGuard` held by the test keeps
/// the counter > 0; close's `mark_invalid_and_await` must not complete until the guard
/// drops.
#[allow(clippy::disallowed_methods)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_waits_for_in_flight_counter_to_drain() {
    let store = in_memory_for_tests("close-wait-test").await;
    let store_handle = handle::register(store.clone());
    let guard = OpGuard::enter(store_handle).expect("enter must succeed");

    let close_task = tokio::spawn(async move {
        close(
            LoreGlobalArgs::default(),
            LoreStorageCloseArgs {
                handle: store_handle,
            },
            None,
        )
        .await
    });

    let deadline = Instant::now() + Duration::from_secs(1);
    while handle::lookup(store_handle).is_some() {
        if Instant::now() > deadline {
            panic!("close never unregistered the handle");
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // The guard pins the in-flight counter at 1, so close must still be parked inside
    // `mark_invalid_and_await`.
    assert!(
        !close_task.is_finished(),
        "close must block while the in-flight counter is non-zero",
    );

    drop(guard);

    let status = close_task.await.expect("close task join");
    assert_eq!(
        status, 0,
        "close should report success after the counter drains"
    );
}

/// The store outlives its storage handle for exactly as long as a revision tree still
/// references it. That reference is what makes reads work after a parent close, so it
/// has to be the last one dropped, not merely present.
#[tokio::test]
async fn the_store_tears_down_only_once_the_last_revision_handle_closes() {
    let store = in_memory_for_tests("close-refcount").await;
    let alive = Arc::downgrade(&store);
    let store_handle = handle::register(store);
    let tree = load_revision_tree(store_handle, Partition::from([0x1Au8; 16])).await;

    let status = close(
        LoreGlobalArgs::default(),
        LoreStorageCloseArgs {
            handle: store_handle,
        },
        None,
    )
    .await;
    assert_eq!(status, 0, "closing the storage handle must succeed");
    assert!(
        alive.upgrade().is_some(),
        "the revision tree's reference must hold the store up",
    );

    let internal = tree_handle::unregister(tree).expect("the tree must still be registered");
    drop(internal);
    assert!(
        alive.upgrade().is_none(),
        "and dropping it must be what finally tears the store down",
    );
}
