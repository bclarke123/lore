// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Barrier;
use std::thread;

use lore::storage::handle::*;
use lore::storage::store::StoreInternal;
use lore::storage::store::in_memory_for_tests;

async fn make_store() -> Arc<StoreInternal> {
    in_memory_for_tests("handle-test").await
}

#[tokio::test]
async fn register_then_lookup_round_trip() {
    let store_handle = register(make_store().await);
    assert_ne!(store_handle.handle_id, 0);
    let found = lookup(store_handle).expect("registered handle must look up");
    // Registry entry + the local clone = at least 2.
    assert!(Arc::strong_count(&found) >= 2);
    unregister(store_handle);
}

#[tokio::test]
async fn stale_id_lookup_returns_none() {
    let store_handle = register(make_store().await);
    unregister(store_handle);
    assert!(lookup(store_handle).is_none());
}

#[test]
fn invalid_handle_lookup_returns_none() {
    assert!(lookup(LoreStore::INVALID).is_none());
    assert!(unregister(LoreStore::INVALID).is_none());
}

#[tokio::test]
async fn two_registrations_produce_distinct_ids() {
    let a = register(make_store().await);
    let b = register(make_store().await);
    assert_ne!(a.handle_id, b.handle_id);
    unregister(a);
    unregister(b);
}

#[tokio::test]
async fn concurrent_registration_yields_unique_ids() {
    const THREADS: usize = 16;
    const PER_THREAD: usize = 128;
    // The store identity is irrelevant — share one Arc across threads to keep memory flat.
    let store = make_store().await;
    let barrier = Arc::new(Barrier::new(THREADS));
    let mut joins = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let b = barrier.clone();
        let store = store.clone();
        joins.push(thread::spawn(move || {
            b.wait();
            let mut ids = Vec::with_capacity(PER_THREAD);
            for _ in 0..PER_THREAD {
                ids.push(register(store.clone()));
            }
            ids
        }));
    }
    let mut all = Vec::with_capacity(THREADS * PER_THREAD);
    for j in joins {
        all.extend(j.join().unwrap());
    }
    let mut ids: Vec<u64> = all.iter().map(|h| h.handle_id).collect();
    ids.sort_unstable();
    let before = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), before, "ids must be unique across threads");
    for h in all {
        unregister(h);
    }
}

#[tokio::test]
async fn unregister_returns_last_strong_ref() {
    let store = make_store().await;
    let store_handle = register(store.clone());
    // Drop the local Arc so only the registry holds a strong ref before unregister.
    drop(store);
    let returned = unregister(store_handle).expect("unregister returns the held Arc");
    assert_eq!(Arc::strong_count(&returned), 1);
}
