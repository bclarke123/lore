// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_storage::error::StorageError;
use lore_storage::write_tracker::*;

fn ok_result() -> Result<(), StorageError> {
    Ok(())
}

/// The size of the task [`WriteTracker::spawn`] makes of `future`.
fn task_size<F>(_future: &F) -> usize {
    size_of::<TrackedTask<F>>()
}

#[test]
fn a_task_holds_its_future_once() {
    let data = [0u8; 1024];
    let future = async move {
        tokio::task::yield_now().await;
        std::hint::black_box(data);
        ok_result()
    };
    assert!(task_size(&future) < 2 * size_of_val(&future));
}

#[test]
fn a_task_dropped_before_it_runs_is_no_longer_in_flight() {
    let tracker = WriteTracker::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    {
        let _entered = runtime.enter();
        tracker.spawn_leader(async { ok_result() });
    }
    drop(runtime);
    assert_eq!(tracker.state.in_flight.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn await_all_empty_returns_ok() {
    let tracker = Arc::new(WriteTracker::new());
    assert!(tracker.await_all().await.is_ok());
}

#[tokio::test]
async fn await_all_leader_and_follower_success() {
    let tracker = Arc::new(WriteTracker::new());
    tracker.spawn_leader(async { ok_result() });
    tracker.register_follower(async { ok_result() });
    assert!(tracker.await_all().await.is_ok());
}

#[tokio::test]
async fn await_all_drains_all_leaders_even_when_one_fails() {
    let tracker = Arc::new(WriteTracker::new());
    let slow_done = Arc::new(AtomicUsize::new(0));

    tracker.spawn_leader(async { Err::<(), _>(StorageError::internal("boom")) });
    for _ in 0..3 {
        let slow_done = Arc::clone(&slow_done);
        tracker.spawn_leader(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            slow_done.fetch_add(1, Ordering::SeqCst);
            ok_result()
        });
    }

    let result = tracker.await_all().await;
    assert!(result.is_err(), "failing leader should surface as error");
    assert_eq!(
        slow_done.load(Ordering::SeqCst),
        3,
        "all slow leaders must run to completion even after a sibling fails"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn in_flight_counter_returns_to_zero() {
    let tracker = Arc::new(WriteTracker::new());
    for _ in 0..1000 {
        tracker.spawn_leader(async { ok_result() });
    }
    assert!(tracker.await_all().await.is_ok());
}

#[tokio::test]
async fn await_all_returns_first_error_drops_later() {
    let tracker = Arc::new(WriteTracker::new());
    tracker.spawn_leader(async {
        tokio::time::sleep(Duration::from_millis(5)).await;
        Err::<(), _>(StorageError::internal("first"))
    });
    tracker.spawn_leader(async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        Err::<(), _>(StorageError::internal("second"))
    });
    let err = tracker
        .await_all()
        .await
        .expect_err("at least one leader failed");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("first"),
        "expected first error preserved, got: {msg}"
    );
    assert!(
        !msg.contains("second"),
        "expected later errors dropped, got: {msg}"
    );
}

#[tokio::test]
async fn arc_into_inner_uniqueness_check() {
    let tracker = Arc::new(WriteTracker::new());
    let stray = Arc::clone(&tracker);
    let err = tracker
        .await_all()
        .await
        .expect_err("second live Arc must make await_all fail");
    let msg = format!("{err:?}");
    assert!(msg.contains("Arc handle is live"));
    drop(stray);
}
