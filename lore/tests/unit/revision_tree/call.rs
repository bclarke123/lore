// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use lore::revision_tree::call::*;
use lore::revision_tree::handle;
use lore::revision_tree::handle::LoreRevisionTree;
use lore_base::error::InvalidArguments;
use lore_error_set::prelude::*;
use lore_revision::interface::LoreGlobalArgs;

use crate::call::test_support::CapturedEvent;
use crate::call::test_support::completes;
use crate::call::test_support::has_error_event;
use crate::call::test_support::make_callback;
use crate::revision_tree::handle::test_support;

#[tokio::test]
async fn handle_miss_completes_with_error_code_and_no_error_event() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let missed = Arc::new(AtomicBool::new(false));
    let missed_setter = missed.clone();
    let status = revision_tree_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        LoreRevisionTree::INVALID,
        (),
        "handle_miss_test",
        move |_args: &()| missed_setter.store(true, Ordering::SeqCst),
        |_internal, _args: ()| async move { Ok::<_, DispatchError>(()) },
    )
    .await;
    assert!(
        missed.load(Ordering::SeqCst),
        "on_handle_miss must fire when the handle is unknown"
    );
    let events = sink.lock().unwrap().clone();
    assert!(
        !has_error_event(&events),
        "no Error event must be emitted on terminal failure"
    );

    let completes = completes(&events);
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let expected = DispatchError::from(InvalidArguments {
        reason: "revision tree handle is unknown or has been closed".into(),
    });
    let expected_code = expected.ffi_code();
    assert_eq!(status, expected_code);
    let data = &completes[0];
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert_eq!(data.error.message.as_str(), expected.to_string());
}

#[tokio::test]
async fn happy_path_completes_with_status_zero_and_decrements_counter() {
    let internal = test_support::new_for_testing().await;
    let handle_value = handle::register(internal.clone());
    assert_eq!(internal.in_flight.load(Ordering::Acquire), 0);

    let invoked = Arc::new(AtomicU64::new(0));
    let invoked_clone = invoked.clone();

    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let missed = Arc::new(AtomicBool::new(false));
    let missed_setter = missed.clone();
    let status = revision_tree_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        handle_value,
        (),
        "happy_path_test",
        move |_args: &()| missed_setter.store(true, Ordering::SeqCst),
        move |internal_arc, _args: ()| async move {
            invoked_clone.fetch_add(1, Ordering::AcqRel);
            assert!(internal_arc.in_flight.load(Ordering::Acquire) >= 1);
            Ok::<_, DispatchError>(())
        },
    )
    .await;

    assert_eq!(status, 0);
    assert!(
        !missed.load(Ordering::SeqCst),
        "on_handle_miss must not fire on the happy path"
    );
    assert_eq!(invoked.load(Ordering::Acquire), 1);
    assert_eq!(
        internal.in_flight.load(Ordering::Acquire),
        0,
        "counter must return to zero after the verb"
    );
    let events = sink.lock().unwrap().clone();
    let completes = completes(&events);
    assert_eq!(completes.len(), 1, "exactly one Complete event");
    let data = &completes[0];
    assert_eq!(data.status, 0);
    assert_eq!(data.error.error_code, 0);
    assert!(data.error.message.is_empty());
    assert!(data.error.trace_locations.is_empty());
    handle::unregister(handle_value);
}

#[tokio::test]
async fn verb_error_completes_with_error_code_and_no_error_event() {
    let internal = test_support::new_for_testing().await;
    let handle_value = handle::register(internal.clone());
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let missed = Arc::new(AtomicBool::new(false));
    let missed_setter = missed.clone();
    let status = revision_tree_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        handle_value,
        (),
        "verb_error_test",
        move |_args: &()| missed_setter.store(true, Ordering::SeqCst),
        move |_internal, _args: ()| async move {
            Err::<(), _>(DispatchError::from(InvalidArguments {
                reason: "simulated verb error".into(),
            }))
        },
    )
    .await;
    assert!(
        !missed.load(Ordering::SeqCst),
        "on_handle_miss must not fire when the handle resolves"
    );
    assert_eq!(
        internal.in_flight.load(Ordering::Acquire),
        0,
        "counter must return to zero even on error"
    );

    let events = sink.lock().unwrap().clone();
    assert!(
        !has_error_event(&events),
        "no Error event must be emitted on terminal failure"
    );

    let completes = completes(&events);
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let expected = DispatchError::from(InvalidArguments {
        reason: "simulated verb error".into(),
    });
    let expected_code = expected.ffi_code();
    assert_eq!(status, expected_code);
    let data = &completes[0];
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert_eq!(data.error.message.as_str(), expected.to_string());
    handle::unregister(handle_value);
}
