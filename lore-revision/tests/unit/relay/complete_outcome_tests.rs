// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Mutex;

use lore_revision::event::LoreCompleteEventData;
use lore_revision::event::LoreErrorDetail;
use lore_revision::event::LoreEvent;
use lore_revision::interface::LoreString;
use lore_revision::relay::EventDispatcher;

// Captures the single `Complete` event a `complete` call emits. The
// callback is the real dispatch boundary, so the assertion reads the
// event a consumer would actually receive.
fn capture_complete(error: LoreErrorDetail) -> LoreCompleteEventData {
    let captured: Arc<Mutex<Option<LoreCompleteEventData>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();
    let callback: lore_revision::interface::LoreEventCallback =
        Some(Box::new(move |event: &LoreEvent| {
            if let LoreEvent::Complete(data) = event {
                *sink.lock().unwrap() = Some(data.clone());
            }
        }));

    let dispatcher = EventDispatcher::new(callback);
    lore_base::runtime::runtime().block_on(dispatcher.complete(error));

    let data = captured.lock().unwrap().take();
    data.expect("complete must emit a Complete event")
}

#[test]
fn default_detail_completes_with_status_zero_and_empty_detail() {
    let data = capture_complete(LoreErrorDetail::default());

    assert_eq!(data.status, 0);
    assert_eq!(data.error.error_code, 0);
    assert!(data.error.message.is_empty());
    assert!(data.error.trace_locations.is_empty());
}

#[test]
fn populated_detail_completes_with_its_code_and_carries_detail() {
    let detail = LoreErrorDetail {
        error_code: 13,
        message: LoreString::from("not found"),
        ..LoreErrorDetail::default()
    };

    let data = capture_complete(detail);

    // `status` is the detail's `error_code`, so the two agree.
    assert_eq!(data.status, 13);
    assert_eq!(data.error.error_code, 13);
    assert_eq!(data.error.message.as_str(), "not found");
}
