// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Shared test harness for the dispatch wrappers. The storage and
//! revision-tree dispatch helpers capture the same callback event shape, so
//! the capture enum and sink helpers live here once.

use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore_revision::event::LoreCompleteEventData;
use lore_revision::event::LoreEvent;

/// The full event a callback receives, kept verbatim so a test can read the
/// `Complete` detail (code, message, trace) a real consumer would see.
#[derive(Clone)]
pub(crate) enum CapturedEvent {
    Error,
    Complete(LoreCompleteEventData),
    Other,
}

impl CapturedEvent {
    pub(crate) fn from_event(event: &LoreEvent) -> Self {
        match event {
            LoreEvent::Error(_) => Self::Error,
            LoreEvent::Complete(data) => Self::Complete(data.clone()),
            _ => Self::Other,
        }
    }
}

/// Build a callback that pushes each event into the shared sink.
pub(crate) fn make_callback(sink: Arc<Mutex<Vec<CapturedEvent>>>) -> LoreEventCallback {
    Some(Box::new(move |event: &LoreEvent| {
        sink.lock().unwrap().push(CapturedEvent::from_event(event));
    }))
}

/// Collect just the `Complete` event payloads from a captured sink.
pub(crate) fn completes(events: &[CapturedEvent]) -> Vec<LoreCompleteEventData> {
    events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect()
}

pub(crate) fn has_error_event(events: &[CapturedEvent]) -> bool {
    events.iter().any(|e| matches!(e, CapturedEvent::Error))
}
