// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore_base::error::RepositoryNotFound;
use lore_revision::event::EventError;
use lore_revision::repository::RepositoryError;

pub(crate) mod test_support;

use std::sync::Mutex;

use lore::call::*;
use lore_base::error::NotFound;
use lore_error_set::Location;
use lore_error_set::prelude::*;
use lore_revision::event::LoreEvent;
use lore_revision::interface::LoreGlobalArgs;

// A concrete `#[error_set]` error for the wrapper closures. Its `NotFound`
// variant wraps `lore_base::error::NotFound`, which carries error code 79, so
// the failure path has a known non-internal code to assert against.
#[error_set]
enum SampleError {
    NotFound,
}

impl EventError for SampleError {}

// The full event a callback receives, kept verbatim so a test can read the
// `Complete` detail (code, message, trace) a real consumer would see.
#[derive(Clone)]
enum CapturedEvent {
    Error,
    Complete(lore_revision::event::LoreCompleteEventData),
    Other,
}

impl CapturedEvent {
    fn from_event(event: &LoreEvent) -> Self {
        match event {
            LoreEvent::Error(_) => Self::Error,
            LoreEvent::Complete(data) => Self::Complete(data.clone()),
            _ => Self::Other,
        }
    }
}

fn make_callback(sink: Arc<Mutex<Vec<CapturedEvent>>>) -> LoreEventCallback {
    Some(Box::new(move |event: &LoreEvent| {
        sink.lock().unwrap().push(CapturedEvent::from_event(event));
    }))
}

#[tokio::test]
async fn failing_op_completes_with_error_code_and_no_error_event() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "failing_op",
        |()| async move { Err::<(), SampleError>(NotFound.into()) },
    )
    .await;

    let events = sink.lock().unwrap().clone();

    assert!(
        !events.iter().any(|e| matches!(e, CapturedEvent::Error)),
        "no Error event must be emitted on terminal failure"
    );

    // Exactly one `Complete` event.
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    // The status holds the error code (79 for `NotFound`) and the detail is
    // populated with that code and the error's message.
    let data = &completes[0];
    let expected_code = SampleError::from(NotFound).ffi_code();
    // The synchronous return equals the error code, matching `Complete.status`.
    assert_eq!(status, expected_code);
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert_eq!(
        data.error.message.as_str(),
        SampleError::from(NotFound).to_string()
    );
}

#[tokio::test]
async fn succeeding_op_completes_with_status_zero_and_empty_detail() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "succeeding_op",
        |()| async move { Ok::<(), SampleError>(()) },
    )
    .await;

    assert_eq!(status, 0);

    let events = sink.lock().unwrap().clone();
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let data = &completes[0];
    assert_eq!(data.status, 0);
    assert_eq!(data.error.error_code, 0);
    assert!(data.error.message.is_empty());
    assert!(data.error.trace_locations.is_empty());
}

#[tokio::test]
async fn missing_repository_completes_with_real_ffi_code() {
    // A path with no repository fails in `prepare_repository_call` before
    // any command runs. The failure must report the real
    // repository-not-found error code (45), not the old flat `1`.
    let temp = std::env::temp_dir().join(format!(
        "lore-missing-repo-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let globals = LoreGlobalArgs {
        repository_path: temp.display().to_string().into(),
        ..LoreGlobalArgs::default()
    };

    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let status = repository_call_read(
        globals,
        make_callback(sink.clone()),
        (),
        "missing_repo",
        |_repo, ()| async move { Ok::<(), SampleError>(()) },
    )
    .await;

    let events = sink.lock().unwrap().clone();
    let completes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(completes.len(), 1, "exactly one Complete event");

    let expected_code = RepositoryError::from(RepositoryNotFound {
        repository: temp.display().to_string(),
    })
    .ffi_code();
    assert_ne!(expected_code, 1, "must report a real code, not the flat 1");
    assert_ne!(expected_code, 0);

    let data = &completes[0];
    // status, the synchronous return, and the detail all carry the real code.
    assert_eq!(status, expected_code);
    assert_eq!(data.status, expected_code);
    assert_eq!(data.error.error_code, expected_code);
    assert!(
        !data.error.message.is_empty(),
        "the detail must carry the error message"
    );
}

#[tokio::test]
async fn failing_op_lets_consumer_read_trace_locations() {
    let sink: Arc<Mutex<Vec<CapturedEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let _status = no_repository_call(
        LoreGlobalArgs::default(),
        make_callback(sink.clone()),
        (),
        "trace_op",
        |()| async move {
            // Add a known trace entry so the consumer can read it back from
            // the `Complete` detail.
            let mut err: SampleError = NotFound.into();
            err.push_trace(Location::with_context(
                "src/trace_op.rs",
                7,
                3,
                std::sync::Arc::from("running trace op"),
            ));
            Err::<(), SampleError>(err)
        },
    )
    .await;

    let events = sink.lock().unwrap().clone();
    let data = events
        .iter()
        .find_map(|e| match e {
            CapturedEvent::Complete(data) => Some(data.clone()),
            _ => None,
        })
        .expect("a Complete event must be emitted");

    // The pushed location is reconstructable from the trace; with
    // `track-locations` on, the `From` conversion prepends its own caller
    // location, so the entry we pushed is the last one.
    let locations = data.error.trace_locations.as_slice();
    assert!(
        !locations.is_empty(),
        "trace must carry at least one location"
    );
    let last = locations.last().unwrap();
    assert_eq!(last.file.as_str(), "src/trace_op.rs");
    assert_eq!(last.line, 7);
    assert_eq!(last.column, 3);
    assert_eq!(last.context.as_str(), "running trace op");
}
