// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::error::NotFound;
use lore_error_set::FfiError;
use lore_error_set::Location;
use lore_error_set::Trace;
use lore_error_set::prelude::*;
use lore_revision::event::LoreErrorDetail;

// A concrete `#[error_set]` error used to exercise the constructor. Its
// `NotFound` variant wraps `lore_base::error::NotFound`, which carries FFI
// code 79, so the detail's `error_code` has a known, non-internal value to
// assert against.
#[error_set]
enum SampleError {
    NotFound,
}

#[test]
fn from_error_holds_code_message_and_one_location_per_trace_entry() {
    // Build a concrete error and give it a trace with two entries.
    let mut error: SampleError = NotFound.into();
    error.push_trace(Location::new("src/first.rs", 10, 2));
    error.push_trace(Location::new("src/second.rs", 20, 4));

    let detail = LoreErrorDetail::from_error(&error);

    // The code is the error's error code.
    assert_eq!(detail.error_code, error.ffi_code());
    // The message is the error's `Display` output.
    assert_eq!(detail.message.as_str(), error.to_string());

    // One trace location per trace entry. The `From` conversion adds its
    // own caller location ahead of the two we pushed, so the count and
    // the contents must match the trace exactly.
    let locations = error.trace().locations();
    assert_eq!(detail.trace_locations.len(), locations.len());
    for (built, source) in detail.trace_locations.as_slice().iter().zip(locations) {
        assert_eq!(built.file.as_str(), source.file);
        assert_eq!(built.line, source.line);
        assert_eq!(built.column, source.column);
    }
}

#[test]
fn default_is_the_empty_success_detail() {
    let detail = LoreErrorDetail::default();

    assert_eq!(detail.error_code, 0);
    assert!(detail.message.is_empty());
    assert!(detail.trace_locations.is_empty());
}

#[test]
fn error_set_enum_exposes_trace_through_has_trace_bound() {
    use lore_error_set::HasTrace;

    // A generic function can only read the trace through the bound, not the
    // inherent method, so this exercises the trait `#[error_set]` generates.
    fn locations_through_bound<E: HasTrace>(error: &E) -> usize {
        error.trace().locations().len()
    }

    let mut error: SampleError = NotFound.into();
    error.push_trace(Location::new("src/bound.rs", 5, 1));

    // The trait access matches the inherent access on the same error.
    assert_eq!(
        locations_through_bound(&error),
        error.trace().locations().len()
    );
}

#[test]
fn empty_trace_yields_empty_location_array() {
    // An empty trace is the observable behavior when `track-locations` is
    // off: `Trace::locations()` reports no entries, so the array is empty
    // and the path stays safe. With the feature on, an error built with an
    // empty trace exercises the same empty-array path.
    let error: SampleError = NotFound.into();
    let empty_trace = Trace::new();

    let detail = LoreErrorDetail::from_error_with_trace(&error, &empty_trace);

    assert!(detail.trace_locations.is_empty());
    assert_eq!(detail.error_code, error.ffi_code());
}

#[test]
fn message_with_trace_appends_one_indented_line_per_location() {
    use lore_revision::event::LoreTraceLocation;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreString;

    let detail = LoreErrorDetail {
        error_code: 13,
        message: LoreString::from("not found"),
        trace_locations: LoreArray::from_vec(vec![
            LoreTraceLocation {
                file: LoreString::from("src/a.rs"),
                line: 10,
                column: 2,
                context: LoreString::default(),
            },
            LoreTraceLocation {
                file: LoreString::from("src/b.rs"),
                line: 20,
                column: 4,
                context: LoreString::from("loading"),
            },
        ]),
    };

    assert_eq!(
        detail.message_with_trace(),
        "not found\n  at src/a.rs:10:2\n  at src/b.rs:20 - loading"
    );
}

#[test]
fn message_with_trace_is_just_the_message_when_no_trace() {
    use lore_revision::interface::LoreString;

    let detail = LoreErrorDetail {
        error_code: 13,
        message: LoreString::from("boom"),
        trace_locations: Default::default(),
    };

    assert_eq!(detail.message_with_trace(), "boom");
}
