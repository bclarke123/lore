// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_error_set::Location;
use lore_revision::event::LoreTraceLocation;

#[test]
fn builds_from_location_with_context() {
    let location = Location::with_context("src/main.rs", 42, 7, Arc::from("loading config"));

    let trace = LoreTraceLocation::from_location(&location);

    assert_eq!(trace.file.as_str(), "src/main.rs");
    assert_eq!(trace.line, 42);
    assert_eq!(trace.column, 7);
    assert_eq!(trace.context.as_str(), "loading config");
}

#[test]
fn builds_from_location_without_context_yields_empty_context() {
    let location = Location::new("src/lib.rs", 1, 1);

    let trace = LoreTraceLocation::from_location(&location);

    assert_eq!(trace.file.as_str(), "src/lib.rs");
    assert_eq!(trace.line, 1);
    assert_eq!(trace.column, 1);
    assert!(trace.context.is_empty());
    assert_eq!(trace.context.as_str(), "");
}

#[test]
fn clone_is_independent_deep_copy_and_both_drop_cleanly() {
    let location = Location::with_context("src/clone.rs", 3, 9, Arc::from("deep copy"));
    let trace = LoreTraceLocation::from_location(&location);

    let clone = trace.clone();

    // The clone holds its own allocations, not shared pointers.
    assert_ne!(trace.file.string, clone.file.string);
    assert_ne!(trace.context.string, clone.context.string);

    // The clone is value-equal to the original. `LoreTraceLocation` does
    // not derive `Debug`, so compare through `PartialEq` directly.
    assert!(trace == clone);
    assert_eq!(clone.file.as_str(), "src/clone.rs");
    assert_eq!(clone.context.as_str(), "deep copy");

    // Dropping the original must not affect the clone's strings.
    drop(trace);
    assert_eq!(clone.file.as_str(), "src/clone.rs");
    assert_eq!(clone.context.as_str(), "deep copy");

    // Dropping the clone frees its own strings; under leak detection this
    // confirms no double free and no leak.
    drop(clone);
}

#[test]
fn displays_file_line_column_without_context() {
    let trace = LoreTraceLocation::from_location(&Location::new("src/lib.rs", 12, 4));
    assert_eq!(trace.to_string(), "src/lib.rs:12:4");
}

#[test]
fn displays_context_in_place_of_column_when_present() {
    let location = Location::with_context("src/main.rs", 7, 2, Arc::from("loading config"));
    let trace = LoreTraceLocation::from_location(&location);
    assert_eq!(trace.to_string(), "src/main.rs:7 - loading config");
}
