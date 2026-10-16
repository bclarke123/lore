// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

use lore_error_set::location::Location;
use lore_error_set::traced::*;

// -- Trace tests (feature-gated behavior) --------------------------------

#[test]
fn trace_push_and_locations() {
    let mut trace = Trace::new();
    trace.push(Location::new("test.rs", 1, 1));

    #[cfg(feature = "track-locations")]
    {
        assert_eq!(trace.len(), 1);
        assert!(!trace.is_empty());
        assert!(!trace.has_overflow());
        assert_eq!(trace.locations()[0], Location::new("test.rs", 1, 1));
    }

    #[cfg(not(feature = "track-locations"))]
    {
        assert_eq!(trace.len(), 0);
        assert!(trace.is_empty());
        assert!(!trace.has_overflow());
    }
}

#[cfg(feature = "track-locations")]
#[test]
fn trace_overflow_at_max_depth() {
    let mut trace = Trace::new();

    // Push exactly MAX_TRACE_DEPTH locations — should not overflow.
    for i in 0..MAX_TRACE_DEPTH {
        trace.push(Location::new("file.rs", i as u32, 0));
    }
    assert_eq!(trace.len(), MAX_TRACE_DEPTH);
    assert!(!trace.has_overflow());

    // Push one more — should trigger overflow and remain at MAX_TRACE_DEPTH.
    trace.push(Location::new("file.rs", 999, 0));
    assert_eq!(trace.len(), MAX_TRACE_DEPTH);
    assert!(trace.has_overflow());

    // The oldest entry (line 0) should have been removed.
    assert_eq!(trace.locations()[0].line, 1);
    // The newest entry should be at the end.
    assert_eq!(trace.locations()[MAX_TRACE_DEPTH - 1].line, 999);
}

#[cfg(feature = "track-locations")]
#[test]
fn trace_overflow_continues_after_multiple_pushes() {
    let mut trace = Trace::new();

    // Push MAX_TRACE_DEPTH + 5 locations.
    for i in 0..(MAX_TRACE_DEPTH + 5) {
        trace.push(Location::new("file.rs", i as u32, 0));
    }

    assert_eq!(trace.len(), MAX_TRACE_DEPTH);
    assert!(trace.has_overflow());

    // First remaining entry should be line 5 (entries 0-4 dropped).
    assert_eq!(trace.locations()[0].line, 5);
}

// -- Traced tests -------------------------------------------------------

#[test]
fn traced_deref() {
    let traced = Traced::new(42_i32, Trace::new());
    // Deref should give access to the inner value.
    assert_eq!(*traced, 42);
}

#[test]
fn traced_into_inner() {
    let traced = Traced::new(String::from("hello"), Trace::new());
    let inner = traced.into_inner();
    assert_eq!(inner, "hello");
}

#[test]
fn traced_into_parts() {
    let mut trace = Trace::new();
    trace.push(Location::new("test.rs", 10, 5));

    let traced = Traced::new(100_u32, trace);
    let (val, _trace) = traced.into_parts();
    assert_eq!(val, 100);

    #[cfg(feature = "track-locations")]
    {
        assert_eq!(_trace.len(), 1);
    }
}

#[test]
fn traced_display() {
    let traced = Traced::new(String::from("some error"), Trace::new());
    assert_eq!(traced.to_string(), "some error");
}

// -- ChainError tests ---------------------------------------------------

#[test]
fn chain_err_preserves_inner() {
    let source = Traced::new(42_i32, Trace::new());
    let chained = String::from("new error").chain_err(source, "converting");
    assert_eq!(*chained, "new error");
}

#[cfg(feature = "track-locations")]
#[test]
fn chain_err_preserves_and_extends_trace() {
    let mut trace = Trace::new();
    trace.push(Location::new("origin.rs", 10, 1));
    let source = Traced::new(42_i32, trace);

    let chained = String::from("new error").chain_err(source, "converting type");

    // Should have the original location plus the chain point
    assert_eq!(chained.trace().len(), 2);
    assert_eq!(chained.trace().locations()[0].line, 10);
    assert_eq!(
        chained.trace().locations()[1].context(),
        Some("converting type")
    );
}

#[test]
fn chain_err_with_lazy_context() {
    let source = Traced::new(42_i32, Trace::new());
    let chained =
        String::from("new error").chain_err_with(source, || format!("lazy context {}", 123));
    assert_eq!(*chained, "new error");
}
