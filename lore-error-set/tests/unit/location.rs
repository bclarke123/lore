// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_error_set::location::*;

#[test]
fn location_display() {
    let loc = Location::new("src/main.rs", 42, 5);
    assert_eq!(loc.to_string(), "src/main.rs:42:5");
}

#[test]
fn location_display_with_context() {
    let loc = Location::with_context("src/main.rs", 42, 5, Arc::from("loading config"));
    assert_eq!(loc.to_string(), "src/main.rs:42 - loading config");
}

#[test]
fn location_clone() {
    let loc = Location::new("src/lib.rs", 1, 1);
    let loc2 = loc.clone();
    let loc3 = loc;
    assert_eq!(loc2, loc3);
}

#[test]
fn location_context_accessor() {
    let loc = Location::new("src/lib.rs", 1, 1);
    assert_eq!(loc.context(), None);

    let loc2 = Location::with_context("src/lib.rs", 1, 1, Arc::from("test context"));
    assert_eq!(loc2.context(), Some("test context"));
}
