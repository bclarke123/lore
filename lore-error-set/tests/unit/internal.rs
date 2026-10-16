// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

use std::error::Error;
use std::io;
use std::sync::Arc;

use lore_error_set::internal::*;

#[test]
fn internal_display_delegates_to_source() {
    let source = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
    let internal = Internal::new(Arc::new(source));
    assert_eq!(internal.to_string(), "access denied");
}

#[test]
fn internal_source_chain() {
    let source = io::Error::new(io::ErrorKind::NotFound, "not found");
    let internal = Internal::new(Arc::new(source));

    let src = internal.source().expect("should have a source");
    let io_err = src
        .downcast_ref::<io::Error>()
        .expect("should be io::Error");
    assert_eq!(io_err.kind(), io::ErrorKind::NotFound);
}

#[test]
fn internal_ffi_code() {
    assert_eq!(Internal::FFI_CODE, -1);
}

// -- Internal::msg() tests --

#[test]
fn internal_msg_display() {
    let err = Internal::msg("store does not support operation");
    assert_eq!(err.to_string(), "store does not support operation");
}

#[test]
fn internal_msg_source() {
    let err = Internal::msg("boom");
    assert!(err.source().is_some(), "msg() should set a source");
    assert_eq!(err.source().unwrap().to_string(), "boom");
}
