// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::ffi::OsString;

mod network;
mod service_process;

use lore::remote::*;

#[test]
fn a_named_socket_is_used() {
    assert_eq!(
        socket_name_from(Some(OsString::from("lore_service-test-abc123"))),
        "lore_service-test-abc123"
    );
    // Surrounding space is not part of a file name.
    assert_eq!(socket_name_from(Some(OsString::from("  named  "))), "named");
}

#[test]
fn no_named_socket_uses_the_default() {
    assert_eq!(socket_name_from(None), LORE_SERVICE_SOCKET_NAME);
    assert_eq!(
        socket_name_from(Some(OsString::new())),
        LORE_SERVICE_SOCKET_NAME
    );
    assert_eq!(
        socket_name_from(Some(OsString::from("   "))),
        LORE_SERVICE_SOCKET_NAME
    );
}

/// Refused in favour of the default rather than honoured: a value carrying a
/// path could put the socket somewhere with weaker permissions.
#[test]
fn a_named_socket_that_is_a_path_is_refused() {
    for named in ["../escape", "sub/lore_service", "/tmp/lore_service", ".."] {
        assert_eq!(
            socket_name_from(Some(OsString::from(named))),
            LORE_SERVICE_SOCKET_NAME,
            "{named} must not be honoured"
        );
    }
}

#[test]
fn a_single_file_name_is_allowed() {
    for name in ["lore_service", "lore_service-1", "lore.service", "a"] {
        assert!(is_single_file_name(name), "{name} names one file");
    }
}

/// A value carrying a path would move the socket out of the directory
/// chosen for being private to the user.
#[test]
fn anything_carrying_a_path_is_refused() {
    for name in [
        "",
        ".",
        "..",
        "../lore_service",
        "sub/lore_service",
        "/tmp/lore_service",
        "..\\lore_service",
        "C:\\lore_service",
        "lore\0service",
    ] {
        assert!(
            !is_single_file_name(name),
            "{name:?} does not name a single file"
        );
    }
}
