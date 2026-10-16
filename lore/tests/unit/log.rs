// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore::log::*;
use lore_base::error::InvalidArguments;
use lore_error_set::FfiError;
use lore_revision::interface::LoreString;

/// `lore_log_configure` takes caller text without going through the
/// argument wrappers, so it is the one entry point that has to check its own
/// strings before reading them as a path.
#[test]
fn configure_rejects_a_file_path_that_is_not_utf8() {
    let config = LoreLogConfig {
        file: 1,
        file_path: LoreString::from_bytes(&[b'/', 0xff, 0xfe]),
        ..LoreLogConfig::default()
    };

    let status = configure(&config);

    assert_eq!(
        status,
        InvalidArguments {
            reason: String::new()
        }
        .ffi_code(),
        "a non-UTF-8 log path must be rejected"
    );
}

/// A configuration that asks for no log file applies without touching the
/// filesystem, so the check is the only thing standing between the caller
/// and a bad path.
#[test]
fn configure_accepts_a_configuration_with_no_file_logging() {
    assert_eq!(configure(&LoreLogConfig::default()), 0);
}
