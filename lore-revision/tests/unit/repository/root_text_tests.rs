// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Coverage for [`require_text_root`], the one place a working copy whose path has no
//! text spelling is refused.
use lore_revision::repository::require_text_root;

#[test]
fn a_root_that_is_text_is_accepted() {
    assert!(require_text_root(std::path::Path::new("/work/repository")).is_ok());
}

/// A root without a text spelling is refused where the working copy is opened, so no
/// path built from it is ever reported in a spelling it cannot be parsed back from.
#[cfg(target_family = "unix")]
#[test]
fn a_root_that_is_not_text_is_refused() {
    use std::os::unix::ffi::OsStrExt;
    let root = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/work/\xff\xfe"));
    assert!(
        require_text_root(root).is_err(),
        "a root with no text spelling must be refused"
    );
}
