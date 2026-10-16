// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_io::psync::*;

/// The shape of a Windows container bind-mount root: `mkdir` fails, but the target already
/// stats as a directory, so the failure is forgiven.
#[test]
fn forgive_existing_dir_forgives_a_failure_on_an_existing_directory() {
    let dir = lore_base::test_util::TempDir::new("lore-io-psync-forgive-");
    let synthetic_error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

    forgive_existing_dir(Err(synthetic_error), dir.path())
        .expect("an existing directory must not fail the caller");
}

#[test]
fn forgive_existing_dir_propagates_a_failure_on_a_file() {
    let dir = lore_base::test_util::TempDir::new("lore-io-psync-forgive-");
    let file_path = dir.path().join("blocker");
    std::fs::File::create(&file_path).expect("create blocker file");
    let synthetic_error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

    let error = forgive_existing_dir(Err(synthetic_error), &file_path)
        .expect_err("a file where a directory belongs must still fail");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn forgive_existing_dir_propagates_a_failure_on_a_missing_path() {
    let dir = lore_base::test_util::TempDir::new("lore-io-psync-forgive-");
    let missing_path = dir.path().join("nowhere");
    let synthetic_error = std::io::Error::from(std::io::ErrorKind::PermissionDenied);

    let error = forgive_existing_dir(Err(synthetic_error), &missing_path)
        .expect_err("a genuinely missing path must still fail");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn forgive_existing_dir_passes_success_through() {
    let dir = lore_base::test_util::TempDir::new("lore-io-psync-forgive-");

    forgive_existing_dir(Ok(()), dir.path()).expect("success must not become a failure");
}
