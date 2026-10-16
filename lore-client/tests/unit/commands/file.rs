// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_client::commands::file::parse_context_lines;

#[test]
fn rejects_non_numeric() {
    assert_eq!(
        parse_context_lines("abc").unwrap_err(),
        "expected a non-negative integer; got 'abc'"
    );
}

#[test]
fn rejects_negative() {
    assert_eq!(
        parse_context_lines("-1").unwrap_err(),
        "expected a non-negative integer; got '-1'"
    );
}

#[test]
fn accepts_valid() {
    assert_eq!(parse_context_lines("5").unwrap(), 5);
}

/// Verify `-1` reaches the value parser (rather than being rejected as an
/// unexpected argument), which is the behavior `allow_negative_numbers` enables.
#[test]
fn diff_negative_context_reaches_parser() {
    use clap::Parser;
    let result =
        lore_client::cli::LoreCli::try_parse_from(["lore", "diff", "-U", "-1", "original.txt"]);
    let err = result
        .err()
        .expect("expected -U -1 to be rejected")
        .to_string();
    assert!(err.contains("non-negative integer"), "got: {err}");
}
