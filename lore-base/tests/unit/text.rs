// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::error::InvalidArguments;
use lore_base::text::*;

/// The failing field is named the way a caller reading the arguments would
/// write it, so the rejection says which string to fix.
#[test]
fn a_failure_names_the_field_it_came_from() {
    assert_eq!(TextNotUtf8::here().inside("path").field(), "path");
    assert_eq!(
        TextNotUtf8::here().at(2).inside("paths").field(),
        "paths[2]"
    );
    assert_eq!(
        TextNotUtf8::here()
            .inside("remote_url")
            .inside("remote_config")
            .field(),
        "remote_config.remote_url"
    );
    assert_eq!(
        TextNotUtf8::here()
            .inside("name")
            .at(3)
            .inside("entries")
            .field(),
        "entries[3].name"
    );
}

#[test]
fn a_failure_reads_as_an_invalid_argument_naming_the_field() {
    let error = InvalidArguments::from(TextNotUtf8::here().inside("identity"));

    assert_eq!(
        error.to_string(),
        "invalid arguments: identity is not valid UTF-8"
    );
}

#[test]
fn a_value_that_carries_no_text_passes() {
    assert!(7u64.validate_text().is_ok());
    assert!(lore_base::types::Hash::default().validate_text().is_ok());
}
