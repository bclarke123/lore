// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::lore::RepositoryId;
use lore_server::auth::anonymous::*;

#[test]
fn allowlist_contains_no_mutating_methods() {
    for method in READ_ONLY_METHODS.iter().chain(LOOKUP_METHODS) {
        for verb in [
            "Put",
            "Copy",
            "Verify",
            "MutableStore",
            "MutableCompareAndSwap",
            "Create",
            "Delete",
            "Push",
            "Set",
            "Protect",
            "Obliterate",
        ] {
            assert!(
                !method.contains(verb),
                "{method} looks like a mutating method"
            );
        }
    }
}

#[test]
fn anonymous_token_is_read_scoped() {
    let repository = RepositoryId::default();
    let token = anonymous_token(repository);
    assert!(is_anonymous(&token));
    let resources = token.resources.expect("resources");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].permission, vec!["read"]);

    // The lookup token authenticates but authorizes nothing.
    let lookup = anonymous_lookup_token();
    assert!(is_anonymous(&lookup));
    assert_eq!(lookup.resources, Some(vec![]));
}
