// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::file::stage::*;

#[test]
fn empty_mask_never_masks() {
    let empty: [&str; 0] = [];
    assert!(!is_path_under_layer_mask("external/lib", &empty));
    assert!(!is_path_under_layer_mask("", &empty));
}

#[test]
fn exact_mask_match_is_masked() {
    assert!(is_path_under_layer_mask("external/lib", &["external/lib"]));
}

#[test]
fn path_inside_masked_subtree_is_masked() {
    assert!(is_path_under_layer_mask(
        "external/lib/src/foo.rs",
        &["external/lib"]
    ));
}

#[test]
fn ancestor_of_masked_path_is_not_masked() {
    // Walker entering "external" should still descend; the mask kicks in
    // when it reaches "external/lib".
    assert!(!is_path_under_layer_mask("external", &["external/lib"]));
}

#[test]
fn disjoint_path_is_not_masked() {
    assert!(!is_path_under_layer_mask("src/main.rs", &["external/lib"]));
}

#[test]
fn empty_path_with_mask_is_not_masked() {
    // The parent's root is never itself masked.
    assert!(!is_path_under_layer_mask("", &["external/lib"]));
}

#[test]
fn prefix_string_match_without_separator_is_not_masked() {
    assert!(!is_path_under_layer_mask(
        "external_other/file.rs",
        &["external"]
    ));
}

#[test]
fn multiple_mask_entries_any_match_is_masked() {
    let mask = ["external/lib", "vendor/foo"];
    assert!(is_path_under_layer_mask("vendor/foo/x.rs", &mask));
    assert!(is_path_under_layer_mask("external/lib", &mask));
    assert!(!is_path_under_layer_mask("src/main.rs", &mask));
}
