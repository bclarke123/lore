// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::file::stage::*;
use lore_revision::util::path::RelativePath;

#[test]
fn empty_path_no_layers_is_disjoint() {
    assert_eq!(classify_stage_path("", &[]), LayerRoute::Disjoint);
}

#[test]
fn empty_path_with_layers_is_ancestor_of_all() {
    let layers = ["external/lib", "vendor/foo"];
    assert_eq!(
        classify_stage_path("", &layers),
        LayerRoute::AncestorOf {
            layer_indices: vec![0, 1],
        }
    );
}

#[test]
fn exact_layer_match_is_inside_with_empty_remain() {
    let layers = ["external/lib"];
    assert_eq!(
        classify_stage_path("external/lib", &layers),
        LayerRoute::Inside {
            layer_index: 0,
            remain: RelativePath::new(),
        }
    );
}

#[test]
fn path_inside_layer_is_inside_with_remain() {
    let layers = ["external/lib"];
    assert_eq!(
        classify_stage_path("external/lib/src/foo.rs", &layers),
        LayerRoute::Inside {
            layer_index: 0,
            remain: RelativePath::new_from_clean_parts("src/foo.rs", ""),
        }
    );
}

#[test]
fn path_ancestor_of_one_layer_is_ancestor_of_that_layer() {
    let layers = ["external/lib", "src/main.rs"];
    assert_eq!(
        classify_stage_path("external", &layers),
        LayerRoute::AncestorOf {
            layer_indices: vec![0],
        }
    );
}

#[test]
fn path_ancestor_of_multiple_layers_lists_them_all() {
    let layers = ["vendor/a", "vendor/b", "external/lib"];
    assert_eq!(
        classify_stage_path("vendor", &layers),
        LayerRoute::AncestorOf {
            layer_indices: vec![0, 1],
        }
    );
}

#[test]
fn disjoint_path_with_layers_is_disjoint() {
    let layers = ["external/lib", "vendor/foo"];
    assert_eq!(
        classify_stage_path("src/main.rs", &layers),
        LayerRoute::Disjoint
    );
}

#[test]
fn prefix_string_match_without_separator_is_disjoint_not_inside() {
    // "external" is a string prefix of "external_other" but not a path-prefix.
    // Confirms we check '/' boundary, not bare string prefix.
    let layers = ["external"];
    assert_eq!(
        classify_stage_path("external_other", &layers),
        LayerRoute::Disjoint
    );
}
