// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::path::PathBuf;

use lore_chaos_client::probability::*;

#[test]
pub fn merge_states() {
    let mut engine = ProbabilityEngine::new(Default::default(), Some(1000));
    let source_files: Vec<PathBuf> = ["a", "b", "c", "d"].map(PathBuf::from).to_vec();
    let target_files: Vec<PathBuf> = ["b", "c", "d", "e"].map(PathBuf::from).to_vec();
    let (resolutions, mut all_files) =
        engine.pick_merge_resolutions(target_files.clone(), &source_files);

    for resolution in resolutions {
        assert!(target_files.contains(&resolution.0));
        assert!(source_files.contains(&resolution.0));
    }

    let mut expected_files = ["a", "b", "c", "d", "e"].map(PathBuf::from).to_vec();
    expected_files.sort();
    all_files.sort();
    assert_eq!(expected_files, all_files);
}
