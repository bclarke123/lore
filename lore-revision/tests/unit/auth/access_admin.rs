// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::auth::access_admin::*;

#[test]
fn repository_ref_parses_ids_and_names() {
    assert!(matches!(
        repository_ref("0194b726b34e72b0b45550b88a967076"),
        AccessRepositoryRef::Id(_)
    ));
    assert!(matches!(
        repository_ref("project1"),
        AccessRepositoryRef::Name(_)
    ));
}
