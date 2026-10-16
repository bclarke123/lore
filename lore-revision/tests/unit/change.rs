// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::change::*;

#[test]
fn dirty_flag_exists_and_is_independent() {
    let dirty = Flags::Dirty;
    let staged = Flags::Staged;
    // Dirty and Staged don't overlap
    assert_eq!(dirty & staged, Flags::None);
}

#[test]
fn is_dirty_method() {
    let flags = Flags::Dirty;
    assert!(flags.is_dirty());
    assert!(!flags.is_stage());

    let flags = Flags::Staged;
    assert!(!flags.is_dirty());
    assert!(flags.is_stage());

    let flags = Flags::Dirty | Flags::Staged;
    assert!(flags.is_dirty());
    assert!(flags.is_stage());
}

#[test]
fn dirty_and_modify_combine() {
    let flags = Flags::Dirty | Flags::Modify;
    assert!(flags.is_dirty());
    assert!(flags.contains(Flags::Modify));
    assert!(!flags.is_stage());
}
