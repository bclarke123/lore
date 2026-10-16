// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::ZeroHeapAlloc;
use lore_revision::interface::LoreNodeType;
use zerocopy::IntoBytes;

mod cycle_tests;
mod reserved_name_tests;

use lore_revision::node::*;

/// A legacy block keeps its flags, version and 511 entries, and the entry the
/// current format adds is zero.
#[test]
fn a_legacy_file_metadata_block_converts_to_the_current_format() {
    let mut legacy = NodeFileMetadataBlockDataV0::new_from_heap_zeroed();
    legacy.flags = 3;
    legacy.version = 7;
    for (index, entry) in legacy.node.iter_mut().enumerate() {
        entry.node = [index as u32 + 1, 0];
    }

    let current = legacy.to_current();

    assert_eq!((current.flags, current.version), (3, 7));
    for (index, entry) in current.node[..BLOCK_NODE_FILE_METADATA_COUNT_V0]
        .iter()
        .enumerate()
    {
        assert_eq!(entry.node, [index as u32 + 1, 0], "entry {index}");
    }
    assert!(
        current.node[BLOCK_NODE_FILE_METADATA_COUNT_V0..]
            .iter()
            .all(|entry| entry.as_bytes().iter().all(|&byte| byte == 0)),
        "the added entry is zero"
    );
}

fn node_with_flags(flags: u16) -> Node {
    Node {
        flags,
        ..Default::default()
    }
}

#[test]
fn dirty_flag_bit_positions() {
    // V1: Dirty at bit 3
    assert_eq!(NodeFlags::Dirty.bits(), 0b1000);
    // V1: Dirty does not overlap with Staged (bit 4)
    assert_eq!(NodeFlags::Dirty.bits() & NodeFlags::Staged.bits(), 0);
    // V1: Dirty does not overlap with File/Module/ExternalName
    assert_eq!(NodeFlags::Dirty.bits() & NodeFlags::File.bits(), 0);
    assert_eq!(NodeFlags::Dirty.bits() & NodeFlags::Link.bits(), 0);

    // V2: Dirty at bit 15
    assert_eq!(NodeFlagsV2::Dirty.bits(), 1 << 15);
    // V2: Dirty does not overlap with Staged (bit 16)
    assert_eq!(NodeFlagsV2::Dirty.bits() & NodeFlagsV2::Staged.bits(), 0);
}

#[test]
fn dirty_compound_flags_v1() {
    assert_eq!(
        NodeFlags::DirtyModify.bits(),
        NodeFlags::Dirty.bits() | NodeFlags::StagedModify.bits() & NodeFlags::ActionBits.bits()
    );
    assert_eq!(
        NodeFlags::DirtyAdd.bits(),
        NodeFlags::Dirty.bits() | NodeFlags::StagedAdd.bits() & NodeFlags::ActionBits.bits()
    );
    assert_eq!(
        NodeFlags::DirtyDelete.bits(),
        NodeFlags::Dirty.bits() | NodeFlags::StagedDelete.bits() & NodeFlags::ActionBits.bits()
    );
    assert_eq!(
        NodeFlags::DirtyMove.bits(),
        NodeFlags::Dirty.bits() | NodeFlags::StagedMove.bits() & NodeFlags::ActionBits.bits()
    );
    assert_eq!(
        NodeFlags::DirtyCopy.bits(),
        NodeFlags::Dirty.bits() | NodeFlags::StagedCopy.bits() & NodeFlags::ActionBits.bits()
    );
}

#[test]
fn dirty_bits_mask() {
    // DirtyBits = Dirty + ActionBits (bits 3, 5-9)
    let expected = NodeFlags::Dirty.bits() | NodeFlags::ActionBits.bits();
    assert_eq!(NodeFlags::DirtyBits.bits(), expected);
    // DirtyBits does NOT include Staged (bit 4)
    assert_eq!(NodeFlags::DirtyBits.bits() & NodeFlags::Staged.bits(), 0);
    // DirtyBits does NOT include MergeBits
    assert_eq!(NodeFlags::DirtyBits.bits() & NodeFlags::MergeBits.bits(), 0);
}

#[test]
fn action_bits_mask() {
    // ActionBits = bits 5-9 (shared between Dirty and Staged)
    let expected = (NodeFlags::StagedModify.bits()
        | NodeFlags::StagedAdd.bits()
        | NodeFlags::StagedDelete.bits()
        | NodeFlags::StagedMove.bits()
        | NodeFlags::StagedCopy.bits())
        & !NodeFlags::Staged.bits();
    assert_eq!(NodeFlags::ActionBits.bits(), expected);
}

#[test]
fn node_is_dirty_queries() {
    // Clean node
    let node = Node::default();
    assert!(!node.is_dirty());
    assert!(!node.is_dirty_modify());

    // Dirty only
    let node = node_with_flags(NodeFlags::DirtyModify.bits());
    assert!(node.is_dirty());
    assert!(node.is_dirty_modify());
    assert!(!node.is_dirty_add());
    assert!(!node.is_staged());

    // Dirty+Staged (orthogonal)
    let node = node_with_flags(NodeFlags::Dirty.bits() | NodeFlags::StagedModify.bits());
    assert!(node.is_dirty());
    assert!(node.is_staged());
    assert!(node.is_staged_modify());
    assert!(node.is_dirty_or_staged());
}

#[test]
fn node_has_any_change_flags() {
    assert!(!Node::default().has_any_change_flags());
    assert!(node_with_flags(NodeFlags::Dirty.bits()).has_any_change_flags());
    assert!(node_with_flags(NodeFlags::Staged.bits()).has_any_change_flags());
    assert!(!node_with_flags(NodeFlags::File.bits()).has_any_change_flags());
}

#[test]
fn clear_staged_flags_preserves_dirty() {
    let mut node = node_with_flags(NodeFlags::Dirty.bits() | NodeFlags::StagedModify.bits());
    node.clear_staged_flags();
    assert!(node.is_dirty());
    assert!(!node.is_staged());
    assert_ne!(node.flags & NodeFlags::ActionBits.bits(), 0);
}

#[test]
fn clear_staged_flags_clears_action_when_no_dirty() {
    let mut node = node_with_flags(NodeFlags::StagedModify.bits());
    node.clear_staged_flags();
    assert_eq!(
        node.flags & (NodeFlags::StagedBits.bits() | NodeFlags::Dirty.bits()),
        0
    );
}

#[test]
fn clear_dirty_flags_preserves_staged() {
    let mut node = node_with_flags(NodeFlags::Dirty.bits() | NodeFlags::StagedModify.bits());
    node.clear_dirty_flags();
    assert!(!node.is_dirty());
    assert!(node.is_staged());
    assert!(node.is_staged_modify());
}

#[test]
fn clear_dirty_flags_clears_action_when_no_staged() {
    let mut node = node_with_flags(NodeFlags::DirtyModify.bits());
    node.clear_dirty_flags();
    assert_eq!(
        node.flags & (NodeFlags::DirtyBits.bits() | NodeFlags::StagedBits.bits()),
        0
    );
}

#[test]
fn clear_all_change_flags() {
    let mut node = node_with_flags(
        NodeFlags::File.bits() | NodeFlags::Dirty.bits() | NodeFlags::StagedModify.bits(),
    );
    node.clear_all_change_flags();
    assert!(node.is_file());
    assert!(!node.is_dirty());
    assert!(!node.is_staged());
    assert_eq!(node.flags & NodeFlags::ActionBits.bits(), 0);
}

#[test]
fn action_bits_extraction() {
    let node = node_with_flags(NodeFlags::DirtyMove.bits());
    assert_eq!(
        node.action_bits(),
        NodeFlags::StagedMove.bits() & NodeFlags::ActionBits.bits()
    );
}

#[test]
fn node_type_reads_the_kind_bits_and_ignores_the_rest() {
    assert_eq!(Node::default().node_type(), LoreNodeType::Directory);
    assert_eq!(
        node_with_flags(NodeFlags::File.bits()).node_type(),
        LoreNodeType::File
    );
    assert_eq!(
        node_with_flags(NodeFlags::Link.bits() | NodeFlags::StagedAdd.bits()).node_type(),
        LoreNodeType::Link
    );
    assert_eq!(
        node_with_flags(NodeFlags::DirtyModify.bits()).node_type(),
        LoreNodeType::Directory
    );
}
