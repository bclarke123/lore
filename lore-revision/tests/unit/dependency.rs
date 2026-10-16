// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::dependency::*;

/// Build a raw dependency blob header (16 bytes) with the given
/// `entry_count`. Used by tests to craft malformed inputs without going
/// through the well-formed `serialize` path.
fn blob_header(entry_count: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE);
    buf.extend_from_slice(&MAGIC.to_le_bytes());
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&entry_count.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf
}

#[test]
fn deserialize_roundtrip() {
    let mut data = DependencyData::new();
    data.add(7, &["foo", "bar"]);
    data.add(42, &["baz"]);
    let bytes = data.serialize();
    let parsed = DependencyData::deserialize(&bytes).expect("roundtrip");
    assert_eq!(parsed, data);
}

#[test]
fn deserialize_empty_blob_ok() {
    let bytes = DependencyData::new().serialize();
    let parsed = DependencyData::deserialize(&bytes).expect("empty roundtrip");
    assert!(parsed.entries.is_empty());
}

#[test]
fn deserialize_rejects_entry_count_exceeding_buffer() {
    // Header declares 1_000_000 entries but buffer only has the header.
    // Without the cap, this triggers a ~32 MiB Vec::with_capacity.
    let bytes = blob_header(1_000_000);
    let err = DependencyData::deserialize(&bytes).expect_err("should reject");
    assert!(
        err.to_string().contains("entry_count exceeds"),
        "unexpected error: {err}"
    );
}

#[test]
fn deserialize_rejects_u32_max_entry_count() {
    let bytes = blob_header(u32::MAX);
    let err = DependencyData::deserialize(&bytes).expect_err("should reject");
    assert!(
        err.to_string().contains("entry_count exceeds"),
        "unexpected error: {err}"
    );
}

#[test]
fn deserialize_rejects_tag_count_exceeding_remaining_buffer() {
    // Header says 1 entry. Entry header says tag_count = 65535. Remaining
    // buffer (0 bytes after the entry header) can't fit 65535 * 2 bytes.
    // Without the cap, this triggers a ~1 MiB Vec::with_capacity for tags.
    let mut bytes = blob_header(1);
    bytes.extend_from_slice(&7u32.to_le_bytes()); // node_id
    bytes.extend_from_slice(&u16::MAX.to_le_bytes()); // tag_count
    bytes.extend_from_slice(&0u16.to_le_bytes()); // reserved
    let err = DependencyData::deserialize(&bytes).expect_err("should reject");
    assert!(
        err.to_string().contains("tag_count exceeds"),
        "unexpected error: {err}"
    );
}

#[test]
fn deserialize_accepts_legitimate_tag_counts() {
    // Confirm the tag_count cap doesn't break well-formed blobs with
    // multiple tags.
    let mut data = DependencyData::new();
    data.add(1, &["a", "b", "c", "d", "e"]);
    let bytes = data.serialize();
    let parsed = DependencyData::deserialize(&bytes).expect("should accept");
    assert_eq!(parsed, data);
}

#[test]
fn deserialize_rejects_bad_magic() {
    let mut bytes = blob_header(0);
    bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
    assert!(DependencyData::deserialize(&bytes).is_err());
}

#[test]
fn deserialize_rejects_unsupported_version() {
    let mut bytes = blob_header(0);
    bytes[4..8].copy_from_slice(&999u32.to_le_bytes());
    assert!(DependencyData::deserialize(&bytes).is_err());
}

#[test]
fn deserialize_rejects_blob_shorter_than_header() {
    let bytes = vec![0u8; HEADER_SIZE - 1];
    assert!(DependencyData::deserialize(&bytes).is_err());
}
