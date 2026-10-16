// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_revision::event::LoreMetadataEventData;
use lore_revision::interface::LoreMetadata;
use lore_revision::metadata::MetadataType;

/// Bytes stored under the string tag that are not text cannot be delivered
/// as a string, so the decode fails rather than reporting an empty value:
/// an empty string is a value a key can legitimately hold, and a caller
/// cannot tell the two apart. Argument text is checked at the entry point,
/// but a value read back out of a stored buffer never passed through it.
#[test]
fn a_string_value_that_is_not_text_fails_to_decode() {
    assert!(
        LoreMetadataEventData::new("key", b"\xff\xfe", MetadataType::String).is_err(),
        "bytes that are not text must not decode to an empty string"
    );
    let decoded = LoreMetadataEventData::new("key", b"text", MetadataType::String)
        .expect("valid text must decode");
    assert_eq!(
        decoded.value,
        LoreMetadata::String(lore_revision::interface::LoreString::from("text"))
    );
}
