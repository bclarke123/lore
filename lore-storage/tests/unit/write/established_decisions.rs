// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_storage::Address;
use lore_storage::hash::hash_slice;
use lore_storage::write::ContentHashes;
use lore_storage::write::FileMatch;

fn address_of(bytes: &[u8]) -> Address {
    Address::zero_context_hash(hash_slice(bytes))
}

/// A size of its own settles a comparison, before anything about the content is known.
#[test]
fn another_size_differs_from_nothing_established() {
    let established = ContentHashes::default();
    assert!(matches!(
        established.decides(address_of(b"content"), Some(41), 42),
        Some(FileMatch::Differs)
    ));
}

/// Empty is empty under any fragmentation, which settles it without a hash either way.
#[test]
fn an_empty_file_is_settled_by_the_address_alone() {
    let established = ContentHashes::default();
    assert!(matches!(
        established.decides(Address::default(), Some(0), 0),
        Some(FileMatch::Match)
    ));
    assert!(matches!(
        established.decides(address_of(b"content"), Some(0), 0),
        Some(FileMatch::Differs)
    ));
}

/// An address naming no content is held by no file.
#[test]
fn an_address_of_nothing_differs() {
    let established = ContentHashes::default();
    assert!(matches!(
        established.decides(Address::default(), Some(42), 42),
        Some(FileMatch::Differs)
    ));
}

/// Below the minimum cut the whole content's hash answers, and nothing answers until it is
/// established.
#[test]
fn below_the_minimum_cut_the_whole_hash_answers_once_it_is_known() {
    let content = b"small enough to be one chunk";
    let established = ContentHashes::default();
    let size = 1024;

    assert!(
        established
            .decides(address_of(content), Some(size), size)
            .is_none(),
        "nothing is established yet"
    );

    established
        .whole
        .set(hash_slice(content))
        .expect("the cell is empty");

    assert!(matches!(
        established.decides(address_of(content), Some(size), size),
        Some(FileMatch::Match)
    ));
    assert!(matches!(
        established.decides(address_of(b"other content"), Some(size), size),
        Some(FileMatch::Differs)
    ));
}

/// Above the minimum cut the stored fragmentation decides, which neither hash stands in for.
#[test]
fn above_the_minimum_cut_nothing_established_answers() {
    let content = b"content";
    let established = ContentHashes::default();
    established
        .whole
        .set(hash_slice(content))
        .expect("the cell is empty");
    let size = lore_storage::concurrency::FRAGMENT_SIZE_MINIMUM as u64 + 1;

    assert!(
        established
            .decides(address_of(content), Some(size), size)
            .is_none()
    );
}

/// A caller that measured no stored size asks about the content alone.
#[test]
fn an_unknown_stored_size_settles_nothing_by_size() {
    let established = ContentHashes::default();
    let size = lore_storage::concurrency::FRAGMENT_SIZE_MINIMUM as u64 + 1;
    assert!(
        established
            .decides(address_of(b"content"), None, size)
            .is_none()
    );
}
