// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
#![cfg(feature = "oodle")]

use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_server::protocol::oodle_ingress::*;
use lore_storage::CompressionMode;
use lore_storage::hash_slice;

/// A highly compressible payload (a unique prefix plus a long constant run) that both Oodle
/// and Zstd will happily compress.
fn compressible_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(1024);
    payload.extend_from_slice(b"oodle-ingress-test");
    payload.resize(1024, 0xab);
    payload
}

fn address_of(content: &[u8]) -> Address {
    Address {
        hash: hash_slice(content),
        ..Default::default()
    }
}

#[tokio::test]
async fn transcodes_oodle_to_non_oodle_preserving_content() {
    let content = compressible_payload();
    let address = address_of(&content);
    let base = Fragment {
        flags: 0,
        size_payload: content.len() as u32,
        size_content: content.len() as u64,
    };
    let (oodle_fragment, oodle_payload) =
        lore_storage::compress::compress_without_deprecation_checks(
            base,
            content.as_slice(),
            CompressionMode::Oodle,
        )
        .expect("payload should Oodle-compress");
    assert_ne!(
        oodle_fragment.flags & FragmentFlags::PayloadCompressedOodle2,
        0,
        "precondition: the input must be Oodle compressed"
    );

    let (converted, payload) =
        transcode_oodle_to_zstd(address, oodle_fragment, Some(oodle_payload)).await;
    let payload = payload.expect("conversion must keep the payload");

    // No longer Oodle, sizes consistent, and the content still decodes to the original.
    assert_eq!(converted.flags & FragmentFlags::PayloadCompressedOodle2, 0);
    assert_eq!(converted.size_content, base.size_content);
    assert_eq!(payload.len(), converted.size_payload as usize);
    let recovered_hash = lore_storage::hash_fragment(converted, payload.as_ref())
        .expect("converted fragment should hash");
    assert_eq!(recovered_hash, address.hash);
}

#[tokio::test]
async fn leaves_non_oodle_fragment_unchanged() {
    let content = compressible_payload();
    let address = address_of(&content);
    let base = Fragment {
        flags: 0,
        size_payload: content.len() as u32,
        size_content: content.len() as u64,
    };
    let (zstd_fragment, zstd_payload) =
        lore_storage::compress(base, content.as_slice(), CompressionMode::Zstd)
            .expect("payload should Zstd-compress");

    let (fragment, payload) =
        transcode_oodle_to_zstd(address, zstd_fragment, Some(zstd_payload.clone())).await;

    assert_eq!(fragment, zstd_fragment);
    assert_eq!(payload, Some(zstd_payload));
}

#[tokio::test]
async fn leaves_metadata_only_put_unchanged() {
    let fragment = Fragment {
        flags: FragmentFlags::PayloadCompressedOodle2.bits(),
        size_payload: 64,
        size_content: 128,
    };

    let (out_fragment, out_payload) =
        transcode_oodle_to_zstd(Address::default(), fragment, None).await;

    assert_eq!(out_fragment, fragment);
    assert!(out_payload.is_none());
}
