// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Ingress filter that transcodes incoming Oodle-compressed fragments to Zstd.
//!
//! Unless disabled (via the `LORE_DISABLE_CONVERT_OODLE_ON_PUT` environment variable), every fragment a
//! client puts is inspected: if it is Oodle-compressed it is decompressed and re-compressed as
//! Zstd (or stored uncompressed if Zstd is not worthwhile) before being written. Because a
//! fragment's identity is the hash of its *uncompressed* content, the address is unchanged; only
//! `flags`, `size_payload`, and the stored blob change.

use std::sync::LazyLock;

use bytes::Bytes;
use lore_base::types::Address;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_storage::CompressionMode;
use tracing::warn;

const CONVERT_DISABLED_ENV: &str = "LORE_DISABLE_CONVERT_OODLE_ON_PUT";

static CONVERT_DISABLED: LazyLock<bool> = LazyLock::new(
    || matches!(std::env::var(CONVERT_DISABLED_ENV), Ok(value) if value.eq_ignore_ascii_case("true") || value == "1"),
);

/// Apply the ingress conversion if it is enabled; otherwise the
/// inputs are returned unchanged.
pub(crate) async fn convert_oodle_on_ingress(
    address: Address,
    fragment: Fragment,
    payload: Option<Bytes>,
) -> (Fragment, Option<Bytes>) {
    if *CONVERT_DISABLED {
        return (fragment, payload);
    }

    transcode_oodle_to_zstd(address, fragment, payload).await
}

/// Transcode an unfragmented Oodle payload to Zstd (or uncompressed, if Zstd is not worthwhile),
/// returning the rewritten fragment and blob. Non-Oodle, fragmented, and payload-less inputs are
/// returned unchanged, as is any input that fails to decompress, so a put is never broken by the
/// filter.
#[lore_macro::test_pub]
async fn transcode_oodle_to_zstd(
    address: Address,
    fragment: Fragment,
    payload: Option<Bytes>,
) -> (Fragment, Option<Bytes>) {
    let Some(payload) = payload else {
        return (fragment, None);
    };

    if fragment.flags & FragmentFlags::PayloadCompressedOodle2 == 0
        // compression + fragmented is never sent by legit clients
        || fragment.flags & FragmentFlags::PayloadFragmented != 0
    {
        return (fragment, Some(payload));
    }

    let (decompressed_fragment, decompressed) =
        match lore_storage::decompress(fragment, payload.as_ref()) {
            Ok(result) => result,
            Err(error) => {
                warn!(
                    address = %address,
                    ?error,
                    "Oodle->Zstd put conversion skipped: failed to decompress"
                );
                return (fragment, Some(payload));
            }
        };
    let decompressed = decompressed.freeze();

    match lore_storage::compress(
        decompressed_fragment,
        decompressed.as_ref(),
        CompressionMode::Zstd,
    ) {
        Ok((zstd_fragment, zstd_payload)) => (zstd_fragment, Some(zstd_payload)),
        // Zstd was not worthwhile/successful; store the content uncompressed. Either way it is no longer Oodle.
        Err(_) => (decompressed_fragment, Some(decompressed)),
    }
}
