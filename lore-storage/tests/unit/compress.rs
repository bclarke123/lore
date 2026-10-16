// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use bytes::BytesMut;
use lore_base::types::FRAGMENT_SIZE_EXPECTED;
use lore_storage::Fragment;
use lore_storage::FragmentFlags;
use lore_storage::compress::*;

/// Compressible bytes, with enough structure that zstd beats the 5% threshold
/// at every size below and a shape that does not depend on the length.
fn payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let word = index / 37;
            ((word * 31 + index % 37) % 251) as u8
        })
        .collect()
}

fn raw_fragment(length: usize) -> Fragment {
    Fragment {
        flags: 0,
        size_payload: length as u32,
        size_content: length as u64,
    }
}

/// Bytes with no repetition for a window to find and a flat distribution for the
/// entropy coder, so there is nothing for any encoder to save. splitmix64 over a
/// counter.
fn incompressible_payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| {
            let mut value = (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            (value ^ (value >> 31)) as u8
        })
        .collect()
}

/// Whether a payload of `length` bytes is too small for any encoder to save 5%
/// on, in which case refusing it is correct and there is nothing to round trip.
fn below_compressible_size(length: usize) -> bool {
    length < 1024
}

/// Fragment lengths spanning the ranges zstd keys its compression parameters on,
/// both sides of every boundary in [`ZSTD_PARAMETER_TABLE_SIZES`] and both ends
/// of the permitted range.
const FRAGMENT_LENGTHS: &[usize] = &[
    1,
    17,
    64,
    FRAGMENT_COMPRESS_SIZE_LIMIT + 1,
    1024,
    4 * 1024,
    16 * 1024 - 1,
    16 * 1024,
    16 * 1024 + 1,
    32 * 1024,
    FRAGMENT_SIZE_EXPECTED,
    100 * 1024,
    128 * 1024 - 1,
    128 * 1024,
    128 * 1024 + 1,
    FRAGMENT_SIZE_THRESHOLD - 1,
    FRAGMENT_SIZE_THRESHOLD,
];

/// Every fragment size has to survive the round trip through the pooled context
/// that [`compress`] uses.
#[test]
fn zstd_round_trips_every_fragment_size() {
    for &length in FRAGMENT_LENGTHS {
        let source = payload(length);
        let Ok((compressed_fragment, compressed)) = compress_zstd_impl(
            raw_fragment(length),
            source.as_slice(),
            BytesMut::with_capacity(compress_bound(length, CompressionMode::Zstd)),
        ) else {
            assert!(
                below_compressible_size(length),
                "{length} bytes should have compressed"
            );
            continue;
        };

        assert_eq!(compressed_fragment.size_content, length as u64);
        assert!(
            (compressed_fragment.flags & FragmentFlags::PayloadCompressedZstd) != 0,
            "{length} bytes was not marked as zstd"
        );
        assert_eq!(compressed.len(), compressed_fragment.size_payload as usize);

        let (_, decompressed) = decompress(compressed_fragment, compressed.as_ref())
            .unwrap_or_else(|err| panic!("{length} bytes failed to decompress: {err:?}"));
        assert_eq!(
            decompressed.as_ref(),
            source.as_slice(),
            "{length} bytes did not round trip"
        );
    }
}

/// Decompression is handed `Fragment::size_content` and an output buffer, and
/// must fill it from a context that cannot allocate either.
#[test]
fn zstd_decompresses_from_the_fragment_header_alone() {
    let length = FRAGMENT_SIZE_EXPECTED;
    let source = payload(length);
    let (compressed_fragment, compressed) = compress_zstd_impl(
        raw_fragment(length),
        source.as_slice(),
        BytesMut::with_capacity(compress_bound(length, CompressionMode::Zstd)),
    )
    .expect("compresses");

    let mut into = vec![0u8; length];
    decompress_into_slice(
        compressed_fragment,
        compressed.as_ref(),
        into.as_mut_slice(),
    )
    .expect("decompresses");
    assert_eq!(into, source);
}

/// Fragment sizes fine enough to find every size at which zstd changes its
/// compression parameters: a stride below the smallest interval between changes,
/// and each power of two with its neighbours, which is where they fall.
fn fragment_size_scan() -> Vec<usize> {
    let mut sizes: Vec<usize> = (0..=18)
        .flat_map(|power: u32| {
            let size = 1usize << power;
            [size - 1, size, size + 1]
        })
        .filter(|size| (1..=FRAGMENT_SIZE_THRESHOLD).contains(size))
        .collect();

    let mut size = 1;
    while size <= FRAGMENT_SIZE_THRESHOLD {
        sizes.push(size);
        size += 64;
    }
    sizes.push(FRAGMENT_SIZE_THRESHOLD);
    sizes
}

/// The bound has to be the largest requirement across every fragment size, not
/// only across [`ZSTD_PARAMETER_TABLE_SIZES`]. Those are the boundaries of zstd's
/// internal parameter tables, which no header states, so a release that moves them
/// has to fail here rather than in a silent loss of compression.
#[test]
fn the_workspace_bound_is_the_largest_over_every_fragment_size() {
    let scan = fragment_size_scan();
    for level in 1..=22 {
        let (worst, at) = scan
            .iter()
            .map(|&size| (zstd_compress_workspace_size_at(level, size), size))
            .max()
            .expect("the scan is not empty");

        assert_eq!(
            zstd_compress_workspace_size_for(level),
            worst,
            "level {level}: {at} bytes needs {worst}, which no size in \
                 ZSTD_PARAMETER_TABLE_SIZES accounts for"
        );
    }
}

/// The workspace has to hold a context and compress every fragment size at every
/// level the configuration accepts, not only the default: zstd selects its
/// parameters from one of several tables keyed on the size of the input, so a
/// smaller fragment can demand more workspace than a larger one, and an
/// undersized workspace fails the compression rather than growing.
#[test]
fn the_workspace_estimate_holds_at_every_level() {
    for level in 1..=22 {
        let bytes = zstd_compress_workspace_size_for(level);
        let mut workspace = zstd_workspace(bytes).expect("allocates a workspace");
        // Safety: the buffer is the estimated size and `u64`-aligned.
        let context = unsafe {
            zstd_sys::ZSTD_initStaticCCtx(
                workspace.as_mut_ptr().cast::<std::ffi::c_void>(),
                workspace.capacity() * size_of::<u64>(),
            )
        };
        assert!(
            !context.is_null(),
            "level {level}: {bytes} bytes did not hold a context"
        );

        for &length in FRAGMENT_LENGTHS {
            let source = payload(length);
            let mut destination = vec![0u8; compress_bound(length, CompressionMode::Zstd)];
            // Safety: the context is non-null, the destination holds the bound
            // for `length` bytes, and the source is `length` bytes long.
            let compressed_size = unsafe {
                zstd_sys::ZSTD_compressCCtx(
                    context,
                    destination.as_mut_ptr().cast::<std::ffi::c_void>(),
                    destination.len(),
                    source.as_ptr().cast::<std::ffi::c_void>(),
                    length,
                    level,
                )
            };
            // Safety: Pure query on the return value, no pointer dereference.
            assert!(
                unsafe { zstd_sys::ZSTD_isError(compressed_size) } == 0,
                "level {level}, {length} bytes: {} in {bytes} bytes of workspace",
                zstd_error_name(compressed_size)
            );
        }
    }
}

/// The decompression estimate has to hold a context. Unlike compression its size
/// depends on neither the input nor the level.
#[test]
fn the_decompress_workspace_estimate_builds_a_context() {
    // Safety: a pure calculation with no arguments.
    let bytes = unsafe { zstd_sys::ZSTD_estimateDCtxSize() };
    let mut workspace = zstd_workspace(bytes).expect("allocates a workspace");
    // Safety: the buffer is the estimated size and `u64`-aligned.
    let context = unsafe {
        zstd_sys::ZSTD_initStaticDCtx(
            workspace.as_mut_ptr().cast::<std::ffi::c_void>(),
            workspace.capacity() * size_of::<u64>(),
        )
    };
    assert!(
        !context.is_null(),
        "{bytes} bytes did not hold a decompression context"
    );
}

/// The pool stops claiming slots at its limit, which is what keeps resident
/// workspace bounded independently of the core count.
#[test]
fn the_pool_claims_at_most_its_limit() {
    let count = AtomicUsize::new(0);
    let claimed = (0..ZSTD_CTX_POOL_LIMIT + 8)
        .filter(|_| zstd_claim_pooled_slot(&count))
        .count();

    assert_eq!(claimed, ZSTD_CTX_POOL_LIMIT);
    assert_eq!(
        count.load(std::sync::atomic::Ordering::Relaxed),
        ZSTD_CTX_POOL_LIMIT
    );
}

/// A context built past the pool limit is a working context; only its fate on
/// release differs, and releasing it must not disturb the pool.
#[test]
fn contexts_past_the_pool_limit_are_usable() {
    let contexts: Vec<ZstdDCtx> = (0..ZSTD_CTX_POOL_LIMIT + 4)
        .map(|_| zstd_decompress_ctx())
        .collect();

    assert!(contexts.iter().all(|ctx| !ctx.context.is_null()));
    assert!(
        contexts.iter().filter(|ctx| !ctx.pooled).count() >= 4,
        "the pool kept more contexts than its limit"
    );

    for ctx in contexts {
        zstd_decompress_ctx_done(ctx);
    }

    let ctx = zstd_decompress_ctx();
    assert!(
        !ctx.context.is_null(),
        "the pool did not survive releasing transient contexts"
    );
    zstd_decompress_ctx_done(ctx);
}

/// Content that would not shrink is refused as [`InefficientCompression`], not as
/// a zstd failure: the two are distinct so that a context too small for its input
/// cannot pass for content that does not compress.
#[test]
fn zstd_refuses_content_it_cannot_shrink() {
    let length = 16 * 1024;
    let source = incompressible_payload(length);

    let result = compress_zstd_impl(
        raw_fragment(length),
        source.as_slice(),
        BytesMut::with_capacity(compress_bound(length, CompressionMode::Zstd)),
    );

    assert!(
        matches!(
            result,
            Err(CompressFragmentError::InefficientCompression(_))
        ),
        "incompressible content was not refused as inefficient"
    );
}

/// A zstd failure is an internal error rather than [`InefficientCompression`], so
/// that a context too small for its input cannot pass for content that does not
/// compress and be stored uncompressed in silence.
#[test]
fn a_zstd_failure_is_not_inefficient_compression() {
    let source = payload(4 * 1024);
    let mut destination = [0u8; 8];
    let ctx = zstd_compress_ctx();
    assert!(!ctx.context.is_null());

    // Safety: the context is non-null and both buffers are valid for the lengths
    // given. The destination is deliberately too small to hold a frame.
    let code = unsafe {
        zstd_sys::ZSTD_compressCCtx(
            ctx.context,
            destination.as_mut_ptr().cast::<std::ffi::c_void>(),
            destination.len(),
            source.as_ptr().cast::<std::ffi::c_void>(),
            source.len(),
            zstd_compression_level(),
        )
    };
    zstd_compress_ctx_done(ctx);

    // Safety: Pure query on the return value, no pointer dereference.
    assert!(unsafe { zstd_sys::ZSTD_isError(code) } != 0);
    assert!(zstd_compress_failure(&zstd_error_name(code)).is_internal());
}

/// New Oodle compressed fragments are refused, so no new Oodle fragments
/// can be generated for a local store.
///
/// Existing Oodle fragments can be read so they can be migrated off Oodle.
#[cfg(feature = "oodle")]
mod oodle_deprecation {
    use super::*;

    #[test]
    fn compress_refuses_oodle() {
        let length = FRAGMENT_SIZE_EXPECTED;
        let source = payload(length);

        let error = compress(
            raw_fragment(length),
            source.as_slice(),
            CompressionMode::Oodle,
        )
        .expect_err("Oodle is refused");

        let not_supported = error
            .as_not_supported()
            .unwrap_or_else(|| panic!("refused as {error:?}, not as unsupported"));
        assert!(
            not_supported
                .operation
                .contains("this mode is being deprecated"),
            "refused for a reason other than the deprecation: {}",
            not_supported.operation
        );
    }

    // Until Local Immutable Stores are migrated off Oodle, storage
    // should still be able to read Oodle
    #[test]
    fn decompress_can_read_an_oodle_fragment() {
        let length = FRAGMENT_SIZE_EXPECTED;
        let source = payload(length);

        let (compressed_fragment, compressed) = compress_without_deprecation_checks(
            raw_fragment(length),
            source.as_slice(),
            CompressionMode::Oodle,
        )
        .expect("Oodle compresses");
        assert_ne!(
            compressed_fragment.flags & FragmentFlags::PayloadCompressedOodle2,
            0,
            "fragment was not marked as Oodle"
        );

        let (decompressed_fragment, decompressed) =
            decompress(compressed_fragment, compressed.as_ref()).expect("Oodle decompresses");

        assert_eq!(decompressed.as_ref(), source.as_slice());
        assert_eq!(decompressed_fragment.size_content, length as u64);
        assert_eq!(
            decompressed_fragment.flags & FragmentFlags::PayloadCompressed,
            0,
            "the decompressed fragment still carries a compression flag"
        );
    }
}

/// What a mode a server states it prefers does to the mode payloads are written under.
mod suggestions {
    use super::*;

    /// A selection standing where a suggestion arrives, as one made through the API does.
    fn selected(mode: CompressionMode) -> AtomicU32 {
        AtomicU32::new(mode as u32)
    }

    #[test]
    fn a_suggestion_is_taken_where_no_mode_is_selected() {
        let selection = selected(CompressionMode::NotSpecified);

        assert!(apply_mode_suggestion(&selection, CompressionMode::Lz4));
        assert_eq!(
            selection.load(Ordering::Relaxed),
            CompressionMode::Lz4 as u32
        );
    }

    #[test]
    fn a_suggestion_does_not_displace_a_selected_mode() {
        let selection = selected(CompressionMode::NoCompression);

        assert!(!apply_mode_suggestion(&selection, CompressionMode::Zstd));
        assert_eq!(
            selection.load(Ordering::Relaxed),
            CompressionMode::NoCompression as u32
        );
    }

    /// `NotSpecified` states no preference, so it is not a suggestion and leaves the selection
    /// where it is rather than reporting itself as the mode now in force.
    #[test]
    fn no_preference_is_not_a_suggestion() {
        let selection = selected(CompressionMode::NotSpecified);

        assert!(!apply_mode_suggestion(
            &selection,
            CompressionMode::NotSpecified
        ));
        assert_eq!(
            selection.load(Ordering::Relaxed),
            CompressionMode::NotSpecified as u32
        );
    }

    #[test]
    fn only_the_first_suggestion_decides() {
        let selection = selected(CompressionMode::NotSpecified);

        assert!(apply_mode_suggestion(&selection, CompressionMode::Lz4));
        assert!(!apply_mode_suggestion(&selection, CompressionMode::Zstd));
        assert_eq!(
            selection.load(Ordering::Relaxed),
            CompressionMode::Lz4 as u32
        );
    }

    #[test]
    fn every_mode_a_payload_can_be_written_under_is_named() {
        for (value, mode) in [
            (0, CompressionMode::NotSpecified),
            (1, CompressionMode::NoCompression),
            (2, CompressionMode::Lz4),
            (4, CompressionMode::Zstd),
        ] {
            assert_eq!(writable_compression_mode(value), Some(mode));
        }
    }

    /// Oodle and any number no variant carries answer `None` alike, so neither a server nor a
    /// caller can select a mode the first write would fail on.
    #[test]
    fn a_mode_no_payload_can_be_written_under_is_refused() {
        assert_eq!(writable_compression_mode(3), None);
        assert_eq!(writable_compression_mode(5), None);
        assert_eq!(writable_compression_mode(u32::MAX), None);
    }
}

/// What each source contributes to the level a codec ends up at, over zstd's range and
/// Oodle's, which is the narrower of the two.
mod levels {
    use super::*;

    #[test]
    fn a_level_the_environment_names_outranks_a_selection() {
        assert_eq!(
            accepted_compression_level(Some(3), Some(19), 1..=22),
            Some(3)
        );
    }

    #[test]
    fn a_selection_decides_where_the_environment_names_nothing() {
        assert_eq!(accepted_compression_level(None, Some(19), 1..=22), Some(19));
    }

    #[test]
    fn a_level_outside_the_range_is_not_taken_from_the_environment() {
        assert_eq!(
            accepted_compression_level(Some(99), Some(19), 1..=22),
            Some(19)
        );
        assert_eq!(accepted_compression_level(Some(99), None, 1..=22), None);
    }

    #[test]
    fn a_selection_outside_the_range_is_clamped_into_it() {
        assert_eq!(accepted_compression_level(None, Some(99), 1..=22), Some(22));
        assert_eq!(accepted_compression_level(None, Some(0), 1..=22), Some(1));
        assert_eq!(accepted_compression_level(None, Some(19), 0..=9), Some(9));
    }

    #[test]
    fn nothing_configured_leaves_the_codec_at_its_default() {
        assert_eq!(accepted_compression_level(None, None, 1..=22), None);
    }

    #[test]
    fn the_default_level_selects_none() {
        assert_eq!(selected_level(DEFAULT_COMPRESSION_LEVEL), None);
    }

    /// A level below every codec's range is a level, not the absence of one: it selects, and
    /// each codec clamps it to the lowest that codec accepts.
    #[test]
    fn a_level_below_every_range_still_selects() {
        let selected = selected_level(-5);

        assert_eq!(selected, Some(-5));
        assert_eq!(
            accepted_compression_level(None, selected, ZSTD_LEVELS),
            Some(1)
        );
        assert_eq!(accepted_compression_level(None, selected, 0..=9), Some(0));
    }
}
