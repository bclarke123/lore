// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::borrow::Cow;

use crate::errors::InvalidArguments;

/// The order a UTF-16 buffer pairs its bytes in.
#[lore_macro::test_pub]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Utf16ByteOrder {
    Little,
    Big,
}

impl Utf16ByteOrder {
    /// The name the byte order goes by in a message a person reads.
    fn label(self) -> &'static str {
        match self {
            Self::Little => "LE",
            Self::Big => "BE",
        }
    }
}

/// An encoding a byte-order mark names.
enum Encoding {
    Utf8,
    Utf16(Utf16ByteOrder),
    /// Recognised only so that it can be refused: Lore does not decode UTF-32.
    Utf32,
}

/// Splits a leading byte-order mark off `bytes`, naming the encoding it marks
/// and returning the bytes after it.
///
/// The marks are `FF FE 00 00` for UTF-32 LE, `00 00 FE FF` for UTF-32 BE,
/// `FF FE` for UTF-16 LE, `FE FF` for UTF-16 BE and `EF BB BF` for UTF-8. UTF-32
/// LE is matched before UTF-16 LE because it opens with the same two bytes, and
/// a UTF-32 file read as UTF-16 decodes to its text with a NUL beside every
/// character rather than to anything a reader would question.
///
/// A mark is the one case where the encoding does not have to be inferred from
/// the text, so every decode consults this first.
fn split_bom(bytes: &[u8]) -> Option<(Encoding, &[u8])> {
    if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE, 0x00, 0x00]) {
        return Some((Encoding::Utf32, payload));
    }
    if let Some(payload) = bytes.strip_prefix(&[0x00, 0x00, 0xFE, 0xFF]) {
        return Some((Encoding::Utf32, payload));
    }
    if let Some(payload) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return Some((Encoding::Utf16(Utf16ByteOrder::Little), payload));
    }
    if let Some(payload) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return Some((Encoding::Utf16(Utf16ByteOrder::Big), payload));
    }
    if let Some(payload) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return Some((Encoding::Utf8, payload));
    }
    None
}

/// The code units of an already-paired UTF-16 payload, read in `order`.
fn utf16_units(pairs: &[[u8; 2]], order: Utf16ByteOrder) -> impl Iterator<Item = u16> + '_ {
    pairs.iter().map(move |pair| match order {
        Utf16ByteOrder::Little => u16::from_le_bytes(*pair),
        Utf16ByteOrder::Big => u16::from_be_bytes(*pair),
    })
}

/// Decodes a UTF-16 payload, with any byte-order mark already removed,
/// substituting U+FFFD for an unpaired surrogate as `String::from_utf8_lossy`
/// does for a malformed sequence.
///
/// A trailing odd byte cannot complete a code unit and is dropped.
#[lore_macro::test_pub]
fn decode_utf16_lossy(payload: &[u8], order: Utf16ByteOrder) -> String {
    char::decode_utf16(utf16_units(payload.as_chunks::<2>().0, order))
        .map(|unit| unit.unwrap_or('\u{FFFD}'))
        .collect()
}

/// Decodes a UTF-16 payload, with any byte-order mark already removed, refusing
/// a trailing byte that cannot complete a code unit and any unpaired surrogate.
fn decode_utf16(payload: &[u8], order: Utf16ByteOrder) -> Result<String, InvalidArguments> {
    let (pairs, remainder) = payload.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(InvalidArguments {
            reason: format!("UTF-16 {} ends mid code unit", order.label()),
        });
    }
    char::decode_utf16(utf16_units(pairs, order))
        .collect::<Result<String, _>>()
        .map_err(|error| InvalidArguments {
            reason: format!("not valid UTF-16 {}: {error}", order.label()),
        })
}

/// The refusal UTF-32 meets wherever it is recognised, by its mark or by its
/// shape: Lore does not decode it.
fn refuse_utf32() -> InvalidArguments {
    InvalidArguments {
        reason: "UTF-32 is not a supported encoding".to_string(),
    }
}

/// Decodes UTF-8, with any byte-order mark already removed, refusing a malformed
/// sequence.
fn decode_utf8(bytes: &[u8]) -> Result<&str, InvalidArguments> {
    std::str::from_utf8(bytes).map_err(|error| InvalidArguments {
        reason: format!("not valid UTF-8: {error}"),
    })
}

/// Refuses decoded text holding a NUL, whatever encoding produced it.
///
/// No platform admits a NUL in a path, so a rule holding one matches nothing,
/// which is the silent failure this decode exists to prevent. A mark settles
/// what the bytes are, not what a rule may hold, so `EF BB BF *.log\0\n` is
/// refused like any other.
///
/// On mark-less bytes a NUL also marks an encoding that went unnamed: UTF-16 too
/// far outside ASCII for [`detect_bomless_utf16`] still leaves the NULs of its
/// line endings. UTF-16 LE `你好\n` is `60 4F 7D 59 0A 00`, valid UTF-8 spelling
/// `` `O}Y `` and a NUL.
fn refuse_nul(text: &str) -> Result<(), InvalidArguments> {
    match text.find('\0') {
        Some(offset) => Err(InvalidArguments {
            reason: format!(
                "NUL at byte {offset} of the decoded text: no rule can hold one, \
                 and UTF-16 or UTF-32 needs a byte-order mark to be decoded as such"
            ),
        }),
        None => Ok(()),
    }
}

/// Whether the side more NULs fall on holds enough of a majority to name the
/// encoding they are evidence of.
///
/// The winning side must cover at least half the code units, so a file merely
/// containing a NUL is not taken for a wider encoding, and it must leave the
/// other side well behind. The other side need not be empty: a character of the
/// form U+xx00, U+4E00 among them, puts a NUL on it.
fn nul_majority_holds(winner: usize, loser: usize, units: usize) -> bool {
    winner * 2 >= units && winner > loser * 4
}

/// Whether `bytes` holds UTF-32 that carries no byte-order mark.
///
/// A character in the Basic Multilingual Plane, which a filter file is made of,
/// encodes to UTF-32 as two bytes beside two NULs: the last two under LE, the
/// first two under BE. [`nul_majority_holds`] decides it, over quads rather than
/// the pairs UTF-16 is counted in.
///
/// The winning order is not reported and a trailing remainder is not weighed,
/// since UTF-32 is refused either way.
///
/// Asked before UTF-16, as [`split_bom`] matches the UTF-32 marks first. Read as
/// UTF-8, a UTF-32 buffer decodes to its text with three NULs beside every
/// character, all of them valid UTF-8.
#[lore_macro::test_pub]
fn is_bomless_utf32(bytes: &[u8]) -> bool {
    let units = bytes.as_chunks::<4>().0;
    if units.is_empty() {
        return false;
    }

    let (little, big) = units.iter().fold((0usize, 0usize), |(little, big), quad| {
        (
            little + usize::from(quad[2] == 0 && quad[3] == 0),
            big + usize::from(quad[0] == 0 && quad[1] == 0),
        )
    });

    nul_majority_holds(little.max(big), little.min(big), units.len())
}

/// Names the byte order of a buffer holding UTF-16 that carries no byte-order
/// mark, or `None` when the buffer is not UTF-16.
///
/// The evidence is NUL bytes: an ASCII character encodes to UTF-16 as its own
/// byte beside a NUL — at the odd offset under LE, the even one under BE — while
/// UTF-8 text has no reason to hold a NUL at all. The side the NULs fall on
/// therefore names the byte order, once [`nul_majority_holds`] is satisfied
/// there are enough of them to go on.
///
/// A trailing byte that pairs with nothing does not rule UTF-16 out; it says the
/// buffer is cut mid code unit. The order is named for it too, so that
/// [`decode_utf16`] refuses it as truncated rather than leaving ASCII beside
/// NULs to pass as UTF-8. An odd length is evidence against UTF-16 as well, so a
/// lone code unit's NUL does not settle it.
///
/// Detection needs ASCII to find. A mark-less UTF-16 file whose text lies mostly
/// outside ASCII leaves too little alternation to name an order by, and
/// [`refuse_nul`] then refuses it on the NUL its line endings leave. Only a
/// buffer with no character below U+0100 in it at all, line ending included,
/// leaves no evidence either way, and that one has to carry a mark.
#[lore_macro::test_pub]
fn detect_bomless_utf16(bytes: &[u8]) -> Option<Utf16ByteOrder> {
    let (units, remainder) = bytes.as_chunks::<2>();
    let minimum = if remainder.is_empty() { 1 } else { 2 };
    if units.len() < minimum {
        return None;
    }

    let (little, big) = units
        .iter()
        .fold((0usize, 0usize), |(little, big), [even, odd]| {
            (
                little + usize::from(*odd == 0),
                big + usize::from(*even == 0),
            )
        });

    let (order, winner, loser) = if little >= big {
        (Utf16ByteOrder::Little, little, big)
    } else {
        (Utf16ByteOrder::Big, big, little)
    };
    nul_majority_holds(winner, loser, units.len()).then_some(order)
}

/// Decodes raw file bytes for **display or read-only inspection**: diff
/// rendering, conflict-marker scanning, log output, and similar paths where the
/// caller never writes the result back to disk.
///
/// Strips a UTF-8 BOM (`EF BB BF`) and converts UTF-16 LE / BE BOM input to
/// UTF-8. Both transformations are lossy from a round-trip-to-disk
/// perspective: the BOM bytes are gone, and the UTF-16 byte order is
/// gone. Never feed this function's output into a writer that persists to
/// disk — use `String::from_utf8_lossy` (which is a lossless passthrough
/// for valid UTF-8, including UTF-8 BOM) for that case.
///
/// Borrows valid UTF-8, marked or not, and allocates only to transcode UTF-16 or
/// to stand U+FFFD in for what it cannot read. Malformed input is rendered
/// rather than refused, because something unreadable on screen is more use to a
/// person than nothing at all. Use [`decode_text_for_parsing`] where the result
/// is read by code, which needs the opposite.
///
/// Acts on a byte-order mark only, so mark-less UTF-16 is not recognised, and
/// UTF-32 is left as the bytes it is rather than read as the UTF-16 its mark
/// opens like.
pub fn decode_text_for_display(bytes: &[u8]) -> Cow<'_, str> {
    match split_bom(bytes) {
        Some((Encoding::Utf16(order), payload)) => Cow::Owned(decode_utf16_lossy(payload, order)),
        Some((Encoding::Utf8, payload)) => String::from_utf8_lossy(payload),
        Some((Encoding::Utf32, _)) | None => String::from_utf8_lossy(bytes),
    }
}

/// Decodes the bytes of a text file Lore **parses** — a filter file, and
/// anything else read for its lines rather than shown to a person.
///
/// Accepts the six shapes such a file arrives in: UTF-8, UTF-16 LE and UTF-16
/// BE, each with or without a byte-order mark. The mark is consumed rather than
/// decoded, so the first line parses as itself rather than as itself behind an
/// invisible U+FEFF. Where [`decode_text_for_display`] acts on a mark alone,
/// this reads the bytes themselves as well, through [`is_bomless_utf32`] and
/// [`detect_bomless_utf16`]: a parser has nothing downstream that would notice
/// text arriving as characters alternating with NULs, and would take the NULs as
/// part of the rules.
///
/// Mark-less UTF-16 is inferred rather than declared, so it carries a bound.
/// Rules mostly of ASCII are detected and decoded; rules mostly outside ASCII
/// are refused on the NUL their line endings leave, rather than decoded as the
/// unrelated UTF-8 text the same bytes spell; a buffer with no character below
/// U+0100 in it at all has to carry a mark.
///
/// No decode yields a NUL, whatever named its encoding. [`refuse_nul`] runs on
/// every result, a mark settling what the bytes are and not what a rule may hold.
///
/// Malformed input is refused rather than repaired, and UTF-32 is refused
/// outright, mark or no mark. A U+FFFD standing in for bytes that could not be
/// read is silent by the time it reaches a parser, which carries it into a rule
/// that then matches something other than what the file names; an error leaves
/// the caller able to name the file it cannot honour.
///
/// Borrows valid UTF-8, marked or not. Allocating is confined to transcoding
/// UTF-16.
///
/// Like [`decode_text_for_display`], the result does not round-trip to disk: the
/// mark and the UTF-16 byte order are both gone from it, so a caller that writes
/// the file back writes UTF-8 without a mark.
pub fn decode_text_for_parsing(bytes: &[u8]) -> Result<Cow<'_, str>, InvalidArguments> {
    let text = match split_bom(bytes) {
        Some((Encoding::Utf32, _)) => Err(refuse_utf32()),
        Some((Encoding::Utf16(order), payload)) => decode_utf16(payload, order).map(Cow::Owned),
        Some((Encoding::Utf8, payload)) => decode_utf8(payload).map(Cow::Borrowed),
        None if is_bomless_utf32(bytes) => Err(refuse_utf32()),
        None => match detect_bomless_utf16(bytes) {
            Some(order) => decode_utf16(bytes, order).map(Cow::Owned),
            None => decode_utf8(bytes).map(Cow::Borrowed),
        },
    }?;
    refuse_nul(&text)?;
    Ok(text)
}

/// Returns `true` when `bytes` starts with a UTF-16 LE (FF FE) or BE (FE FF) byte-order mark.
pub fn is_utf16_bom(bytes: &[u8]) -> bool {
    matches!(split_bom(bytes), Some((Encoding::Utf16(_), _)))
}
