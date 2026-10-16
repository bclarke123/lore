// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::borrow::Cow;

use lore_revision::util::encoding::*;

/// The text of a filter file, in the shape that tells the encodings apart:
/// ASCII rules on several lines.
const RULES: &str = "# comment\n*.log\n/Intermediate\n!keep.txt\n";

const ORDERS: [Utf16ByteOrder; 2] = [Utf16ByteOrder::Little, Utf16ByteOrder::Big];

/// `text` as UTF-8, behind the byte-order mark when `bom`.
fn as_utf8(text: &str, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend([0xEF, 0xBB, 0xBF]);
    }
    bytes.extend(text.as_bytes());
    bytes
}

/// `text` as UTF-16 in `order`, behind the matching byte-order mark when
/// `bom`.
fn as_utf16(text: &str, order: Utf16ByteOrder, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend(match order {
            Utf16ByteOrder::Little => [0xFF, 0xFE],
            Utf16ByteOrder::Big => [0xFE, 0xFF],
        });
    }
    bytes.extend(text.encode_utf16().flat_map(|unit| match order {
        Utf16ByteOrder::Little => unit.to_le_bytes(),
        Utf16ByteOrder::Big => unit.to_be_bytes(),
    }));
    bytes
}

/// `text` as UTF-32 in `order`, behind the matching byte-order mark when
/// `bom`. The byte order is the same idea UTF-16 has, so it is named with
/// the same type.
fn as_utf32(text: &str, order: Utf16ByteOrder, bom: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    if bom {
        bytes.extend(match order {
            Utf16ByteOrder::Little => [0xFF, 0xFE, 0x00, 0x00],
            Utf16ByteOrder::Big => [0x00, 0x00, 0xFE, 0xFF],
        });
    }
    bytes.extend(text.chars().flat_map(|character| match order {
        Utf16ByteOrder::Little => u32::from(character).to_le_bytes(),
        Utf16ByteOrder::Big => u32::from(character).to_be_bytes(),
    }));
    bytes
}

#[test]
fn decode_utf8_passthrough() {
    assert_eq!(decode_text_for_display(&as_utf8(RULES, false)), RULES);
}

#[test]
fn decode_utf8_with_bom() {
    assert_eq!(decode_text_for_display(&as_utf8(RULES, true)), RULES);
}

#[test]
fn decode_utf16_with_bom() {
    for order in ORDERS {
        assert_eq!(
            decode_text_for_display(&as_utf16(RULES, order, true)),
            RULES,
            "{order:?}"
        );
    }
}

#[test]
fn decode_utf16_le_with_crlf() {
    let content = "Line one\r\nLine two\r\n";
    let bytes = as_utf16(content, Utf16ByteOrder::Little, true);
    assert_eq!(decode_text_for_display(&bytes), content);
}

/// [`decode_text_for_display`] acts on a mark alone, so mark-less UTF-16
/// reaches it as the bytes it is.
#[test]
fn decode_leaves_bomless_utf16_undecoded() {
    for order in ORDERS {
        let bytes = as_utf16(RULES, order, false);
        assert_ne!(decode_text_for_display(&bytes), RULES, "{order:?}");
    }
}

#[test]
fn decode_empty_input() {
    assert_eq!(decode_text_for_display(b""), "");
}

#[test]
fn is_utf16_bom_detects_le() {
    assert!(is_utf16_bom(&[0xFF, 0xFE, 0x00]));
}

#[test]
fn is_utf16_bom_detects_be() {
    assert!(is_utf16_bom(&[0xFE, 0xFF, 0x00]));
}

#[test]
fn is_utf16_bom_rejects_short_or_other() {
    assert!(!is_utf16_bom(b""));
    assert!(!is_utf16_bom(&[0xFF]));
    assert!(!is_utf16_bom(&[0xEF, 0xBB, 0xBF]));
    assert!(!is_utf16_bom(b"hello"));
}

#[test]
fn parsing_decodes_every_encoding() {
    for bom in [false, true] {
        assert_eq!(
            decode_text_for_parsing(&as_utf8(RULES, bom)).expect("UTF-8"),
            RULES,
            "UTF-8, mark: {bom}"
        );
        for order in ORDERS {
            assert_eq!(
                decode_text_for_parsing(&as_utf16(RULES, order, bom)).expect("UTF-16"),
                RULES,
                "UTF-16 {order:?}, mark: {bom}"
            );
        }
    }
}

/// UTF-8 needs no transcoding, so the decode hands back the input.
#[test]
fn parsing_borrows_utf8() {
    for bom in [false, true] {
        let bytes = as_utf8(RULES, bom);
        assert!(
            matches!(decode_text_for_parsing(&bytes), Ok(Cow::Borrowed(_))),
            "UTF-8 was copied, mark: {bom}"
        );
    }
}

/// CRLF is what an editor that writes UTF-16 also tends to write, and the
/// `\r` has to survive to where the parser trims it.
#[test]
fn parsing_decodes_utf16_crlf_without_bom() {
    let text = "*.log\r\n/Intermediate\r\n";
    let bytes = as_utf16(text, Utf16ByteOrder::Little, false);
    assert_eq!(decode_text_for_parsing(&bytes).expect("UTF-16 LE"), text);
}

#[test]
fn parsing_decodes_empty_input() {
    assert_eq!(decode_text_for_parsing(b"").expect("empty"), "");
}

/// A NUL is refused wherever it decodes from, and a mark does not excuse it:
/// no rule can hold one, so a rule that does matches nothing. A stray NUL is
/// also not the alternation UTF-16 leaves, so the file is not taken for
/// UTF-16 on the way there.
#[test]
fn parsing_refuses_a_nul_from_every_encoding() {
    let mut marked_utf16 = as_utf16(RULES, Utf16ByteOrder::Little, true);
    marked_utf16.extend([0x00, 0x00]);

    let cases: [(&str, Vec<u8>); 4] = [
        ("mark-less UTF-8", {
            let mut bytes = as_utf8(RULES, false);
            bytes.extend([0x00, b'x']);
            bytes
        }),
        ("UTF-8 behind a mark", {
            let mut bytes = as_utf8(RULES, true);
            bytes.extend([0x00, b'x']);
            bytes
        }),
        ("the reviewed case", b"\xEF\xBB\xBF*.log\0\n".to_vec()),
        ("U+0000 out of a UTF-16 code unit", marked_utf16),
    ];

    for (name, bytes) in cases {
        let error = decode_text_for_parsing(&bytes)
            .expect_err(&format!("{name} decoded instead of being refused"));
        assert!(
            error.reason.contains("NUL"),
            "{name}: the refusal must name the NUL, got {:?}",
            error.reason
        );
    }

    let mut stray = as_utf8(RULES, false);
    stray.extend([0x00, b'x']);
    assert_eq!(
        detect_bomless_utf16(&stray),
        None,
        "a stray NUL must not turn a UTF-8 file into UTF-16"
    );
}

/// A mark-less UTF-16 file whose rules lie outside ASCII leaves too little
/// alternation to name a byte order by, and what it leaves is valid UTF-8 of
/// unrelated text: UTF-16 LE `你好\n` is `` `O}Y `` and a NUL. It is refused
/// on that NUL rather than filtered on a rule it never held.
#[test]
fn parsing_refuses_bomless_utf16_of_non_ascii_rules() {
    let text = "你好\n";
    assert_eq!(
        as_utf16(text, Utf16ByteOrder::Little, false),
        [0x60, 0x4F, 0x7D, 0x59, 0x0A, 0x00],
        "the case rests on these bytes"
    );

    for order in ORDERS {
        let bytes = as_utf16(text, order, false);
        assert_eq!(
            detect_bomless_utf16(&bytes),
            None,
            "{order:?} must be the case detection cannot name"
        );
        assert!(
            std::str::from_utf8(&bytes).is_ok(),
            "{order:?} must be the case where a UTF-8 decode would succeed"
        );
        assert!(
            decode_text_for_parsing(&bytes).is_err(),
            "mark-less UTF-16 {order:?} of non-ASCII rules was decoded, as {:?}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// The bound on that, stated so it is not mistaken for support. With no
/// character below U+0100 in it at all, a mark-less UTF-16 buffer leaves no
/// NUL either, and nothing tells it from the UTF-8 text its bytes spell. It
/// reads as that text, and such a file has to carry a mark.
#[test]
fn parsing_reads_bomless_utf16_with_no_ascii_at_all_as_utf8() {
    for (order, spelled) in [
        (Utf16ByteOrder::Little, "`O}Y"),
        (Utf16ByteOrder::Big, "O`Y}"),
    ] {
        let bytes = as_utf16("你好", order, false);
        assert_eq!(
            decode_text_for_parsing(&bytes).expect("valid UTF-8"),
            spelled,
            "{order:?}"
        );
    }
}

/// A mark-less UTF-16 file cut mid code unit is left holding ASCII beside
/// NULs, which is valid UTF-8. It is refused as the truncated UTF-16 it is.
#[test]
fn parsing_refuses_truncated_bomless_utf16() {
    for order in ORDERS {
        let mut bytes = as_utf16(RULES, order, false);
        bytes.pop();
        let error = decode_text_for_parsing(&bytes)
            .expect_err(&format!("truncated UTF-16 {order:?} was decoded"));
        assert!(
            error.reason.contains("UTF-16"),
            "truncation must be reported against UTF-16, got {:?}",
            error.reason
        );
    }
}

/// Bytes no encoding accounts for are refused, so a parser is never handed a
/// U+FFFD where the file had something it could not read.
#[test]
fn parsing_refuses_malformed_input() {
    let cases: [(&str, Vec<u8>); 10] = [
        ("invalid UTF-8", vec![b'*', 0xC3, 0x28, b'\n']),
        ("invalid UTF-8 behind a mark", {
            let mut bytes = vec![0xEF, 0xBB, 0xBF];
            bytes.extend([b'*', 0xC3, 0x28, b'\n']);
            bytes
        }),
        ("truncated UTF-16 code unit", {
            let mut bytes = as_utf16(RULES, Utf16ByteOrder::Little, true);
            bytes.pop();
            bytes
        }),
        ("truncated mark-less UTF-16 LE", {
            let mut bytes = as_utf16(RULES, Utf16ByteOrder::Little, false);
            bytes.pop();
            bytes
        }),
        ("truncated mark-less UTF-16 BE", {
            let mut bytes = as_utf16(RULES, Utf16ByteOrder::Big, false);
            bytes.pop();
            bytes
        }),
        ("unpaired UTF-16 surrogate", {
            let mut bytes = as_utf16(RULES, Utf16ByteOrder::Little, true);
            bytes.splice(2..2, [0x00, 0xD8]);
            bytes
        }),
        ("UTF-32 LE", as_utf32(RULES, Utf16ByteOrder::Little, true)),
        ("UTF-32 BE", as_utf32(RULES, Utf16ByteOrder::Big, true)),
        (
            "mark-less UTF-32 LE",
            as_utf32(RULES, Utf16ByteOrder::Little, false),
        ),
        (
            "mark-less UTF-32 BE",
            as_utf32(RULES, Utf16ByteOrder::Big, false),
        ),
    ];

    for (name, bytes) in cases {
        assert!(
            decode_text_for_parsing(&bytes).is_err(),
            "{name} was decoded instead of refused"
        );
    }
}

/// A mark-less UTF-32 file is ASCII interleaved with NULs, which is valid
/// UTF-8. The shape has to be recognised on its own and refused as UTF-32.
#[test]
fn parsing_refuses_bomless_utf32() {
    for order in ORDERS {
        let bytes = as_utf32(RULES, order, false);
        assert!(
            std::str::from_utf8(&bytes).is_ok(),
            "{order:?} must be the case where a UTF-8 decode would succeed"
        );

        let error = decode_text_for_parsing(&bytes)
            .expect_err(&format!("mark-less UTF-32 {order:?} was decoded"));
        assert!(
            error.reason.contains("UTF-32"),
            "the refusal must name UTF-32, got {:?}",
            error.reason
        );
    }
}

/// Mark-less UTF-16 must not answer to the UTF-32 shape. That shape is
/// checked first, so a false positive would refuse a file this module
/// decodes.
#[test]
fn detect_tells_utf32_from_utf16_and_utf8() {
    for order in ORDERS {
        assert!(
            is_bomless_utf32(&as_utf32(RULES, order, false)),
            "{order:?}"
        );
        assert!(
            !is_bomless_utf32(&as_utf16(RULES, order, false)),
            "UTF-16 {order:?} was taken for UTF-32"
        );
    }
    assert!(!is_bomless_utf32(b""));
    assert!(!is_bomless_utf32(RULES.as_bytes()));
}

/// UTF-32 LE opens with the UTF-16 LE mark, and must not be taken for it:
/// parsing refuses it, and neither [`is_utf16_bom`] nor
/// [`decode_text_for_display`] reads it as UTF-16.
#[test]
fn utf32_is_not_taken_for_utf16() {
    let bytes = as_utf32(RULES, Utf16ByteOrder::Little, true);

    assert!(
        decode_text_for_parsing(&bytes).is_err(),
        "UTF-32 must be refused"
    );
    assert!(!is_utf16_bom(&bytes), "UTF-32 must report no UTF-16 mark");
    assert_ne!(
        decode_text_for_display(&bytes),
        decode_utf16_lossy(&bytes[2..], Utf16ByteOrder::Little),
        "UTF-32 must not be rendered as UTF-16"
    );
}

/// UTF-8, and a single code unit ahead of a trailing byte: too little to
/// name an order over.
#[test]
fn detect_rejects_utf8_and_a_lone_code_unit() {
    assert_eq!(detect_bomless_utf16(b""), None);
    assert_eq!(detect_bomless_utf16(RULES.as_bytes()), None);
    assert_eq!(detect_bomless_utf16(&[b'a', 0x00, b'b']), None);
}

/// NULs at both offsets are not the every-other-byte pattern UTF-16 leaves,
/// so neither order wins.
#[test]
fn detect_rejects_nuls_at_both_offsets() {
    assert_eq!(detect_bomless_utf16(&[0x00; 8]), None);
}

#[test]
fn detect_names_the_byte_order() {
    for order in ORDERS {
        let bytes = as_utf16(RULES, order, false);
        assert_eq!(detect_bomless_utf16(&bytes), Some(order));
    }
}

/// A trailing byte does not hide the pattern. Naming the order for a
/// truncated buffer is what carries it to the UTF-16 decode that refuses it.
#[test]
fn detect_names_the_byte_order_of_truncated_utf16() {
    for order in ORDERS {
        let mut bytes = as_utf16(RULES, order, false);
        bytes.pop();
        assert_eq!(detect_bomless_utf16(&bytes), Some(order), "{order:?}");
    }
}
