// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::lore::thin_client::v1::ContentDiffHeader;
use lore_proto::lore::thin_client::v1::ContentDiffRequest;
use lore_proto::lore::thin_client::v1::content_diff_response::Payload;
use lore_server::grpc::thinclient::v1::content_diff::*;
use lore_storage::WriteOptions;
use tokio_stream::StreamExt;
use tonic::Request;

use crate::store::test_support::test_store_create;

async fn write_blob(
    store: &Arc<dyn lore_storage::ImmutableStore>,
    partition: lore_base::types::Partition,
    content: &[u8],
) -> Option<lore_proto::lore::model::v1::Address> {
    // Non-default context: exact (hash, context) addressing is exercised
    // end to end, mirroring production DiffChange addresses against an
    // isolating store.
    let result = lore_storage::write_content(
        store.clone(),
        partition,
        Context::from([7u8; 16].as_ref()),
        bytes::Bytes::copy_from_slice(content),
        WriteOptions::default().no_remote_write(),
        None,
        lore_storage::WriteContext::none(),
        None,
    )
    .await
    .expect("write blob");
    Some(lore_proto::lore::model::v1::Address::from(&result.address))
}

async fn run_diff(
    store: Arc<dyn lore_storage::ImmutableStore>,
    partition: lore_base::types::Partition,
    from: Option<lore_proto::lore::model::v1::Address>,
    to: Option<lore_proto::lore::model::v1::Address>,
    max_diff_size: Option<u64>,
) -> (ContentDiffHeader, String) {
    let mut request = Request::new(ContentDiffRequest {
        address_from: from,
        address_to: to,
        address_base: None,
        context_lines: None,
        ignore_whitespace_eol: false,
        ignore_whitespace_inline: false,
        max_diff_size,
    });
    request.metadata_mut().insert_bin(
        "urc-repository-id-bin",
        tonic::metadata::BinaryMetadataValue::from_bytes(partition.as_ref()),
    );
    let mut stream = handler(request, store).await.expect("diff").into_inner();
    let mut header = None;
    let mut text = String::new();
    while let Some(item) = stream.next().await {
        match item.expect("stream item").payload {
            Some(Payload::Header(h)) => header = Some(h),
            Some(Payload::Chunk(chunk)) => text.push_str(&chunk.diff),
            None => panic!("payload unset"),
        }
    }
    (header.expect("header first"), text)
}

#[tokio::test]
async fn diff_modify_add_delete_binary_and_truncation() {
    let (store, _mutable, execution) = test_store_create().await.expect("test stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = lore_base::types::Partition::default();

        let old = write_blob(&store, partition, b"alpha\nbravo\ncharlie\n").await;
        let new = write_blob(&store, partition, b"alpha\nBRAVO\ncharlie\ndelta\n").await;

        // Modify: one line changed, one added.
        let (header, text) =
            run_diff(store.clone(), partition, old.clone(), new.clone(), None).await;
        assert_eq!(header.lines_added, 2);
        assert_eq!(header.lines_deleted, 1);
        assert!(!header.binary && !header.truncated);
        assert!(text.contains("-bravo\n"), "diff text: {text}");
        assert!(text.contains("+BRAVO\n"));
        assert!(text.contains("+delta\n"));

        // Add: empty from side.
        let (header, text) = run_diff(store.clone(), partition, None, new.clone(), None).await;
        assert_eq!(header.lines_added, 4);
        assert_eq!(header.lines_deleted, 0);
        assert!(text.contains("+alpha\n"));

        // Delete: empty to side.
        let (header, _text) = run_diff(store.clone(), partition, old.clone(), None, None).await;
        assert_eq!(header.lines_added, 0);
        assert_eq!(header.lines_deleted, 3);

        // Binary input short-circuits (PNG magic → non-diffable mime).
        let binary = write_blob(&store, partition, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR").await;
        let (header, text) = run_diff(store.clone(), partition, old.clone(), binary, None).await;
        assert!(header.binary);
        assert!(text.is_empty());
        assert_eq!(header.lines_added, 0);

        // Truncation: stats survive, no chunks.
        let (header, text) = run_diff(store.clone(), partition, old, new, Some(4)).await;
        assert!(header.truncated);
        assert!(text.is_empty());
        assert_eq!(header.lines_added, 2);
    }))
    .await;
}

/// Deterministic pseudo-random bytes with a PNG magic prefix, so the
/// content both fragments (when large) and sniffs as binary.
fn binary_buffer(len: usize, seed: u64) -> Vec<u8> {
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut state = seed | 1;
    while out.len() < len {
        // xorshift64
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[tokio::test]
async fn binary_ranges_mutation_and_shift() {
    let (store, _mutable, execution) = test_store_create().await.expect("test stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = lore_base::types::Partition::default();
        const SIZE: usize = 1024 * 1024;

        let v1 = binary_buffer(SIZE, 42);
        // Same-length mutation of a 10 KiB slice in the middle.
        let mut v2 = v1.clone();
        for byte in &mut v2[500_000..510_240] {
            *byte ^= 0xA5;
        }

        let a1 = write_blob(&store, partition, &v1).await;
        let a2 = write_blob(&store, partition, &v2).await;
        let (header, text) = run_diff(store.clone(), partition, a1.clone(), a2, None).await;
        assert!(header.binary);
        assert!(text.is_empty());
        assert_eq!(header.size_from, SIZE as u64);
        assert_eq!(header.size_to, SIZE as u64);
        assert!(!header.runs_truncated);
        assert!(!header.matched_runs.is_empty(), "chunks should re-sync");
        // Prefix run anchors at 0/0; a gap covers the mutation.
        let first = &header.matched_runs[0];
        assert_eq!((first.offset_from, first.offset_to), (0, 0));
        let matched: u64 = header.matched_runs.iter().map(|r| r.length).sum();
        assert!(matched < SIZE as u64, "mutation must leave a gap");
        assert!(
            matched > SIZE as u64 / 2,
            "most content unchanged, matched only {matched}"
        );
        // Same-length mutation: matched runs must not drift.
        for run in &header.matched_runs {
            assert_eq!(run.offset_from, run.offset_to);
        }

        // Insertion: splice bytes in mid-file; suffix runs shift by the
        // inserted length (content-defined chunking re-syncs).
        const INSERTED: usize = 100_000;
        let mut v3 = v1.clone();
        let insert = binary_buffer(INSERTED, 7);
        v3.splice(500_000..500_000, insert);
        let a3 = write_blob(&store, partition, &v3).await;
        let (header, _) = run_diff(store.clone(), partition, a1, a3, None).await;
        assert_eq!(header.size_from, SIZE as u64);
        assert_eq!(header.size_to, (SIZE + INSERTED) as u64);
        assert!(
            header
                .matched_runs
                .iter()
                .any(|r| r.offset_to - r.offset_from == INSERTED as u64),
            "expected a run shifted by the inserted length; runs: {:?}",
            header
                .matched_runs
                .iter()
                .map(|r| (r.offset_from, r.offset_to, r.length))
                .collect::<Vec<_>>()
        );
    }))
    .await;
}

#[tokio::test]
async fn binary_section_move_to_end_is_detected() {
    let (store, _mutable, execution) = test_store_create().await.expect("test stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = lore_base::types::Partition::default();
        const SIZE: usize = 2 * 1024 * 1024;
        let v1 = binary_buffer(SIZE, 21);
        // Cut 256 KiB from the middle and append it at the end — the
        // moved section sits EARLIER in from-order than the tail, so
        // only the relocation pass can pair it.
        const CUT_AT: usize = 800_000;
        const CUT_LEN: usize = 256 * 1024;
        let mut v2 = Vec::with_capacity(SIZE);
        v2.extend_from_slice(&v1[..CUT_AT]);
        v2.extend_from_slice(&v1[CUT_AT + CUT_LEN..]);
        v2.extend_from_slice(&v1[CUT_AT..CUT_AT + CUT_LEN]);

        let a1 = write_blob(&store, partition, &v1).await;
        let a2 = write_blob(&store, partition, &v2).await;
        let (header, _) = run_diff(store.clone(), partition, a1, a2, None).await;
        assert!(header.binary);
        // A run must land near the end of the to side while pointing
        // back into the middle of the from side: the moved section.
        let moved = header
            .matched_runs
            .iter()
            .find(|r| {
                r.offset_to > (SIZE - CUT_LEN - 100_000) as u64 && r.offset_from < r.offset_to
            })
            .unwrap_or_else(|| {
                panic!(
                    "expected relocated run near the end; runs: {:?}",
                    header
                        .matched_runs
                        .iter()
                        .map(|r| (r.offset_from, r.offset_to, r.length))
                        .collect::<Vec<_>>()
                )
            });
        // It must cover most of the moved section (splice-boundary
        // chunks legitimately re-chunk).
        assert!(
            moved.length > (CUT_LEN / 2) as u64,
            "moved run too small: {}",
            moved.length
        );
        // And point back to roughly where the section used to live.
        assert!(
            (moved.offset_from as i64 - CUT_AT as i64).unsigned_abs() < 200_000,
            "moved run origin {} not near cut point {CUT_AT}",
            moved.offset_from
        );
    }))
    .await;
}

#[tokio::test]
async fn binary_over_input_cap_still_gets_ranges() {
    let (store, _mutable, execution) = test_store_create().await.expect("test stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = lore_base::types::Partition::default();
        // Over MAX_INPUT_BYTES: full reassembly is refused, but the
        // chunk-table path never reads content, so ranges still flow.
        const SIZE: usize = MAX_INPUT_BYTES as usize + 1024 * 1024;
        let v1 = binary_buffer(SIZE, 9);
        let mut v2 = v1.clone();
        for byte in &mut v2[1_000_000..1_050_000] {
            *byte ^= 0x5A;
        }
        let a1 = write_blob(&store, partition, &v1).await;
        let a2 = write_blob(&store, partition, &v2).await;
        let (header, text) = run_diff(store.clone(), partition, a1, a2, None).await;
        assert!(header.binary, "prefix sniff must classify as binary");
        assert!(!header.truncated);
        assert!(text.is_empty());
        assert_eq!(header.size_from, SIZE as u64);
        assert_eq!(header.size_to, SIZE as u64);
        assert!(!header.matched_runs.is_empty());
        let matched: u64 = header.matched_runs.iter().map(|r| r.length).sum();
        assert!(matched > SIZE as u64 / 2);
        assert!(matched < SIZE as u64);
    }))
    .await;
}

#[tokio::test]
async fn binary_small_files_single_chunk() {
    let (store, _mutable, execution) = test_store_create().await.expect("test stores");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let partition = lore_base::types::Partition::default();
        // Below FRAGMENT_SIZE_THRESHOLD: unfragmented, one pseudo-chunk
        // per side; differing content → no shared runs, sizes reported.
        let a = write_blob(&store, partition, &binary_buffer(4096, 1)).await;
        let b = write_blob(&store, partition, &binary_buffer(4096, 2)).await;
        let (header, _) = run_diff(store.clone(), partition, a, b, None).await;
        assert!(header.binary);
        assert_eq!(header.size_from, 4096);
        assert_eq!(header.size_to, 4096);
        assert!(header.matched_runs.is_empty());
        assert!(!header.runs_truncated);
    }))
    .await;
}

#[test]
fn match_tables_coalesces_and_caps() {
    fn chunk(hash_byte: u8, offset: u64, len: u64) -> Chunk {
        Chunk {
            hash: Hash::from([hash_byte; 32].as_ref()),
            offset,
            len,
        }
    }

    // Adjacent equal-drift matches coalesce into one run.
    let from = vec![chunk(1, 0, 10), chunk(2, 10, 10), chunk(3, 20, 10)];
    let to = vec![chunk(1, 5, 10), chunk(2, 15, 10), chunk(3, 25, 10)];
    let (runs, truncated) = match_tables(&from, &to);
    assert!(!truncated);
    assert_eq!(runs.len(), 1);
    assert_eq!(
        (runs[0].offset_from, runs[0].offset_to, runs[0].length),
        (0, 5, 30)
    );

    // Non-contiguous matches stay separate runs; cap flags truncation.
    let from: Vec<Chunk> = (0..MAX_MATCHED_RUNS as u64 + 10)
        .map(|i| chunk((i % 251) as u8, i * 100, 10))
        .collect();
    // Every to-chunk matches but offsets never line up contiguously
    // (gap between runs), forcing one run per match.
    let to: Vec<Chunk> = (0..MAX_MATCHED_RUNS as u64 + 10)
        .map(|i| chunk((i % 251) as u8, i * 200, 10))
        .collect();
    let (runs, truncated) = match_tables(&from, &to);
    assert!(truncated);
    assert_eq!(runs.len(), MAX_MATCHED_RUNS);
}
