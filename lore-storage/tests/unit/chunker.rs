// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::io::Write;

use lore_base::test_util::TempDir;
use lore_storage::chunker::*;
use lore_storage::compress::FRAGMENT_SIZE_THRESHOLD;
use lore_storage::concurrency::FRAGMENT_SIZE_EXPECTED;
use lore_storage::concurrency::FRAGMENT_SIZE_MINIMUM;

/// Boundaries the current whole-buffer implementation produces, which the
/// streaming chunker must reproduce byte for byte.
fn reference_boundaries(buffer: &[u8]) -> Vec<(u64, usize)> {
    fastcdc::v2020::FastCDC::with_level(
        buffer,
        FRAGMENT_SIZE_MINIMUM as u32,
        FRAGMENT_SIZE_EXPECTED as u32,
        FRAGMENT_SIZE_THRESHOLD as u32,
        fastcdc::v2020::Normalization::Level1,
    )
    .map(|c| (c.offset as u64, c.length))
    .collect()
}

/// Boundaries the current fixed-size implementation produces.
fn reference_fixed_boundaries(size: usize, step: usize) -> Vec<(u64, usize)> {
    (0..size)
        .step_by(step)
        .map(|offset| (offset as u64, (offset + step).min(size) - offset))
        .collect()
}

async fn streamed_chunks(
    dir: &TempDir,
    name: &str,
    content: &[u8],
    fixed_size: usize,
) -> Vec<Chunk> {
    let path = dir.path().join(name);
    let mut file = std::fs::File::create(&path).expect("create test file");
    file.write_all(content).expect("write test file");
    file.sync_all().expect("sync test file");
    drop(file);

    let (file, file_size) = lore_storage::content::ContentSource::file(&path)
        .open()
        .await
        .expect("open test file");
    let mut chunker = if fixed_size > 0 {
        FileChunker::fixed_size(file, file_size, fixed_size).await
    } else {
        FileChunker::content_defined(file, file_size).await
    };
    let mut chunks = Vec::new();
    while let Some(chunk) = chunker.next_chunk().await.expect("chunking succeeds") {
        chunks.push(chunk);
    }
    chunks
}

/// The property the whole change rests on: streaming must not move a boundary.
async fn assert_matches_reference(name: &str, content: &[u8]) {
    let dir = TempDir::new("lore-storage-chunker-test-");
    let chunks = streamed_chunks(&dir, name, content, 0).await;

    let actual: Vec<(u64, usize)> = chunks.iter().map(|c| (c.offset, c.data.len())).collect();
    assert_eq!(
        actual,
        reference_boundaries(content),
        "streaming boundaries diverged from whole-buffer FastCDC for {name} ({} bytes)",
        content.len()
    );

    assert_covers(&chunks, content);
}

async fn assert_matches_fixed_reference(name: &str, content: &[u8], step: usize) {
    let dir = TempDir::new("lore-storage-chunker-test-");
    let chunks = streamed_chunks(&dir, name, content, step).await;

    let actual: Vec<(u64, usize)> = chunks.iter().map(|c| (c.offset, c.data.len())).collect();
    assert_eq!(
        actual,
        reference_fixed_boundaries(content.len(), step),
        "streaming fixed-size boundaries diverged for {name} ({} bytes, step {step})",
        content.len()
    );

    assert_covers(&chunks, content);
}

fn assert_covers(chunks: &[Chunk], content: &[u8]) {
    for chunk in chunks {
        let start = chunk.offset as usize;
        assert_eq!(
            chunk.data.as_ref(),
            &content[start..start + chunk.data.len()],
            "chunk data at offset {start} does not match the source"
        );
    }

    let covered: usize = chunks.iter().map(|c| c.data.len()).sum();
    assert_eq!(covered, content.len(), "chunks do not cover the whole file");
}

fn random_buffer(size: usize) -> Vec<u8> {
    use rand::Rng;
    let mut data = vec![0u8; size];
    rand::rng().fill(&mut data[..]);
    data
}

#[tokio::test]
async fn matches_reference_on_random_data() {
    for size in [
        1024,
        FRAGMENT_SIZE_MINIMUM - 1,
        FRAGMENT_SIZE_EXPECTED + 13,
        5 * WINDOW_SIZE + 4097,
    ] {
        assert_matches_reference(&format!("random-{size}"), &random_buffer(size)).await;
    }
}

/// All zeroes never trips the rolling hash, so every cut is a forced maximum-size
/// cut — the case where an undersized window would cut early instead.
#[tokio::test]
async fn matches_reference_on_all_zero_data() {
    assert_matches_reference("zeros", &vec![0u8; 5 * WINDOW_SIZE + 977]).await;
}

/// A period far below the minimum fragment size: the hash repeats constantly, so
/// candidate cuts cluster and the minimum-size skip does the work.
#[tokio::test]
async fn matches_reference_on_highly_repetitive_data() {
    let pattern: Vec<u8> = (0u8..=63).collect();
    let content: Vec<u8> = pattern
        .iter()
        .copied()
        .cycle()
        .take(4 * WINDOW_SIZE + 31)
        .collect();
    assert_matches_reference("repetitive", &content).await;
}

/// Sizes landing exactly on the window and fragment limits, where an off-by-one in
/// the refill or lookahead check would show up.
#[tokio::test]
async fn matches_reference_on_boundary_sizes() {
    for size in [
        FRAGMENT_SIZE_THRESHOLD - 1,
        FRAGMENT_SIZE_THRESHOLD,
        FRAGMENT_SIZE_THRESHOLD + 1,
        WINDOW_SIZE - 1,
        WINDOW_SIZE,
        WINDOW_SIZE + 1,
        2 * WINDOW_SIZE,
    ] {
        assert_matches_reference(&format!("boundary-{size}"), &random_buffer(size)).await;
    }
}

/// Fixed-size chunking is what `WriteOptions::with_fixed_size_chunk` selects, and
/// it reaches the streaming path through `write_from_file`.
#[tokio::test]
async fn matches_reference_on_fixed_size_chunking() {
    for (size, step) in [
        (10 * 1024 + 17, 1024),
        (100, 1024),
        (WINDOW_SIZE + 1, FRAGMENT_SIZE_THRESHOLD),
        (3 * FRAGMENT_SIZE_THRESHOLD, FRAGMENT_SIZE_THRESHOLD),
        (5 * WINDOW_SIZE + 331, FRAGMENT_SIZE_EXPECTED),
        // A step that does not divide the read size, so every window carries a
        // remainder over into the next one.
        (5 * WINDOW_SIZE + 331, 100_003),
    ] {
        assert_matches_fixed_reference(&format!("fixed-{size}-{step}"), &random_buffer(size), step)
            .await;
    }
}

async fn open_chunker(dir: &TempDir, name: &str, size: usize) -> FileChunker {
    let path = dir.path().join(name);
    std::fs::write(&path, random_buffer(size)).expect("write test file");
    let (file, _) = lore_storage::content::ContentSource::file(&path)
        .open()
        .await
        .expect("open test file");

    FileChunker::content_defined(file, size as u64).await
}

fn reserved_permits(chunker: &FileChunker) -> usize {
    chunker
        ._reservation
        .as_ref()
        .expect("window budget reserved")
        .num_permits()
}

/// The reservation has to cover every byte the chunker can hold, which since a cut
/// queues boundaries rather than buffers is exactly its windows plus the chunk it
/// pre-pays for the caller.
#[tokio::test]
async fn the_reservation_covers_every_window() {
    let dir = TempDir::new("lore-storage-chunker-test-");

    let read_ahead = open_chunker(&dir, "read-ahead-budget", 4 * WINDOW_SIZE).await;
    assert_eq!(
        reserved_permits(&read_ahead),
        (2 * WINDOW_SIZE + FRAGMENT_SIZE_THRESHOLD) / 1024,
        "two windows and one chunk"
    );

    let single_read = open_chunker(&dir, "single-read-budget", WINDOW_SIZE).await;
    assert_eq!(
        reserved_permits(&single_read),
        (WINDOW_SIZE + FRAGMENT_SIZE_THRESHOLD) / 1024,
        "one window and one chunk"
    );
    assert_eq!(single_read.headroom, 0, "nothing to carry over");
    assert!(single_read.spare.is_none(), "no second window to read into");
}

/// The next read must already be running while chunks are handed out, or disk
/// latency is back on the critical path.
#[tokio::test]
async fn a_read_runs_while_chunks_are_handed_out() {
    let dir = TempDir::new("lore-storage-chunker-test-");
    let mut chunker = open_chunker(&dir, "read-ahead", 4 * WINDOW_SIZE).await;

    for index in 0..4 {
        let chunk = chunker.next_chunk().await.expect("chunking succeeds");
        assert!(chunk.is_some(), "chunk {index} missing");
        assert!(
            chunker.pending.is_some(),
            "no read running behind chunk {index}"
        );
    }
}

/// A file appended to after it was sized must still yield exactly the recorded size:
/// the caller stores that size in the root fragment, and a longer chunk list than the
/// recorded content underflows the offset arithmetic in `hash_file`.
#[tokio::test]
async fn never_reads_past_the_opened_size() {
    let dir = TempDir::new("lore-storage-chunker-test-");
    let path = dir.path().join("growing");
    let declared = 3 * WINDOW_SIZE + 517;
    std::fs::write(&path, random_buffer(declared)).expect("write test file");

    let (file, _) = lore_storage::content::ContentSource::file(&path)
        .open()
        .await
        .expect("open test file");
    let mut chunker = FileChunker::content_defined(file, declared as u64).await;

    // Grow the file behind the chunker, as an appender would.
    let mut appended = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .expect("reopen for append");
    appended
        .write_all(&random_buffer(2 * WINDOW_SIZE))
        .expect("append");
    appended.sync_all().expect("sync append");

    let mut covered = 0usize;
    while let Some(chunk) = chunker.next_chunk().await.expect("chunking succeeds") {
        covered += chunk.data.len();
    }
    assert_eq!(
        covered, declared,
        "chunker emitted bytes beyond the size it was opened at"
    );
}

/// A file holding less than the size it was measured at is rejected at the read that
/// crosses the end, part-way through a scan that was succeeding: the chunk list would
/// otherwise cover fewer bytes than the root fragment records, and readers trust that
/// count.
///
/// The short file stands in for one truncated behind the chunker, which cannot be staged
/// portably — truncation needs a second, writing handle, and the reader may hold a share
/// mode that denies one.
#[tokio::test]
async fn a_file_shorter_than_its_measured_size_fails() {
    let dir = TempDir::new("lore-storage-chunker-shrink-");
    let path = dir.path().join("short");
    let declared = 4 * WINDOW_SIZE;
    std::fs::write(&path, random_buffer(2 * WINDOW_SIZE)).expect("write test file");

    let (file, _) = lore_storage::content::ContentSource::file(&path)
        .open()
        .await
        .expect("open test file");
    let mut chunker = FileChunker::content_defined(file, declared as u64).await;
    chunker
        .next_chunk()
        .await
        .expect("first chunk")
        .expect("a chunk");

    let err = loop {
        match chunker.next_chunk().await {
            Ok(Some(_)) => {}
            Ok(None) => panic!("a shrunk file must not report a complete scan"),
            Err(err) => break err,
        }
    };
    assert!(
        format!("{err}").contains("read file for chunking"),
        "expected the read itself to fail: {err}"
    );

    let Err(_) = chunker.next_chunk().await else {
        panic!("a failed chunker stays failed");
    };
}

#[tokio::test]
async fn empty_file_yields_no_chunks() {
    let dir = TempDir::new("lore-storage-chunker-test-");
    assert!(streamed_chunks(&dir, "empty", &[], 0).await.is_empty());
    assert!(
        streamed_chunks(&dir, "empty-fixed", &[], FRAGMENT_SIZE_EXPECTED)
            .await
            .is_empty()
    );
}
/// A read failure leaves no pending read and no window: the buffer went with the failed
/// task. A second call must not treat that as the single-read regime and steal the live
/// window.
#[tokio::test]
async fn a_failed_read_does_not_leave_the_chunker_usable() {
    let dir = TempDir::new("lore-storage-chunker-poison-");
    let path = dir.path().join("write-only");
    std::fs::write(&path, vec![7u8; 4 * FRAGMENT_SIZE_THRESHOLD]).expect("seed file");
    // Write-only handle: every positional read fails.
    let file = lore_io::IoDriver::global()
        .open(&path, &lore_io::OpenOptions::new().write(true))
        .await
        .expect("open write-only");

    let mut chunker = FileChunker::content_defined(
        lore_storage::content::ContentHandle::File(file),
        4 * FRAGMENT_SIZE_THRESHOLD as u64,
    )
    .await;
    let Err(first) = chunker.next_chunk().await else {
        panic!("read must fail");
    };
    assert!(
        format!("{first}").contains("read file for chunking"),
        "expected the read itself to fail: {first}"
    );

    // Distinguishes the fuse from the read simply failing again.
    let Err(second) = chunker.next_chunk().await else {
        panic!("must not resume after a failure");
    };
    assert!(
        format!("{second}").contains("used again after a read failure"),
        "expected the fuse, got: {second}"
    );
}
