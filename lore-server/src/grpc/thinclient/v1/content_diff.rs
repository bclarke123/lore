// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_proto::lore::thin_client::v1::ContentDiffChunkResponse;
use lore_proto::lore::thin_client::v1::ContentDiffHeader;
use lore_proto::lore::thin_client::v1::ContentDiffRequest;
use lore_proto::lore::thin_client::v1::ContentDiffResponse;
use lore_proto::lore::thin_client::v1::MatchedRun;
use lore_proto::lore::thin_client::v1::content_diff_response::Payload;
use lore_revision::file::diff::DEFAULT_CONTEXT_LINES;
use lore_revision::file::diff::DiffOptions;
use lore_revision::file::diff::build_unified_patch;
use lore_revision::infer::infer_is_diffable_by_slice;
use lore_revision::util::encoding::decode_text_for_display;
use lore_storage::ReadOptions;
use lore_storage::TypedBytes;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::util::setup_execution;

type ContentDiffStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ContentDiffResponse, Status>> + Send + 'static>>;

/// Characters of diff text streamed per `ContentDiffResponse`.
const CHUNK_SIZE: usize = 64 * 1024;

/// Per-side input cap: inputs larger than this report `truncated = true`
/// rather than being read and diffed.
const MAX_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// `lore.thin_client.v1.ThinClientService.ContentDiff` handler.
///
/// Two-way unified diff between two CAS addresses (either side may be
/// empty bytes = "no content", for adds/deletes). Content is reassembled
/// and decompressed server-side and diffed with the same pipeline the
/// client diff path uses, so output is byte-identical. The first stream
/// message carries the header (stats / binary / truncated); chunks follow
/// unless the header short-circuits.
///
/// Three-way mode (`address_base` set) is not implemented yet.
#[tracing::instrument(name = "ContentDiff::v1::handle", skip_all)]
pub async fn handler(
    request: Request<ContentDiffRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
) -> Result<Response<ContentDiffStream>, Status> {
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();

    if req.address_base.as_ref().is_some_and(|b| !b.is_empty()) {
        return Err(Status::unimplemented(
            "lore.thin_client.v1.ThinClientService.ContentDiff 3-way mode not yet implemented",
        ));
    }
    if req.address_from.is_empty() && req.address_to.is_empty() {
        return Err(Status::invalid_argument(
            "at least one of address_from / address_to must be set",
        ));
    }

    let options = DiffOptions {
        context_lines: req.context_lines.unwrap_or(DEFAULT_CONTEXT_LINES),
        ignore_whitespace_eol: req.ignore_whitespace_eol,
        ignore_whitespace_inline: req.ignore_whitespace_inline,
    };
    let max_diff_size = req.max_diff_size;

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    LORE_CONTEXT
        .scope(execution, async move {
            // Read both sides up front so failures surface as a unary Status
            // before the stream opens. `None` = empty side (add / delete);
            // oversized input short-circuits to a truncated header.
            let from = read_side(&immutable_store, repository_id, &req.address_from).await?;
            let to = read_side(&immutable_store, repository_id, &req.address_to).await?;

            let header;
            let mut text = String::new();
            {
                // Sniff on whatever bytes each side has: full content for
                // in-cap reads, an 8 KiB prefix for oversized ones. Empty
                // sides (add/delete) are trivially diffable; the binary
                // sniffer treats an empty slice as non-diffable. Prefix
                // sniffing is a heuristic (a binary file with a clean-text
                // first 8 KiB reads as text), matching how the mime probes
                // work on leading bytes.
                let binary = |bytes: &[u8]| !bytes.is_empty() && !infer_is_diffable_by_slice(bytes);
                let any_oversized =
                    matches!(from, Side::Oversized { .. }) || matches!(to, Side::Oversized { .. });
                if binary(from.sniff_bytes()) || binary(to.sniff_bytes()) {
                    // Binary: no text diff, but the FastCDC chunk tables
                    // give byte-range change metadata for free — load
                    // each side's fragment table (metadata only, never
                    // content) and report the runs both sides share. Works
                    // regardless of content size, since content is never
                    // read.
                    let table_from =
                        chunk_table(&immutable_store, repository_id, &req.address_from).await?;
                    let table_to =
                        chunk_table(&immutable_store, repository_id, &req.address_to).await?;
                    let (matched_runs, runs_truncated) =
                        match_tables(&table_from.chunks, &table_to.chunks);
                    header = ContentDiffHeader {
                        binary: true,
                        size_from: table_from.size_content,
                        size_to: table_to.size_content,
                        matched_runs,
                        runs_truncated,
                        ..Default::default()
                    };
                } else if any_oversized {
                    // Text (as far as the prefix shows) but too large to
                    // diff: stats-free truncation, as before.
                    header = ContentDiffHeader {
                        truncated: true,
                        ..Default::default()
                    };
                } else {
                    let old = decode_text_for_display(from.sniff_bytes());
                    let new = decode_text_for_display(to.sniff_bytes());
                    let patch =
                        build_unified_patch(&old, &new, "from", "to", options).unwrap_or_default();
                    let (added, deleted) = count_changes(&patch);
                    let truncated = max_diff_size.is_some_and(|max| patch.len() as u64 > max);
                    header = ContentDiffHeader {
                        lines_added: added,
                        lines_deleted: deleted,
                        truncated,
                        ..Default::default()
                    };
                    if !truncated {
                        text = patch;
                    }
                }
            }

            let (tx, rx) = mpsc::channel(4);
            lore_spawn!(async move {
                if tx
                    .send(Ok(ContentDiffResponse {
                        payload: Some(Payload::Header(header)),
                    }))
                    .await
                    .is_err()
                {
                    return; // receiver dropped
                }
                let mut offset = 0;
                while offset < text.len() {
                    // Chunk on a char boundary so every chunk is valid UTF-8.
                    let mut end = (offset + CHUNK_SIZE).min(text.len());
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    let response = ContentDiffResponse {
                        payload: Some(Payload::Chunk(ContentDiffChunkResponse {
                            diff: text[offset..end].to_string(),
                        })),
                    };
                    if tx.send(Ok(response)).await.is_err() {
                        return;
                    }
                    offset = end;
                }
            });

            Ok(Response::new(
                Box::pin(ReceiverStream::new(rx)) as ContentDiffStream
            ))
        })
        .await
}

/// Cap on emitted matched runs; a change so fragmented it exceeds this is
/// summarised with `runs_truncated = true`.
const MAX_MATCHED_RUNS: usize = 2048;

/// Recursion guard for multi-level fragment tables (mirrors the
/// defragment path's `MAX_FRAGMENT_TREE_DEPTH`).
const MAX_TABLE_DEPTH: usize = 8;

/// One leaf chunk of a side's content: FastCDC chunk hash plus its byte
/// placement.
#[derive(Clone, Copy)]
struct Chunk {
    hash: Hash,
    offset: u64,
    len: u64,
}

/// A side's chunk table: total content size plus flat leaf chunks.
struct ChunkTable {
    size_content: u64,
    chunks: Vec<Chunk>,
}

/// Load a side's FastCDC chunk table by content hash — metadata only, the
/// chunk payloads are never read. Non-fragmented content is a single
/// pseudo-chunk. The reference list is stored raw (not compressed, not a
/// content-hash target), so decompress/verify are disabled, mirroring the
/// chunk-reuse path in `lore-storage`'s write pipeline.
async fn chunk_table(
    immutable_store: &Arc<dyn lore_storage::ImmutableStore>,
    repository_id: lore_base::types::Partition,
    hash_bytes: &[u8],
) -> Result<ChunkTable, Status> {
    let empty = ChunkTable {
        size_content: 0,
        chunks: Vec::new(),
    };
    if hash_bytes.is_empty() {
        return Ok(empty);
    }
    let root_hash = Hash::from(hash_bytes);
    if root_hash.is_zero() {
        return Ok(empty);
    }

    let options = ReadOptions::default()
        .no_isolation()
        .no_decompress()
        .no_verify();

    // Worklist of (hash, absolute offset, length, depth) still to resolve
    // into leaves. Lengths above the fragmentation threshold may be
    // intermediate nodes whose payload is another reference list.
    let root = load_table_entry(immutable_store, repository_id, root_hash, options).await?;
    let size_content = root.0.size_content;
    let mut work: Vec<(Hash, u64, u64, usize)> = vec![(root_hash, 0, size_content, 0)];
    let mut chunks = Vec::new();

    while let Some((hash, offset, len, depth)) = work.pop() {
        if depth > MAX_TABLE_DEPTH {
            return Err(Status::internal("fragment table recursion depth exceeded"));
        }
        // Anything at or below the threshold is a leaf by construction.
        if depth > 0 && len <= lore_base::types::FRAGMENT_SIZE_THRESHOLD as u64 {
            chunks.push(Chunk { hash, offset, len });
            continue;
        }
        let (fragment, payload) =
            load_table_entry(immutable_store, repository_id, hash, options).await?;
        if fragment.flags & lore_base::types::FragmentFlags::PayloadFragmented.bits() == 0 {
            // Unfragmented content (small file, or an oversized-but-unsplit
            // chunk): one leaf.
            chunks.push(Chunk { hash, offset, len });
            continue;
        }

        let refs_bytes = payload.to_aligned::<lore_storage::FragmentReference>();
        let stride = std::mem::size_of::<lore_storage::FragmentReference>();
        if refs_bytes.len() < stride || refs_bytes.len() % stride != 0 {
            return Err(Status::internal("malformed fragment reference list"));
        }
        let refs = refs_bytes.as_type_slice::<lore_storage::FragmentReference>();
        // Per-chunk size = offset delta to the next entry; the tail closes
        // against this node's content end. Offsets are absolute within the
        // full content; the node's own (offset, len) bound them.
        let base = refs[0].offset_content;
        let end = base
            .checked_add(fragment.size_content)
            .ok_or_else(|| Status::internal("fragment table offset overflow"))?;
        for (i, r) in refs.iter().enumerate() {
            let next = if i + 1 < refs.len() {
                refs[i + 1].offset_content
            } else {
                end
            };
            let child_len = next
                .checked_sub(r.offset_content)
                .ok_or_else(|| Status::internal("fragment table offsets not increasing"))?;
            if child_len == 0 {
                continue;
            }
            // Rebase against this node's absolute placement.
            let child_offset = offset + (r.offset_content - base);
            work.push((r.hash, child_offset, child_len, depth + 1));
        }
    }

    chunks.sort_by_key(|c| c.offset);
    Ok(ChunkTable {
        size_content,
        chunks,
    })
}

/// Load one fragment header + payload for table walking, with the same
/// error mapping as content reads.
async fn load_table_entry(
    immutable_store: &Arc<dyn lore_storage::ImmutableStore>,
    repository_id: lore_base::types::Partition,
    hash: Hash,
    options: ReadOptions,
) -> Result<(lore_base::types::Fragment, bytes::Bytes), Status> {
    let address = Address {
        hash,
        context: Default::default(),
    };
    lore_storage::load_fragment(
        immutable_store.clone(),
        repository_id,
        address,
        options,
        None, /* server has the data locally; no remote session */
    )
    .await
    .map_err(|err| match err {
        lore_storage::StorageError::AddressNotFound(_) => Status::not_found("content not found"),
        other => Status::internal(format!("fragment load failed: {other}")),
    })
}

/// Match two chunk tables into coalesced byte runs present in both sides.
/// Greedy with a monotonically advancing from-cursor: each to-side chunk
/// pairs with the nearest same-hash from-side chunk at or after the
/// cursor, keeping runs ordered and handling repeated chunks (zero-fill
/// etc.) without pathological cross-matching. A second, order-free pass
/// then pairs leftovers whose hashes are unique among the unmatched on
/// both sides — this is what detects relocated sections (content moved
/// *earlier* relative to matched order, e.g. a block cut from the middle
/// and appended at the end), which the monotonic cursor cannot reach; the
/// uniqueness requirement keeps repeated chunks from cross-matching.
/// Returns the runs (ascending to-offset) and whether the list was capped.
fn match_tables(from: &[Chunk], to: &[Chunk]) -> (Vec<MatchedRun>, bool) {
    use std::collections::HashMap;

    let mut by_hash: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (i, chunk) in from.iter().enumerate() {
        by_hash.entry(chunk.hash.as_ref()).or_default().push(i);
    }

    let mut runs: Vec<MatchedRun> = Vec::new();
    let mut truncated = false;
    let mut cursor = 0usize;
    let mut from_matched = vec![false; from.len()];
    let mut to_unmatched: Vec<usize> = Vec::new();
    for (to_idx, chunk) in to.iter().enumerate() {
        let idx = by_hash
            .get(chunk.hash.as_ref())
            .and_then(|indices| indices.iter().find(|&&i| i >= cursor).copied());
        let Some(idx) = idx else {
            to_unmatched.push(to_idx);
            continue;
        };
        let matched = &from[idx];
        cursor = idx + 1;
        from_matched[idx] = true;

        if let Some(last) = runs.last_mut()
            && last.offset_from + last.length == matched.offset
            && last.offset_to + last.length == chunk.offset
        {
            last.length += chunk.len;
            continue;
        }
        if runs.len() >= MAX_MATCHED_RUNS {
            truncated = true;
            break;
        }
        runs.push(MatchedRun {
            offset_from: matched.offset,
            offset_to: chunk.offset,
            length: chunk.len,
        });
    }

    // Relocation pass: pair unmatched to-chunks with unmatched from-chunks
    // when the hash is unique among the leftovers on both sides.
    if !truncated && !to_unmatched.is_empty() {
        let mut leftover_from: HashMap<&[u8], Option<usize>> = HashMap::new();
        for (i, matched) in from_matched.iter().enumerate() {
            if !matched {
                // Duplicate leftover hashes are ambiguous: mark as None.
                leftover_from
                    .entry(from[i].hash.as_ref())
                    .and_modify(|entry| *entry = None)
                    .or_insert(Some(i));
            }
        }
        let mut moved: Vec<MatchedRun> = Vec::new();
        let mut seen_to: HashMap<&[u8], u32> = HashMap::new();
        for &to_idx in &to_unmatched {
            *seen_to.entry(to[to_idx].hash.as_ref()).or_default() += 1;
        }
        for &to_idx in &to_unmatched {
            let chunk = &to[to_idx];
            // Unique among unmatched on the to side too.
            if seen_to.get(chunk.hash.as_ref()) != Some(&1) {
                continue;
            }
            let Some(&Some(from_idx)) = leftover_from.get(chunk.hash.as_ref()) else {
                continue;
            };
            let matched = &from[from_idx];
            if let Some(last) = moved.last_mut()
                && last.offset_from + last.length == matched.offset
                && last.offset_to + last.length == chunk.offset
            {
                last.length += chunk.len;
                continue;
            }
            if runs.len() + moved.len() >= MAX_MATCHED_RUNS {
                truncated = true;
                break;
            }
            moved.push(MatchedRun {
                offset_from: matched.offset,
                offset_to: chunk.offset,
                length: chunk.len,
            });
        }
        runs.extend(moved);
        runs.sort_by_key(|r| r.offset_to);
    }

    (runs, truncated)
}

/// Bytes read for text/binary sniffing when the content exceeds
/// [`MAX_INPUT_BYTES`].
const SNIFF_BYTES: usize = 8192;

enum Side {
    Empty,
    Content(bytes::Bytes),
    /// Content larger than [`MAX_INPUT_BYTES`]; carries only a leading
    /// prefix for sniffing.
    Oversized {
        prefix: bytes::Bytes,
    },
}

impl Side {
    /// The bytes available for text/binary sniffing (and, for in-cap
    /// content, the full body).
    fn sniff_bytes(&self) -> &[u8] {
        match self {
            Side::Content(bytes) => bytes,
            Side::Oversized { prefix } => prefix,
            Side::Empty => &[],
        }
    }
}

/// Read one side's content by its hash bytes. Empty bytes = no content.
/// The hash-only address resolves through the store's `MatchHash`
/// fallback (`DiffChange.content_from`/`content_to` carry hashes without
/// the context half).
async fn read_side(
    immutable_store: &Arc<dyn lore_storage::ImmutableStore>,
    repository_id: lore_base::types::Partition,
    hash_bytes: &[u8],
) -> Result<Side, Status> {
    if hash_bytes.is_empty() {
        return Ok(Side::Empty);
    }
    let address = Address {
        hash: Hash::from(hash_bytes),
        context: Default::default(),
    };
    if address.hash.is_zero() {
        return Ok(Side::Empty);
    }
    // The server enables LOCAL_ISOLATION globally, which restricts reads
    // to full (hash, context) matches — but DiffChange only carries the
    // hash half, so the MatchHash fallback must be allowed. This does not
    // widen access: the lookup is still scoped to the caller's authorized
    // partition, and the content hash itself proves the bytes.
    let options = ReadOptions::default()
        .no_isolation()
        .with_max_content_size(MAX_INPUT_BYTES);
    match lore_storage::read(
        immutable_store.clone(),
        repository_id,
        address,
        None,
        options,
        None, /* server has the data locally; no remote session */
    )
    .await
    {
        Ok(bytes) => Ok(Side::Content(bytes)),
        Err(lore_storage::StorageError::Oversized(_)) => {
            // Too large to reassemble in full — fetch just a leading
            // prefix (ranged read, no size cap) so text/binary sniffing
            // still works; the binary path never needs the body.
            let prefix = lore_storage::read(
                immutable_store.clone(),
                repository_id,
                address,
                Some(0..SNIFF_BYTES),
                ReadOptions::default().no_isolation(),
                None,
            )
            .await
            .unwrap_or_default();
            Ok(Side::Oversized { prefix })
        }
        Err(lore_storage::StorageError::AddressNotFound(_)) => {
            Err(Status::not_found("content not found"))
        }
        Err(other) => Err(Status::internal(format!("read failed: {other}"))),
    }
}

/// Count added/deleted lines in a unified patch, skipping the `---`/`+++`
/// file headers.
fn count_changes(patch: &str) -> (u64, u64) {
    let mut added = 0;
    let mut deleted = 0;
    for line in patch.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if line.starts_with('+') {
            added += 1;
        } else if line.starts_with('-') {
            deleted += 1;
        }
    }
    (added, deleted)
}

#[cfg(test)]
mod tests {
    use lore_base::types::Context;
    use lore_storage::WriteOptions;
    use tokio_stream::StreamExt;

    use super::*;
    use crate::store::test_store_create;

    async fn write_blob(
        store: &Arc<dyn lore_storage::ImmutableStore>,
        partition: lore_base::types::Partition,
        content: &[u8],
    ) -> bytes::Bytes {
        // Non-default context: the handler only receives the hash half, so
        // this forces the MatchHash fallback path (a full-address match
        // misses), mirroring production DiffChange addresses.
        let address = lore_storage::write_content(
            store.clone(),
            partition,
            Context::from([7u8; 16].as_ref()),
            bytes::Bytes::copy_from_slice(content),
            WriteOptions::default().no_remote_write(),
            None,
            None,
            None,
        )
        .await
        .expect("write blob");
        bytes::Bytes::copy_from_slice(address.hash.as_ref())
    }

    async fn run_diff(
        store: Arc<dyn lore_storage::ImmutableStore>,
        partition: lore_base::types::Partition,
        from: bytes::Bytes,
        to: bytes::Bytes,
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
            let (header, text) = run_diff(
                store.clone(),
                partition,
                bytes::Bytes::new(),
                new.clone(),
                None,
            )
            .await;
            assert_eq!(header.lines_added, 4);
            assert_eq!(header.lines_deleted, 0);
            assert!(text.contains("+alpha\n"));

            // Delete: empty to side.
            let (header, _text) = run_diff(
                store.clone(),
                partition,
                old.clone(),
                bytes::Bytes::new(),
                None,
            )
            .await;
            assert_eq!(header.lines_added, 0);
            assert_eq!(header.lines_deleted, 3);

            // Binary input short-circuits (PNG magic → non-diffable mime).
            let binary =
                write_blob(&store, partition, b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR").await;
            let (header, text) =
                run_diff(store.clone(), partition, old.clone(), binary, None).await;
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
}
