// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_proto::lore::thin_client::v1::ContentDiffChunkResponse;
use lore_proto::lore::thin_client::v1::ContentDiffHeader;
use lore_proto::lore::thin_client::v1::ContentDiffRequest;
use lore_proto::lore::thin_client::v1::ContentDiffResponse;
use lore_proto::lore::thin_client::v1::content_diff_response::Payload;
use lore_revision::file::diff::DEFAULT_CONTEXT_LINES;
use lore_revision::file::diff::DiffOptions;
use lore_revision::file::diff::build_unified_patch;
use lore_revision::infer::infer_is_diffable_by_slice;
use lore_revision::util::encoding::decode_text_for_display;
use lore_storage::ReadOptions;
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
            match (from, to) {
                (Side::Oversized, _) | (_, Side::Oversized) => {
                    header = ContentDiffHeader {
                        truncated: true,
                        ..Default::default()
                    };
                }
                (from, to) => {
                    let from_bytes = from.bytes();
                    let to_bytes = to.bytes();
                    // Empty sides (add/delete) are trivially diffable; the
                    // binary sniffer treats an empty slice as non-diffable.
                    let binary =
                        |bytes: &[u8]| !bytes.is_empty() && !infer_is_diffable_by_slice(bytes);
                    if binary(from_bytes) || binary(to_bytes) {
                        header = ContentDiffHeader {
                            binary: true,
                            ..Default::default()
                        };
                    } else {
                        let old = decode_text_for_display(from_bytes);
                        let new = decode_text_for_display(to_bytes);
                        let patch = build_unified_patch(&old, &new, "from", "to", options)
                            .unwrap_or_default();
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
            }

            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
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

enum Side {
    Empty,
    Content(bytes::Bytes),
    Oversized,
}

impl Side {
    fn bytes(&self) -> &[u8] {
        match self {
            Side::Content(bytes) => bytes,
            _ => &[],
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
        Err(lore_storage::StorageError::Oversized(_)) => Ok(Side::Oversized),
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
        let (address, _fragment) = lore_storage::write_content(
            store.clone(),
            partition,
            Context::from([7u8; 16].as_ref()),
            bytes::Bytes::copy_from_slice(content),
            WriteOptions::default().no_remote_write(),
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
}
