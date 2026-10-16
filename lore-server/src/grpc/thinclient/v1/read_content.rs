// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::lore::thin_client::v1::ReadContentRequest;
use lore_proto::lore::thin_client::v1::ReadContentResponse;
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

type ReadContentStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ReadContentResponse, Status>> + Send + 'static>>;

/// Bytes streamed per `ReadContentResponse`.
const CHUNK_SIZE: usize = 64 * 1024;

/// `lore.thin_client.v1.ThinClientService.ReadContent` handler.
///
/// Reads a file's content by CAS address, reassembling fragments and
/// decompressing (all codecs) server-side, and streams the bytes. The
/// first message carries `size_content`; each message carries a `chunk`.
#[tracing::instrument(name = "ReadContent::v1::handle", skip_all)]
pub async fn handler(
    request: Request<ReadContentRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
) -> Result<Response<ReadContentStream>, Status> {
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();

    let proto_address = req
        .address
        .ok_or_else(|| Status::invalid_argument("ReadContentRequest.address must be set"))?;
    let address = Address {
        hash: Hash::from(proto_address.hash.as_ref()),
        context: Context::from(proto_address.context.as_ref()),
    };
    if address.hash.is_zero() {
        return Err(Status::invalid_argument("Cannot read a zeroed address"));
    }

    // A requested byte range bounds the defragment allocation by itself, so
    // the storage-level whole-content cap is only applied to full reads —
    // ranged reads of arbitrarily large content are the point of the range.
    // `max_bytes` then caps the range: a bounded range larger than the cap
    // is rejected up front; an open-ended range is read to `max + 1` bytes
    // so overflow is detected after the (bounded) read.
    let range: Option<std::ops::Range<usize>> = match (req.offset, req.length) {
        (None, None) => None,
        (offset, length) => {
            let start = offset.unwrap_or(0);
            if let (Some(len), Some(max)) = (length, req.max_bytes)
                && len > max
            {
                return Err(Status::failed_precondition("file too large"));
            }
            let end = match (length, req.max_bytes) {
                (Some(len), _) => start.saturating_add(len),
                (None, Some(max)) => start.saturating_add(max).saturating_add(1),
                (None, None) => u64::MAX,
            };
            let clamp = |v: u64| usize::try_from(v).unwrap_or(usize::MAX);
            Some(clamp(start)..clamp(end))
        }
    };

    let mut options = ReadOptions::default();
    if range.is_none()
        && let Some(max) = req.max_bytes
    {
        options = options.with_max_content_size(max);
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    LORE_CONTEXT
        .scope(execution, async move {
            // Read (defragment + decompress) up front so failures surface as a
            // unary Status before the stream opens. `read` also
            // yields the root fragment, whose `size_content` is the total
            // content size — reported alongside ranged reads so callers can
            // say "bytes X-Y of Z" without a second round-trip.
            let (fragment, bytes) = lore_storage::read(
                immutable_store.clone(),
                repository_id,
                address,
                range.clone(),
                options,
                None, /* server has the data locally; no remote session */
            )
            .await
            .map_err(map_read_error)?;

            // Open-ended range: the read was bounded to `max + 1` bytes, so
            // landing past `max` means the tail exceeds the cap.
            if let (Some(_), Some(max)) = (&range, req.max_bytes)
                && bytes.len() as u64 > max
            {
                return Err(Status::failed_precondition("file too large"));
            }

            let total_size_content = fragment.size_content;
            let (tx, rx) = mpsc::channel(4);
            lore_spawn!(async move {
                let size_content = bytes.len() as u64;
                // Always emit at least one message (carries size; empty file
                // → single empty chunk).
                let mut offset = 0;
                let mut first = true;
                loop {
                    let end = (offset + CHUNK_SIZE).min(bytes.len());
                    let chunk = bytes.slice(offset..end);
                    let response = ReadContentResponse {
                        size_content: if first { size_content } else { 0 },
                        total_size_content: if first { total_size_content } else { 0 },
                        chunk,
                    };
                    if tx.send(Ok(response)).await.is_err() {
                        return; // receiver dropped
                    }
                    first = false;
                    offset = end;
                    if offset >= bytes.len() {
                        break;
                    }
                }
            });

            Ok(Response::new(
                Box::pin(ReceiverStream::new(rx)) as ReadContentStream
            ))
        })
        .await
}

fn map_read_error(err: lore_storage::StorageError) -> Status {
    use lore_storage::StorageError;
    match err {
        StorageError::AddressNotFound(_) => Status::not_found("content not found"),
        StorageError::Oversized(_) => Status::failed_precondition("file too large"),
        other => Status::internal(format!("read failed: {other}")),
    }
}
