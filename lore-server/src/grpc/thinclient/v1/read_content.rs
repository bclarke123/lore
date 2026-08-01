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

    let mut options = ReadOptions::default();
    if let Some(max) = req.max_bytes {
        options = options.with_max_content_size(max);
    }

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    LORE_CONTEXT
        .scope(execution, async move {
            // Read (defragment + decompress) up front so failures surface as a
            // unary Status before the stream opens.
            let bytes = match lore_storage::read(
                immutable_store.clone(),
                repository_id,
                address,
                None,
                options,
                None, /* server has the data locally; no remote session */
            )
            .await
            {
                // Hash-only address (no context half): fall back to the
                // store's MatchHash lookup, the same way ContentDiff reads
                // `DiffChange.content_from`/`content_to`. This does not
                // widen access — the lookup stays scoped to the caller's
                // authorized partition, and the content hash itself proves
                // the bytes. Callers holding a full (hash, context) address
                // never take this path.
                Err(lore_storage::StorageError::AddressNotFound(_))
                    if address.context.is_zero() =>
                {
                    let mut fallback = ReadOptions::default().no_isolation();
                    if let Some(max) = req.max_bytes {
                        fallback = fallback.with_max_content_size(max);
                    }
                    lore_storage::read(
                        immutable_store,
                        repository_id,
                        address,
                        None,
                        fallback,
                        None,
                    )
                    .await
                    .map_err(map_read_error)?
                }
                other => other.map_err(map_read_error)?,
            };

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

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use lore_base::types::Partition;
    use lore_storage::WriteOptions;

    use super::*;
    use crate::store::test_store_create;

    /// Store a blob and return its address, using the same write path the
    /// server uses so reassembly/compression is exercised realistically.
    async fn put_blob(
        store: &Arc<dyn lore_storage::ImmutableStore>,
        partition: Partition,
        content: &[u8],
    ) -> Address {
        let (address, _fragment) = lore_storage::write_content(
            store.clone(),
            partition,
            Context::default(),
            Bytes::copy_from_slice(content),
            WriteOptions::default().no_remote_write(),
            None,
            None,
            None,
        )
        .await
        .expect("write blob");
        address
    }

    async fn read_all(
        store: Arc<dyn lore_storage::ImmutableStore>,
        partition: Partition,
        address: Address,
        max_bytes: Option<u64>,
    ) -> Result<Vec<u8>, Status> {
        let mut request = Request::new(ReadContentRequest {
            address: Some(lore_proto::lore::model::v1::Address {
                hash: address.hash.data().to_vec().into(),
                context: address.context.data().to_vec().into(),
            }),
            max_bytes,
        });
        request.metadata_mut().insert_bin(
            crate::grpc::REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(partition.data()),
        );
        let response = handler(request, store).await?;
        let mut out = Vec::new();
        let mut stream = response.into_inner();
        use tokio_stream::StreamExt;
        while let Some(item) = stream.next().await {
            out.extend_from_slice(&item?.chunk);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn reads_small_blob_roundtrip() {
        let (store, _mut, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let partition = Partition::default();
            let content = b"hello, lorehub\n";
            let address = put_blob(&store, partition, content).await;
            let got = read_all(store, partition, address, None)
                .await
                .expect("read");
            assert_eq!(got, content);
        }))
        .await;
    }

    #[tokio::test]
    async fn reads_large_blob_roundtrip() {
        let (store, _mut, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let partition = Partition::default();
            // Larger than CHUNK_SIZE and likely fragmented/compressed.
            let content: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
            let address = put_blob(&store, partition, &content).await;
            let got = read_all(store, partition, address, None)
                .await
                .expect("read");
            assert_eq!(got, content);
        }))
        .await;
    }

    #[tokio::test]
    async fn max_bytes_rejects_oversized() {
        let (store, _mut, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let partition = Partition::default();
            let content = vec![7u8; 10_000];
            let address = put_blob(&store, partition, &content).await;
            let err = read_all(store, partition, address, Some(1000))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        }))
        .await;
    }

    #[tokio::test]
    async fn unknown_address_is_not_found() {
        let (store, _mut, execution) = test_store_create().await.expect("stores");
        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let address = Address {
                hash: Hash::from([9u8; 32].as_ref()),
                context: Context::default(),
            };
            let err = read_all(store, Partition::default(), address, None)
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::NotFound);
        }))
        .await;
    }
}
