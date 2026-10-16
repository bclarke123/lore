// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_base::lore_spawn;
use lore_base::types::Partition;
use lore_proto::PutResponse;
use lore_proto::ReplicationPutRequest;
use lore_proto::rpc::replication_service_client::ReplicationServiceClient;
use lore_proto::rpc::replication_service_server::ReplicationService as ReplicationServiceTrait;
use lore_proto::rpc::replication_service_server::ReplicationServiceServer;
use lore_revision::fragment::generate_random;
use lore_revision::util;
use lore_server::store::grpc_replica::*;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

/// A test gRPC server that responds normally for the first `n` requests
/// per stream, then sends an error status that closes the response stream.
struct ErrorAfterNService {
    n: usize,
}

#[tonic::async_trait]
impl ReplicationServiceTrait for ErrorAfterNService {
    type PutStream = Pin<Box<dyn Stream<Item = Result<PutResponse, Status>> + Send>>;

    async fn put(
        &self,
        request: Request<Streaming<ReplicationPutRequest>>,
    ) -> Result<Response<Self::PutStream>, Status> {
        let n = self.n;
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel(100);

        lore_spawn!(async move {
            let mut count = 0;
            while let Some(req) = stream.next().await {
                let Ok(req) = req else { break };
                count += 1;

                if count > n {
                    let _ = tx
                        .send(Err(Status::internal("test: intentional stream error")))
                        .await;
                    break;
                }

                // Delay so requests accumulate in the client's inflight map
                tokio::time::sleep(Duration::from_millis(50)).await;

                let address = req.put_request.and_then(|p| p.address);
                let _ = tx.send(Ok(PutResponse { address })).await;
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Starts a test gRPC server on a random port and returns the port number.
async fn start_test_server(service: ErrorAfterNService) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let addr: SocketAddr = ([127, 0, 0, 1], port).into();

    lore_spawn!(async move {
        tonic::transport::Server::builder()
            .add_service(ReplicationServiceServer::new(service))
            .serve(addr)
            .await
            .unwrap();
    });

    // Allow the server to start listening
    tokio::time::sleep(Duration::from_millis(100)).await;

    port
}

async fn connect_client(port: u16) -> ReplicationClientImpl {
    let channel = tonic::transport::Channel::from_shared(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .connect()
        .await
        .unwrap();

    ReplicationClientImpl::new(
        ReplicationServiceClient::new(channel),
        100, /* buffer */
        util::time::RetryPolicy::builder()
            .with_initial_backoff_millis(10)
            .with_max_backoff_millis(100)
            .with_limit(0)
            .build(),
    )
}

/// Verifies that in-flight requests resolve (don't hang) when the server
/// errors the response stream. The server responds to the first 3 requests
/// with a delay, then errors on request 4+. Because the client
/// sends all 20 concurrently, requests 5-20 are inflight
/// map when the error arrives.
#[tokio::test]
async fn test_inflight_requests_resolve_on_stream_error() {
    let port = start_test_server(ErrorAfterNService { n: 3 }).await;
    let client = Arc::new(connect_client(port).await);

    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let client = client.clone();
        lore_spawn!(join_set, async move {
            let repository = rand::random::<Partition>();
            let (fragment, address, payload) = generate_random();
            client
                .put(repository, address, fragment, Some(payload))
                .await
        });
    }

    // All 20 puts must resolve
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(_result) = join_set.join_next().await {}
    })
    .await;

    assert!(result.is_ok(), "Timed out — inflight requests are hanging");
}

/// Verifies that the client recovers after a stream error: the first
/// puts succeed, then the stream errors, and a subsequent put succeeds
/// after the client reconnects on a new stream.
#[tokio::test]
async fn test_client_recovers_after_stream_error() {
    let port = start_test_server(ErrorAfterNService { n: 3 }).await;
    let client = connect_client(port).await;

    assert_eq!(client.current_epoch.load(Ordering::SeqCst), 0);

    // Send 3 sequential puts — these all succeed on the first stream
    for _ in 0..3 {
        let repository = rand::random::<Partition>();
        let (fragment, address, payload) = generate_random();
        client
            .put(repository, address, fragment, Some(payload))
            .await
            .expect("put should succeed within server's limit");
    }

    // First stream was created during put 1
    assert_eq!(client.current_epoch.load(Ordering::SeqCst), 1);

    // 4th put triggers stream error;
    let repository = rand::random::<Partition>();
    let (fragment, address, payload) = generate_random();
    client
        .put(repository, address, fragment, Some(payload.clone()))
        .await
        .expect_err("4th should cause error");

    // 5th put creates a new stream (epoch 2) and succeeds
    client
        .put(repository, address, fragment, Some(payload.clone()))
        .await
        .expect("5th request should work");

    assert_eq!(client.current_epoch.load(Ordering::SeqCst), 2);
}
