// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use http::HeaderMap;
use http::Request;
use http::Response;
use http::header::USER_AGENT;
use lore_server::grpc::tower::malformed_request::*;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use tonic::Code;
use tonic::Status;
use tower::Layer;
use tower::Service;

/// Uses tonic's own encoding so these tests cannot drift from the wire
/// format the server actually produces.
fn response_for(code: Code, message: &str) -> Response<()> {
    Status::new(code, message.to_owned()).into_http()
}

fn status_of(response: &Response<()>) -> Status {
    Status::from_header_map(response.headers()).expect("a gRPC status in the headers")
}

mod is_missing_request_message {
    use super::*;

    #[test]
    fn detects_the_undecodable_unary_body_rejection() {
        let response = response_for(Code::Internal, MISSING_REQUEST_MESSAGE);

        assert!(is_missing_request_message(response.headers()));
    }

    /// The message is percent-encoded on the wire, so the comparison has to
    /// decode it rather than match the header bytes.
    #[test]
    fn detects_the_rejection_through_the_wire_encoding() {
        let response = response_for(Code::Internal, MISSING_REQUEST_MESSAGE);
        let encoded = response
            .headers()
            .get("grpc-message")
            .expect("a grpc-message header")
            .to_str()
            .expect("a valid header value");

        assert_eq!(encoded, "Missing%20request%20message.");
        assert!(is_missing_request_message(response.headers()));
    }

    /// A server fault carrying its own message stays `Internal`, so real
    /// faults keep reaching alerting.
    #[test]
    fn ignores_an_internal_status_with_another_message() {
        let response = response_for(Code::Internal, "store unavailable");

        assert!(!is_missing_request_message(response.headers()));
    }

    #[test]
    fn ignores_the_same_message_under_another_code() {
        let response = response_for(Code::InvalidArgument, MISSING_REQUEST_MESSAGE);

        assert!(!is_missing_request_message(response.headers()));
    }

    /// A status delivered in trailers leaves none in the headers.
    #[test]
    fn ignores_headers_carrying_no_grpc_status() {
        assert!(!is_missing_request_message(&HeaderMap::new()));
    }
}

mod set_invalid_argument {
    use super::*;

    #[test]
    fn replaces_the_code_and_keeps_the_message() {
        let mut response = response_for(Code::Internal, MISSING_REQUEST_MESSAGE);

        set_invalid_argument(&mut response);

        let status = status_of(&response);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), MISSING_REQUEST_MESSAGE);
    }
}

mod service {
    use std::convert::Infallible;
    use std::future::Ready;

    use super::*;

    struct Inner(Option<(Code, &'static str)>);

    impl Service<Request<()>> for Inner {
        type Response = Response<()>;
        type Error = Infallible;
        type Future = Ready<Result<Response<()>, Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _request: Request<()>) -> Self::Future {
            let response = match self.0 {
                Some((code, message)) => response_for(code, message),
                None => Response::new(()),
            };
            std::future::ready(Ok(response))
        }
    }

    async fn call_through(inner: Inner, user_agent: &str) -> Response<()> {
        let mut service =
            MalformedRequestLayer::new(Arc::new(UserAgentFilter::default())).layer(inner);
        let request = Request::builder()
            .uri("/urc.rpc.AdminService/ServerInfo")
            .header(USER_AGENT, user_agent)
            .body(())
            .expect("a valid request");

        service
            .call(request)
            .await
            .expect("the inner service cannot fail")
    }

    #[tokio::test]
    async fn the_undecodable_body_rejection_becomes_invalid_argument() {
        let response = call_through(
            Inner(Some((Code::Internal, MISSING_REQUEST_MESSAGE))),
            "curl/8.5.0",
        )
        .await;

        let status = status_of(&response);
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), MISSING_REQUEST_MESSAGE);
    }

    #[tokio::test]
    async fn a_genuine_internal_status_passes_through_untouched() {
        let response = call_through(
            Inner(Some((Code::Internal, "store unavailable"))),
            "lore/1.0",
        )
        .await;

        let status = status_of(&response);
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "store unavailable");
    }

    /// Drives a real generated service so the constant stays tied to the
    /// status tonic actually produces. Every other test builds its input
    /// from [`MISSING_REQUEST_MESSAGE`], so a tonic release that reworded
    /// the message would leave them green while the reclassification
    /// silently stopped.
    #[tokio::test]
    async fn tonic_still_rejects_an_unframed_body_with_the_matched_message() {
        use http_body_util::Empty;
        use lore_revision::environment::EnvironmentConfig;
        use lore_server::grpc::environment_service::LoreEnvironmentService;
        use lore_server::legacy::rpc::environment_service_server::EnvironmentServiceServer;

        let inner = EnvironmentServiceServer::new(LoreEnvironmentService::maintenance(
            EnvironmentConfig::default(),
        ));
        let mut service =
            MalformedRequestLayer::new(Arc::new(UserAgentFilter::default())).layer(inner);
        let request = Request::builder()
            .method("POST")
            .uri("/urc.rpc.EnvironmentService/Get")
            .header("content-type", "application/grpc")
            .body(Empty::<bytes::Bytes>::new())
            .expect("a valid request");

        let response = service
            .call(request)
            .await
            .expect("the generated service answers with a status");
        let status =
            Status::from_header_map(response.headers()).expect("a gRPC status in the headers");

        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), MISSING_REQUEST_MESSAGE);
    }

    #[tokio::test]
    async fn a_response_carrying_no_grpc_status_passes_through_untouched() {
        let response = call_through(Inner(None), "lore/1.0").await;

        assert!(Status::from_header_map(response.headers()).is_none());
    }
}
