// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;
use std::sync::LazyLock;
use std::task::Context;
use std::task::Poll;

use http::HeaderMap;
use http::HeaderName;
use http::HeaderValue;
use http::Request;
use http::Response;
use http::Uri;
use http::header::USER_AGENT;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::USER_AGENT_NONE;
use lore_telemetry::USER_AGENT_UNKNOWN;
use lore_telemetry::user_agent_filter::NormalizeOutput;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use opentelemetry_semantic_conventions::attribute::USER_AGENT_NAME;
use opentelemetry_semantic_conventions::trace::HTTP_ROUTE;
use pin_project::pin_project;
use tonic::Code;
use tonic::Status;
use tower::Layer;
use tower::Service;
use tracing::debug;

const GRPC_STATUS_HEADER: &str = "grpc-status";

struct MalformedRequestInstrumentProvider;

impl InstrumentProvider for MalformedRequestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "lore.grpc"
    }
}

static MISSING_REQUEST_MESSAGES: LazyLock<Counter<u64>> =
    LazyLock::new(|| MalformedRequestInstrumentProvider.counter("missing_request_message"));

/// The message tonic pairs with [`Code::Internal`] when a unary request body
/// carries no decodable gRPC message, as an HTTP/2 POST without gRPC
/// length-prefix framing does.
///
/// Matching it is what separates that caller-side rejection from a genuine
/// server fault, because tonic maps both to [`Code::Internal`].
///
/// A caller that resets the request stream reaches the same message, so a
/// match does not by itself mean the caller sent something malformed.
#[lore_macro::test_pub]
const MISSING_REQUEST_MESSAGE: &str = "Missing request message.";

/// Reclassifies tonic's [`MISSING_REQUEST_MESSAGE`] rejection from
/// [`Code::Internal`] to [`Code::InvalidArgument`].
///
/// Mounted innermost, so every layer outside it observes the reclassified
/// status and [`Code::Internal`] keeps meaning a genuine server fault.
///
/// The other caller-side bodies tonic rejects with [`Code::Internal`] —
/// `"Unexpected EOF decoding stream."` for a body shorter than its length
/// prefix, and `"Error decompressing: ..."` for a corrupt compressed body —
/// are out of scope and still answer [`Code::Internal`].
#[derive(Clone)]
pub struct MalformedRequestLayer {
    filter: Arc<UserAgentFilter>,
}

impl MalformedRequestLayer {
    pub fn new(filter: Arc<UserAgentFilter>) -> Self {
        Self { filter }
    }
}

impl<S> Layer<S> for MalformedRequestLayer {
    type Service = MalformedRequestService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MalformedRequestService {
            service: inner,
            filter: self.filter.clone(),
        }
    }
}

#[derive(Clone)]
pub struct MalformedRequestService<S> {
    service: S,
    filter: Arc<UserAgentFilter>,
}

impl<S, B, C> Service<Request<B>> for MalformedRequestService<S>
where
    S: Service<Request<B>, Response = Response<C>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = MalformedRequestFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // Cloned rather than resolved into labels here: both are refcounted,
        // while the labels allocate and almost no request needs them.
        let uri = request.uri().clone();
        let user_agent = request.headers().get(USER_AGENT).cloned();

        MalformedRequestFuture {
            inner: self.service.call(request),
            uri,
            user_agent,
            filter: self.filter.clone(),
        }
    }
}

#[pin_project]
pub struct MalformedRequestFuture<F> {
    #[pin]
    inner: F,
    uri: Uri,
    user_agent: Option<HeaderValue>,
    filter: Arc<UserAgentFilter>,
}

impl<F, C, E> Future for MalformedRequestFuture<F>
where
    F: Future<Output = Result<Response<C>, E>>,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let Poll::Ready(result) = this.inner.poll(cx) else {
            return Poll::Pending;
        };

        Poll::Ready(result.map(|mut response| {
            if is_missing_request_message(response.headers()) {
                set_invalid_argument(&mut response);

                // Without the leading slash, matching the `http.route` the
                // other gRPC metrics carry so queries can join on it.
                let path = this.uri.path();
                let route = path.strip_prefix('/').unwrap_or(path);
                let user_agent = normalized_user_agent(this.filter, this.user_agent.as_ref());

                debug!(
                    route,
                    user_agent = user_agent.as_ref(),
                    "Reclassified a request carrying no gRPC message as InvalidArgument"
                );
                record_missing_request_message(route, user_agent);
            }
            response
        }))
    }
}

/// Resolves the `User-Agent` to the value recorded, without sampling the
/// unrecognised ones into the log: the metrics layer already samples the same
/// request, and this path answers callers that can repeat it at will.
fn normalized_user_agent(filter: &UserAgentFilter, value: Option<&HeaderValue>) -> Arc<str> {
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return USER_AGENT_NONE.clone();
    };

    match filter.normalize(value) {
        NormalizeOutput::KnownAgent(label) => label,
        NormalizeOutput::Unknown => USER_AGENT_UNKNOWN.clone(),
    }
}

fn record_missing_request_message(route: &str, user_agent: Arc<str>) {
    MISSING_REQUEST_MESSAGES.add(
        1,
        &[
            KeyValue::new(HTTP_ROUTE, Arc::from(route)),
            KeyValue::new(USER_AGENT_NAME, user_agent),
        ],
    );
}

#[lore_macro::test_pub]
fn is_missing_request_message(headers: &HeaderMap) -> bool {
    // `Status::from_header_map` clones the header map to build a `MetadataMap`,
    // so the code is compared first to keep that off every other response.
    let Some(code) = headers.get(GRPC_STATUS_HEADER) else {
        return false;
    };
    if Code::from_bytes(code.as_bytes()) != Code::Internal {
        return false;
    }

    Status::from_header_map(headers)
        .is_some_and(|status| status.message() == MISSING_REQUEST_MESSAGE)
}

/// The message tonic set still describes the failure, so only `grpc-status`
/// changes.
#[lore_macro::test_pub]
fn set_invalid_argument<C>(response: &mut Response<C>) {
    response.headers_mut().insert(
        HeaderName::from_static(GRPC_STATUS_HEADER),
        HeaderValue::from(i32::from(Code::InvalidArgument)),
    );
}
