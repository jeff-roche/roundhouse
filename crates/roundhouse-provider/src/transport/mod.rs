use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{self, Stream};
use std::pin::Pin;

/// The `sigv4-eventstream` transport shim (§9.4, Phase 6 Task 7): decodes
/// AWS's binary `application/vnd.amazon.eventstream` framing, the one wire
/// format in this crate that isn't SSE (Bedrock's legacy non-Claude
/// `ConverseStream` responses). `pub`, not `pub(crate)`, so
/// `codec::bedrock_converse` — a sibling module, not a child of `transport`
/// — can reach it via `crate::transport::eventstream::EventStreamDecoder`;
/// `transport` itself stays a crate-private `mod` in `lib.rs`; see that
/// declaration's doc comment for why that's still visible everywhere in this
/// crate.
pub mod eventstream;

/// The `azure-deployment-routing` transport shim (§9.4, Phase 6 Task 14):
/// pure URL construction for Azure OpenAI's deployment-name-based routing.
/// `pub`, not `pub(crate)`, for the same reason as `eventstream` above
/// (`transport` itself stays a crate-private `mod` in `lib.rs`) — re-exported
/// at the crate root (`lib.rs`) so external test crates can reach it despite
/// `transport` being private.
pub mod azure_deployment_routing;

/// HTTP request to be sent via `HttpTransport`.
pub struct HttpRequest {
    /// HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// Request URL.
    pub url: String,
    /// Request headers as key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Request body bytes.
    pub body: Vec<u8>,
}

/// HTTP response body streamed via `futures::Stream`.
pub struct HttpResponseStream {
    /// HTTP status code.
    pub status: u16,
    /// Response headers as key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Response body streamed in chunks.
    pub body: Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>>,
}

/// Errors that can occur during HTTP transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("transport io error: {0}")]
    Io(String),
    #[error("cassette exhausted: no more recorded chunks")]
    CassetteExhausted,
}

/// Trait for HTTP transport implementations, allowing for both real network
/// transports and test-time cassette replays.
pub trait HttpTransport: Send + Sync {
    /// Send an HTTP request and receive a streamed response.
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>>;
}

/// Helper: splits a body into fixed-size chunks (or one whole chunk if `chunk_size == 0`).
pub(crate) fn chunk_body(body: Vec<u8>, chunk_size: usize) -> Vec<Bytes> {
    if chunk_size == 0 || body.is_empty() {
        return vec![Bytes::from(body)];
    }
    body.chunks(chunk_size)
        .map(Bytes::copy_from_slice)
        .collect()
}

/// Helper: converts a Vec of Bytes into a pinned stream.
pub(crate) fn stream_from_chunks(
    chunks: Vec<Bytes>,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>> {
    Box::pin(stream::iter(chunks.into_iter().map(Ok)))
}
