use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{self, Stream};
use std::pin::Pin;

/// HTTP request to be sent via `HttpTransport`.
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// HTTP response body streamed via `futures::Stream`.
pub struct HttpResponseStream {
    pub status: u16,
    pub headers: Vec<(String, String)>,
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
        .map(|c| Bytes::copy_from_slice(c))
        .collect()
}

/// Helper: converts a Vec of Bytes into a pinned stream.
pub(crate) fn stream_from_chunks(
    chunks: Vec<Bytes>,
) -> Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>> {
    Box::pin(stream::iter(chunks.into_iter().map(Ok)))
}
