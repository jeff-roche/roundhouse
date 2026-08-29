//! The one real, network-backed [`HttpTransport`] — and, per §9.10, the one
//! place in the workspace allowed to construct a `reqwest::Client`.

use futures::future::BoxFuture;
use futures::StreamExt;

use crate::transport::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};

/// The one real, network-backed `HttpTransport`. This is the sanctioned single
/// construction site for `reqwest::Client` per §9.10's rule ("no adapter ever
/// constructs a `reqwest::Client` directly, so tests inject a
/// `CassetteTransport`") — every adapter and every test goes through
/// `HttpTransport`, injected via `RequestCtx`, instead. This struct is what
/// production code injects there.
///
/// Holds the client rather than building one per request on purpose: a
/// `reqwest::Client` owns the connection pool, so a fresh one per call would
/// throw away every keep-alive connection and pay a new TLS handshake on every
/// turn of a conversation.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds a transport over a fresh `reqwest::Client` with default settings.
    ///
    /// Panics only if the TLS backend cannot initialize at all, which is a
    /// process-startup environment failure, not something reachable from
    /// request data — `Client::new()`'s own documented behaviour. Nothing an
    /// adversarial *response* can contain reaches this code path.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpTransport for ReqwestTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async move {
            // `HttpRequest.method` is a bare `String`, so nothing upstream
            // guarantees it is a valid HTTP token. Parsed with `?` rather than
            // `expect` so a bad method is an error the caller can classify, not
            // a panic inside the daemon's request path.
            let method = reqwest::Method::from_bytes(req.method.as_bytes())
                .map_err(|e| TransportError::Io(e.to_string()))?;
            let mut builder = self.client.request(method, &req.url).body(req.body);
            for (name, value) in &req.headers {
                // `header()` defers an invalid name/value to `send()` rather
                // than panicking, and neither `InvalidHeaderValue`'s nor
                // `reqwest::Error`'s `Display` echoes the offending value — so
                // a malformed credential can't leak through this error path
                // (§9.9: "keys stay out of the log by construction").
                builder = builder.header(name, value);
            }
            let response = builder
                .send()
                .await
                .map_err(|e| TransportError::Io(e.to_string()))?;
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                // A header value that isn't valid UTF-8 becomes empty rather
                // than aborting the whole response: the body is what callers
                // are here for, and a hostile or merely broken server must not
                // be able to fail an otherwise-good stream on a stray byte in a
                // header nobody reads.
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
                .collect();
            // Streamed, not buffered: §9.3 makes streaming the only path, and
            // `bytes_stream()` (the `stream` feature) hands chunks to the SSE
            // decoder as they arrive instead of materializing a whole response
            // an adversarial server could make arbitrarily large.
            let body = response
                .bytes_stream()
                .map(|chunk| chunk.map_err(|e| TransportError::Io(e.to_string())))
                .boxed();
            Ok(HttpResponseStream {
                status,
                headers,
                body,
            })
        })
    }
}
