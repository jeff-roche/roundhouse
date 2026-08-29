//! The one real, network-backed [`HttpTransport`] — and, per §9.10, the one
//! place in the workspace allowed to construct a `reqwest::Client`.

use std::time::Duration;

use futures::future::BoxFuture;
use futures::StreamExt;

use crate::transport::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};

/// How long to wait for a TCP+TLS connection before giving up. Generous enough
/// for a cold TLS handshake over a slow link, short enough that an unroutable
/// host fails the turn instead of wedging the daemon.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read inactivity timeout — the clock resets on every chunk that arrives,
/// so an arbitrarily long *legitimate* stream (a model thinking for ten minutes
/// and emitting tokens throughout) is never cut off, while a server that
/// accepts the connection and then goes silent is. A total request timeout
/// would get this exactly backwards: it cannot distinguish a stalled peer from
/// a productive long generation, so any value large enough to be safe for the
/// latter is too large to bound the former.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

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
///
/// **Implicit network path:** `reqwest`'s default `system-proxy` feature is
/// enabled, so `HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY` in the daemon's environment
/// silently route requests through a proxy. That is not a credential leak —
/// HTTPS goes through a `CONNECT` tunnel, so headers (including `x-api-key`)
/// stay inside TLS and the proxy sees only the destination host — but it is a
/// network path nobody configured in this codebase, so it is written down here
/// rather than discovered during an incident.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds the transport production uses: HTTPS only, no redirect following,
    /// and bounded connect/read timeouts.
    ///
    /// **`redirect::Policy::none()` is a credential control, not a preference.**
    /// `reqwest`'s default policy follows up to 10 redirects, and its
    /// `remove_sensitive_headers` strips only `Authorization`, `Cookie`,
    /// `Cookie2`, `Proxy-Authorization` and `WWW-Authenticate` when a redirect
    /// crosses origins. `x-api-key` — the header Anthropic authenticates with,
    /// and the one this crate sets — is a *custom* header and is on none of
    /// those lists, so a `302` would re-send the live credential verbatim to
    /// whatever origin the redirect names. Not following redirects at all
    /// closes that hole outright, and has the second benefit of making a 3xx
    /// reach `AnthropicMessagesProvider`'s status check as a real error instead
    /// of being transparently followed.
    ///
    /// **`https_only(true)`** stops the same credential from ever going out in
    /// cleartext if a base URL is misconfigured — `AnthropicMessagesProvider`'s
    /// `base_url` is a public field, documented as where §9.9's future
    /// `ROUNDHOUSE_<PROVIDER>_BASE_URL` override will land, so an
    /// environment-controlled `http://` value has to fail closed.
    ///
    /// Panics only if the TLS backend cannot initialize at all, which is a
    /// process-startup environment failure and matches `Client::new()`'s own
    /// documented behaviour. Nothing in a request, and nothing an adversarial
    /// *response* can contain, reaches this code path.
    pub fn new() -> Self {
        Self {
            client: Self::builder()
                .https_only(true)
                .build()
                .expect("TLS backend initialization"),
        }
    }

    /// Same as [`new`](Self::new) in every respect except that plaintext
    /// `http://` is permitted.
    ///
    /// Exists because two legitimate callers cannot use HTTPS: this crate's own
    /// hermetic round-trip test, whose local TCP responder would need a
    /// generated certificate chain to speak TLS, and Phase 6's local providers
    /// (Ollama, llama.cpp and friends bind plaintext `http://127.0.0.1`).
    /// Deliberately a separate, named constructor rather than a flag on
    /// [`new`](Self::new): the safe configuration stays the one you get by
    /// default, and every caller that gives up HTTPS has to say so at its own
    /// call site, where a reviewer will see it.
    pub fn allowing_plaintext_http() -> Self {
        Self {
            client: Self::builder()
                .https_only(false)
                .build()
                .expect("TLS backend initialization"),
        }
    }

    /// The settings both constructors share, so the two can never drift apart
    /// on the parts that are not about scheme.
    fn builder() -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
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
            // `bytes_stream()` (the `stream` feature) yields chunks as they
            // arrive rather than buffering the response here, which is what
            // §9.3's "streaming is the only path" needs from the transport
            // layer.
            //
            // It does *not* by itself bound memory end-to-end, and an earlier
            // version of this comment wrongly implied it did: today's only
            // consumer, `decode_anthropic_messages_stream`, drains this stream
            // into a `Vec<StreamEvent>` before returning, and `sse-stream`'s
            // internal line buffer is unbounded too. `READ_TIMEOUT` is what
            // actually stops an infinite-body endpoint — it bounds the *gap*
            // between chunks, so a server that trickles forever is still
            // trickling within the timeout. Bounding total response size is
            // Phase 2's, alongside making the decoder genuinely incremental.
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
