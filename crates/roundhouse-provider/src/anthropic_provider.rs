//! The first concrete, live-network `Provider`: Anthropic's Messages API,
//! built by bridging Task 9's pure encoder and Task 10's pure decoder across
//! whatever [`HttpTransport`](crate::HttpTransport) `RequestCtx` carries.

use crate::audit::redact_transport_error_text;
use crate::codec::anthropic_messages::{
    decode_anthropic_messages_events, encode_anthropic_messages, StreamFailure, StreamFailureKind,
};
use futures::StreamExt;
// Note: `Capabilities`/`ModelInfo`/`Plan`/`ProviderError`/`TokenCount` live in
// `ir`, not in `provider_trait` — `provider_trait` re-exports nothing and
// defines only `BoxFut` and the trait itself.
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// Rejection reason for an operator-supplied `ROUNDHOUSE_ANTHROPIC_BASE_URL`
/// that [`parse_anthropic_base_url`] refused. Every variant carries at most
/// the offending scheme or host -- never the raw input, which may embed a
/// query string or userinfo carrying a credential (exactly the shape
/// [`BaseUrlError::Credentials`]/[`BaseUrlError::Query`] themselves reject).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BaseUrlError {
    #[error("ROUNDHOUSE_ANTHROPIC_BASE_URL is not a valid URL")]
    Unparseable,
    #[error("ROUNDHOUSE_ANTHROPIC_BASE_URL must not include a username or password")]
    Credentials,
    #[error("ROUNDHOUSE_ANTHROPIC_BASE_URL must not include a query string")]
    Query,
    #[error("ROUNDHOUSE_ANTHROPIC_BASE_URL must not include a fragment")]
    Fragment,
    #[error(
        "ROUNDHOUSE_ANTHROPIC_BASE_URL must start with \"https://\", or \"http://\" only for \
         a loopback host (127.0.0.0/8, ::1, localhost); got scheme {0:?}"
    )]
    UnsupportedScheme(String),
    #[error(
        "ROUNDHOUSE_ANTHROPIC_BASE_URL uses \"http://\" but {0:?} is not a loopback host \
         (127.0.0.0/8, ::1, localhost)"
    )]
    NonLoopbackHttp(String),
}

/// Which `ReqwestTransport` constructor a validated
/// `ROUNDHOUSE_ANTHROPIC_BASE_URL` requires. [`parse_anthropic_base_url`]
/// only ever hands back [`HttpLoopback`](Self::HttpLoopback) for a URL it has
/// already confirmed is `http://` against a loopback host -- but it does not
/// build the transport itself, so the plaintext escape hatch is always
/// chosen visibly at the caller's own call site (`roundhouse-daemon`'s
/// `main`), not silently inside this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnthropicBaseUrlTransport {
    /// `https://` -- the safe default, `ReqwestTransport::new()`.
    Https,
    /// `http://` against a loopback host -- `ReqwestTransport::
    /// allowing_plaintext_http()`.
    HttpLoopback,
}

/// Validates and normalizes an operator-supplied `ROUNDHOUSE_ANTHROPIC_BASE_URL`.
///
/// Parses with `reqwest::Url::parse` -- the exact WHATWG-compliant parser
/// `reqwest` itself uses for every outbound request -- rather than hand-rolled
/// string splitting. A hand-rolled authority scan that ends only at `/ ? #`
/// disagrees with the real parser about where the host ends whenever the
/// input contains a backslash: a "special" scheme like `http` treats `\`
/// exactly like `/` (a WHATWG quirk), so `http://evil.com\@127.0.0.1` scans,
/// under naive splitting, as host `127.0.0.1` with a stray path-looking
/// suffix -- while `reqwest`'s own parser (proven directly against `url`
/// 2.5.8) resolves the very same string to host `evil.com`, with
/// `/@127.0.0.1` as its path. A prior version of this function used that
/// naive scan and accepted the string as loopback; the real request would
/// have gone to `evil.com` instead. Delegating entirely to the real parser
/// and reading its own `.host()` back closes that class of bug by
/// construction, rather than chasing each new bypass string one at a time.
///
/// `https` is always allowed. `http` is allowed only when the parsed host is
/// a loopback `Ipv4`/`Ipv6` address (`127.0.0.0/8`, `::1`) or the literal
/// domain `localhost` (`Url::host()` itself lowercases domains, so this is
/// effectively case-insensitive). A non-empty username or password, any
/// query string, or any fragment is rejected outright, regardless of scheme
/// -- each is a place an operator-supplied gateway URL could carry a
/// credential (`https://u:secret@gw.example`, `https://gw.example/?k=secret`)
/// that this value's own `info!` log line at the call site would otherwise
/// echo verbatim. A path prefix is fine (`https://gw.example/anthropic`). A
/// trailing `/` is trimmed, because `AnthropicMessagesProvider::stream_chat`
/// appends `/v1/messages`.
pub fn parse_anthropic_base_url(
    raw: &str,
) -> Result<(String, AnthropicBaseUrlTransport), BaseUrlError> {
    let url = reqwest::Url::parse(raw).map_err(|_| BaseUrlError::Unparseable)?;

    if !url.username().is_empty() || url.password().is_some() {
        return Err(BaseUrlError::Credentials);
    }
    if url.query().is_some() {
        return Err(BaseUrlError::Query);
    }
    if url.fragment().is_some() {
        return Err(BaseUrlError::Fragment);
    }

    let is_loopback = match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    };

    let transport = match url.scheme() {
        "https" => AnthropicBaseUrlTransport::Https,
        "http" if is_loopback => AnthropicBaseUrlTransport::HttpLoopback,
        "http" => {
            return Err(BaseUrlError::NonLoopbackHttp(
                url.host_str().unwrap_or_default().to_string(),
            ));
        }
        other => return Err(BaseUrlError::UnsupportedScheme(other.to_string())),
    };

    Ok((url.as_str().trim_end_matches('/').to_string(), transport))
}

/// Anthropic's required API-version header. Pinned rather than tracking
/// "latest": the version string *is* the wire contract this crate's encoder and
/// decoder were written against, so bumping it is a deliberate change that
/// comes with re-checking both codecs, not a silent drift.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic's documented status for `overloaded_error`. It is not in the 5xx
/// range, so it needs naming explicitly or it would fall through to the generic
/// client-error bucket and be treated as fatal instead of retryable.
const HTTP_OVERLOADED: u16 = 529;

/// The first concrete, live-network `Provider` anywhere in this plan.
///
/// Bridges Tasks 9-10's pure `encode`/`decode` functions to a real
/// `HttpTransport` — [`ReqwestTransport`](crate::ReqwestTransport) in
/// production, `CassetteTransport` in this task's own tests. The transport is
/// never constructed here; it arrives on `RequestCtx`, which is the whole point
/// of §9.10's single seam.
///
/// Deliberately holds no credential: §9.9 keeps the key on the per-request
/// context, so a long-lived provider value in the registry never owns secret
/// material, and this struct stays trivially shareable across sessions.
pub struct AnthropicMessagesProvider {
    /// API origin, without a trailing slash. Overridable so a gateway or a
    /// local mock can be pointed at without touching this adapter:
    /// `roundhouse-daemon`'s `main` sets it from the operator's
    /// `ROUNDHOUSE_ANTHROPIC_BASE_URL` (Phase 8, Task 8), once this module's
    /// own [`parse_anthropic_base_url`] has confirmed the value is `https://`
    /// or a loopback `http://` (127.0.0.0/8, `::1`, `localhost`), rejected any
    /// userinfo/query/fragment, and named which `ReqwestTransport` the daemon
    /// must build alongside it — never a raw, unvalidated string.
    pub base_url: String,
}

impl AnthropicMessagesProvider {
    /// Builds a provider pointed at Anthropic's public API.
    pub fn new() -> Self {
        Self {
            base_url: "https://api.anthropic.com".to_string(),
        }
    }
}

impl Default for AnthropicMessagesProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps a non-2xx HTTP status onto the `ProviderError` variant carrying the
/// right §9.8 *disposition*, so Phase 2's retry/fallback middleware gets a
/// correct answer to "should this be retried?" without having to re-derive it.
///
/// This is only §9.8's **third** classification layer ("provider error code →
/// message regex → HTTP status default"): the first two need the per-provider
/// `[errors]` profile tables that land in Phase 2. Lumping everything into
/// `Unsupported` instead would be the actively wrong default — `Unsupported`
/// reads as fatal, so a transient 503 or a 429 would never be retried.
///
/// **The response body is deliberately not read, and no snippet of it appears
/// in any returned error.** §9.9's redaction pass — which scrubs API-key-shaped
/// strings out of persisted error bodies precisely because "providers echo
/// request bodies in 400s more often than you'd like" — is Phase 2 work and
/// does not exist yet. Until it does, the safe amount of unredacted provider
/// output to put into a loggable error is none, so `BadRequest.body_snippet` is
/// left empty rather than filled from an unscrubbed body.
fn classify_status(status: u16) -> ProviderError {
    match status {
        429 => ProviderError::RateLimited {
            // Phase 2 owns `retry-after` parsing along with the rest of the
            // backoff policy; asserting a value here would be a guess.
            retry_after: None,
        },
        404 => ProviderError::ModelNotFound,
        // The whole 4xx family, not just 400: every one of them is "the server
        // rejected this request", i.e. fatal, never retry. `status` is carried
        // on the variant, so nothing is lost by sharing the bucket.
        400..=499 => ProviderError::BadRequest {
            status,
            body_snippet: String::new(),
        },
        HTTP_OVERLOADED => ProviderError::Overloaded,
        500..=599 => ProviderError::Server { status },
        // 1xx and 3xx: not a success, and not an error the provider chose
        // either — the HTTP layer handed back something undecodable (an
        // unfollowed redirect, most likely). Transport-level, not provider-level.
        _ => ProviderError::Transport(format!(
            "anthropic-messages returned unexpected HTTP {status}"
        )),
    }
}

impl Provider for AnthropicMessagesProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        // Phase 0's Task 7 ships `Capabilities` as `{ streaming, tools,
        // thinking, max_breakpoints }` — narrower than an earlier draft's
        // `supports_tools`/`supports_thinking`/`max_context_tokens` fields.
        // `max_context_tokens`'s concept lives on `ModelInfo::context_window`
        // instead. Anthropic's API supports up to 4 `cache_control` breakpoints
        // per request.
        //
        // Not per-model yet: a real registry keyed by `ModelId` is Phase 6's
        // provider-breadth work, and every model this adapter can reach today
        // supports all three flags.
        Capabilities {
            streaming: true,
            tools: true,
            thinking: true,
            max_breakpoints: 4,
        }
    }

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "anthropic-messages".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let body = encode_anthropic_messages(req);
            let http_req = HttpRequest {
                method: "POST".to_string(),
                url: format!("{}/v1/messages", self.base_url),
                headers: vec![
                    // The key's only destination. `HttpRequest` derives no
                    // `Debug`, and neither does `RequestCtx`, so there is no
                    // formatter anywhere that can print it by accident.
                    ("x-api-key".to_string(), ctx.api_key.clone()),
                    (
                        "anthropic-version".to_string(),
                        ANTHROPIC_VERSION.to_string(),
                    ),
                    ("content-type".to_string(), "application/json".to_string()),
                ],
                // `encode_anthropic_messages` returns a `serde_json::Value`,
                // which cannot fail to serialize (no custom `Serialize` impl,
                // no non-string map keys, no NaN) — but this stays a `?` rather
                // than an `expect` so a future encoder change that *can* fail
                // becomes an error instead of a panic in the request path.
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // `ProviderError` has no `#[from] TransportError` (Phase 0's Task 7
            // shape is `Transport(String)`), so the conversion is explicit.
            // `TransportError`'s `Display` never includes request headers, so
            // the API key cannot ride along here.
            //
            // Fix round 6, J4 (superseded by Phase 8, Task 8): `base_url` is
            // no longer only ever set by `::new()` -- `roundhouse-daemon`'s
            // `main` now sets it from the operator's
            // `ROUNDHOUSE_ANTHROPIC_BASE_URL`, gated by this module's own
            // `parse_anthropic_base_url`, which parses with `reqwest::Url`
            // (not hand-rolled splitting -- fix round 1 found a real
            // backslash-authority bypass in an earlier hand-rolled version),
            // accepts only `https://` or a loopback `http://` (127.0.0.0/8,
            // `::1`, `localhost`), and separately rejects any userinfo, query
            // string, or fragment. That really does reject the
            // credential-in-URL shape this note used to warn about (a
            // gateway URL carrying userinfo or a query-string secret) before
            // it can ever reach this field. The `redact_transport_error_text`
            // routing below is unchanged and still the actual guarantee for
            // whatever URL text does land in a `TransportError`'s `Display`.
            let response = ctx.transport.send(http_req).await.map_err(|e| {
                ProviderError::Transport(redact_transport_error_text(&e.to_string()))
            })?;

            // "Is it 2xx", not "is it below 400". A 3xx would otherwise be
            // handed to the SSE decoder, which skips every frame it cannot
            // parse and never errors — so a redirect body would surface to the
            // caller as a perfectly successful, silently empty stream.
            if !(200..300).contains(&response.status) {
                return Err(classify_status(response.status));
            }

            // §9.3: "streaming is the only path" -- decode incrementally
            // (`decode_anthropic_messages_events`) and hand back a
            // `ChatStream` as soon as its first item exists, rather than
            // buffering the whole body first the way
            // `decode_anthropic_messages_stream` does.
            //
            // `stream_chat`'s own `Result` therefore only ever reports a
            // failure that happens *before* that first item, matching every
            // other error path in this function: once at least one item has
            // decoded, a later mid-stream failure becomes the stream's own
            // terminal `Err` item instead (`ChatStream`'s Task 1 fallible
            // item type exists precisely for this).
            //
            // `decode_anthropic_messages_events` already returns a
            // `FusedStream` (it fuses the `futures::stream::unfold` it is
            // built on, which would otherwise panic if polled after ending),
            // so boxing it here as a bare `dyn Stream` is safe for any
            // `select!`/`chain`/replay wrapper a caller later builds on the
            // returned `ChatStream`.
            let mut decoded: std::pin::Pin<
                Box<
                    dyn futures::Stream<
                            Item = Result<crate::stream_event::StreamEvent, StreamFailure>,
                        > + Send,
                >,
            > = Box::pin(decode_anthropic_messages_events(response.body));

            let first = match decoded.next().await {
                // Structurally unreachable: `DecodeLoopGuard::finish`
                // defaults to `Err(Truncated)` whenever `message_stop` was
                // never observed, including on a body with zero frames at
                // all, so an empty decode still yields that one terminal
                // `Err` rather than ending with no items. Belt and braces
                // anyway -- but reported as the failure the decoder itself
                // produces for a zero-frame body (what
                // `stream_chat_returns_err_when_the_body_closes_before_any_content_arrives`
                // asserts), never as a successful empty stream: that is the
                // exact silently-empty-success failure mode the status-code
                // check above exists to prevent, and a caller cannot tell it
                // apart from a real model response with no content.
                None => {
                    return Err(ProviderError::StreamInterrupted {
                        partial: String::new(),
                    })
                }
                Some(Err(failure)) => return Err(stream_failure_to_provider_error(failure)),
                Some(Ok(event)) => event,
            };

            let rest = decoded.map(|item| item.map_err(stream_failure_to_provider_error));
            let stream =
                futures::stream::once(futures::future::ready(Ok::<_, ProviderError>(first)))
                    .chain(rest);
            Ok(ChatStream(Box::pin(stream)))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move {
            // `Ok(TokenCount::default())` would be worse than useless: a caller
            // budgeting against a confidently-reported zero would over-commit.
            Err(ProviderError::Unsupported(
                "count_tokens requires the /v1/messages/count_tokens endpoint, not built in this task"
                    .into(),
            ))
        })
    }

    // `list_models` is deliberately *not* overridden. The trait's default
    // returns `Unsupported("list_models")`, which is the truthful answer until
    // `/v1/models` is wired; an override returning `Ok(vec![])` would instead
    // assert "this provider offers no models at all", which a caller enumerating
    // providers would believe.
}

/// Ruling R17, item 3: modeled on `codec::cohere_v2::provider`'s identical
/// `stream_failure_to_provider_error` — `decode_anthropic_messages_events`
/// now knows, at decode time, exactly which real wire condition produced a
/// failure, so this function trusts `StreamFailure::kind` rather than
/// re-deriving a disposition from an always-200 HTTP status.
fn stream_failure_to_provider_error(failure: StreamFailure) -> ProviderError {
    tracing::warn!(
        kind = ?failure.kind,
        message = %redact_transport_error_text(&failure.message),
        "anthropic-messages stream failed mid-generation"
    );
    match failure.kind {
        StreamFailureKind::Transport => ProviderError::Transport(failure.message),
        StreamFailureKind::Truncated => ProviderError::StreamInterrupted {
            partial: failure.partial_text,
        },
    }
}

#[cfg(test)]
mod base_url_tests {
    use super::{parse_anthropic_base_url, AnthropicBaseUrlTransport, BaseUrlError};

    /// Table test covering the brief's original acceptance/rejection cases
    /// plus every adversarial string the security review (fix round 1)
    /// added. Each backslash-bearing row is a real bypass a hand-rolled
    /// authority scan fell for: `reqwest::Url::parse` (proven directly
    /// against `url` 2.5.8 in this fix) resolves every one of them to host
    /// `evil.com`, not the loopback address the raw string suggests, so
    /// they are rejected as `NonLoopbackHttp("evil.com")`.
    type ExpectedBaseUrl = Result<(&'static str, AnthropicBaseUrlTransport), BaseUrlError>;

    #[test]
    fn parse_anthropic_base_url_table() {
        let cases: &[(&str, ExpectedBaseUrl)] = &[
            // --- brief's original cases ---
            (
                "https://api.anthropic.com",
                Ok((
                    "https://api.anthropic.com",
                    AnthropicBaseUrlTransport::Https,
                )),
            ),
            (
                "http://127.0.0.1:4317",
                Ok((
                    "http://127.0.0.1:4317",
                    AnthropicBaseUrlTransport::HttpLoopback,
                )),
            ),
            (
                "http://example.com",
                Err(BaseUrlError::NonLoopbackHttp("example.com".to_string())),
            ),
            (
                "ftp://example.com",
                Err(BaseUrlError::UnsupportedScheme("ftp".to_string())),
            ),
            (
                "https://api.anthropic.com/",
                Ok((
                    "https://api.anthropic.com",
                    AnthropicBaseUrlTransport::Https,
                )),
            ),
            (
                "http://localhost:9999/",
                Ok((
                    "http://localhost:9999",
                    AnthropicBaseUrlTransport::HttpLoopback,
                )),
            ),
            (
                "http://[::1]:9999",
                Ok(("http://[::1]:9999", AnthropicBaseUrlTransport::HttpLoopback)),
            ),
            // --- 127.0.0.0/8 range, not just 127.0.0.1; 128.0.0.1 is NOT loopback ---
            (
                "http://127.255.0.1:8080",
                Ok((
                    "http://127.255.0.1:8080",
                    AnthropicBaseUrlTransport::HttpLoopback,
                )),
            ),
            (
                "http://128.0.0.1",
                Err(BaseUrlError::NonLoopbackHttp("128.0.0.1".to_string())),
            ),
            // --- fix round 1, IMPORTANT 1: backslash-authority bypass ---
            // Each resolves (per the real WHATWG parser) to host `evil.com`.
            (
                r"http://evil.com\@127.0.0.1",
                Err(BaseUrlError::NonLoopbackHttp("evil.com".to_string())),
            ),
            (
                r"http://\evil.com\@127.0.0.1",
                Err(BaseUrlError::NonLoopbackHttp("evil.com".to_string())),
            ),
            (
                r"http://evil.com\x@localhost",
                Err(BaseUrlError::NonLoopbackHttp("evil.com".to_string())),
            ),
            (
                r"http://evil.com\t\@127.0.0.1",
                Err(BaseUrlError::NonLoopbackHttp("evil.com".to_string())),
            ),
            // `[::1].evil.com` is not a valid bracketed IPv6 literal (the
            // brackets must enclose the WHOLE host), so the real parser
            // refuses it outright instead of silently taking a prefix.
            ("http://[::1].evil.com", Err(BaseUrlError::Unparseable)),
            // userinfo `127.0.0.1`, host `evil.com` -- rejected on both the
            // userinfo check and (independently) the host check.
            ("http://127.0.0.1@evil.com", Err(BaseUrlError::Credentials)),
            (
                "http://localhost.evil.com",
                Err(BaseUrlError::NonLoopbackHttp(
                    "localhost.evil.com".to_string(),
                )),
            ),
            ("http://evil.com#@127.0.0.1", Err(BaseUrlError::Fragment)),
            // Scheme is case-insensitive (the real parser lowercases it);
            // still rejected on the real (non-loopback) host, not accepted
            // by accident of case.
            (
                "HTTP://evil.com",
                Err(BaseUrlError::NonLoopbackHttp("evil.com".to_string())),
            ),
            // --- WHATWG's alternate IPv4 notations: real loopback addresses
            // a naive `std::net::Ipv4Addr::from_str` (decimal-dotted only)
            // would have wrongly rejected. ---
            (
                "http://0x7f.0.0.1",
                Ok(("http://127.0.0.1", AnthropicBaseUrlTransport::HttpLoopback)),
            ),
            (
                "http://2130706433",
                Ok(("http://127.0.0.1", AnthropicBaseUrlTransport::HttpLoopback)),
            ),
            // --- fix round 1, IMPORTANT 3: credential-in-URL shapes ---
            ("http://user:pass@127.0.0.1", Err(BaseUrlError::Credentials)),
            (
                "https://u:secret@gw.example",
                Err(BaseUrlError::Credentials),
            ),
            ("https://gw.example/?k=secret", Err(BaseUrlError::Query)),
            ("https://gw.example/#frag", Err(BaseUrlError::Fragment)),
            // A path prefix (no query, no fragment, no userinfo) is fine.
            (
                "https://gw.example/anthropic/",
                Ok((
                    "https://gw.example/anthropic",
                    AnthropicBaseUrlTransport::Https,
                )),
            ),
            // --- whitespace: the real parser trims leading/trailing space
            // as WHATWG requires; not a bypass, just proven here rather than
            // assumed. ---
            (
                " https://api.anthropic.com",
                Ok((
                    "https://api.anthropic.com",
                    AnthropicBaseUrlTransport::Https,
                )),
            ),
            (
                "https://api.anthropic.com ",
                Ok((
                    "https://api.anthropic.com",
                    AnthropicBaseUrlTransport::Https,
                )),
            ),
        ];

        for (input, expected) in cases {
            let actual = parse_anthropic_base_url(input);
            let expected_owned = expected.clone().map(|(s, t)| (s.to_string(), t));
            assert_eq!(actual, expected_owned, "input: {input:?}");
        }
    }

    /// The controller's exact wiring test: a validated http loopback base
    /// URL comes back tagged for the plaintext-capable transport, and a
    /// validated https base URL does not.
    #[test]
    fn validated_http_loopback_is_tagged_for_the_plaintext_transport() {
        let (_, transport) = parse_anthropic_base_url("http://127.0.0.1:9999").unwrap();
        assert_eq!(transport, AnthropicBaseUrlTransport::HttpLoopback);
    }

    #[test]
    fn validated_https_is_tagged_for_the_default_transport() {
        let (_, transport) = parse_anthropic_base_url("https://api.anthropic.com").unwrap();
        assert_eq!(transport, AnthropicBaseUrlTransport::Https);
    }
}
