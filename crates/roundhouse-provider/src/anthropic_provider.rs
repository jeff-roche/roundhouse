//! The first concrete, live-network `Provider`: Anthropic's Messages API,
//! built by bridging Task 9's pure encoder and Task 10's pure decoder across
//! whatever [`HttpTransport`](crate::HttpTransport) `RequestCtx` carries.

use crate::audit::redact_transport_error_text;
use crate::codec::anthropic_messages::{
    decode_anthropic_messages_stream, encode_anthropic_messages, StreamFailure, StreamFailureKind,
};
// Note: `Capabilities`/`ModelInfo`/`Plan`/`ProviderError`/`TokenCount` live in
// `ir`, not in `provider_trait` — `provider_trait` re-exports nothing and
// defines only `BoxFut` and the trait itself.
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

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
    /// local mock can be pointed at without touching this adapter; §9.9's
    /// `ROUNDHOUSE_<PROVIDER>_BASE_URL` resolution chain lands in Phase 2 and
    /// will set this field rather than replace it.
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
            // Fix round 6, J4: `base_url` is only ever set by `::new()` today
            // (a fixed, non-secret literal), so this sink has no live
            // exposure -- but the field is `pub`, and its own doc comment
            // above (`base_url`'s field doc) says the §9.9
            // `ROUNDHOUSE_<PROVIDER>_BASE_URL` override "will set this field",
            // at which point a gateway URL carrying credentials in its query
            // string or userinfo would flow straight into a
            // `TransportError::Io`'s `Display` (`reqwest`'s error text embeds
            // the full request URL) and then onto a physically-immutable
            // `events` row. Routed through the same `redact_transport_error_text`
            // every other codec's transport-error sinks use, so the guarantee
            // holds structurally before that override ever lands, not only
            // once someone remembers to add it then.
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

            let events = decode_anthropic_messages_stream(response.body)
                .await
                .map_err(stream_failure_to_provider_error)?;
            let stream = ChatStream(Box::pin(futures::stream::iter(events)));
            Ok(stream)
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
/// `stream_failure_to_provider_error` — `decode_anthropic_messages_stream`
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
