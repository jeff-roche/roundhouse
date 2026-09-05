//! `OpenAiChatProvider`: the `Provider` trait wrapper Phase 1 never built for
//! the `openai-chat` codec (unlike `anthropic_messages`, which got
//! `AnthropicMessagesProvider` in full). Built once here (Task 10) so every
//! later `openai-chat` profile (Tasks 11-14) is pure data reusing this one
//! adapter unchanged (§9.1's thesis).
//!
//! Unlike the Phase 6 codecs (`cohere_v2`, `google_genai`, ...),
//! `encode_openai_chat`/`decode_openai_chat_stream` are FROZEN Phase 1 pure
//! functions that take no `&ProviderProfile` argument at all (REALITY-
//! CORRECTIONS §1) -- this wrapper supplies everything profile-driven
//! (base URL resolution, auth, `[errors]`-table classification) around them
//! without touching either function.
//!
//! `encode_openai_chat` is infallible (`-> Value`, not `-> Result<..>`), so
//! unlike the sibling codecs' `encode(..)?` propagation, this module owns its
//! own pre-flight guard (`contains_unencodable_content`) and calls it on
//! BOTH `resolve` and `stream_chat` -- `resolve` has zero production callers
//! anywhere in this workspace (REALITY-CORRECTIONS §13b item 5), so the
//! `stream_chat` guard is the one that actually matters for "content the
//! codec can't encode fails closed."

use super::decode::{StreamFailure, StreamFailureKind};
use super::{decode_openai_chat_stream, encode_openai_chat};
use crate::audit::{redact_error_body, redact_transport_error_text};
use crate::credential::{resolve_base_url, CredentialCtx};
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId, Plan, ProviderError, RequestCtx,
    TokenCount,
};
use crate::profile::{AuthKind, ProviderProfile};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// A single, profile-parameterized `Provider` for every `openai-chat`
/// profile: one endpoint (`POST {base_url}/chat/completions`), one wire
/// shape, differing only in which TOML file is loaded.
pub struct OpenAiChatProvider {
    profile: ProviderProfile,
}

impl OpenAiChatProvider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for OpenAiChatProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: true,
            // `encode_openai_chat` has no wire representation for Thinking
            // blocks (drops them silently -- a documented Phase 1 scope
            // gap), so this family does not advertise thinking support.
            thinking: false,
            // `encode_openai_chat` emits no cache-control/breakpoint field.
            max_breakpoints: 0,
        }
    }

    /// Cheap, I/O-free pre-flight (REALITY-CORRECTIONS §13b item 5: `resolve`
    /// has zero production callers anywhere in this workspace) -- the guard
    /// that matters lives in `stream_chat`'s identical check below, since
    /// `encode_openai_chat` cannot itself fail (it returns a bare `Value`,
    /// not a `Result`).
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_content(req) {
            return Err(ProviderError::Unsupported(
                "openai-chat codec does not encode Image/Document/Thinking/Opaque blocks".into(),
            ));
        }
        Ok(Plan {
            endpoint: "openai-chat".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            if contains_unencodable_content(req) {
                return Err(ProviderError::Unsupported(
                    "openai-chat codec does not encode Image/Document/Thinking/Opaque blocks"
                        .into(),
                ));
            }

            let body = encode_openai_chat(req, &self.profile);

            let (base_url, _host_only) = resolve_base_url(
                &self.profile.id,
                &self.profile.defaults.base_url,
                None,
                false,
            )
            .map_err(|e| ProviderError::Transport(redact_transport_error_text(&e.to_string())))?;
            let endpoint_url = build_endpoint_url(&base_url);

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                // Fix round 3, Q5: the one error sink in `stream_chat` that
                // bypassed `redact_error_body` -- effectively infallible
                // (`body` is a `serde_json::Value` this function just
                // built, so this is a `serde_json::Error` over data this
                // codec constructed itself, never wire text), but this
                // project persists error text onto physically-immutable
                // `Event` rows, so consistency here costs nothing and closes
                // the gap. This sink carries no URL (it never touches
                // `resolve_base_url`/`HttpTransport`), so `redact_error_body`
                // -- not the stronger `redact_transport_error_text` the
                // other three sinks in this function use (fix round 5, H1)
                // -- remains the right tool here.
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(redact_error_body(&e.to_string())))?,
            };

            // REALITY-CORRECTIONS §6: prefer the real `CredentialProvider`
            // mechanism when present, falling back to the Phase 1 bare
            // `api_key` path (Bearer, matching every batch-A profile's
            // `auth = { kind = "bearer" }`) when it is not.
            if let Some(credentials) = &ctx.credentials {
                let cred_ctx = CredentialCtx {
                    provider_id: &self.profile.id,
                    transport: ctx.transport.as_ref(),
                    now: std::time::Instant::now(),
                };
                credentials
                    .apply(&mut http_req, &cred_ctx)
                    .await
                    .map_err(|e| {
                        ProviderError::Transport(redact_transport_error_text(&e.to_string()))
                    })?;
            } else {
                match &self.profile.defaults.auth {
                    // An empty or whitespace-only `api_key` must fail
                    // closed, not silently send a header-shaped-but-
                    // credential-less `authorization: Bearer ` that only
                    // earns a remote 401 (matches `cohere_v2`'s and
                    // `google_genai`'s identical guard).
                    AuthKind::Bearer if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "openai-chat codec requires a non-empty api_key (or a \
                             CredentialProvider) for Bearer auth"
                                .into(),
                        ));
                    }
                    AuthKind::Bearer => {
                        http_req.headers.push((
                            "authorization".to_string(),
                            format!("Bearer {}", ctx.api_key),
                        ));
                    }
                    // Every batch-A profile (and moonshot) declares
                    // `bearer`; a missing credential must fail closed rather
                    // than silently send an unauthenticated request if that
                    // ever changes.
                    other => {
                        return Err(ProviderError::Unsupported(format!(
                            "openai-chat codec has no CredentialProvider and its bare api_key \
                             fallback cannot express {other:?} auth"
                        )));
                    }
                }
            }

            let response = ctx.transport.send(http_req).await.map_err(|e| {
                ProviderError::Transport(redact_transport_error_text(&e.to_string()))
            })?;

            if !(200..300).contains(&response.status) {
                // §9.8: never `?` on JSON parsing in the error path.
                let headers = to_header_map(&response.headers);
                let body_bytes = match crate::body_cap::collect_body_capped(
                    response.body,
                    crate::body_cap::MAX_RESPONSE_BODY_BYTES,
                )
                .await
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        return Err(ProviderError::Transport(redact_transport_error_text(
                            &e.to_string(),
                        )))
                    }
                };
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &body_bytes,
                    &headers,
                ));
            }

            let events = decode_openai_chat_stream(response.body)
                .await
                .map_err(stream_failure_to_provider_error)?;
            Ok(ChatStream(Box::pin(futures::stream::iter(events))))
        })
    }

    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move {
            Err(ProviderError::Unsupported(
                "count_tokens is not offered by openai-chat-family providers".into(),
            ))
        })
    }
}

/// Maps a mid-stream [`StreamFailure`] directly onto a `ProviderError`, by
/// `kind` (fix round 3, Q1) -- never through `crate::errors::classify` at
/// the enclosing (always 200) HTTP status, which has no 2xx arm and would
/// land everything in a permanently-fatal `BadRequest { status: 200, .. }`,
/// discarding this module's diagnostics along with any chance of a correct
/// retry decision. Mirrors `cohere_v2::provider::stream_failure_to_provider_error`.
///
/// - `Transport`: a genuine transport-layer error mid-stream -- becomes
///   `ProviderError::Transport`, retried with backoff by `retry.rs` (a
///   transient blip, not a permanent client error).
/// - `Truncated`/`Length`/`ContentFilter`/`UnrecognizedFinishReason`: real
///   partial output exists (or might), and this generic retry loop should
///   not transparently retry a request whose prefix would need to be
///   resent at the caller's discretion -- `ProviderError::StreamInterrupted
///   { partial }` is `retry.rs`'s own `Disposition::Fatal` from ITS
///   perspective, exactly because that decision belongs to the agent loop,
///   not to this transport-retry layer. Mirrors `cohere_v2`'s identical use
///   of this variant for the same "ended without a clean stop" shape.
/// - `Error`: an opaque, provider-side in-band failure (an OpenAI-
///   compatible gateway's `{"error": {...}}` frame) -- treated like an
///   opaque 5xx (`ProviderError::Server`), also retried with backoff,
///   matching `cohere_v2`'s identical treatment of its own `finish_reason:
///   "ERROR"`.
///
/// Fix round 4, R3: `ProviderError::StreamInterrupted`'s `Display`
/// deliberately omits `partial` (`ir.rs:417`'s own doc comment; model output
/// must never land in a persisted error row -- `roundhouse-engine::chat`
/// persists `provider_err.to_string()` verbatim as `TaskError.message` on a
/// physically-immutable `Event` row). That's the right call for `partial`,
/// but it also meant `failure.message` -- the actual, spec-verified reason
/// this stream failed (an unrecognized `finish_reason` value included) --
/// reached NOTHING observable for every kind but `Transport`: an operator
/// saw `StreamInterrupted` with no cause, and couldn't file the capture
/// that would let a real new `finish_reason` value be added. A `tracing`
/// event at this mapping site makes the *reason* visible without ever
/// touching `partial_text` -- the model's content is never passed to this
/// event.
///
/// Fix round 5, H3: this is `warn!`, not `errors.rs`'s `debug!` convention --
/// that crate precedent is for a silent classification fallback that still
/// yields a working, correctly-classified error (nothing user-visible
/// degrades). A `StreamFailure` kills the entire turn, which is the shape
/// `retry.rs` logs at `warn!` seven times over for exactly this reason
/// ("user-visible degrades"). `debug!` also would not survive an eventual
/// default `EnvFilter` (which typically admits `info` and above), silently
/// discarding the one diagnostic this fix exists to make observable.
///
/// Fix round 6, J2: `warn!` surviving a default `EnvFilter` is exactly why
/// `failure.message` cannot ride along unredacted here. `decode.rs`'s
/// `StreamFailureKind::Error` arm builds this message from a provider's own
/// in-band `{"error": {...}}` frame via `sanitize_untrusted_wire_string`,
/// which now redacts (fix round 7, K1) before it caps length and
/// `{:?}`-escapes control characters -- but a provider echoing the request
/// back (`audit/redact.rs`'s own module doc: "more often than you'd like")
/// can still carry an embedded URL whose query string or userinfo holds a
/// credential that no *shape*-based matcher recognizes (e.g. a gateway's
/// `?key=...` rather than a labeled `api_key=...`).
///
/// Fix round 7, K2: routed through `redact_transport_error_text` at the log
/// site itself, not the weaker `redact_error_body` -- belt-and-braces on top
/// of `decode.rs`'s own construction-site redaction, so the guarantee that
/// this event never carries an unredacted URL credential does not depend on
/// every current and future `StreamFailure.message` construction site in
/// `decode.rs` staying disciplined forever.
fn stream_failure_to_provider_error(failure: StreamFailure) -> ProviderError {
    tracing::warn!(
        kind = ?failure.kind,
        message = %redact_transport_error_text(&failure.message),
        "openai-chat stream failed mid-generation"
    );
    match failure.kind {
        StreamFailureKind::Transport => ProviderError::Transport(failure.message),
        StreamFailureKind::Truncated
        | StreamFailureKind::Length
        | StreamFailureKind::ContentFilter
        | StreamFailureKind::UnrecognizedFinishReason => ProviderError::StreamInterrupted {
            partial: failure.partial_text,
        },
        StreamFailureKind::Error => ProviderError::Server { status: 500 },
    }
}

/// `encode_openai_chat` silently drops `Image`/`Document`/`Thinking`/
/// `Opaque` blocks (see its own doc comments: "not handled in Phase 1
/// scope" / "the LossEvent this drop should emit is Phase 2's loss-plumbing
/// task"). Per REALITY-CORRECTIONS §13b item 5, "content the codec can't
/// encode fails closed" -- silently dropping it would mean a user who
/// attached a document, image, or thinking block gets an answer computed
/// without it, with no error, warning, or log entry.
fn contains_unencodable_content(req: &ChatRequest) -> bool {
    req.messages.iter().any(|m| {
        m.content.iter().any(|b| {
            matches!(
                b,
                ContentBlock::Image { .. }
                    | ContentBlock::Document { .. }
                    | ContentBlock::Thinking { .. }
                    | ContentBlock::Opaque { .. }
            )
        })
    })
}

/// Builds the full request URL: `{base}/chat/completions` (every
/// openai-chat-family provider's real, verified endpoint shape -- e.g.
/// `https://openrouter.ai/api/v1/chat/completions`). Preserves `base`'s
/// existing path prefix and query string, matching `cohere_v2::provider`'s
/// and `google_genai::provider`'s identical `build_endpoint_url` precedent
/// (a gateway base URL carrying its own query string must keep it).
fn build_endpoint_url(base: &url::Url) -> url::Url {
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!("{base_path}/chat/completions"));
    url
}

fn to_header_map(raw: &[(String, String)]) -> http::HeaderMap {
    let mut headers = http::HeaderMap::new();
    for (name, value) in raw {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    }
    headers
}

#[cfg(test)]
mod build_endpoint_url_tests {
    use super::build_endpoint_url;

    #[test]
    fn targets_chat_completions() {
        let base = url::Url::parse("https://openrouter.ai/api/v1").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(
            url.as_str(),
            "https://openrouter.ai/api/v1/chat/completions"
        );
    }

    /// A gateway base URL carrying its own query string must keep it (matches
    /// `cohere_v2`'s/`google_genai`'s identical fix-round-1 concern).
    #[test]
    fn preserves_a_gateway_query_string() {
        let base = url::Url::parse("https://gateway.example.com/proxy?key=abc123").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(
            url.as_str(),
            "https://gateway.example.com/proxy/chat/completions?key=abc123"
        );
    }
}

#[cfg(test)]
mod stream_failure_diagnosability_tests {
    //! Fix round 4, R3: `stream_failure_to_provider_error` discarded
    //! `StreamFailure.message` for every kind except `Transport`, and
    //! `ProviderError::StreamInterrupted`'s `Display` deliberately omits
    //! `partial` (`ir.rs`'s own doc comment; `roundhouse-engine::chat`
    //! persists `provider_err.to_string()` verbatim as `TaskError.message`
    //! on a physically-immutable `Event` row) -- so an operator saw
    //! `StreamInterrupted` with no cause at all, and could not file the
    //! capture that would let a future value be added to the fail-closed
    //! `finish_reason` match. This hand-rolled `tracing::Subscriber` (no new
    //! dependency -- `tracing` is already a real dependency of this crate)
    //! proves both halves of the constraint at once: the *reason* reaches an
    //! observable event, and the model's *content* never does, not even via
    //! the tracing event itself.
    use super::{
        decode_openai_chat_stream, stream_failure_to_provider_error, StreamFailure,
        StreamFailureKind,
    };
    use crate::ir::ProviderError;
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};

    #[derive(Default)]
    struct LineVisitor {
        line: String,
    }

    impl Visit for LineVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.line, "{}={:?} ", field.name(), value);
        }
    }

    struct CapturingSubscriber {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut visitor = LineVisitor::default();
            event.record(&mut visitor);
            self.lines.lock().unwrap().push(visitor.line);
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    #[test]
    fn the_failure_reason_reaches_a_tracing_event_but_the_partial_content_never_does() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CapturingSubscriber {
            lines: lines.clone(),
        };
        let failure = StreamFailure {
            kind: StreamFailureKind::Length,
            message: "openai-chat generation stopped: length (a token/context limit was reached \
                       before the model finished)"
                .into(),
            partial_text: "TOP SECRET MODEL OUTPUT".into(),
        };

        let provider_err = tracing::subscriber::with_default(subscriber, || {
            stream_failure_to_provider_error(failure)
        });

        // Half 1 (ir.rs:417 / chat.rs's persisted `TaskError.message`): the
        // Display impl -- what actually reaches a persisted, immutable row
        // -- must never carry the model's partial output.
        assert!(matches!(
            provider_err,
            ProviderError::StreamInterrupted { .. }
        ));
        assert!(!provider_err.to_string().contains("TOP SECRET"));

        // Half 2: the reason must be observable somewhere -- here, a
        // tracing event -- so an operator can file the capture that would
        // let this value be added.
        let captured = lines.lock().unwrap();
        assert!(
            captured
                .iter()
                .any(|line| line.contains("length") && line.contains("token/context limit")),
            "expected the failure reason to reach a tracing event: {captured:?}"
        );
        // And the partial content must never leak into the diagnostic
        // event either -- only the reason is observable, never the content.
        assert!(
            !captured.iter().any(|line| line.contains("TOP SECRET")),
            "the model's partial output must never be logged: {captured:?}"
        );
    }

    /// Fix round 6, J2: `decode.rs`'s `StreamFailureKind::Error` arm builds
    /// `message` straight from a provider's own in-band `{"error": {...}}`
    /// frame, passed only through `sanitize_untrusted_wire_string` (length
    /// cap + `{:?}` escaping -- no redaction). A gateway echoing the request
    /// back in that frame (`audit/redact.rs`'s own module doc: "more often
    /// than you'd like") can carry an `sk-`-shaped key or a `Bearer` token
    /// straight into this `warn!` event, which -- unlike `debug!` -- survives
    /// a default `EnvFilter`. This proves the log site itself redacts,
    /// regardless of which `StreamFailureKind` produced the message.
    #[test]
    fn a_key_shaped_token_in_an_in_band_error_frame_does_not_reach_the_event() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CapturingSubscriber {
            lines: lines.clone(),
        };
        let failure = StreamFailure {
            kind: StreamFailureKind::Error,
            message: "openai-chat stream carried an in-band error frame: \
                      \"invalid Authorization header: Bearer sk-live-abcdefgh12345678\""
                .into(),
            partial_text: String::new(),
        };

        let provider_err = tracing::subscriber::with_default(subscriber, || {
            stream_failure_to_provider_error(failure)
        });
        assert!(matches!(
            provider_err,
            ProviderError::Server { status: 500 }
        ));

        let captured = lines.lock().unwrap();
        assert!(
            !captured
                .iter()
                .any(|line| line.contains("sk-live-abcdefgh12345678")),
            "an sk-shaped key leaked into the tracing event unredacted: {captured:?}"
        );
        assert!(
            !captured
                .iter()
                .any(|line| line.contains("Bearer sk-live-abcdefgh12345678")),
            "a Bearer token leaked into the tracing event unredacted: {captured:?}"
        );
    }

    /// Fix round 7, K2: a mid-stream in-band failure frame's own message can
    /// embed a full URL whose credential is NOT shape-matched by
    /// `redact_error_body` (a differently-named query param like `?sig=...`
    /// rather than a labeled `api_key=...`, or userinfo -- Phase 7 Task 16
    /// added a bare `key=...` alternative to `LABELED_SECRET_VALUE`, so this
    /// fixture uses `sig=...` instead to keep exercising a genuinely
    /// unmatched shape rather than one construction-site redaction now
    /// itself catches). `decode.rs`'s
    /// `sanitize_untrusted_wire_string` (fix round 7, K1) only ever runs the
    /// shape-based `redact_error_body`, so `failure.message` itself still
    /// carries the credential intact -- this test's first assertion pins
    /// that down as a sanity check, so a future strengthening of K1 doesn't
    /// silently make this test vacuous. The real guarantee under test is
    /// that the `tracing::warn!` log site's `redact_transport_error_text`
    /// catches what construction-site redaction structurally cannot.
    /// Driven through the real decoder, per REALITY-CORRECTIONS §15/§13b:
    /// a hand-built `StreamFailure` would never exercise `decode.rs`'s own
    /// message-construction path at all.
    #[tokio::test]
    async fn an_in_band_error_message_embedding_a_credentialed_url_is_redacted_at_the_log_site() {
        fn sse_body(
            frames: &[&str],
        ) -> impl futures::Stream<Item = Result<bytes::Bytes, crate::TransportError>> {
            let mut raw = String::new();
            for frame in frames {
                raw.push_str("data: ");
                raw.push_str(frame);
                raw.push_str("\n\n");
            }
            futures::stream::iter(vec![Ok(bytes::Bytes::from(raw))])
        }

        let body = sse_body(&[
            r#"{"error":{"message":"upstream rejected https://gwuser:gwpass@gw.example.invalid/v1?sig=gw-live-9f2b8c1d4e6a7b3c"}}"#,
        ]);
        let failure = match decode_openai_chat_stream(body).await {
            Ok(_) => panic!("expected a StreamFailure"),
            Err(f) => f,
        };
        assert_eq!(failure.kind, StreamFailureKind::Error);
        assert!(
            failure.message.contains("gwuser:gwpass")
                && failure.message.contains("gw-live-9f2b8c1d4e6a7b3c"),
            "sanity check: this fixture's URL credential is not shape-matched by the \
             construction-site redactor, so it must still be present on `failure.message` -- \
             if this assertion fails, this test no longer exercises the log-site guarantee: {}",
            failure.message
        );

        let lines = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CapturingSubscriber {
            lines: lines.clone(),
        };
        let provider_err = tracing::subscriber::with_default(subscriber, || {
            stream_failure_to_provider_error(failure)
        });
        assert!(matches!(
            provider_err,
            ProviderError::Server { status: 500 }
        ));

        let captured = lines.lock().unwrap();
        assert!(
            !captured.iter().any(|line| line.contains("gwuser:gwpass")),
            "URL userinfo leaked into the tracing event unredacted: {captured:?}"
        );
        assert!(
            !captured
                .iter()
                .any(|line| line.contains("gw-live-9f2b8c1d4e6a7b3c")),
            "the URL query-string credential leaked into the tracing event unredacted: {captured:?}"
        );
        assert!(
            captured
                .iter()
                .any(|line| line.contains("gw.example.invalid")),
            "the host itself should still be visible for diagnosability: {captured:?}"
        );
    }
}

#[cfg(test)]
mod contains_unencodable_content_tests {
    use super::contains_unencodable_content;
    use crate::ir::{
        ChatRequest, ContentBlock, MediaSource, Message, MessageRole, ModelId, Params, ProviderExt,
        ReasoningRequest, RequestPolicy, ResponseFormat, ToolChoice,
    };
    use std::collections::BTreeMap;

    fn request_with(content: Vec<ContentBlock>) -> ChatRequest {
        ChatRequest {
            model: ModelId("m".into()),
            system: vec![],
            messages: vec![Message {
                role: MessageRole::User,
                content,
            }],
            tools: vec![],
            tool_choice: ToolChoice::Auto,
            params: Params::default(),
            reasoning: ReasoningRequest::default(),
            response_format: ResponseFormat::default(),
            ext: ProviderExt::None,
            extra: BTreeMap::new(),
            policy: RequestPolicy::Drop,
        }
    }

    #[test]
    fn plain_text_request_is_encodable() {
        let req = request_with(vec![ContentBlock::Text {
            text: "hi".into(),
            cache: None,
            citations: vec![],
        }]);
        assert!(!contains_unencodable_content(&req));
    }

    #[test]
    fn image_content_is_unencodable() {
        let req = request_with(vec![ContentBlock::Image {
            source: MediaSource {
                mime_type: "image/png".into(),
                data: vec![0, 1, 2, 3],
            },
            cache: None,
        }]);
        assert!(contains_unencodable_content(&req));
    }

    #[test]
    fn thinking_content_is_unencodable() {
        let req = request_with(vec![ContentBlock::Thinking {
            text: "reasoning...".into(),
            signature: None,
            redacted: false,
        }]);
        assert!(contains_unencodable_content(&req));
    }
}
