//! `CohereV2Provider`: bridges this module's pure `encode`/`decode` functions
//! to a real [`HttpTransport`]. Mirrors `google_genai::provider`'s shape
//! (profile-driven, `[errors]`-table classification via `crate::errors::classify`
//! for HTTP-level errors) -- but a mid-stream [`StreamFailure`] (an in-band
//! failure arriving after a 200) is mapped DIRECTLY onto a `ProviderError`
//! by [`StreamFailureKind`], never through `classify` (fix round 1, L2):
//! `classify` has no 2xx arm, so laundering a mid-stream failure through it
//! at the response's real (200) status landed everything in
//! `BadRequest { status: 200, body_snippet: "" }` -- permanently fatal per
//! `retry.rs`'s disposition table, discarding both the correct retry
//! semantics (a transient blip must not become permanently fatal) and every
//! diagnostic message `decode.rs` builds.

use super::decode::{decode_cohere_v2_stream, StreamFailure, StreamFailureKind};
use super::encode::{contains_unencodable_media, encode, requests_unsupported_tool_choice};
use crate::audit::redact_transport_error_text;
use crate::credential::{resolve_base_url, CredentialCtx};
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::profile::{AuthKind, ProviderProfile};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// The live `Provider` for the Cohere v2 codec: one profile, one endpoint
/// (`POST {base_url}/chat`) -- unlike `google_genai`, this codec has no
/// endpoint-mode switch to construct with.
pub struct CohereV2Provider {
    profile: ProviderProfile,
}

impl CohereV2Provider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for CohereV2Provider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: true,
            thinking: true,
            // Cohere v2 documents no per-block prompt-cache breakpoint
            // mechanism.
            max_breakpoints: 0,
        }
    }

    /// Fails closed on a request containing a block this codec cannot
    /// encode (`Image`/`Document`/`Opaque`) or a `tool_choice` it cannot
    /// honor (`Named` -- fix round 1, L4) as a cheap pre-flight. The guard
    /// that matters lives in `stream_chat`'s `encode(...)?` propagation --
    /// see `encode.rs`'s `EncodeError` doc comment (`resolve` has zero
    /// production callers anywhere in this workspace).
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_media(req) {
            return Err(ProviderError::Unsupported(
                "cohere-v2 codec does not encode Image/Document/Opaque blocks".into(),
            ));
        }
        if requests_unsupported_tool_choice(req) {
            return Err(ProviderError::Unsupported(
                "cohere-v2 codec cannot force one specific named tool via tool_choice".into(),
            ));
        }
        Ok(Plan {
            endpoint: "cohere-v2".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let body = encode(req, &self.profile)?;

            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None).map_err(
                    |e| ProviderError::Transport(redact_transport_error_text(&e.to_string())),
                )?;
            let endpoint_url = build_endpoint_url(&base_url);

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §6/§12d: prefer the real `CredentialProvider`
            // mechanism when present, falling back to the Phase 1 bare
            // `api_key` path (Bearer, per `cohere-v2.toml`'s
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
                    // Fix round 1, L7 (tightened by fix round 2, N4): an
                    // empty OR whitespace-only `api_key` must fail closed,
                    // not silently send a header-shaped-but-credential-less
                    // `authorization: Bearer ` (or `Bearer   `) that only
                    // earns a remote 401 -- matching the doc comment on the
                    // `other` arm below, which already makes this exact
                    // promise for a missing `CredentialProvider`.
                    AuthKind::Bearer if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "cohere-v2 codec requires a non-empty api_key (or a \
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
                    // A missing credential must fail closed, not silently
                    // send an unauthenticated request -- mirrors
                    // `google_genai::provider`'s identical fix-round-1 F7
                    // guard. `cohere-v2.toml` only ever declares `bearer`
                    // today, so this arm is unreachable in practice but must
                    // not silently no-op if that ever changes.
                    other => {
                        return Err(ProviderError::Unsupported(format!(
                            "cohere-v2 codec has no CredentialProvider and its bare api_key \
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
                let body_bytes = collect_body(response.body).await;
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &body_bytes,
                    &headers,
                ));
            }

            let events = decode_cohere_v2_stream(response.body)
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
            Err(ProviderError::Unsupported(
                "count_tokens is not built for the cohere-v2 codec in this task".into(),
            ))
        })
    }
}

/// Builds the full request URL: `{base}/chat` (verified:
/// `https://api.cohere.com/v2/chat`, no model interpolation, no required
/// query parameters). Preserves `base`'s existing path prefix and query
/// string, matching `google_genai::provider::build_endpoint_url`'s
/// established `append_path_segment` precedent.
fn build_endpoint_url(base: &url::Url) -> url::Url {
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!("{base_path}/chat"));
    url
}

/// Maps a mid-stream [`StreamFailure`] directly onto a `ProviderError`, by
/// `kind` (fix round 1, L2) -- never through `crate::errors::classify` at
/// the enclosing (always 200) HTTP status, which has no 2xx arm and would
/// land everything in a permanently-fatal `BadRequest { status: 200,
/// body_snippet: "" }`, discarding this module's diagnostics along with any
/// chance of a correct retry decision.
///
/// - `Transport`: a genuine transport-layer error mid-stream -- becomes
///   `ProviderError::Transport`, which `retry.rs` retries with backoff (a
///   transient blip, not a permanent client error).
/// - `Timeout`: Cohere's own verified `finish_reason` value -- maps directly
///   onto this crate's existing, exact-fit `ProviderError::Timeout`
///   variant, also retried with backoff.
/// - `Error`: Cohere's "the generation failed due to an internal error" --
///   treated like an opaque provider-side 5xx (`ProviderError::Server`),
///   also retried with backoff.
/// - `MaxTokens`, `UnrecognizedFinishReason`, `Truncated`: real partial
///   output exists (or might), and this generic retry loop should not
///   transparently retry a request whose prefix would need to be resent at
///   the caller's discretion -- `ProviderError::StreamInterrupted { partial }`
///   is `retry.rs`'s own `Disposition::Fatal` from ITS perspective, exactly
///   because that decision belongs to the agent loop (its own doc comment:
///   "resuming means re-sending a prefix, which changes billing and
///   discards reasoning-model state"), not to this transport-retry layer.
///   Mirrors `roundhouse-engine::compact::fold_stream_text`'s identical use
///   of this variant for the same "ended without a clean stop" shape.
///
/// Fix round 5, H3: `failure.message` -- the actual, spec-verified reason
/// this stream failed -- used to reach nothing observable for every kind but
/// `Transport`, the same gap fix round 4 closed for
/// `openai_chat::provider::stream_failure_to_provider_error`. A `warn!`
/// event here (matching that fix's level, not `errors.rs`'s `debug!`
/// convention -- a `StreamFailure` kills the entire turn, a user-visible
/// degrade) makes the reason observable without ever touching
/// `partial_text`. Every `message` construction site in `decode.rs` builds
/// this from a fixed diagnostic string interpolating at most a verified
/// `finish_reason` value (capped and escaped for the unrecognized case by
/// `sanitize_finish_reason_for_message`) or a `redact_transport_error_text`-
/// passed transport error -- never the model's own generated content, which
/// only ever flows into the separate `partial_text` field this event does
/// not log.
///
/// Fix round 6, J2: `decode.rs`'s `sanitize_finish_reason_for_message` builds
/// this field from an unrecognized `finish_reason` value, and (fix round 7,
/// K1) now redacts it before `{:?}`-escaping -- but that is still only a
/// *shape*-based redaction. `sanitize_finish_reason_for_message` and
/// `redact_transport_error_text` are maintained as mirrors of
/// `openai_chat::decode`'s/`openai_chat::provider`'s identical functions, and
/// a provider-controlled `finish_reason` or transport-error string could
/// still carry an embedded URL whose query string or userinfo holds a
/// credential no shape-based matcher recognizes (e.g. `?key=...` rather than
/// a labeled `api_key=...`).
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
        "cohere-v2 stream failed mid-generation"
    );
    match failure.kind {
        StreamFailureKind::Transport => ProviderError::Transport(failure.message),
        StreamFailureKind::Timeout => ProviderError::Timeout,
        StreamFailureKind::Error => ProviderError::Server { status: 500 },
        StreamFailureKind::MaxTokens
        | StreamFailureKind::UnrecognizedFinishReason
        | StreamFailureKind::Truncated => ProviderError::StreamInterrupted {
            partial: failure.partial_text,
        },
    }
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

async fn collect_body(
    mut body: std::pin::Pin<
        Box<
            dyn futures::Stream<Item = Result<bytes::Bytes, crate::transport::TransportError>>
                + Send,
        >,
    >,
) -> Vec<u8> {
    use futures::StreamExt;
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        if let Ok(chunk) = chunk {
            out.extend_from_slice(&chunk);
        }
    }
    out
}

#[cfg(test)]
mod build_endpoint_url_tests {
    use super::build_endpoint_url;

    #[test]
    fn targets_v2_chat() {
        let base = url::Url::parse("https://api.cohere.com/v2").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(url.as_str(), "https://api.cohere.com/v2/chat");
    }

    /// Same fix-round-1 C5 concern `google_genai`/`openai_responses` guard
    /// against: a gateway base URL carrying its own query string must keep
    /// it.
    #[test]
    fn preserves_a_gateway_query_string() {
        let base = url::Url::parse("https://gateway.example.com/proxy?key=abc123").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(
            url.as_str(),
            "https://gateway.example.com/proxy/chat?key=abc123"
        );
    }
}

#[cfg(test)]
mod stream_failure_to_provider_error_tests {
    //! Fix round 1, L2: proves the direct mapping, not a `classify`-at-200
    //! round trip -- every arm here would previously have produced
    //! `ProviderError::BadRequest { status: 200, body_snippet: "" }`.
    use super::stream_failure_to_provider_error;
    use crate::codec::cohere_v2::decode::{StreamFailure, StreamFailureKind};
    use crate::ProviderError;

    fn failure(kind: StreamFailureKind, partial_text: &str) -> StreamFailure {
        StreamFailure {
            kind,
            message: "synthetic".into(),
            partial_text: partial_text.into(),
        }
    }

    #[test]
    fn transport_maps_to_provider_transport_with_the_message_preserved() {
        let f = StreamFailure {
            message: "redacted transport message".into(),
            ..failure(StreamFailureKind::Transport, "")
        };
        let err = stream_failure_to_provider_error(f);
        assert!(matches!(err, ProviderError::Transport(m) if m == "redacted transport message"));
    }

    #[test]
    fn timeout_maps_to_provider_timeout() {
        let err = stream_failure_to_provider_error(failure(StreamFailureKind::Timeout, ""));
        assert!(matches!(err, ProviderError::Timeout));
    }

    #[test]
    fn error_maps_to_server_500() {
        let err = stream_failure_to_provider_error(failure(StreamFailureKind::Error, ""));
        assert!(matches!(err, ProviderError::Server { status: 500 }));
    }

    #[test]
    fn max_tokens_maps_to_stream_interrupted_carrying_the_partial_text() {
        let err =
            stream_failure_to_provider_error(failure(StreamFailureKind::MaxTokens, "partial out"));
        assert!(
            matches!(err, ProviderError::StreamInterrupted { partial } if partial == "partial out")
        );
    }

    #[test]
    fn truncated_maps_to_stream_interrupted() {
        let err = stream_failure_to_provider_error(failure(StreamFailureKind::Truncated, "so far"));
        assert!(matches!(err, ProviderError::StreamInterrupted { partial } if partial == "so far"));
    }

    #[test]
    fn unrecognized_finish_reason_maps_to_stream_interrupted() {
        let err = stream_failure_to_provider_error(failure(
            StreamFailureKind::UnrecognizedFinishReason,
            "",
        ));
        assert!(matches!(err, ProviderError::StreamInterrupted { .. }));
    }
}

#[cfg(test)]
mod stream_failure_diagnosability_tests {
    //! Fix round 5, H3: mirrors `openai_chat::provider`'s identical
    //! `stream_failure_diagnosability_tests` module verbatim in shape --
    //! proves both halves of the same constraint for this codec's own
    //! `stream_failure_to_provider_error`: the failure *reason* reaches an
    //! observable `tracing` event, and the model's partial *content* never
    //! does, not even via that event.
    use super::decode_cohere_v2_stream;
    use super::{stream_failure_to_provider_error, StreamFailure, StreamFailureKind};
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
            kind: StreamFailureKind::MaxTokens,
            message: "cohere-v2 chat generation stopped: MAX_TOKENS".into(),
            partial_text: "TOP SECRET MODEL OUTPUT".into(),
        };

        let provider_err = tracing::subscriber::with_default(subscriber, || {
            stream_failure_to_provider_error(failure)
        });

        // Half 1: the `Display` impl -- what actually reaches a persisted,
        // immutable row -- must never carry the model's partial output.
        assert!(matches!(
            provider_err,
            ProviderError::StreamInterrupted { .. }
        ));
        assert!(!provider_err.to_string().contains("TOP SECRET"));

        // Half 2: the reason must be observable somewhere -- here, a
        // tracing event -- so an operator can act on it.
        let captured = lines.lock().unwrap();
        assert!(
            captured.iter().any(|line| line.contains("MAX_TOKENS")),
            "expected the failure reason to reach a tracing event: {captured:?}"
        );
        // And the partial content must never leak into the diagnostic
        // event either -- only the reason is observable, never the content.
        assert!(
            !captured.iter().any(|line| line.contains("TOP SECRET")),
            "the model's partial output must never be logged: {captured:?}"
        );
    }

    /// Fix round 7, K2: mirrors `openai_chat::provider`'s identical
    /// fix-round-7 test. An unrecognized `finish_reason` can embed a full
    /// URL whose credential is NOT shape-matched by `redact_error_body` (a
    /// differently-named query param, or userinfo) -- `decode.rs`'s
    /// `sanitize_finish_reason_for_message` (fix round 7, K1) only ever runs
    /// the shape-based `redact_error_body`, so `failure.message` itself
    /// still carries the credential intact; the first assertion pins that
    /// down as a sanity check. The real guarantee under test is that the
    /// `tracing::warn!` log site's `redact_transport_error_text` catches
    /// what construction-site redaction structurally cannot. Driven through
    /// the real decoder, per REALITY-CORRECTIONS §15/§13b.
    #[tokio::test]
    async fn an_unrecognized_finish_reason_embedding_a_credentialed_url_is_redacted_at_the_log_site(
    ) {
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

        // Kept to 63 chars total (under `MAX_FINISH_REASON_ECHO_LEN`'s 64,
        // whose cap runs AFTER redaction but before the `{:?}` escape) so
        // the construction-site sanity check below observes the whole,
        // untruncated credential -- a longer fixture would have its tail
        // cut off by truncation alone, which would make that assertion fail
        // for an unrelated reason.
        let body = sse_body(&[
            r#"{"type":"message-end","delta":{"finish_reason":"https://gwuser:gwpass@gw.example.invalid/v1?key=gw-live-9f2b8c1"}}"#,
        ]);
        let failure = match decode_cohere_v2_stream(body).await {
            Ok(_) => panic!("expected a StreamFailure"),
            Err(f) => f,
        };
        assert_eq!(failure.kind, StreamFailureKind::UnrecognizedFinishReason);
        assert!(
            failure.message.contains("gwuser:gwpass")
                && failure.message.contains("gw-live-9f2b8c1"),
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
            ProviderError::StreamInterrupted { .. }
        ));

        let captured = lines.lock().unwrap();
        assert!(
            !captured.iter().any(|line| line.contains("gwuser:gwpass")),
            "URL userinfo leaked into the tracing event unredacted: {captured:?}"
        );
        assert!(
            !captured
                .iter()
                .any(|line| line.contains("gw-live-9f2b8c1")),
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
