//! `OpenAiResponsesProvider`: bridges this module's pure `encode`/`decode`
//! functions to a real [`HttpTransport`], the same shape
//! `AnthropicMessagesProvider` established in Phase 1. Unlike that adapter,
//! this one is profile-driven (§9.5): it holds a [`ProviderProfile`] rather
//! than a bare `base_url` string, and uses the profile's `[errors]` table
//! (REALITY-CORRECTIONS §14g) for status/body classification instead of a
//! hand-written `match`.

use crate::audit::redact_transport_error_text;
use crate::codec::openai_responses::decode::{decode_openai_responses_stream, StreamFailure};
use crate::codec::openai_responses::encode::{contains_unencodable_media, encode};
use crate::credential::resolve_base_url;
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::profile::{AuthKind, ProviderProfile};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// The live `Provider` for the Open Responses codec, parameterized by a
/// [`ProviderProfile`] (`openai-responses.toml` for OpenAI first-party; later
/// batch tasks reuse this same struct with other profiles on the same wire
/// format).
pub struct OpenAiResponsesProvider {
    profile: ProviderProfile,
}

impl OpenAiResponsesProvider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for OpenAiResponsesProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: true,
            thinking: true,
            // Open Responses has no explicit prompt-cache breakpoint
            // mechanism (it caches automatically via `prompt_cache_key`) --
            // see the spec-verification note's `system_prompt_with_cache_breakpoint`
            // discussion. 0 rather than a made-up number.
            max_breakpoints: 0,
        }
    }

    /// Fails closed on a request containing an `Image`/`Document` block,
    /// rather than letting `encode` silently drop it. There is no
    /// `LossEvent` type anywhere in this codebase to declare a drop against
    /// (every reference is a comment promising a future one), so "declare it
    /// as a loss" was never actually available -- an observable, fail-closed
    /// rejection (§9.8: "a degrade like this must be observable, not
    /// silent") is the only honest option until real `input_image`/
    /// `input_file` encoding lands (blocked on this crate gaining a `base64`
    /// dependency, deliberately out of this task's scope -- see the
    /// spec-verification note).
    ///
    /// Fix-round-2 D1: fix-round-1 C6 put this check ONLY here, and the
    /// review found `Provider::resolve` has zero production callers anywhere
    /// in this workspace -- every real path calls `stream_chat` directly, so
    /// the guard never actually ran and production behavior was unchanged by
    /// C6. This check is kept as a cheap, I/O-free pre-flight a caller MAY
    /// use, but the guarantee that actually holds on the path every
    /// production caller takes now lives structurally in `encode_block`'s
    /// own return type (`EncodeError::UnencodableMedia`, propagated through
    /// `encode` and then `stream_chat` below) -- see `encode.rs`'s
    /// `EncodeError` doc comment.
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_media(req) {
            return Err(ProviderError::Unsupported(
                "openai-responses codec does not encode Image/Document blocks".into(),
            ));
        }
        Ok(Plan {
            endpoint: "openai-responses".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            // Fix-round-2 D1: `encode` returning `Err` here (including for a
            // request containing an `Image`/`Document` block, per
            // `EncodeError::UnencodableMedia`) now converts into
            // `ProviderError` via `?` and the `From<EncodeError>` impl in
            // `encode.rs` -- this is the guard that actually runs on
            // production's `stream_chat` path, not just on `resolve` (which
            // fix-round-1 review found has zero production callers).
            let body = encode(req, &self.profile)?;

            // Fix-round-1 C5: routed through the §9.9 seam
            // (`resolve_base_url`/host-only recording) instead of reading
            // `self.profile.defaults.base_url` directly, and the `responses`
            // segment is appended on the *parsed* `Url` rather than by string
            // concatenation -- a gateway `base_url` carrying its own query
            // string (`...?key=abc`) must not have `/responses` appended
            // AFTER the query (`...?key=abc/responses`), and appending via
            // `Url::set_path` (not `Url::join`, which would drop that query
            // entirely per WHATWG relative-URL resolution) preserves it
            // untouched.
            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None).map_err(
                    |e| ProviderError::Transport(redact_transport_error_text(&e.to_string())),
                )?;
            let endpoint_url = append_path_segment(&base_url, "responses");

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §6: prefer the real `CredentialProvider`
            // mechanism when present, falling back to the Phase 1 bare
            // `api_key` path when it is not. No `Provider` impl anywhere in
            // this phase matches on which concrete credential kind it was
            // GIVEN (`ctx.credentials`'s kind) -- `apply` alone decides that.
            // This `else` branch is different: it matches on the profile's
            // own DECLARED `auth` kind, the same shape every sibling codec in
            // this crate uses (`openai_chat`, `azure_provider`, `cohere_v2`,
            // `anthropic_messages`, `google_genai`) so a bare `api_key`
            // string is only ever used where it can actually express the
            // declared scheme.
            //
            // Fix-round-2 Fix 1 (security): resolved. Until this fix, this
            // branch unconditionally wrote a Bearer header regardless of the
            // profile's declared auth kind -- the only fallback in this
            // crate without this match. `aws-open-responses.toml` declares
            // `auth = { kind = "sigv4", ... }`, and the sole production
            // `RequestCtx` always has `credentials: None` with `api_key`
            // sourced from `ANTHROPIC_API_KEY`, so selecting that profile
            // would have sent the operator's Anthropic key, as a Bearer
            // token, to a real AWS host. See
            // `aws_open_responses_bare_api_key_fallback_fails_closed_for_sigv4`
            // in `tests/conformance_openai_responses_batch.rs` for the
            // fail-closed proof.
            //
            // Fix-round-2 Fix 6: the `https`-only half of the old deferral
            // comment here was already moot -- `ReqwestTransport::new()` sets
            // `https_only(true)` (`reqwest_transport.rs`), so an `http://`
            // base-URL override fails closed at the transport regardless of
            // this match. Only the auth-kind half was ever live.
            if let Some(credentials) = &ctx.credentials {
                let cred_ctx = crate::credential::CredentialCtx {
                    provider_id: &self.profile.id,
                    transport: ctx.transport.as_ref(),
                    now: std::time::Instant::now(),
                };
                // A `CredentialError` (no material found, a failed OAuth
                // refresh, a failed exec-command helper, ...) is an
                // infrastructure-level failure preventing the request from
                // ever reaching the wire -- `Transport`, not `Unsupported`
                // (which reads as "this codec cannot do this at all").
                credentials
                    .apply(&mut http_req, &cred_ctx)
                    .await
                    .map_err(|e| {
                        ProviderError::Transport(redact_transport_error_text(&e.to_string()))
                    })?;
            } else {
                match &self.profile.defaults.auth {
                    // Fix-round-2 Fix 2: an empty/whitespace-only api_key
                    // must fail locally rather than emit a bare
                    // `Authorization: Bearer ` and let the vendor's remote
                    // 401 be the caller's first signal -- matches every
                    // sibling codec's identical guard.
                    AuthKind::Bearer if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "openai-responses codec requires a non-empty api_key for bearer \
                             auth and no CredentialProvider was supplied"
                                .into(),
                        ));
                    }
                    AuthKind::Bearer => {
                        http_req.headers.push((
                            "authorization".to_string(),
                            format!("Bearer {}", ctx.api_key),
                        ));
                    }
                    // Same guarantee as the `Bearer` arm above, for
                    // `HeaderKey` auth. No `openai-responses` profile
                    // declares `header_key` today, so this arm is
                    // unreachable in practice, but it must not silently
                    // no-op if that ever changes.
                    AuthKind::HeaderKey { .. } if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "openai-responses codec requires a non-empty api_key for \
                             header_key auth and no CredentialProvider was supplied"
                                .into(),
                        ));
                    }
                    AuthKind::HeaderKey { header } => {
                        http_req.headers.push((header.clone(), ctx.api_key.clone()));
                    }
                    // SigV4/AzureEntra need the real `CredentialProvider`
                    // (signing/token-exchange logic no bare api_key string
                    // can express) -- a silent Bearer header here would send
                    // the request UNAUTHENTICATED (or, worse, authenticated
                    // as an entirely different principal) rather than
                    // failing it locally. A missing credential must fail
                    // closed, not become a remote request the caller has to
                    // notice went out wrong.
                    AuthKind::SigV4 { .. } | AuthKind::AzureEntra { .. } => {
                        return Err(ProviderError::Unsupported(format!(
                            "openai-responses codec has no CredentialProvider and its bare \
                             api_key fallback cannot express {:?} auth",
                            self.profile.defaults.auth
                        )));
                    }
                }
            }

            // Fix-round-1 C5: the reviewer traced a real leak through this
            // exact call -- `reqwest`'s `Display` appends `" for url
            // ({url})"` (userinfo and query string included) to its error,
            // which otherwise flows straight into `ProviderError::Transport`
            // and then onto a physically-immutable `events` row.
            //
            // Fix round 5, H1: C5's original fix called plain
            // `redact_error_body` here, which does NOT strip a URL's query
            // string or userinfo (it only matches labeled, shaped secrets) --
            // so the claim two paragraphs up was false for every sink in
            // this file. Switched to `redact_transport_error_text`, which
            // strips the embedded URL down to host-only THEN runs
            // `redact_error_body` on top, so the leak this comment describes
            // is now actually closed at all three of this file's transport-
            // error sinks, not just described as closed.
            let response = ctx.transport.send(http_req).await.map_err(|e| {
                ProviderError::Transport(redact_transport_error_text(&e.to_string()))
            })?;

            if !(200..300).contains(&response.status) {
                // §9.8: never `?` on JSON parsing in the error path -- an
                // outage returning HTML (see `error_500.cassette`) must not
                // become a decode panic. `classify` already honors this.
                let headers = to_header_map(&response.headers);
                let body_bytes = collect_body(response.body).await;
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &body_bytes,
                    &headers,
                ));
            }

            // Fix-round-1 C2: `response.failed`/`response.incomplete`/`error`
            // arrive IN-BAND after this 200, so the status check above can
            // never catch them -- `decode_openai_responses_stream` returns
            // `Err(StreamFailure)` for these instead of a `StreamEvent`
            // (the frozen `StreamEvent` enum has no error variant).
            //
            // Phase 7 Task 13b: `response.incomplete` is not a genuine
            // provider-side failure -- it is a lossy-but-real completion
            // (truncated at max tokens, or cut short by a content filter),
            // which is exactly what `StreamFailure.loss` names
            // (`decode.rs`'s doc comment). Route it to
            // `ProviderError::StreamInterrupted` instead of `classify`,
            // matching every sibling codec's convention for this same shape
            // (`cohere_v2`, `openai_chat`, `anthropic_messages` all map
            // max-tokens/content-filter to `StreamInterrupted`, never a bare
            // `BadRequest`). `response.failed`/bare `error` (`loss: None`)
            // keep the original `classify`-through-the-`[errors]`-table
            // path, using the response's real status (200) since there is
            // no other status to report -- a code that happens to match one
            // of the profile's declared error codes (plausible: some
            // providers reuse the same code vocabulary in-band and
            // out-of-band) still gets the right disposition; anything else
            // falls through to `classify`'s HTTP-status default tier.
            //
            // Known gap (see `LossEvent::into_payload`'s doc comment): the
            // real `LossEvent` this failure carries has no channel out of
            // `stream_chat` today -- `Provider`/`ChatStream`/`StreamEvent`
            // are all frozen Phase 0 contracts with no field for it. Logging
            // it here is strictly better than the pre-13b silence, but it is
            // not yet a persisted `EventPayload::Loss` -- that needs a real
            // return channel, which is lane W1's engine-wiring call.
            let headers = to_header_map(&response.headers);
            let events = decode_openai_responses_stream(response.body)
                .await
                .map_err(|failure| match failure.loss {
                    Some(loss) => {
                        tracing::warn!(
                            kind = loss.kind.tag(),
                            description = %loss.description,
                            blocks_affected = loss.blocks_affected,
                            "openai-responses stream ended lossy (response.incomplete) with no \
                             EventWriter channel yet to persist this as EventPayload::Loss"
                        );
                        ProviderError::StreamInterrupted {
                            partial: String::new(),
                        }
                    }
                    None => classify(
                        &self.profile.error_profile(),
                        response.status,
                        &stream_failure_body(&failure),
                        &headers,
                    ),
                })?;
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
                "count_tokens is not built for the openai-responses codec in this task".into(),
            ))
        })
    }
}

/// Appends `segment` as a new path component of `base`, preserving `base`'s
/// query string untouched (fix-round-1 C5). Deliberately uses `Url::set_path`
/// rather than `Url::join`: joining a plain relative reference like
/// `"responses"` onto a base URL that has its own query string drops that
/// query per WHATWG URL relative-resolution rules -- exactly the kind of
/// gateway API key (`?key=...`) this fix exists to preserve, not lose.
fn append_path_segment(base: &url::Url, segment: &str) -> url::Url {
    let mut url = base.clone();
    let joined_path = if url.path().ends_with('/') {
        format!("{}{segment}", url.path())
    } else {
        format!("{}/{segment}", url.path())
    };
    url.set_path(&joined_path);
    url
}

/// Builds an `http::HeaderMap` from the transport's plain `Vec<(String,
/// String)>` headers. A malformed header name/value is simply not carried
/// into the map (matches `ReqwestTransport`'s own best-effort header
/// handling) rather than failing the whole error-classification path over
/// one bad header.
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

/// Renders a [`StreamFailure`] as the same `{"error": {"type", "message"}}`
/// shape `classify` already expects from an HTTP error body, so an in-band
/// terminal failure goes through the exact same §9.8 classification path
/// (provider error code -> message regex -> HTTP status default) as a
/// transport-level one, rather than a second, parallel mapping.
fn stream_failure_body(failure: &StreamFailure) -> Vec<u8> {
    let mut error_obj = serde_json::json!({ "message": failure.message });
    if let Some(code) = &failure.code {
        error_obj["type"] = serde_json::json!(code);
    }
    serde_json::to_vec(&serde_json::json!({ "error": error_obj })).unwrap_or_default()
}

/// Drains a response body stream into a byte buffer for the error-
/// classification path only. Not used on the success path (`§9.3`'s
/// streaming decode reads directly from the stream).
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
mod append_path_segment_tests {
    use super::append_path_segment;

    #[test]
    fn appends_a_segment_to_a_base_with_no_trailing_slash() {
        let base = url::Url::parse("https://api.openai.com/v1").unwrap();
        let joined = append_path_segment(&base, "responses");
        assert_eq!(joined.as_str(), "https://api.openai.com/v1/responses");
    }

    #[test]
    fn appends_a_segment_to_a_base_with_a_trailing_slash() {
        let base = url::Url::parse("https://api.openai.com/v1/").unwrap();
        let joined = append_path_segment(&base, "responses");
        assert_eq!(joined.as_str(), "https://api.openai.com/v1/responses");
    }

    /// Fix-round-1 C5's whole point: a gateway `base_url` carrying its own
    /// query string (a real pattern for gateways that put an API key in
    /// `?key=...`) must keep that query string after the path is extended --
    /// `Url::join` would silently drop it (a relative reference like
    /// `"responses"` has no query of its own, and per WHATWG URL relative
    /// resolution that clears the base's query too), which is exactly the
    /// bug this helper exists to avoid.
    #[test]
    fn preserves_a_gateway_query_string_when_appending_a_segment() {
        let base = url::Url::parse("https://gateway.example.com/v1?key=abc123").unwrap();
        let joined = append_path_segment(&base, "responses");
        assert_eq!(
            joined.as_str(),
            "https://gateway.example.com/v1/responses?key=abc123"
        );
    }
}
