//! `OpenAiResponsesProvider`: bridges this module's pure `encode`/`decode`
//! functions to a real [`HttpTransport`], the same shape
//! `AnthropicMessagesProvider` established in Phase 1. Unlike that adapter,
//! this one is profile-driven (§9.5): it holds a [`ProviderProfile`] rather
//! than a bare `base_url` string, and uses the profile's `[errors]` table
//! (REALITY-CORRECTIONS §14g) for status/body classification instead of a
//! hand-written `match`.

use crate::audit::redact_error_body;
use crate::codec::openai_responses::decode::{decode_openai_responses_stream, StreamFailure};
use crate::codec::openai_responses::encode::{contains_unencodable_media, encode};
use crate::credential::resolve_base_url;
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::profile::ProviderProfile;
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

    /// Fix-round-1 C6: fails closed on a request containing an `Image`/
    /// `Document` block, rather than letting `encode` silently drop it.
    /// There is no `LossEvent` type anywhere in this codebase to declare a
    /// drop against (every reference is a comment promising a future one),
    /// so "declare it as a loss" was never actually available -- an
    /// observable, fail-closed rejection (§9.8: "a degrade like this must be
    /// observable, not silent") is the only honest option until real
    /// `input_image`/`input_file` encoding lands (blocked on this crate
    /// gaining a `base64` dependency, deliberately out of this task's scope
    /// -- see the spec-verification note).
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
            let body = encode(req, &self.profile)
                .map_err(|e| ProviderError::Unsupported(format!("reasoning encode failed: {e}")))?;

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
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None)
                    .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;
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
            // `api_key` path (a plain bearer header) when it is not. No
            // `Provider` impl anywhere in this phase matches on which
            // concrete credential kind it was given -- `apply` alone decides.
            //
            // Not in scope (fix-round-1, filed for Task 16): this fallback
            // hardcodes the `Bearer` scheme and never checks the resolved
            // URL is `https`, both fine for `api.openai.com` but worth
            // revisiting once this codec is reused for arbitrary gateways.
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
                    .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;
            } else {
                http_req.headers.push((
                    "authorization".to_string(),
                    format!("Bearer {}", ctx.api_key),
                ));
            }

            // Fix-round-1 C5: the reviewer traced a real leak through this
            // exact call -- `reqwest`'s `Display` appends `" for url
            // ({url})"` (userinfo and query string included) to its error,
            // which otherwise flows straight into `ProviderError::Transport`
            // and then onto a physically-immutable `events` row.
            // `redact_error_body` (§9.9's complementary, shape-based pass)
            // is applied here rather than relied on further downstream,
            // since this is the one place in this codec a raw transport
            // error string is turned into persisted text.
            let response = ctx
                .transport
                .send(http_req)
                .await
                .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;

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
            // (the frozen `StreamEvent` enum has no error variant), and that
            // failure is classified here through the same `[errors]`-table
            // path as an HTTP-level error, using the response's real status
            // (200) since there is no other status to report -- a code that
            // happens to match one of the profile's declared error codes
            // (plausible: some providers reuse the same code vocabulary
            // in-band and out-of-band) still gets the right disposition;
            // anything else falls through to `classify`'s HTTP-status
            // default tier.
            let headers = to_header_map(&response.headers);
            let events = decode_openai_responses_stream(response.body)
                .await
                .map_err(|failure| {
                    classify(
                        &self.profile.error_profile(),
                        response.status,
                        &stream_failure_body(&failure),
                        &headers,
                    )
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
