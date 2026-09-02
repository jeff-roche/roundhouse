//! `GoogleGenAiProvider`: bridges this module's pure `encode`/`decode`
//! functions to a real [`HttpTransport`], parameterized by [`EndpointMode`]
//! at construction (the brief's Interfaces line: "constructed with an
//! `EndpointMode`"). Mirrors `openai_responses::provider`'s shape (profile-
//! driven, `[errors]`-table classification via `crate::errors::classify`).

use serde_json::Value;

use super::decode::{decode_google_genai_stream, StreamFailure};
use super::encode::{contains_unencodable_media, encode};
use super::EndpointMode;
use crate::audit::redact_transport_error_text;
use crate::credential::{resolve_base_url, CredentialCtx};
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::profile::{AuthKind, ProviderProfile};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// The live `Provider` for the Google GenAI codec. One `ProviderProfile`
/// (`google-genai.toml`) serves both endpoint modes; which wire surface a
/// given instance speaks is fixed at construction via `mode`.
pub struct GoogleGenAiProvider {
    profile: ProviderProfile,
    mode: EndpointMode,
}

impl GoogleGenAiProvider {
    pub fn new(profile: ProviderProfile, mode: EndpointMode) -> Self {
        Self { profile, mode }
    }
}

impl Provider for GoogleGenAiProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: true,
            thinking: true,
            // Gemini has no explicit prompt-cache breakpoint mechanism on
            // either surface (it caches automatically) -- see the
            // `system_prompt_with_cache_breakpoint` golden case.
            max_breakpoints: 0,
        }
    }

    /// Fails closed on a request containing a block this codec cannot
    /// encode (`Image`/`Document`/`Thinking`/`Opaque` -- fix-round-2 G3:
    /// this doc comment and the error string below went stale when F1
    /// extended `contains_unencodable_media` past `Image`/`Document`), as a
    /// cheap pre-flight. The guard that matters lives in `stream_chat`'s
    /// `encode(...)?` propagation -- see `encode.rs`'s `EncodeError` doc
    /// comment for why (Task 5's fix-round-2 D1 lesson: `resolve` has zero
    /// production callers anywhere in this workspace). Unlike `encode`'s
    /// per-block error (which names the specific offending kind),
    /// `contains_unencodable_media` only reports whether ANY of the four
    /// kinds is present, not which one -- this message names the full set
    /// this pre-flight covers rather than guessing at a specific kind.
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_media(req) {
            return Err(ProviderError::Unsupported(
                "google-genai codec does not encode Image/Document/Thinking/Opaque blocks".into(),
            ));
        }
        Ok(Plan {
            endpoint: "google-genai".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let body = encode(req, &self.profile, self.mode)?;

            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None).map_err(
                    |e| ProviderError::Transport(redact_transport_error_text(&e.to_string())),
                )?;
            let endpoint_url = build_endpoint_url(&base_url, self.mode, &req.model.0)?;

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §6: prefer the real `CredentialProvider`
            // mechanism when present, falling back to the Phase 1 bare
            // `api_key` path when it is not. Unlike `openai_responses`'
            // fallback (which hardcodes a `Bearer` header, flagged there as a
            // known limitation), this fallback reads the profile's own
            // `AuthKind` so a `header_key` auth (this profile's real shape --
            // `x-goog-api-key`) is honored correctly rather than assumed to
            // be Bearer.
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
                    AuthKind::HeaderKey { header } => {
                        http_req.headers.push((header.clone(), ctx.api_key.clone()));
                    }
                    AuthKind::Bearer => {
                        http_req.headers.push((
                            "authorization".to_string(),
                            format!("Bearer {}", ctx.api_key),
                        ));
                    }
                    // Fix-round-1 F7: SigV4/AzureEntra need the real
                    // `CredentialProvider` (signing/token-exchange logic no
                    // bare api_key string can express) -- not reachable via
                    // this profile's own `header_key` auth today, but a
                    // silent `{}` here would have sent the request
                    // completely UNAUTHENTICATED rather than failing it
                    // locally. A missing credential must fail closed, not
                    // become a remote 401 the caller has to notice on its
                    // own.
                    AuthKind::SigV4 { .. } | AuthKind::AzureEntra { .. } => {
                        return Err(ProviderError::Unsupported(format!(
                            "google-genai codec has no CredentialProvider and its bare \
                             api_key fallback cannot express {:?} auth",
                            self.profile.defaults.auth
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
                let remapped = remap_error_body_for_classify(&body_bytes);
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &remapped,
                    &headers,
                ));
            }

            let headers = to_header_map(&response.headers);
            let mode = self.mode;
            let events = decode_google_genai_stream(response.body, mode)
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
                "count_tokens is not built for the google-genai codec in this task".into(),
            ))
        })
    }
}

/// Builds the full request URL for `mode`, preserving `base`'s existing path
/// prefix and query string (matches `openai_responses::provider`'s
/// `append_path_segment` precedent -- never `Url::join`, which drops a base
/// URL's existing query string per WHATWG relative-URL resolution).
///
/// Fix-round-1 F9 / fix-round-2 G1: `model` (only `GenerateContent` mode
/// interpolates it into the path) must pass a positive allowlist before
/// being trusted as a URL path segment. `ModelId` is config-sourced today,
/// so the host cannot actually be redirected and this is not exploitable
/// *yet*, but the moment a model id can arrive from a sub-agent spec, a
/// workflow trigger, or an MCP field, silently trusting it stops being
/// purely theoretical.
///
/// G1: the original check denylisted `/`, `..`, and `%` as raw substrings,
/// but `Url::set_path` normalizes AFTER that check runs, so none of those
/// three ever needed to appear in the pre-check string to reach a traversal:
/// `\` is a path separator for special schemes (`foo\bar` becomes
/// `foo/bar`), and the parser strips tab/LF/CR before parsing (`.` + TAB +
/// `.` reassembles into a literal `..` segment). A positive allowlist --
/// only ASCII alphanumerics, `.`, `-`, `_` -- has no such gap: every one of
/// those bypass characters (`\`, TAB) is rejected outright, and there is no
/// second normalization pass this check runs before that could undo it.
fn build_endpoint_url(
    base: &url::Url,
    mode: EndpointMode,
    model: &str,
) -> Result<url::Url, ProviderError> {
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    match mode {
        EndpointMode::Interactions => {
            url.set_path(&format!("{base_path}/v1beta/interactions"));
        }
        EndpointMode::GenerateContent => {
            // Close-out item 3 (optional, taken): also reject a model id
            // that is entirely `.` characters (".", "..", "...", ...) --
            // makes this guard self-contained rather than relying solely on
            // the `:streamGenerateContent` suffix always staying glued to
            // `model` (see the test's doc comment on why that dependency
            // exists). No abuse path exists today since the suffix is never
            // dropped, but this costs nothing and removes the dependency.
            let all_dots = !model.is_empty() && model.chars().all(|c| c == '.');
            if model.is_empty()
                || all_dots
                || !model
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            {
                // Close-out item 2: `model` failed a character allowlist, so
                // it may contain newlines or other control bytes -- these
                // strings can reach a physically-immutable `events` row via
                // `ProviderError`'s `Display`, so it is escaped with `{:?}`
                // here (the test's own assertion already did this; this is
                // the production string that hadn't).
                return Err(ProviderError::Unsupported(format!(
                    "model id {model:?} contains a character not allowed in a URL path segment \
                     (only ASCII alphanumerics, '.', '-', '_' are permitted, and it may not be \
                     empty or all dots)"
                )));
            }
            // Verified: `streamGenerateContent` requires `?alt=sse` on the
            // URL to be framed as SSE at all -- `query_pairs_mut` appends
            // rather than replacing, so a gateway base URL's own query
            // string (e.g. `?key=...`) survives alongside it.
            url.set_path(&format!(
                "{base_path}/v1beta/models/{model}:streamGenerateContent"
            ));
            url.query_pairs_mut().append_pair("alt", "sse");
        }
    }
    Ok(url)
}

/// Remaps a Gemini error body into the `{"error": {"type", "message"}}` shape
/// `crate::errors::classify` hardcodes reading (`/error/type`) -- the real
/// wire field is named `code` (Interactions API, verified) or `status`
/// (legacy `generateContent`'s long-standing `google.rpc.Status` convention,
/// not directly fetched -- see the decision doc). Falls through to the raw
/// body unchanged when neither is present as a string (e.g. an HTML error
/// page from an outage), so `classify`'s own `serde_json::from_slice` still
/// degrades gracefully to the HTTP-status tier rather than this function
/// inventing a shape.
fn remap_error_body_for_classify(raw: &[u8]) -> Vec<u8> {
    let Ok(parsed) = serde_json::from_slice::<Value>(raw) else {
        return raw.to_vec();
    };
    let code = parsed
        .pointer("/error/code")
        .and_then(Value::as_str)
        .or_else(|| parsed.pointer("/error/status").and_then(Value::as_str));
    let Some(code) = code else {
        return raw.to_vec();
    };
    let message = parsed
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({ "error": { "type": code, "message": message } }))
        .unwrap_or_else(|_| raw.to_vec())
}

/// Renders a [`StreamFailure`] as the same shape `remap_error_body_for_classify`
/// produces, so an in-band terminal failure goes through the identical §9.8
/// classification path as an HTTP-level error. Mirrors
/// `openai_responses::provider::stream_failure_body`.
fn stream_failure_body(failure: &StreamFailure) -> Vec<u8> {
    let mut error_obj = serde_json::json!({ "message": failure.message });
    if let Some(code) = &failure.code {
        error_obj["type"] = serde_json::json!(code);
    }
    serde_json::to_vec(&serde_json::json!({ "error": error_obj })).unwrap_or_default()
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
    use super::{build_endpoint_url, EndpointMode};

    #[test]
    fn interactions_mode_targets_v1beta_interactions() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        let url = build_endpoint_url(&base, EndpointMode::Interactions, "gemini-3.0-pro").unwrap();
        assert_eq!(
            url.as_str(),
            "https://generativelanguage.googleapis.com/v1beta/interactions"
        );
    }

    #[test]
    fn generate_content_mode_targets_the_colon_method_with_alt_sse() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        let url =
            build_endpoint_url(&base, EndpointMode::GenerateContent, "gemini-3.0-pro").unwrap();
        assert_eq!(
            url.as_str(),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-pro:streamGenerateContent?alt=sse"
        );
    }

    /// Same fix-round-1 C5 concern as `openai_responses`: a gateway base URL
    /// carrying its own query string must keep it.
    #[test]
    fn preserves_a_gateway_query_string() {
        let base = url::Url::parse("https://gateway.example.com/proxy?key=abc123").unwrap();
        let url = build_endpoint_url(&base, EndpointMode::Interactions, "gemini-3.0-pro").unwrap();
        assert_eq!(
            url.as_str(),
            "https://gateway.example.com/proxy/v1beta/interactions?key=abc123"
        );
    }

    /// Fix-round-1 F9 / fix-round-2 close-out item 1: this is the allowlist
    /// property, not a denylist of `/`/`../`%` -- a bare `..` alone actually
    /// PASSES the allowlist (`.` is a permitted char), so it is NOT itself
    /// the invariant that prevents traversal. The real guarantee is
    /// structural: `build_endpoint_url` always emits `model` immediately
    /// followed by the literal `:streamGenerateContent` suffix
    /// (`"{base_path}/v1beta/models/{model}:streamGenerateContent"`), so an
    /// allowlisted `model` (alphanumerics, `.`, `-`, `_` only) can never
    /// close out a path segment on its own and therefore can never form a
    /// standalone `..` dot-segment -- the suffix is always still attached.
    /// **This depends on that suffix never being dropped or reordered.**
    /// Anyone changing the URL-building call must keep `model` and the
    /// `:streamGenerateContent` suffix glued together in one segment, or
    /// this guarantee silently stops holding even though every input below
    /// still gets rejected today.
    #[test]
    fn generate_content_mode_rejects_a_path_traversal_shaped_model_id() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        for bad_model in [
            "../v1beta/admin",
            "foo/bar",
            "%2e%2e/admin",
            "gemini-3.0-pro/../../admin",
            // Fix-round-2 G1: the two live bypasses the reviewer reproduced
            // against the original denylist-of-substrings check (`/`, `..`,
            // `%`) using url 2.5.8's actual normalization behavior -- `\` is
            // a path separator for special schemes, and the parser strips
            // tab/LF/CR BEFORE parsing, so a tab-separated `.` + `.`
            // reassembles into a literal `..` segment that never appeared in
            // the pre-check string.
            "foo\\bar",
            ".\t.\\admin",
            "",
            // Close-out item 3 (optional): all-dots is rejected on its own
            // terms now, not merely because the `:streamGenerateContent`
            // suffix happens to stay attached.
            ".",
            "..",
            "...",
        ] {
            assert!(
                build_endpoint_url(&base, EndpointMode::GenerateContent, bad_model).is_err(),
                "expected model id `{bad_model:?}` to be rejected"
            );
        }
    }

    /// Interactions mode never interpolates `model` into the URL at all, so
    /// the same rejection must not false-positive there.
    #[test]
    fn interactions_mode_does_not_validate_model_since_it_never_uses_it_in_the_path() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        assert!(build_endpoint_url(&base, EndpointMode::Interactions, "../whatever").is_ok());
    }

    /// A handful of real, legitimately-formatted Gemini model ids must still
    /// pass -- proves the allowlist doesn't over-reject.
    #[test]
    fn legitimate_model_ids_are_accepted() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        for good_model in [
            "gemini-2.5-flash",
            "gemini-3-pro-preview-11-2025",
            "gemini-1.5-pro-002",
            "gemma-3-27b-it",
        ] {
            assert!(
                build_endpoint_url(&base, EndpointMode::GenerateContent, good_model).is_ok(),
                "expected legitimate model id `{good_model}` to be accepted"
            );
        }
    }

    /// Close-out item 2: a rejected model id, having failed a character
    /// allowlist, may contain newlines or other control bytes -- the
    /// rejection message must escape it (`{:?}`), not interpolate it raw,
    /// since `ProviderError`'s `Display` can reach a persisted event row.
    #[test]
    fn the_rejection_message_escapes_a_newline_in_the_model_id_rather_than_interpolating_it_raw() {
        let base = url::Url::parse("https://generativelanguage.googleapis.com").unwrap();
        let err = build_endpoint_url(&base, EndpointMode::GenerateContent, "gemini\nadmin")
            .expect_err("a model id containing a newline must be rejected");
        let rendered = err.to_string();
        assert!(
            !rendered.contains('\n'),
            "the rejection message must not contain a raw, unescaped newline: {rendered:?}"
        );
        assert!(
            rendered.contains("\\n"),
            "expected the newline to appear escaped (via {{:?}}) in the message: {rendered:?}"
        );
    }
}

#[cfg(test)]
mod remap_error_body_tests {
    use super::remap_error_body_for_classify;

    #[test]
    fn remaps_the_verified_interactions_shape() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "error": { "code": "rate_limit_exceeded", "message": "slow down" }
        }))
        .unwrap();
        let remapped: serde_json::Value =
            serde_json::from_slice(&remap_error_body_for_classify(&raw)).unwrap();
        assert_eq!(remapped["error"]["type"], "rate_limit_exceeded");
        assert_eq!(remapped["error"]["message"], "slow down");
    }

    #[test]
    fn remaps_the_legacy_status_shape() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "error": { "code": 503, "message": "backend down", "status": "UNAVAILABLE" }
        }))
        .unwrap();
        let remapped: serde_json::Value =
            serde_json::from_slice(&remap_error_body_for_classify(&raw)).unwrap();
        assert_eq!(remapped["error"]["type"], "UNAVAILABLE");
    }

    #[test]
    fn a_non_json_html_outage_body_passes_through_unchanged() {
        let raw = b"<html>502 Bad Gateway</html>".to_vec();
        assert_eq!(remap_error_body_for_classify(&raw), raw);
    }

    /// Fix-round-2 G2: `generate_content_mode_error_429_cassette_classifies_via_
    /// the_status_remap_branch` (`conformance_google_genai.rs`) can pass even
    /// with `remap_error_body_for_classify` deleted entirely, because
    /// `classify`'s HTTP-status default tier independently returns
    /// `RateLimited` for a bare 429 regardless of whether this remap (or the
    /// profile's code table) was ever consulted -- the branch does execute,
    /// but the integration test alone cannot fail on a regression in this
    /// function specifically. This asserts on the function's own output,
    /// against the SAME cassette body that integration test replays, so a
    /// regression here is caught directly rather than only by coincidence of
    /// which `ProviderError` variant it happens to land on.
    #[test]
    fn remaps_the_generate_content_error_429_cassette_body_to_the_real_status() {
        let cassette = include_str!(
            "../../../testdata/cassettes/google_genai/generate_content_error_429.cassette"
        );
        let body = cassette
            .split_once("\n\n")
            .expect("cassette must have a header/body separator")
            .1;
        let remapped: serde_json::Value =
            serde_json::from_slice(&remap_error_body_for_classify(body.as_bytes())).unwrap();
        assert_eq!(remapped["error"]["type"], "RESOURCE_EXHAUSTED");
        assert_eq!(
            remapped["error"]["message"],
            "You exceeded your current quota, please check your plan and billing details."
        );
    }
}
