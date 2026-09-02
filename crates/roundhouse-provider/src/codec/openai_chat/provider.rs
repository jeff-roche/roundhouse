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

use super::{decode_openai_chat_stream, encode_openai_chat};
use crate::audit::redact_error_body;
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

            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None)
                    .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;
            let endpoint_url = build_endpoint_url(&base_url);

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
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
                    .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;
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

            let response = ctx
                .transport
                .send(http_req)
                .await
                .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;

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

            let events = decode_openai_chat_stream(response.body).await;
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
