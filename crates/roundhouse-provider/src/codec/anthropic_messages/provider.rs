//! `AnthropicMessagesProfileProvider`: Task 15's profile-parameterized
//! `Provider` for the six batch `anthropic-messages` profiles (Vertex,
//! Microsoft Foundry, Qwen/OpenRouter/DeepInfra Anthropic-compat, Bedrock
//! new-Claude) -- built once here so every profile is pure data reusing this
//! one adapter unchanged (§9.1's thesis), the same shape
//! `OpenAiChatProvider`/`BedrockConverseProvider`/`AzureOpenAiProvider`
//! establish for their own codecs.
//!
//! ## Design note: why this is a NEW wrapper, and why `encode_anthropic_messages`
//! is reused with NO signature change
//!
//! Phase 1 built `AnthropicMessagesProvider` (`crate::anthropic_provider`) as
//! a hardcoded, single-purpose demo `Provider`: a fixed
//! `https://api.anthropic.com` base URL, a raw `ctx.api_key: String` instead
//! of Task 2's `CredentialProvider`, and it calls `encode_anthropic_messages`
//! with no profile input at all. That is not wrong for what Phase 1 needed,
//! but it cannot directly serve six *other* providers with different base
//! URLs and auth mechanisms.
//!
//! REALITY-CORRECTIONS §1 states the existing `encode_anthropic_messages`
//! takes only `&ChatRequest`, and that new Phase 6 codecs' encoders take
//! `(req, profile)` "as a deliberate addition, not drift" -- but also that
//! `AnthropicMessagesProvider`'s wire output must stay byte-identical. This
//! task's addendum §1b calls the reconciliation a genuine design decision to
//! state explicitly, not a transcription step. The decision made here:
//!
//! **`encode_anthropic_messages`'s signature is NOT changed.** Unlike
//! `openai-chat` (where the wire-level reasoning-control field genuinely
//! diverges per profile -- moonshot uses `/reasoning_effort`, Z.ai uses
//! `/thinking/type`, so `encode_openai_chat` NEEDS a profile argument to pick
//! the right wire shape), every one of these six `anthropic-messages`
//! profiles speaks the byte-identical real Anthropic Messages wire format --
//! that is the entire premise of the audit finding this task implements
//! (§9.2: "Bedrock (new Claude models), Vertex Anthropic, Microsoft Foundry,
//! Qwen/OpenRouter/DeepInfra Anthropic-compat" all speak "a real Anthropic
//! Messages endpoint"). None of the six profiles below declares a
//! `[[model]].reasoning` control, so there is no per-profile wire-shape
//! choice for an encoder to make. `AnthropicMessagesProfileProvider` calls
//! `encode_anthropic_messages(req)` -- the exact same frozen function
//! `AnthropicMessagesProvider` already calls, completely unmodified -- so
//! the Phase-1 provider's wire output is trivially still byte-identical
//! (it is, quite literally, the same function call).
//!
//! **The one exception is Vertex, and it is handled OUTSIDE the encoder.**
//! Vertex's request *envelope* (not its content shape) genuinely differs,
//! confirmed against Anthropic's own docs (`vertex-anthropic.toml`'s module
//! comment carries the full citation): `model` is not a body field on
//! Vertex (it lives in the URL instead), and `anthropic_version` is a body
//! field there (not the `anthropic-version` HTTP header every other profile
//! in this batch uses). Mirroring how `openai_chat::provider`'s own
//! `contains_unencodable_content` guard lives in the *provider*, not the
//! frozen `encode_openai_chat`, this file's `stream_chat` post-processes the
//! `serde_json::Value` `encode_anthropic_messages` returns -- for this ONE
//! profile id only -- rather than widening the frozen encoder's signature or
//! teaching it a Vertex-specific branch. See `adjust_body_for_vertex` and
//! `build_endpoint_url` below. This is a profile-IDENTITY branch on wire
//! envelope shape, not a credential-kind branch (REALITY-CORRECTIONS §12b
//! forbids only the latter, and every credential still flows through the
//! single, uniform `ctx.credentials.apply(..)` call below regardless of
//! profile).

use serde_json::Value;

use super::{decode_anthropic_messages_stream, encode_anthropic_messages};
use crate::audit::redact_transport_error_text;
use crate::credential::{resolve_base_url, CredentialCtx};
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId, Plan, ProviderError, RequestCtx,
    TokenCount,
};
use crate::profile::{AuthKind, ProviderProfile};
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// Anthropic's required API-version header -- the same pin
/// `crate::anthropic_provider::AnthropicMessagesProvider` uses, since the
/// wire contract these six profiles all speak is the same one that codec's
/// encoder/decoder were written against. Vertex is the one profile that does
/// NOT receive this header (its `anthropic_version` travels in the body
/// instead -- see `adjust_body_for_vertex`).
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Vertex's documented body-only API-version value (verified,
/// `vertex-anthropic.toml`'s module comment carries the citation) -- NOT the
/// `ANTHROPIC_VERSION` HTTP-header value every other profile in this batch
/// sends; Vertex requires this exact different string in the body instead.
const VERTEX_ANTHROPIC_VERSION: &str = "vertex-2023-10-16";

/// A single, profile-parameterized `Provider` for every batch
/// `anthropic-messages` profile: one wire shape
/// (`encode_anthropic_messages`/`decode_anthropic_messages_stream`, reused
/// unchanged from Phase 1), differing only in which TOML file is loaded --
/// except Vertex's one documented envelope quirk, isolated to
/// `adjust_body_for_vertex`/`build_endpoint_url` below.
pub struct AnthropicMessagesProfileProvider {
    profile: ProviderProfile,
}

impl AnthropicMessagesProfileProvider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for AnthropicMessagesProfileProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        // Matches `AnthropicMessagesProvider`'s own capabilities (Phase 1):
        // every profile in this batch is the same real Anthropic Messages
        // wire format, so nothing here is profile-specific.
        Capabilities {
            streaming: true,
            tools: true,
            thinking: true,
            max_breakpoints: 4,
        }
    }

    /// Cheap, I/O-free pre-flight (REALITY-CORRECTIONS §13b item 5: `resolve`
    /// has zero production callers anywhere in this workspace) -- the guard
    /// that matters lives in `stream_chat`'s identical check below.
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_content(req) {
            return Err(ProviderError::Unsupported(
                "anthropic-messages codec does not encode Image/Document/Opaque blocks".into(),
            ));
        }
        Ok(Plan {
            endpoint: self.profile.id.clone(),
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
                    "anthropic-messages codec does not encode Image/Document/Opaque blocks".into(),
                ));
            }

            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None).map_err(
                    |e| ProviderError::Transport(redact_transport_error_text(&e.to_string())),
                )?;

            let is_vertex = self.profile.id == "vertex-anthropic";

            let endpoint_url = if is_vertex {
                build_vertex_endpoint_url(&base_url, &req.model.0)?
            } else {
                build_endpoint_url(&base_url)
            };

            let mut body = encode_anthropic_messages(req);
            if is_vertex {
                adjust_body_for_vertex(&mut body);
            }

            let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
            // Vertex carries its API-version value in the body instead
            // (`adjust_body_for_vertex`) -- every other profile in this
            // batch uses the ordinary Anthropic header.
            if !is_vertex {
                headers.push((
                    "anthropic-version".to_string(),
                    ANTHROPIC_VERSION.to_string(),
                ));
            }

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers,
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §6/§12b: `ctx.credentials.apply(..)` alone
            // handles Bearer (Vertex/Qwen/OpenRouter/DeepInfra), AzureEntra
            // (Foundry), and SigV4 (Bedrock) alike -- nothing in this
            // function matches on which concrete `CredentialProvider` was
            // supplied. The bare-`api_key` fallback below (matching
            // `openai_chat`'s/`azure_openai`'s identical precedent) only
            // ever fires for this batch's `AuthKind::Bearer` profiles, since
            // a bare string cannot express AzureEntra token exchange or
            // SigV4 signing.
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
                    // earns a remote 401 (matches `openai_chat`'s/
                    // `google_genai`'s/`azure_openai`'s identical guard for
                    // their own auth kinds).
                    AuthKind::Bearer if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "anthropic-messages codec requires a non-empty api_key (or a \
                             CredentialProvider) for Bearer auth"
                                .into(),
                        ));
                    }
                    // `authorization: Bearer <token>`, NOT Anthropic
                    // first-party's `x-api-key` header: this batch's four
                    // Bearer profiles all document `Authorization: Bearer`
                    // (Vertex's Google OAuth2 token and OpenRouter both
                    // document ONLY this form; Qwen and DeepInfra document
                    // it as one of two accepted forms) -- `x-api-key` is
                    // specifically an Anthropic-first-party/Anthropic-
                    // compat-gateway convention this batch's Bearer profiles
                    // do not uniformly share, unlike the shared wire BODY
                    // shape.
                    AuthKind::Bearer => {
                        http_req.headers.push((
                            "authorization".to_string(),
                            format!("Bearer {}", ctx.api_key),
                        ));
                    }
                    // AzureEntra (microsoft-foundry) and SigV4
                    // (bedrock-anthropic-messages) need the real
                    // `CredentialProvider` (token exchange/request signing no
                    // bare api_key string can express) -- a silent no-op
                    // here would send the request completely
                    // UNAUTHENTICATED. A missing credential must fail
                    // closed, not become a remote 401/403 the caller has to
                    // notice on its own.
                    other => {
                        return Err(ProviderError::Unsupported(format!(
                            "anthropic-messages codec has no CredentialProvider and its bare \
                             api_key fallback cannot express {other:?} auth"
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

            let events = decode_anthropic_messages_stream(response.body).await;
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
                "count_tokens is not offered uniformly across anthropic-messages-compat \
                 providers (this task's YAGNI scope: see deepinfra-anthropic.toml's module \
                 comment on the one profile in this batch that does document a real \
                 count_tokens endpoint)"
                    .into(),
            ))
        })
    }
}

/// Builds `{base}/v1/messages` -- the real, verified endpoint shape for
/// five of this batch's six profiles (Microsoft Foundry, Qwen, OpenRouter,
/// DeepInfra, Bedrock Mantle). Preserves `base`'s existing path prefix and
/// query string, matching `openai_chat`/`cohere_v2`/`google_genai`'s
/// identical `build_endpoint_url` precedent. Vertex does NOT use this
/// function -- see `build_vertex_endpoint_url`.
fn build_endpoint_url(base: &url::Url) -> url::Url {
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!("{base_path}/v1/messages"));
    url
}

/// Builds Vertex's `{base}/{model}:streamRawPredict` -- a completely
/// different REST resource shape (a verb-suffixed resource name, not a
/// fixed `/v1/messages` path), verified against Anthropic's and Google's own
/// docs (`vertex-anthropic.toml`'s module comment carries both citations).
/// This codec always sends `"stream": true` (`encode.rs`), so the streaming
/// verb (`:streamRawPredict`) is the one this provider always calls, never
/// the unary `:rawPredict` Anthropic's own curl example demonstrates.
fn build_vertex_endpoint_url(base: &url::Url, model: &str) -> Result<url::Url, ProviderError> {
    if model.is_empty() || model.contains(['/', '\n', '\r']) {
        return Err(ProviderError::Unsupported(format!(
            "model id {model:?} is not a valid Vertex publisher-model path segment"
        )));
    }
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!("{base_path}/{model}:streamRawPredict"));
    Ok(url)
}

/// Vertex's one documented request-envelope quirk (verified,
/// `vertex-anthropic.toml`'s module comment carries the citation): `model`
/// is not a body field there (it lives in the URL instead -- already
/// embedded by `build_vertex_endpoint_url`), and `anthropic_version` is a
/// body field there (`"vertex-2023-10-16"`, not the `anthropic-version` HTTP
/// header every other profile in this batch sends). Mutates the
/// `encode_anthropic_messages`-produced body in place; the frozen encoder
/// itself is never touched.
fn adjust_body_for_vertex(body: &mut Value) {
    if let Value::Object(map) = body {
        map.remove("model");
        map.insert(
            "anthropic_version".to_string(),
            Value::String(VERTEX_ANTHROPIC_VERSION.to_string()),
        );
    }
}

/// `encode_anthropic_messages` silently drops `Image`/`Document`/`Opaque`
/// blocks (see its own `encode_block` doc comment: "not emitted in Phase 1
/// scope"). Per REALITY-CORRECTIONS §13b item 5, "content the codec can't
/// encode fails closed" -- silently dropping it would mean a user who
/// attached an image or a document gets an answer computed without it, with
/// no error, warning, or log entry. `Thinking` is NOT included here: unlike
/// `openai-chat`, this codec's `encode_block` fully encodes `Thinking`
/// blocks (a real wire `type: "thinking"` shape with signature), matching
/// `AnthropicMessagesProvider`'s own `thinking: true` capability.
fn contains_unencodable_content(req: &ChatRequest) -> bool {
    req.messages.iter().any(|m| {
        m.content.iter().any(|b| {
            matches!(
                b,
                ContentBlock::Image { .. }
                    | ContentBlock::Document { .. }
                    | ContentBlock::Opaque { .. }
            )
        })
    })
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
    use super::{build_endpoint_url, build_vertex_endpoint_url};

    #[test]
    fn targets_v1_messages() {
        let base = url::Url::parse("https://api.deepinfra.com/anthropic").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(
            url.as_str(),
            "https://api.deepinfra.com/anthropic/v1/messages"
        );
    }

    #[test]
    fn preserves_a_gateway_query_string() {
        let base = url::Url::parse("https://gateway.example.com/proxy?key=abc123").unwrap();
        let url = build_endpoint_url(&base);
        assert_eq!(
            url.as_str(),
            "https://gateway.example.com/proxy/v1/messages?key=abc123"
        );
    }

    #[test]
    fn vertex_url_embeds_model_and_the_streaming_verb() {
        let base = url::Url::parse(
            "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/anthropic/models",
        )
        .unwrap();
        let url = build_vertex_endpoint_url(&base, "claude-opus-5").unwrap();
        assert_eq!(
            url.as_str(),
            "https://aiplatform.googleapis.com/v1/projects/p/locations/global/publishers/anthropic/models/claude-opus-5:streamRawPredict"
        );
    }

    #[test]
    fn vertex_url_rejects_an_empty_or_path_shaped_model_id() {
        let base = url::Url::parse("https://aiplatform.googleapis.com/v1/x").unwrap();
        assert!(build_vertex_endpoint_url(&base, "").is_err());
        assert!(build_vertex_endpoint_url(&base, "a/../b").is_err());
        assert!(build_vertex_endpoint_url(&base, "a\nb").is_err());
    }
}

#[cfg(test)]
mod adjust_body_for_vertex_tests {
    use super::adjust_body_for_vertex;
    use serde_json::json;

    #[test]
    fn strips_model_and_inserts_the_vertex_api_version() {
        let mut body = json!({
            "model": "claude-opus-5",
            "system": [],
            "messages": [],
            "max_tokens": 4096,
            "stream": true,
        });
        adjust_body_for_vertex(&mut body);
        assert!(body.get("model").is_none(), "model must be removed: {body}");
        assert_eq!(body["anthropic_version"], "vertex-2023-10-16");
        // Every other field survives untouched.
        assert_eq!(body["max_tokens"], 4096);
        assert_eq!(body["stream"], true);
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
    fn thinking_content_is_encodable_unlike_openai_chat() {
        let req = request_with(vec![ContentBlock::Thinking {
            text: "reasoning...".into(),
            signature: None,
            redacted: false,
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
    fn document_content_is_unencodable() {
        let req = request_with(vec![ContentBlock::Document {
            source: MediaSource {
                mime_type: "application/pdf".into(),
                data: vec![0, 1, 2, 3],
            },
            title: None,
            cache: None,
        }]);
        assert!(contains_unencodable_content(&req));
    }
}
