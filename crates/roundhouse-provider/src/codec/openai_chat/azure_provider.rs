//! `AzureOpenAiProvider`: identical request/response BODY handling to
//! `OpenAiChatProvider` (Azure OpenAI speaks ordinary openai-chat JSON,
//! §9.4's design note: "Azure's request/response *bodies* are ordinary
//! `openai-chat` shape, only the URL differs") -- the only override is
//! `stream_chat`'s URL construction, which goes through the
//! `azure_deployment_routing` shim instead of `{base_url}/chat/completions`.
//!
//! This file deliberately does NOT reuse `OpenAiChatProvider::stream_chat`
//! or its private helpers: `Provider::stream_chat` has no seam for
//! overriding just URL construction, and this task's dispatch keeps
//! `codec/openai_chat/provider.rs` off limits (already-committed code under
//! active review). So the small amount of surrounding plumbing this file
//! needs (the unencodable-content guard, the auth fallback, error
//! classification, stream-failure mapping) is its own private copy here --
//! mirroring, not editing, `provider.rs`. This is the established pattern
//! in this crate already: `cohere_v2::provider` and `google_genai::provider`
//! each keep their own private copy of this exact shape of plumbing rather
//! than sharing it (see e.g. `google_genai::provider::stream_failure_body`'s
//! own doc comment: "Mirrors `openai_responses::provider::stream_failure_body`").

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
use crate::transport::azure_deployment_routing::{azure_deployment_url, resolve_deployment_name};
use crate::transport::HttpRequest;

/// Verified against Microsoft's own current REST API reference (fetched
/// 2026-09-02): <https://learn.microsoft.com/en-us/azure/foundry/openai/reference>
/// documents `2024-10-21` as a real, current GA (non-preview) data-plane
/// inference API version for chat completions and sibling operations (its
/// own title is "Azure OpenAI image and audio REST API reference
/// (2024-10-21), Microsoft Foundry", cross-linking chat completions to the
/// same GA release generation). Per REALITY-CORRECTIONS §13b item 1 ("verify
/// enum VALUES, not schema names"), this replaces the plan brief's
/// placeholder literal (`"2026-06-01"`, used only inside this task's own
/// pure-function unit tests, where the exact value is inert) with a value
/// actually confirmed against the vendor's published docs, not invented.
const AZURE_API_VERSION: &str = "2024-10-21";

/// A single, profile-parameterized `Provider` for Azure OpenAI: reuses
/// `encode_openai_chat`/`decode_openai_chat_stream` (Task 10, frozen, taking
/// no profile-specific URL knowledge at all) unchanged, differing from
/// `OpenAiChatProvider` only in how the request URL is built.
pub struct AzureOpenAiProvider {
    profile: ProviderProfile,
}

impl AzureOpenAiProvider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for AzureOpenAiProvider {
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
    /// that matters lives in `stream_chat`'s identical check below.
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_content(req) {
            return Err(ProviderError::Unsupported(
                "openai-chat codec does not encode Image/Document/Thinking/Opaque blocks".into(),
            ));
        }
        Ok(Plan {
            endpoint: "azure-openai".into(),
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

            // Azure's ONE divergence from `OpenAiChatProvider`: routed by
            // deployment name (a per-model, per-resource mapping the
            // profile carries), not by `{base_url}/chat/completions` with
            // the model id in the JSON body.
            let deployment = resolve_deployment_name(&self.profile, &req.model.0)?;
            let (base_url, _host_only) = resolve_base_url(
                &self.profile.id,
                &self.profile.defaults.base_url,
                None,
                false,
            )
            .map_err(|e| ProviderError::Transport(redact_transport_error_text(&e.to_string())))?;
            let endpoint_url =
                azure_deployment_url(base_url.as_str(), deployment, AZURE_API_VERSION)?;

            let body = encode_openai_chat(req, &self.profile);

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(redact_error_body(&e.to_string())))?,
            };

            // REALITY-CORRECTIONS §6: prefer the real `CredentialProvider`
            // mechanism when present (this is how an `AzureEntraCredential`
            // reaches this provider -- the profile's own default auth is
            // `header_key`, but nothing here matches on which concrete
            // `CredentialProvider` was supplied), falling back to the bare
            // `api_key` path honoring the profile's own `header_key` auth
            // (`api-key` header) when it is not.
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
                    // credential-less `api-key: ` that only earns a remote
                    // 401 (matches `openai_chat`'s/`google_genai`'s
                    // identical guard for their own auth kinds).
                    AuthKind::HeaderKey { .. } if ctx.api_key.trim().is_empty() => {
                        return Err(ProviderError::Unsupported(
                            "azure-openai codec requires a non-empty api_key (or a \
                             CredentialProvider) for header_key auth"
                                .into(),
                        ));
                    }
                    AuthKind::HeaderKey { header } => {
                        http_req.headers.push((header.clone(), ctx.api_key.clone()));
                    }
                    // Bearer/SigV4/AzureEntra need the real
                    // `CredentialProvider` (token exchange/signing logic no
                    // bare api_key string can express) -- not reachable via
                    // this profile's own `header_key` auth today, but a
                    // silent no-op here would send the request completely
                    // UNAUTHENTICATED rather than failing it locally. A
                    // missing credential must fail closed, not become a
                    // remote 401 the caller has to notice on its own.
                    other => {
                        return Err(ProviderError::Unsupported(format!(
                            "azure-openai codec has no CredentialProvider and its bare api_key \
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
                "count_tokens is not offered by Azure OpenAI".into(),
            ))
        })
    }
}

/// Maps a mid-stream `StreamFailure` onto a `ProviderError`, by `kind`.
/// Mirrors `openai_chat::provider::stream_failure_to_provider_error` (kept
/// as a private, un-shared copy per this file's module doc: `provider.rs` is
/// off limits for this task).
fn stream_failure_to_provider_error(failure: StreamFailure) -> ProviderError {
    tracing::warn!(
        kind = ?failure.kind,
        message = %redact_transport_error_text(&failure.message),
        "azure-openai stream failed mid-generation"
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
/// `Opaque` blocks. Per REALITY-CORRECTIONS §13b item 5, "content the codec
/// can't encode fails closed" -- silently dropping it would mean a user who
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
}

/// Fail-closed properties specific to this file's `stream_chat`: an unmapped
/// model id, or a missing credential for the profile's declared auth kind,
/// must never reach `HttpTransport::send` at all -- these are exactly the
/// two guards `google_genai::provider`'s and `openai_chat::provider`'s own
/// precedent calls "a missing credential must fail closed, not become a
/// remote 401 the caller has to notice on its own," applied here to Azure's
/// deployment-lookup step specifically. `PanicTransport` proves the "before
/// any transport call" half: if either guard were removed, this test would
/// panic inside `HttpTransport::send` instead of observing a clean `Err`.
#[cfg(test)]
mod stream_chat_fail_closed_tests {
    use super::AzureOpenAiProvider;
    use crate::ir::{
        ChatRequest, ContentBlock, Message, MessageRole, ModelId, Params, ProviderError,
        ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, ToolChoice,
    };
    use crate::provider_trait::Provider;
    use crate::transport::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    struct PanicTransport;
    impl HttpTransport for PanicTransport {
        fn send<'a>(
            &'a self,
            _req: HttpRequest,
        ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
            panic!("stream_chat must fail closed before ever calling HttpTransport::send")
        }
    }

    fn profile() -> crate::profile::ProviderProfile {
        crate::load_profile("azure-openai").expect("azure-openai profile must be registered")
    }

    fn request_for(model_id: &str) -> ChatRequest {
        ChatRequest {
            model: ModelId(model_id.into()),
            system: vec![],
            messages: vec![Message {
                role: MessageRole::User,
                content: vec![ContentBlock::Text {
                    text: "hi".into(),
                    cache: None,
                    citations: vec![],
                }],
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

    fn ctx_with_api_key(api_key: &str) -> RequestCtx {
        RequestCtx {
            trace_id: None,
            transport: Arc::new(PanicTransport),
            api_key: api_key.into(),
            credentials: None,
        }
    }

    #[tokio::test]
    async fn an_unmapped_model_id_fails_closed_before_any_transport_call() {
        let provider = AzureOpenAiProvider::new(profile());
        let req = request_for("some-unmapped-model");
        let ctx = ctx_with_api_key("k");
        // `ChatStream` doesn't derive `Debug` (ir.rs), so a plain `match`
        // stands in for `expect_err`.
        match provider.stream_chat(&req, &ctx).await {
            Err(ProviderError::Unsupported(_)) => {}
            Err(other) => panic!("expected Unsupported, got a different error: {other}"),
            Ok(_) => panic!("an unmapped model id must fail closed"),
        }
    }

    #[tokio::test]
    async fn an_empty_api_key_with_header_key_auth_and_no_credentials_fails_closed() {
        let provider = AzureOpenAiProvider::new(profile());
        let req = request_for("gpt-5.4");
        let ctx = ctx_with_api_key("   ");
        match provider.stream_chat(&req, &ctx).await {
            Err(ProviderError::Unsupported(_)) => {}
            Err(other) => panic!("expected Unsupported, got a different error: {other}"),
            Ok(_) => panic!("an empty api_key with no CredentialProvider must fail closed"),
        }
    }
}
