//! `OpenAiResponsesProvider`: bridges this module's pure `encode`/`decode`
//! functions to a real [`HttpTransport`], the same shape
//! `AnthropicMessagesProvider` established in Phase 1. Unlike that adapter,
//! this one is profile-driven (§9.5): it holds a [`ProviderProfile`] rather
//! than a bare `base_url` string, and uses the profile's `[errors]` table
//! (REALITY-CORRECTIONS §14g) for status/body classification instead of a
//! hand-written `match`.

use crate::codec::openai_responses::decode::decode_openai_responses_stream;
use crate::codec::openai_responses::encode::encode;
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

    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
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
            let body = encode(req, &self.profile);
            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: format!("{}/responses", self.profile.defaults.base_url),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §6: prefer the real `CredentialProvider`
            // mechanism when present, falling back to the Phase 1 bare
            // `api_key` path (a plain bearer header) when it is not. No
            // `Provider` impl anywhere in this phase matches on which
            // concrete credential kind it was given -- `apply` alone decides.
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
                    .map_err(|e| ProviderError::Transport(e.to_string()))?;
            } else {
                http_req.headers.push((
                    "authorization".to_string(),
                    format!("Bearer {}", ctx.api_key),
                ));
            }

            let response = ctx
                .transport
                .send(http_req)
                .await
                .map_err(|e| ProviderError::Transport(e.to_string()))?;

            if !(200..300).contains(&response.status) {
                // §9.8: never `?` on JSON parsing in the error path -- an
                // outage returning HTML (see `error_500.cassette`) must not
                // become a decode panic. `classify` already honors this.
                let mut headers = http::HeaderMap::new();
                for (name, value) in &response.headers {
                    // A malformed header name/value is simply not carried
                    // into the map (matches `ReqwestTransport`'s own
                    // best-effort header handling) rather than failing the
                    // whole error-classification path over one bad header.
                    if let (Ok(name), Ok(value)) = (
                        http::HeaderName::from_bytes(name.as_bytes()),
                        http::HeaderValue::from_str(value),
                    ) {
                        headers.insert(name, value);
                    }
                }
                let body_bytes = collect_body(response.body).await;
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &body_bytes,
                    &headers,
                ));
            }

            let events = decode_openai_responses_stream(response.body).await;
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
