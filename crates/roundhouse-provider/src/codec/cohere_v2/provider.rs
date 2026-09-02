//! `CohereV2Provider`: bridges this module's pure `encode`/`decode` functions
//! to a real [`HttpTransport`]. Mirrors `google_genai::provider`'s shape
//! (profile-driven, `[errors]`-table classification via `crate::errors::classify`).

use super::decode::{decode_cohere_v2_stream, StreamFailure};
use super::encode::{contains_unencodable_media, encode};
use crate::audit::redact_error_body;
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
    /// encode (`Image`/`Document`/`Opaque`) as a cheap pre-flight. The guard
    /// that matters lives in `stream_chat`'s `encode(...)?` propagation --
    /// see `encode.rs`'s `EncodeError` doc comment (`resolve` has zero
    /// production callers anywhere in this workspace).
    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        if contains_unencodable_media(req) {
            return Err(ProviderError::Unsupported(
                "cohere-v2 codec does not encode Image/Document/Opaque blocks".into(),
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
                    .map_err(|e| ProviderError::Transport(redact_error_body(&e.to_string())))?;
            } else {
                match &self.profile.defaults.auth {
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

            let headers = to_header_map(&response.headers);
            let events = decode_cohere_v2_stream(response.body)
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

/// Renders a [`StreamFailure`] as the `{"error": {"type", "message"}}` shape
/// `crate::errors::classify` reads (`/error/type`) -- mirrors
/// `google_genai::provider::stream_failure_body`. Cohere's real HTTP-error
/// bodies carry no such shape at all (see `profiles/cohere-v2.toml`'s doc
/// comment), so this synthetic shape exists purely so an in-band terminal
/// failure (a `finish_reason` failure arriving after a 200) goes through the
/// same §9.8 classification path as any other error, with its `finish_reason`
/// value as the classification code.
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
mod stream_failure_body_tests {
    use super::stream_failure_body;
    use crate::codec::cohere_v2::decode::StreamFailure;
    use serde_json::Value;

    #[test]
    fn renders_the_classify_compatible_shape() {
        let failure = StreamFailure {
            code: Some("MAX_TOKENS".to_string()),
            message: "cohere-v2 chat generation stopped: MAX_TOKENS".to_string(),
        };
        let body = stream_failure_body(&failure);
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["error"]["type"], "MAX_TOKENS");
        assert_eq!(
            parsed["error"]["message"],
            "cohere-v2 chat generation stopped: MAX_TOKENS"
        );
    }
}
