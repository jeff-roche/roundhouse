//! `BedrockConverseProvider`: bridges this module's pure `encode`/`decode`
//! functions to a real [`HttpTransport`], the same shape
//! `OpenAiResponsesProvider`/`GoogleGenAiProvider` establish. SigV4 signing
//! happens entirely through `ctx.credentials.apply(..)` (REALITY-CORRECTIONS
//! §12b): this file contains no credential-kind `match` of any kind -- there
//! is exactly one `AuthKind` this profile ever declares (`sigv4`), and a
//! missing `CredentialProvider` fails closed rather than falling back to a
//! bare `api_key` string, which cannot express AWS request signing at all.

use serde_json::Value;

use super::decode::{decode_bedrock_converse_stream, StreamFailure};
use super::encode::try_encode;
use crate::audit::redact_transport_error_text;
use crate::credential::{resolve_base_url, CredentialCtx};
use crate::errors::classify;
use crate::ir::{
    Capabilities, ChatRequest, ChatStream, ModelId, Plan, ProviderError, RequestCtx, TokenCount,
};
use crate::profile::ProviderProfile;
use crate::provider_trait::{BoxFut, Provider};
use crate::transport::HttpRequest;

/// The live `Provider` for the Bedrock Converse codec (legacy non-Claude
/// model families).
pub struct BedrockConverseProvider {
    profile: ProviderProfile,
}

impl BedrockConverseProvider {
    pub fn new(profile: ProviderProfile) -> Self {
        Self { profile }
    }
}

impl Provider for BedrockConverseProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities {
            streaming: true,
            tools: true,
            // No model declared in this profile has a reasoning control
            // (see `mod.rs`'s module doc comment) -- `thinking: false` is a
            // fact about this profile's declared models today, not a claim
            // that the wire format itself can never carry reasoning content
            // (`decode.rs` does decode `reasoningContent` deltas when a
            // future reasoning-capable model is added to this profile).
            thinking: false,
            max_breakpoints: 0,
        }
    }

    fn resolve(&self, req: &ChatRequest) -> Result<Plan, ProviderError> {
        // Cheap, I/O-free pre-flight -- the guard that matters on the
        // production path is `try_encode`'s own `Err` propagation inside
        // `stream_chat` below (`resolve` has zero production callers
        // anywhere in this workspace, REALITY-CORRECTIONS §13b item 5).
        try_encode(req, &self.profile)?;
        Ok(Plan {
            endpoint: "bedrock-converse".into(),
        })
    }

    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let body = try_encode(req, &self.profile)?;

            let (base_url, _host_only) =
                resolve_base_url(&self.profile.id, &self.profile.defaults.base_url, None).map_err(
                    |e| ProviderError::Transport(redact_transport_error_text(&e.to_string())),
                )?;
            let endpoint_url = build_endpoint_url(&base_url, &req.model.0)?;

            let mut http_req = HttpRequest {
                method: "POST".to_string(),
                url: endpoint_url.to_string(),
                headers: vec![("content-type".to_string(), "application/json".to_string())],
                body: serde_json::to_vec(&body)
                    .map_err(|e| ProviderError::Unsupported(e.to_string()))?,
            };

            // REALITY-CORRECTIONS §12b: no credential-kind `match` anywhere
            // in this file. This profile declares exactly one `AuthKind`
            // (`sigv4`) and has no bare-`api_key` fallback that could
            // meaningfully sign an AWS request -- a missing
            // `CredentialProvider` is therefore always a hard,
            // locally-detected failure, never a silently-unauthenticated
            // request sent to the wire.
            match &ctx.credentials {
                Some(credentials) => {
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
                }
                None => {
                    return Err(ProviderError::Unsupported(
                        "bedrock-converse requires a SigV4 CredentialProvider; it has no bare \
                         api_key fallback that can sign an AWS request"
                            .into(),
                    ));
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
                let remapped = remap_http_error_body(&body_bytes, &headers);
                return Err(classify(
                    &self.profile.error_profile(),
                    response.status,
                    &remapped,
                    &headers,
                ));
            }

            let headers = to_header_map(&response.headers);
            let (events, losses) = decode_bedrock_converse_stream(response.body)
                .await
                .map_err(|failure| {
                    classify(
                        &self.profile.error_profile(),
                        response.status,
                        &stream_failure_body(&failure),
                        &headers,
                    )
                })?;
            // Phase 7 Task 13b: `guardrail_intervened`/`content_filtered`
            // `messageStop.stopReason` values now surface as `LossEvent`s
            // returned in-band from `decode_bedrock_converse_stream`
            // (Ruling R4) alongside the real, actually-observed
            // `MessageStop` -- this is a successful completion, not an
            // error, so there is no `ProviderError` to remap it into.
            //
            // Known gap (see `LossEvent::into_payload`'s doc comment): no
            // channel out of `stream_chat` exists yet to carry this to a
            // persisted `EventPayload::Loss` -- `Provider`/`ChatStream`/
            // `StreamEvent` are all frozen Phase 0 contracts with no field
            // for it. Logging it here is strictly better than the pre-13b
            // silence (every `stopReason` produced an identical bare
            // `MessageStop`); giving it a real return channel is lane W1's
            // engine-wiring call.
            for loss in &losses {
                tracing::warn!(
                    kind = loss.kind.tag(),
                    // Fix round 1, K2: today's two `stopReason` values this
                    // module names (`guardrail_intervened`/`content_filtered`)
                    // are a closed, hardcoded vocabulary, so `description` is
                    // provably safe right now -- but this redacts anyway, for
                    // parity with `openai_responses` and so a future
                    // `_ => LossKind::Other(reason)` catch-all arm here can't
                    // silently reopen the same exposure by relying on this
                    // log site's construction-time safety alone.
                    description = %redact_transport_error_text(&loss.description),
                    blocks_affected = loss.blocks_affected,
                    "bedrock-converse stream stopped lossy (messageStop.stopReason) with no \
                     EventWriter channel yet to persist this as EventPayload::Loss"
                );
            }
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
                "count_tokens is not built for the bedrock-converse codec in this task".into(),
            ))
        })
    }
}

/// Validates `model` as a safe `/model/{modelId}/...` path segment.
///
/// Bedrock's real `modelId` can be a bare model id, an inference-profile id,
/// or a full ARN -- confirmed by AWS's own documented request examples,
/// which insert an ARN like
/// `arn:aws:bedrock:us-west-2:123456789012:prompt/PROMPT12345:1` into this
/// exact path position with its `:` and `/` characters entirely unescaped
/// (fetched from `API_runtime_Converse.html`'s own request-URI parameter
/// pattern and examples). So, unlike `google_genai::provider::build_endpoint_url`'s
/// simpler `[a-zA-Z0-9.\-_]`-only allowlist, `/` and `:` must both be
/// legitimate here -- which means a denylist-of-substrings check would be
/// exactly the shape that codec's fix-round-2 G1 already found broken
/// (bypassable via `\` path-separator normalization and tab/LF/CR stripping
/// that happens INSIDE `Url::set_path`'s own re-parsing, after any pre-check
/// on the raw string has already passed it). This instead validates every
/// `/`-delimited segment independently: non-empty, never exactly `.` or
/// `..` (the only way a charset that already permits `/` could still spell a
/// traversal), and drawn only from the character set every real `modelId`
/// form above actually uses.
fn validate_model_id(model: &str) -> Result<(), ProviderError> {
    let reject = |reason: &str| -> Result<(), ProviderError> {
        Err(ProviderError::Unsupported(format!(
            "model id {model:?} is not a valid Bedrock modelId path segment: {reason}"
        )))
    };
    if model.is_empty() {
        return reject("empty");
    }
    for segment in model.split('/') {
        if segment.is_empty() {
            return reject("contains an empty path segment (a leading, trailing, or doubled `/`)");
        }
        if segment == "." || segment == ".." {
            return reject("contains a `.` or `..` path segment");
        }
        if !segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
        {
            return reject(
                "contains a character outside the allowed set (ASCII alphanumerics, and \
                 '.', '-', '_', ':')",
            );
        }
    }
    Ok(())
}

/// Builds `{base}/model/{modelId}/converse-stream` (verified request URI
/// pattern), preserving `base`'s existing path prefix and query string --
/// matches `google_genai`/`openai_responses`' `Url::set_path` precedent
/// (never `Url::join`, which drops a base URL's existing query string per
/// WHATWG relative-URL resolution).
fn build_endpoint_url(base: &url::Url, model: &str) -> Result<url::Url, ProviderError> {
    validate_model_id(model)?;
    let mut url = base.clone();
    let base_path = url.path().strip_suffix('/').unwrap_or(url.path());
    url.set_path(&format!("{base_path}/model/{model}/converse-stream"));
    Ok(url)
}

/// Remaps an HTTP-level (out-of-band) error body/headers into the
/// `{"error": {"type", "message"}}` shape `crate::errors::classify`
/// hardcodes reading (`/error/type`, `/error/message`).
///
/// Verified via the Smithy `restJson1` protocol spec
/// (<https://smithy.io/2.0/aws/protocols/aws-restjson1-protocol.html>,
/// fetched): the exception SHAPE name is carried in the `X-Amzn-Errortype`
/// response HEADER, not the JSON body -- a real body is typically just
/// `{"message": "..."}`. The header's value may carry a trailing
/// `:<uri>` suffix per that same spec ("clients MUST accept" a shape-name
/// prefix before an optional colon); only the part before the first `:` is
/// kept.
fn remap_http_error_body(raw: &[u8], headers: &http::HeaderMap) -> Vec<u8> {
    let code = headers
        .get("x-amzn-errortype")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(':').next().unwrap_or(v).to_string());
    let Some(code) = code else {
        return raw.to_vec();
    };
    let message = serde_json::from_slice::<Value>(raw)
        .ok()
        .and_then(|v| {
            v.get("message")
                .or_else(|| v.get("Message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    serde_json::to_vec(&serde_json::json!({ "error": { "type": code, "message": message } }))
        .unwrap_or_else(|_| raw.to_vec())
}

/// Renders a [`StreamFailure`] as the same shape `remap_http_error_body`
/// produces, so an in-band terminal failure goes through the identical §9.8
/// classification path as an HTTP-level error.
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

#[cfg(test)]
mod build_endpoint_url_tests {
    use super::build_endpoint_url;

    #[test]
    fn targets_the_verified_model_converse_stream_path() {
        let base = url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        let url = build_endpoint_url(&base, "meta.llama4-70b-instruct-v1:0").unwrap();
        assert_eq!(
            url.as_str(),
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/meta.llama4-70b-instruct-v1:0/converse-stream"
        );
    }

    /// Proves `:` survives `Url::set_path` unescaped -- load-bearing for
    /// every real Bedrock modelId, which always contains at least one (the
    /// version suffix, e.g. `:0`).
    #[test]
    fn colon_in_model_id_is_not_percent_encoded() {
        let base = url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        let url = build_endpoint_url(&base, "meta.llama4-70b-instruct-v1:0").unwrap();
        assert!(url.path().contains("v1:0"), "path was {}", url.path());
        assert!(!url.path().contains("%3A"), "path was {}", url.path());
    }

    /// A full ARN modelId (the documented "inference profile"/"prompt
    /// resource" form) must pass through with its internal `/`s intact as
    /// real path separators, matching AWS's own fetched request example.
    #[test]
    fn accepts_a_real_arn_shaped_model_id() {
        let base = url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        let arn = "arn:aws:bedrock:us-west-2:123456789012:prompt/PROMPT12345:1";
        let url = build_endpoint_url(&base, arn).unwrap();
        assert_eq!(
            url.as_str(),
            format!("https://bedrock-runtime.us-east-1.amazonaws.com/model/{arn}/converse-stream")
        );
    }

    #[test]
    fn preserves_a_gateway_query_string() {
        let base = url::Url::parse("https://gateway.example.com/proxy?key=abc123").unwrap();
        let url = build_endpoint_url(&base, "meta.llama4-70b-instruct-v1:0").unwrap();
        assert_eq!(
            url.as_str(),
            "https://gateway.example.com/proxy/model/meta.llama4-70b-instruct-v1:0/converse-stream?key=abc123"
        );
    }

    #[test]
    fn rejects_a_path_traversal_shaped_model_id() {
        let base = url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        for bad_model in [
            "../admin",
            "meta.llama4/../../admin",
            "",
            ".",
            "..",
            "foo//bar",
            "/leading-slash",
            "trailing-slash/",
            "foo\\bar",
            "meta.llama4\nadmin",
            "meta.llama4?admin",
            "meta.llama4#admin",
        ] {
            assert!(
                build_endpoint_url(&base, bad_model).is_err(),
                "expected model id `{bad_model:?}` to be rejected"
            );
        }
    }

    #[test]
    fn the_rejection_message_escapes_a_newline_in_the_model_id_rather_than_interpolating_it_raw() {
        let base = url::Url::parse("https://bedrock-runtime.us-east-1.amazonaws.com").unwrap();
        let err = build_endpoint_url(&base, "meta\nadmin").expect_err("must be rejected");
        let rendered = err.to_string();
        assert!(!rendered.contains('\n'), "message was: {rendered:?}");
        assert!(rendered.contains("\\n"), "message was: {rendered:?}");
    }
}

#[cfg(test)]
mod remap_http_error_body_tests {
    use super::remap_http_error_body;

    #[test]
    fn remaps_using_the_x_amzn_errortype_header_not_the_body() {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-amzn-errortype", "ThrottlingException".parse().unwrap());
        let raw = serde_json::to_vec(&serde_json::json!({ "message": "slow down" })).unwrap();
        let remapped: serde_json::Value =
            serde_json::from_slice(&remap_http_error_body(&raw, &headers)).unwrap();
        assert_eq!(remapped["error"]["type"], "ThrottlingException");
        assert_eq!(remapped["error"]["message"], "slow down");
    }

    /// Smithy's `restJson1` spec: clients MUST accept a `shapeName:uri`
    /// suffix on this header; only the shape name matters for classification.
    #[test]
    fn strips_a_trailing_uri_suffix_from_the_header_value() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-amzn-errortype",
            "ThrottlingException:http://internal.example.com/coral/x"
                .parse()
                .unwrap(),
        );
        let raw = b"{}".to_vec();
        let remapped: serde_json::Value =
            serde_json::from_slice(&remap_http_error_body(&raw, &headers)).unwrap();
        assert_eq!(remapped["error"]["type"], "ThrottlingException");
    }

    #[test]
    fn a_missing_header_passes_the_body_through_unchanged() {
        let headers = http::HeaderMap::new();
        let raw = b"<html>502 Bad Gateway</html>".to_vec();
        assert_eq!(remap_http_error_body(&raw, &headers), raw);
    }
}
