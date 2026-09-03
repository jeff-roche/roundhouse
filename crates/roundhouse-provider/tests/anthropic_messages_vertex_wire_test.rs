//! Closes the loop on `provider.rs`'s isolated `adjust_body_for_vertex`/
//! `build_vertex_endpoint_url` unit tests: proves the ACTUAL `HttpRequest`
//! `AnthropicMessagesProfileProvider::stream_chat` builds for the
//! `vertex-anthropic` profile -- not just those two helper functions in
//! isolation -- has no `model` body field, carries `anthropic_version` in
//! the body, sends no `anthropic-version` HTTP header, and targets the
//! `{base}/{model}:streamRawPredict` URL. A capturing fake `HttpTransport`
//! (matching `credential_test.rs`'s `NullTransport`/`FixedHeaderCredential`
//! precedent for hand-rolled test doubles) observes the real request that
//! reaches the transport boundary.

use roundhouse_provider::codec::anthropic_messages::AnthropicMessagesProfileProvider;
use roundhouse_provider::{
    ChatRequest, ContentBlock, HttpRequest, HttpResponseStream, HttpTransport, Message, ModelId,
    Params, Provider, ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat,
    Role, ToolChoice, TransportError,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn profile() -> roundhouse_provider::profile::ProviderProfile {
    let path = format!(
        "{}/profiles/vertex-anthropic.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn request() -> ChatRequest {
    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![Message {
            role: Role::User,
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

/// Captures the one `HttpRequest` it receives, then returns a minimal
/// well-formed empty-stream success response (this test only cares about
/// what was SENT, not what comes back).
struct CapturingTransport {
    captured: Arc<Mutex<Option<HttpRequest>>>,
}

impl HttpTransport for CapturingTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        *self.captured.lock().unwrap() = Some(req);
        Box::pin(async move {
            Ok(HttpResponseStream {
                status: 200,
                headers: vec![],
                body: Box::pin(futures::stream::empty()),
            })
        })
    }
}

#[tokio::test]
async fn vertex_stream_chat_sends_the_real_body_and_url_quirks() {
    let captured = Arc::new(Mutex::new(None));
    let transport = CapturingTransport {
        captured: captured.clone(),
    };
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-oauth-access-token".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProfileProvider::new(profile());
    let _ = provider.stream_chat(&request(), &ctx).await;

    let sent = captured
        .lock()
        .unwrap()
        .take()
        .expect("stream_chat must have called HttpTransport::send");

    assert_eq!(
        sent.url,
        "https://aiplatform.googleapis.com/v1/projects/PROJECT_ID/locations/global/publishers/anthropic/models/claude-sonnet-5:streamRawPredict",
        "must target the {{base}}/{{model}}:streamRawPredict verb-suffixed resource URL"
    );

    let body: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert!(
        body.get("model").is_none(),
        "the wire body must not carry a model field on Vertex: {body}"
    );
    assert_eq!(
        body["anthropic_version"], "vertex-2023-10-16",
        "the wire body must carry Vertex's own anthropic_version value: {body}"
    );

    assert!(
        !sent
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("anthropic-version")),
        "Vertex must not send the anthropic-version HTTP header (it uses the body field \
         instead): {:?}",
        sent.headers
    );
    assert!(
        sent.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("authorization")
                && v == "Bearer test-oauth-access-token"),
        "the bare api_key fallback must send it as an ordinary Bearer Authorization header \
         for this profile's AuthKind::Bearer: {:?}",
        sent.headers
    );
}
