//! Proves `AnthropicMessagesProvider`'s shape — that it calls Task 9's encoder
//! and Task 10's decoder around a real `HttpTransport` — using
//! `CassetteTransport` per §9.10's testing philosophy, never a live call. No
//! `ANTHROPIC_API_KEY`, no outbound connection.

use futures::future::BoxFuture;
use futures::StreamExt;
use roundhouse_provider::{
    AnthropicMessagesProvider, BlockDelta, CassetteTransport, ChatRequest, HttpRequest,
    HttpResponseStream, HttpTransport, ModelId, Params, Provider, ProviderError, ProviderExt,
    ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent, ToolChoice,
    TransportError,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

fn sample_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        // Unpopulated in Phase 1 (see Task 6's deliberate-scoping note).
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// A `CassetteTransport` that also keeps the request it was handed, so tests
/// can assert on what the provider *sent* (URL, headers, encoded body) and not
/// only on what it did with the reply.
struct RecordingTransport {
    inner: CassetteTransport,
    seen: Mutex<Option<HttpRequest>>,
}

impl RecordingTransport {
    fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            inner: CassetteTransport {
                status,
                headers: vec![],
                body,
                chunk_size: 0,
            },
            seen: Mutex::new(None),
        }
    }

    fn take(&self) -> HttpRequest {
        self.seen
            .lock()
            .unwrap()
            .take()
            .expect("provider never called the transport")
    }
}

impl HttpTransport for RecordingTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        let echo = HttpRequest {
            method: req.method.clone(),
            url: req.url.clone(),
            headers: req.headers.clone(),
            body: req.body.clone(),
        };
        *self.seen.lock().unwrap() = Some(echo);
        self.inner.send(req)
    }
}

fn hello_cassette() -> Vec<u8> {
    include_bytes!("fixtures/anthropic_hello.sse").to_vec()
}

/// `Result::expect_err` needs `T: Debug`, and `ChatStream` deliberately isn't
/// (it wraps a boxed stream) — so error-path tests unwrap through this instead.
fn expect_err(result: Result<roundhouse_provider::ChatStream, ProviderError>) -> ProviderError {
    match result {
        Ok(_) => panic!("expected an error, got a successful stream"),
        Err(err) => err,
    }
}

#[tokio::test]
async fn stream_chat_encodes_the_request_and_decodes_a_real_shaped_sse_response() {
    let transport = Arc::new(CassetteTransport {
        status: 200,
        headers: vec![],
        body: hello_cassette(),
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProvider::new();
    let mut stream = provider.stream_chat(&sample_request(), &ctx).await.unwrap();

    let mut text = String::new();
    while let Some(event) = stream.next().await {
        if let StreamEvent::BlockDelta {
            delta: BlockDelta::Text(t),
            ..
        } = event
        {
            text.push_str(&t);
        }
    }
    assert_eq!(text, "Hello from Anthropic.");
}

/// Pins the wire request the provider builds: the Messages endpoint, the three
/// headers Anthropic requires, and a body that is genuinely Task 9's encoder
/// output (`stream: true` is the encoder's, not something re-added here).
#[tokio::test]
async fn stream_chat_posts_the_encoded_body_to_the_messages_endpoint() {
    let transport = Arc::new(RecordingTransport::new(200, hello_cassette()));
    let ctx = RequestCtx {
        trace_id: None,
        transport: transport.clone(),
        api_key: "test-key".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProvider::new();
    provider
        .stream_chat(&sample_request(), &ctx)
        .await
        .expect("200 cassette must decode");

    let sent = transport.take();
    assert_eq!(sent.method, "POST");
    assert_eq!(sent.url, "https://api.anthropic.com/v1/messages");

    let header = |name: &str| {
        sent.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(header("x-api-key").as_deref(), Some("test-key"));
    assert_eq!(header("anthropic-version").as_deref(), Some("2023-06-01"));
    assert_eq!(header("content-type").as_deref(), Some("application/json"));

    let body: serde_json::Value = serde_json::from_slice(&sent.body).expect("body must be JSON");
    assert_eq!(body["model"], "claude-sonnet-5");
    assert_eq!(body["stream"], true);
}

#[tokio::test]
async fn stream_chat_surfaces_non_2xx_status_as_a_provider_error() {
    let transport = Arc::new(CassetteTransport {
        status: 401,
        headers: vec![],
        body: b"{\"error\":\"unauthorized\"}".to_vec(),
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "bad-key".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProvider::new();
    let result = provider.stream_chat(&sample_request(), &ctx).await;
    // Pinned to the exact variant, like every other status in
    // `stream_chat_classifies_error_statuses_by_disposition`: a bare
    // `is_err()` would still pass if 401 silently changed disposition from
    // fatal to retryable, which is the property that actually matters here.
    assert!(
        matches!(
            result,
            Err(ProviderError::BadRequest { status: 401, .. })
        ),
        "a 401 must surface as a fatal BadRequest, never be decoded as if it were a successful stream"
    );
}

/// A 3xx is not a success either. A `status >= 400` guard would let one
/// through and hand its (non-SSE) body to the decoder, which skips every
/// unparseable frame — so the caller would see a silently *empty* successful
/// stream instead of an error. The guard is therefore "is it 2xx", not "is it
/// below 400".
#[tokio::test]
async fn stream_chat_rejects_a_3xx_rather_than_decoding_an_empty_stream() {
    let transport = Arc::new(CassetteTransport {
        status: 302,
        headers: vec![("location".into(), "https://elsewhere.invalid/".into())],
        body: b"<html>moved</html>".to_vec(),
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };

    let provider = AnthropicMessagesProvider::new();
    let result = provider.stream_chat(&sample_request(), &ctx).await;
    assert!(matches!(result, Err(ProviderError::Transport(_))));
}

/// §9.8's third classification layer ("HTTP status default") is the only one
/// implementable here — the provider-error-code and message-regex layers need
/// the profile tables that land in Phase 2. This pins the status→disposition
/// mapping so a retryable outage is never reported as a fatal error (or the
/// reverse).
#[tokio::test]
async fn stream_chat_classifies_error_statuses_by_disposition() {
    async fn error_for(status: u16) -> ProviderError {
        let transport = Arc::new(CassetteTransport {
            status,
            headers: vec![],
            body: b"{\"error\":{\"type\":\"whatever\"}}".to_vec(),
            chunk_size: 0,
        });
        let ctx = RequestCtx {
            trace_id: None,
            transport,
            api_key: "test-key".into(),
            credentials: None,
        };
        expect_err(
            AnthropicMessagesProvider::new()
                .stream_chat(&sample_request(), &ctx)
                .await,
        )
    }

    assert!(matches!(
        error_for(400).await,
        ProviderError::BadRequest { status: 400, .. }
    ));
    assert!(matches!(error_for(404).await, ProviderError::ModelNotFound));
    assert!(matches!(
        error_for(429).await,
        ProviderError::RateLimited { .. }
    ));
    assert!(matches!(
        error_for(500).await,
        ProviderError::Server { status: 500 }
    ));
    // Anthropic's documented "overloaded_error" carries HTTP 529, which is
    // retryable capacity pressure rather than a generic 5xx.
    assert!(matches!(error_for(529).await, ProviderError::Overloaded));
}

/// The API key reaches exactly one place — the `x-api-key` header — and never
/// the error text. §9.9's redaction pass (which scrubs key-shaped strings out
/// of persisted error bodies, because providers echo request bodies in 400s)
/// is Phase 2 work and does not exist yet, so this adapter must not put
/// anything key-adjacent into a `ProviderError` in the first place.
#[tokio::test]
async fn errors_never_contain_the_api_key_or_the_response_body() {
    const KEY: &str = "sk-ant-super-secret-value";
    let transport = Arc::new(CassetteTransport {
        status: 400,
        headers: vec![],
        // A provider echoing the request back, key and all — the exact case
        // §9.9 warns about.
        body: format!("{{\"error\":\"bad request\",\"echoed_key\":\"{KEY}\"}}").into_bytes(),
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: KEY.into(),
        credentials: None,
    };

    let err = expect_err(
        AnthropicMessagesProvider::new()
            .stream_chat(&sample_request(), &ctx)
            .await,
    );

    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains(KEY),
        "the API key leaked into a ProviderError: {rendered}"
    );
    assert!(
        !rendered.contains("echoed_key"),
        "an unredacted response body leaked into a ProviderError: {rendered}"
    );
}

/// A transport that always fails, so the adapter's *other* error path — the one
/// that wraps a `TransportError` rather than classifying a status — can be
/// exercised.
struct FailingTransport;

impl HttpTransport for FailingTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async {
            Err(TransportError::Io(
                "connection reset by peer while sending request".into(),
            ))
        })
    }
}

/// The status-classification path is not the only way out of `stream_chat`; a
/// transport failure produces `ProviderError::Transport(..)` from a
/// `TransportError`'s `Display`. That wrapping must not become a leak either.
///
/// The complementary half of this — that `reqwest` itself never puts request
/// headers into the `TransportError` in the first place — is pinned against the
/// real client in `tests/reqwest_transport.rs`
/// (`transport_errors_never_echo_the_request_headers`).
#[tokio::test]
async fn a_transport_failure_is_a_transport_error_that_omits_the_api_key() {
    const KEY: &str = "sk-ant-super-secret-value";
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(FailingTransport),
        api_key: KEY.into(),
        credentials: None,
    };

    let err = expect_err(
        AnthropicMessagesProvider::new()
            .stream_chat(&sample_request(), &ctx)
            .await,
    );

    assert!(matches!(err, ProviderError::Transport(_)));
    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains(KEY),
        "the API key leaked into a transport ProviderError: {rendered}"
    );
}

/// `count_tokens` needs a second endpoint this task does not build; it must say
/// so rather than silently returning a wrong (zero) count that a caller would
/// use for budgeting.
#[tokio::test]
async fn count_tokens_is_unsupported_rather_than_silently_wrong() {
    let transport = Arc::new(CassetteTransport {
        status: 200,
        headers: vec![],
        body: vec![],
        chunk_size: 0,
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };

    let result = AnthropicMessagesProvider::new()
        .count_tokens(&sample_request(), &ctx)
        .await;
    assert!(matches!(result, Err(ProviderError::Unsupported(_))));
}
