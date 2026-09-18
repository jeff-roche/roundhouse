//! Proves `AnthropicMessagesProvider`'s shape — that it calls Task 9's encoder
//! and Task 10's decoder around a real `HttpTransport` — using
//! `CassetteTransport` per §9.10's testing philosophy, never a live call. No
//! `ANTHROPIC_API_KEY`, no outbound connection.

use futures::channel::mpsc;
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use roundhouse_provider::{
    AnthropicMessagesProvider, BlockDelta, BlockKind, CassetteTransport, ChatRequest, HttpRequest,
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
    while let Some(item) = stream.next().await {
        let event = item.expect("this cassette decodes without a mid-stream error");
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

/// A transport that always fails with an error message shaped like a leaked
/// gateway API key -- the shape `reqwest`'s `Display` actually produces
/// (`" for url ({url})"`, userinfo and query string included), straight into
/// `TransportError::Io`. Distinct from `FailingTransport` above: that one's
/// message carries no URL at all, so it can't exercise the URL-reduction half
/// of `redact_transport_error_text`.
struct LeakyFailingTransport;

impl HttpTransport for LeakyFailingTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async {
            Err(TransportError::Io(
                "error sending request for url \
                 (https://gwuser:gwpass@gateway.example.invalid/v1/messages?key=gw-live-9f2b8c1d4e6a7b3c)"
                    .into(),
            ))
        })
    }
}

/// Fix round 6, J4: `base_url` is only ever set by `::new()` today (a fixed,
/// non-secret literal), so this sink (`anthropic_provider.rs`'s `send(..)`
/// error path) had no live exposure -- but the field is `pub`, and its own
/// doc comment says the §9.9 `ROUNDHOUSE_<PROVIDER>_BASE_URL` override "will
/// set this field", at which point a gateway URL carrying credentials would
/// flow straight into this error. Now routed through the same
/// `redact_transport_error_text` every other codec's transport-error sinks
/// use.
#[tokio::test]
async fn a_transport_failure_never_leaks_a_key_shaped_string_from_the_url() {
    const SECRET: &str = "gw-live-9f2b8c1d4e6a7b3c";
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(LeakyFailingTransport),
        api_key: "test-key".into(),
        credentials: None,
    };

    let err = expect_err(
        AnthropicMessagesProvider::new()
            .stream_chat(&sample_request(), &ctx)
            .await,
    );

    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains(SECRET),
        "the key-shaped string leaked into a ProviderError unredacted: {rendered}"
    );
    assert!(
        rendered.contains("gateway.example.invalid"),
        "the host itself is not secret and should stay, for diagnosability: {rendered}"
    );
    assert!(
        !rendered.contains("gwuser:gwpass"),
        "URL userinfo must not survive into a persisted error field: {rendered}"
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

/// Phase 8 T19b Task 3: `stream_chat`'s response body driven directly by a
/// `futures::channel::mpsc` sender the test holds onto, so a claim like
/// "resolves while the body is still open" is shown by controlling exactly
/// which bytes exist and whether the channel has been closed -- never by
/// sleeping and hoping. `anthropic_messages_decode.rs` proves the same
/// property one level down in
/// `block_start_arrives_while_the_body_is_still_open`, where the decoder is
/// driven off a raw `futures::channel::mpsc` receiver directly -- no
/// transport involved, so there is no helper there to share with this one.
struct ChannelTransport {
    status: u16,
    rx: Mutex<Option<mpsc::UnboundedReceiver<Result<bytes::Bytes, TransportError>>>>,
}

impl ChannelTransport {
    fn new(status: u16, rx: mpsc::UnboundedReceiver<Result<bytes::Bytes, TransportError>>) -> Self {
        Self {
            status,
            rx: Mutex::new(Some(rx)),
        }
    }
}

impl HttpTransport for ChannelTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async move {
            let rx = self
                .rx
                .lock()
                .unwrap()
                .take()
                .expect("ChannelTransport::send called more than once");
            Ok(HttpResponseStream {
                status: self.status,
                headers: vec![],
                body: rx.boxed(),
            })
        })
    }
}

fn channel_ctx(rx: mpsc::UnboundedReceiver<Result<bytes::Bytes, TransportError>>) -> RequestCtx {
    RequestCtx {
        trace_id: None,
        transport: Arc::new(ChannelTransport::new(200, rx)),
        api_key: "test-key".into(),
        credentials: None,
    }
}

/// Task 3's central claim: `stream_chat` must return `Ok(ChatStream)` the
/// moment the *first* decoded event exists, not only once the whole body has
/// arrived. Never closing `tx` and never sending `message_stop` here is the
/// point -- the pre-Task-3 buffered implementation awaited
/// `decode_anthropic_messages_stream`, which only ever completes once the
/// decode loop itself ends (a clean EOF or a mid-stream failure), so it
/// could never resolve under these exact conditions.
#[tokio::test]
async fn stream_chat_resolves_once_the_first_content_event_exists_while_the_body_is_still_open() {
    let (tx, rx) = mpsc::unbounded::<Result<bytes::Bytes, TransportError>>();
    // Queued before `stream_chat` is even called: an unbounded sender does
    // not require the receiver to be polled first.
    tx.unbounded_send(Ok(bytes::Bytes::from(
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
    )))
    .unwrap();

    let ctx = channel_ctx(rx);
    let result = AnthropicMessagesProvider::new()
        .stream_chat(&sample_request(), &ctx)
        .now_or_never()
        .expect(
            "the first content event already arrived -- stream_chat must not wait for the \
             body to close before resolving",
        );

    let mut stream = result.expect("a well-formed first frame must not be an error");
    assert!(
        !tx.is_closed(),
        "the channel must still be open: this proves stream_chat did not wait for EOF"
    );

    let first = stream
        .next()
        .now_or_never()
        .expect("the first event was already decoded before stream_chat returned")
        .expect("must not be end-of-stream")
        .expect("a well-formed content_block_start frame must decode without error");
    assert!(matches!(
        first,
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text
        }
    ));

    drop(tx);
}

/// A body that closes before any content event ever decoded must fail
/// `stream_chat` itself (an `Err`, so retry-before-the-first-token keeps
/// working) rather than returning `Ok` with an empty or immediately-failing
/// stream.
#[tokio::test]
async fn stream_chat_returns_err_when_the_body_closes_before_any_content_arrives() {
    let (tx, rx) = mpsc::unbounded::<Result<bytes::Bytes, TransportError>>();
    drop(tx); // closed immediately: no frames at all, not even message_start

    let ctx = channel_ctx(rx);
    let err = expect_err(
        AnthropicMessagesProvider::new()
            .stream_chat(&sample_request(), &ctx)
            .await,
    );
    match err {
        ProviderError::StreamInterrupted { partial } => assert_eq!(partial, ""),
        other => panic!("expected StreamInterrupted with no partial text, got {other}"),
    }
}

/// Controller ruling R22, at the provider boundary: a `signature_delta`
/// past the decoder's `MAX_THINKING_SIGNATURE_BYTES` ceiling is a wire-
/// protocol violation that fails the turn. With the violating frame first,
/// nothing is ever handed to the engine at all, so no unbounded, unredacted
/// `Delta::Thinking` row can reach the append-only `events` table.
#[tokio::test]
async fn stream_chat_fails_on_a_thinking_signature_past_the_decoders_ceiling() {
    let signature = "s"
        .repeat(roundhouse_provider::codec::anthropic_messages::MAX_THINKING_SIGNATURE_BYTES + 1);
    let (tx, rx) = mpsc::unbounded::<Result<bytes::Bytes, TransportError>>();
    tx.unbounded_send(Ok(bytes::Bytes::from(format!(
        "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\
         \"delta\":{{\"type\":\"signature_delta\",\"signature\":\"{signature}\"}}}}\n\n"
    ))))
    .unwrap();

    let ctx = channel_ctx(rx);
    let err = expect_err(
        AnthropicMessagesProvider::new()
            .stream_chat(&sample_request(), &ctx)
            .await,
    );
    match err {
        ProviderError::Transport(message) => assert!(
            !message.contains(&signature),
            "the error must report the length, never echo the signature: {message}"
        ),
        other => panic!("expected a Transport error for a wire-protocol violation, got {other}"),
    }

    drop(tx);
}

/// Once a first content event has already decoded, a later truncation must
/// surface as the *stream's own* terminal item, not as `stream_chat`'s
/// `Result` -- `stream_chat` already returned `Ok` by that point, and
/// `ChatStream`'s fallible item type (Task 1) exists precisely so a
/// mid-stream failure after the first token doesn't have to be silently
/// dropped.
#[tokio::test]
async fn a_body_that_closes_after_content_but_before_message_stop_ends_the_stream_in_an_error() {
    let (tx, rx) = mpsc::unbounded::<Result<bytes::Bytes, TransportError>>();
    tx.unbounded_send(Ok(bytes::Bytes::from(
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
    )))
    .unwrap();
    tx.unbounded_send(Ok(bytes::Bytes::from(
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"cut off\"}}\n\n",
    )))
    .unwrap();
    drop(tx); // closed before content_block_stop/message_stop ever arrive

    let ctx = channel_ctx(rx);
    let mut stream = AnthropicMessagesProvider::new()
        .stream_chat(&sample_request(), &ctx)
        .await
        .expect("the first content event arrived before the body closed, so this must be Ok");

    let mut items = Vec::new();
    while let Some(item) = stream.next().await {
        items.push(item);
    }

    let (last, rest) = items
        .split_last()
        .expect("must yield at least the BlockStart event before the terminal error");
    assert!(matches!(
        rest.first(),
        Some(Ok(StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Text
        }))
    ));
    match last {
        Err(ProviderError::StreamInterrupted { partial }) => assert_eq!(partial, "cut off"),
        other => panic!("expected the stream's last item to be StreamInterrupted, got {other:?}"),
    }
}
