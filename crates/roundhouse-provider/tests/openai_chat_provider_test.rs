//! Direct `OpenAiChatProvider` mechanics not exercised by
//! `conformance_openai_chat_batch_a.rs`'s generic harness: the fail-closed
//! content guard actually runs before any transport call, the bare
//! `api_key` Bearer fallback actually attaches an `authorization` header,
//! an empty/whitespace `api_key` with no `CredentialProvider` fails closed,
//! and a profile's `[errors]` table actually reaches `classify()` through
//! `ProviderProfile::error_profile()`. Task 10 is the "hinge" every later
//! `openai-chat` profile task reuses unchanged, so these mechanics need
//! their own direct coverage, not just the mask/round-trip/usage checks the
//! shared conformance harness runs.

use roundhouse_provider::codec::openai_chat::OpenAiChatProvider;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    CassetteTransport, ChatStream, ChunkStrategy, ContentBlock, HttpRequest, HttpResponseStream,
    HttpTransport, MediaSource, Message, Provider, ProviderError, RequestCtx, Role, TransportError,
};
use std::sync::Arc;

#[path = "support/openai_chat_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path(id: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes")
        .join(id)
        .join("text.cassette")
}

/// `Result::expect_err` needs `T: Debug`, and `ChatStream` deliberately
/// isn't -- matches `conformance_cohere_v2.rs`'s identical helper.
fn expect_err(result: Result<ChatStream, ProviderError>) -> ProviderError {
    match result {
        Ok(_) => panic!("expected an error, got a successful stream"),
        Err(err) => err,
    }
}

/// A transport that panics if `send` is ever called -- proves a request is
/// rejected before any network I/O is attempted.
struct PanicsIfCalledTransport;

impl HttpTransport for PanicsIfCalledTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        panic!(
            "stream_chat must reject an Image/Document/Thinking/Opaque request before ever \
             calling HttpTransport::send"
        )
    }
}

#[tokio::test]
async fn stream_chat_rejects_image_content_before_any_transport_call() {
    let mut req = fixtures::single_turn_text("openrouter");
    req.messages.push(Message {
        role: Role::User,
        content: vec![ContentBlock::Image {
            source: MediaSource {
                mime_type: "image/png".into(),
                data: vec![0, 1, 2, 3],
            },
            cache: None,
        }],
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    let err = expect_err(provider.stream_chat(&req, &ctx).await);
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

/// An empty `api_key` with no `CredentialProvider` must fail closed BEFORE
/// any transport call, not silently send a header-shaped-but-credential-
/// less `authorization: Bearer ` request. Uses a transport that panics on
/// `send` -- if this test failed to fail closed, it would panic there
/// instead of via the expected `ProviderError::Unsupported`.
#[tokio::test]
async fn an_empty_api_key_with_no_credential_provider_fails_closed() {
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: String::new(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text("openrouter"), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

/// A whitespace-only `api_key` must be treated the same as empty -- `.is_empty()`
/// alone would let `"   "` slip past and still send a credential-less
/// `authorization: Bearer    ` header that only earns a remote 401.
#[tokio::test]
async fn a_whitespace_only_api_key_with_no_credential_provider_fails_closed() {
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: "   ".to_string(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text("openrouter"), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

/// Proves the Bearer auth fallback path (`AuthKind::Bearer`, every batch-A
/// profile's declared auth kind) actually attaches an `authorization:
/// Bearer <key>` header, by driving a real success cassette all the way
/// through `stream_chat` with no `CredentialProvider` supplied
/// (`ctx.credentials: None`).
struct RecordingTransport {
    inner: CassetteTransport,
    captured_headers: std::sync::Mutex<Vec<(String, String)>>,
}

impl HttpTransport for RecordingTransport {
    fn send<'a>(
        &'a self,
        req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        *self.captured_headers.lock().unwrap() = req.headers.clone();
        self.inner.send(req)
    }
}

#[tokio::test]
async fn bare_api_key_fallback_attaches_a_bearer_authorization_header() {
    let cassette =
        CassetteTransport::from_file(&cassette_path("openrouter"), ChunkStrategy::WholeBody)
            .expect("text.cassette must parse");
    let transport = Arc::new(RecordingTransport {
        inner: cassette,
        captured_headers: std::sync::Mutex::new(Vec::new()),
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport: transport.clone(),
        api_key: "sk-test-12345".into(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    provider
        .stream_chat(&fixtures::single_turn_text("openrouter"), &ctx)
        .await
        .expect("must succeed against the text cassette");

    let headers = transport.captured_headers.lock().unwrap();
    let auth = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    assert_eq!(auth, Some("Bearer sk-test-12345"));
}

/// A fixed-status, fixed-body transport, standing in for a real HTTP error
/// response -- proves `ProviderProfile::error_profile()`'s `[errors]` table
/// actually reaches `crate::errors::classify` through this provider (§14g).
struct FixedResponseTransport {
    status: u16,
    body: Vec<u8>,
}

impl HttpTransport for FixedResponseTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        let status = self.status;
        let body = self.body.clone();
        Box::pin(async move {
            Ok(HttpResponseStream {
                status,
                headers: vec![],
                body: Box::pin(futures::stream::once(async move {
                    Ok(bytes::Bytes::from(body))
                })),
            })
        })
    }
}

/// `openrouter.toml`'s `[errors]` table declares `insufficient_credits` as
/// `disposition = "fatal", category = "quota"`, which
/// `ProviderProfile::error_profile()` maps onto `ProviderErrorKind::QuotaExhausted`
/// (§14g). `classify` looks this code up at the real OpenAI-family error
/// shape's `/error/type` JSON pointer.
#[tokio::test]
async fn openrouter_insufficient_credits_error_classifies_as_quota_exhausted() {
    let body =
        br#"{"error":{"type":"insufficient_credits","message":"you are out of credits"}}"#.to_vec();
    let transport = Arc::new(FixedResponseTransport { status: 402, body });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text("openrouter"), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {err:?}"
    );
}

/// A plain 500 with no recognizable `[errors]`-table code falls through
/// `classify`'s HTTP-status default tier.
#[tokio::test]
async fn a_bare_500_with_no_matching_error_code_classifies_as_server_error() {
    let transport = Arc::new(FixedResponseTransport {
        status: 500,
        body: b"internal server error".to_vec(),
    });
    let ctx = RequestCtx {
        trace_id: None,
        transport,
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = OpenAiChatProvider::new(load("openrouter"));
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text("openrouter"), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::Server { status: 500 }),
        "expected Server{{500}}, got {err:?}"
    );
}
