//! `roundhouse-conformance` wiring for the `cohere-v2` codec (§9.10).
//!
//! Cassette provenance (REALITY-CORRECTIONS §13b item 3): every cassette
//! under `testdata/cassettes/cohere_v2/` is hand-authored, not recorded
//! against a live API (this task has no network credential to record one
//! against) -- but every event shape in them is copied from the REAL,
//! VERBATIM example JSON in the fetched Cohere API reference
//! (`https://docs.cohere.com/reference/chat-stream`, fetched 2026-09-02), not
//! invented to match this decoder. `text.cassette`'s `message-start`/
//! `content-start`/`content-delta` frames are near-verbatim copies of that
//! page's own literal examples (down to the `id` UUID shape); `tools.cassette`'s
//! `tool-call-start`/`tool-call-delta` frames copy that page's own
//! `query_daily_sales_report` example's exact JSON shape (with different
//! field values); `error_429`/`error_500`'s bodies use the plain
//! `{"message": "..."}` shape documented at
//! `https://docs.cohere.com/reference/errors` (fetched 2026-09-02), including
//! that page's own verbatim 429 example message text. See
//! `src/codec/cohere_v2/mod.rs`'s module doc comment for the full fetch
//! record. Every SSE cassette ends with a trailing blank line (verified by
//! `every_sse_cassette_has_a_terminator_test.rs`, which walks this whole
//! tree) -- REALITY-CORRECTIONS §13b item 6.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::cohere_v2::encode::encode;
use roundhouse_provider::codec::cohere_v2::CohereV2Provider;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    CassetteTransport, ChatRequest, ChunkStrategy, HttpRequest, HttpResponseStream, HttpTransport,
    Provider, ProviderError, RequestCtx, TransportError,
};
use std::sync::Arc;

#[path = "support/cohere_v2_fixtures.rs"]
mod fixtures;

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/cohere-v2.toml")).unwrap()
}

fn cassette_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes/cohere_v2")
        .join(name)
}

/// Maps one of `cohere-v2.toml`'s own declared `[defaults.params]` field
/// identifiers onto the actual wire-key path this codec's `encode` emits for
/// it (REALITY-CORRECTIONS §12c: the mask must be derived from the profile's
/// own policy). Cohere's wire field names match the profile's declared
/// identifiers 1:1 (unlike `bedrock-converse`'s camelCase translation), with
/// one exception: `k` (top-`k` sampling) has no corresponding field on this
/// crate's IR `Params` at all, so it is a permitted-but-never-emitted mask
/// entry.
fn params_wire_path(field: &str) -> &'static str {
    match field {
        "temperature" => "temperature",
        "p" => "p",
        "k" => "k",
        "max_tokens" => "max_tokens",
        "stop_sequences" => "stop_sequences",
        other => panic!(
            "cohere-v2.toml declares params field {other:?}, which this test's \
             wire-path translation table doesn't know about -- add it here"
        ),
    }
}

/// The union of every flattened field path this codec's `encode` can put on
/// the wire for the four success-path fixture requests below, plus the
/// profile's own declared params fields (REALITY-CORRECTIONS §12c).
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let mut allowed: Vec<String> = vec![
        "messages".into(),
        "messages.role".into(),
        "messages.content".into(),
        "messages.tool_calls".into(),
        "messages.tool_calls.id".into(),
        "messages.tool_calls.type".into(),
        "messages.tool_calls.function".into(),
        "messages.tool_calls.function.name".into(),
        "messages.tool_calls.function.arguments".into(),
        "messages.tool_call_id".into(),
        "stream".into(),
        "tools".into(),
        "tools.type".into(),
        "tools.function".into(),
        "tools.function.name".into(),
        "tools.function.description".into(),
        "tools.function.parameters".into(),
        "tools.function.parameters.$schema".into(),
        "tools.function.parameters.title".into(),
        "tools.function.parameters.type".into(),
        "tool_choice".into(),
        "thinking".into(),
        "thinking.type".into(),
    ];
    for field in &profile.defaults.params.fields {
        allowed.push(params_wire_path(field).to_string());
    }
    SerializeOnlyMask {
        mandatory: vec!["model".into(), "messages".into(), "stream".into()],
        allowed,
    }
}

struct CohereV2Subject;

impl ConformanceSubject for CohereV2Subject {
    type Provider = CohereV2Provider;

    fn provider() -> Self::Provider {
        CohereV2Provider::new(fixture_profile())
    }

    fn cases() -> Vec<ConformanceCase> {
        let mask = mask(&fixture_profile());
        // `tools`/`parallel_tools`: the request's user-turn `Text` prompt is
        // never expected to survive into a ToolUse-only response -- declared,
        // not an undeclared drop (matches `google_genai`/`bedrock_converse`'s
        // identical pattern).
        let text_not_expected_in_a_tool_call_response = vec![
            "the request's Text prompt does not appear in a ToolUse-only response".to_string(),
        ];
        vec![
            ConformanceCase {
                name: "text",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("text.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: None,
            },
            ConformanceCase {
                name: "tools",
                request: fixtures::forced_tool_choice(),
                cassette_path: cassette_path("tools.cassette"),
                mask: mask.clone(),
                declared_loss_events: text_not_expected_in_a_tool_call_response.clone(),
                expected_error: None,
            },
            ConformanceCase {
                name: "parallel_tools",
                request: fixtures::parallel_tool_calls(),
                cassette_path: cassette_path("parallel_tools.cassette"),
                mask: mask.clone(),
                declared_loss_events: text_not_expected_in_a_tool_call_response,
                expected_error: None,
            },
            ConformanceCase {
                name: "reasoning",
                request: fixtures::reasoning_on(),
                cassette_path: cassette_path("reasoning.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: None,
            },
            ConformanceCase {
                name: "error_429",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("error_429.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::RateLimited { .. })),
            },
            ConformanceCase {
                name: "error_500",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("error_500.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::Server { status: 500 })),
            },
            // Fix round 1, L2: there was no conformance case at all covering
            // an IN-BAND failure (a 200 response whose stream carries a
            // failing `finish_reason`) -- which is exactly why the original
            // `classify`-at-200 defect (everything landing in
            // `BadRequest { status: 200, .. }`) went unnoticed. This drives
            // `finish_reason: "ERROR"` through the real `stream_chat`
            // pipeline, at all four chunk strategies.
            ConformanceCase {
                name: "mid_stream_error",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("mid_stream_error.cassette"),
                mask,
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::Server { status: 500 })),
            },
        ]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &fixture_profile()).expect("encode must succeed for this fixture profile")
    }
}

#[tokio::test]
async fn cohere_v2_is_conformant() {
    run::<CohereV2Subject>().await.assert_green();
}

/// `Result::expect_err` needs `T: Debug`, and `ChatStream` deliberately
/// isn't -- matches `conformance_google_genai.rs`'s identical helper.
fn expect_err(result: Result<roundhouse_provider::ChatStream, ProviderError>) -> ProviderError {
    match result {
        Ok(_) => panic!("expected an error, got a successful stream"),
        Err(err) => err,
    }
}

#[tokio::test]
async fn error_429_cassette_classifies_as_rate_limited() {
    let transport = CassetteTransport::from_file(
        &cassette_path("error_429.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("error_429.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::RateLimited { .. }),
        "expected RateLimited via classify's HTTP-status fallback tier (Cohere's real \
         error body carries no machine-readable code field -- see cohere-v2.toml's doc \
         comment), got {err:?}"
    );
}

/// §9.8: "never `?` on JSON parsing in the error path" -- also proves URL
/// construction, header attachment, and the Bearer auth fallback all work
/// end to end before this ever reaches classification.
#[tokio::test]
async fn error_500_cassette_classifies_as_server_error() {
    let transport = CassetteTransport::from_file(
        &cassette_path("error_500.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("error_500.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::Server { status: 500 }),
        "expected Server{{500}}, got {err:?}"
    );
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
            "stream_chat must reject an Image/Document/Opaque request before ever calling \
             HttpTransport::send"
        )
    }
}

#[tokio::test]
async fn stream_chat_rejects_image_content_before_any_transport_call() {
    use roundhouse_provider::{ContentBlock, MediaSource, Message};
    let req = ChatRequest {
        messages: vec![Message {
            role: roundhouse_provider::Role::User,
            content: vec![
                ContentBlock::Text {
                    text: "What's in this image?".into(),
                    cache: None,
                    citations: vec![],
                },
                ContentBlock::Image {
                    source: MediaSource {
                        mime_type: "image/png".into(),
                        data: vec![0, 1, 2, 3],
                    },
                    cache: None,
                },
            ],
        }],
        ..fixtures::single_turn_text()
    };
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(provider.stream_chat(&req, &ctx).await);
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

/// Proves the Bearer auth fallback path (`AuthKind::Bearer`,
/// `cohere-v2.toml`'s declared auth kind) actually attaches an
/// `authorization: Bearer <key>` header, by driving a real success cassette
/// all the way through `stream_chat` with no `CredentialProvider` supplied
/// (`ctx.credentials: None`) -- `error_429_cassette_classifies_as_rate_limited`
/// and `cohere_v2_is_conformant` above already exercise this same fallback
/// path implicitly, but this test asserts on the header directly via a
/// recording transport.
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
        CassetteTransport::from_file(&cassette_path("text.cassette"), ChunkStrategy::WholeBody)
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
    let provider = CohereV2Provider::new(fixture_profile());
    provider
        .stream_chat(&fixtures::single_turn_text(), &ctx)
        .await
        .expect("must succeed against the text cassette");

    let headers = transport.captured_headers.lock().unwrap();
    let auth = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.as_str());
    assert_eq!(auth, Some("Bearer sk-test-12345"));
}

/// Fix round 1, L7: an empty `api_key` with no `CredentialProvider` must
/// fail closed BEFORE any transport call, not silently send a header-shaped-
/// but-credential-less `authorization: Bearer ` request. Uses a transport
/// that panics on `send` -- if this test failed to fail closed, it would
/// panic there instead of via the expected `ProviderError::Unsupported`.
#[tokio::test]
async fn an_empty_api_key_with_no_credential_provider_fails_closed() {
    struct PanicsOnSend;

    impl roundhouse_provider::HttpTransport for PanicsOnSend {
        fn send<'a>(
            &'a self,
            _req: roundhouse_provider::HttpRequest,
        ) -> roundhouse_provider::BoxFut<
            'a,
            Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
        > {
            panic!("must fail closed on an empty api_key before ever calling send()")
        }
    }

    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsOnSend),
        api_key: String::new(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}

/// Fix round 1, L1: a clean EOF with no `message-end` ever observed --
/// `truncated.cassette` ends after a single `content-delta`, mid-block, with
/// no `content-end`/`message-end` at all -- must map to
/// `ProviderError::StreamInterrupted`, carrying the partial text that WAS
/// decoded, driven through the real `stream_chat` pipeline (not just the
/// decode-layer unit test). Before this fix round, the same cassette would
/// have decoded as `Ok(ChatStream)` with no terminal `MessageStop` at all --
/// silently indistinguishable from a real completion to any caller that
/// doesn't itself check for a trailing `MessageStop`.
#[tokio::test]
async fn a_truncated_cassette_maps_to_stream_interrupted_with_partial_text() {
    let transport = CassetteTransport::from_file(
        &cassette_path("truncated.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("truncated.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    match err {
        ProviderError::StreamInterrupted { partial } => {
            assert_eq!(partial, "The answer is cut off here");
        }
        other => panic!("expected StreamInterrupted, got {other:?}"),
    }
}

/// Fix round 1, L1/L2: `finish_reason: "MAX_TOKENS"` must map to
/// `StreamInterrupted` (real partial output, an agent-loop decision to
/// resume or not) rather than the generic-retry-loop-fatal
/// `BadRequest { status: 200, .. }` the original `classify`-at-200 defect
/// produced.
#[tokio::test]
async fn a_max_tokens_cassette_maps_to_stream_interrupted_with_partial_text() {
    let transport = CassetteTransport::from_file(
        &cassette_path("max_tokens.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("max_tokens.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = CohereV2Provider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    match err {
        ProviderError::StreamInterrupted { partial } => {
            assert_eq!(partial, "This response got cut off");
        }
        other => panic!("expected StreamInterrupted, got {other:?}"),
    }
}
