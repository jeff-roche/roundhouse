//! `roundhouse-conformance` wiring for the `google-genai` codec (§9.10), run
//! against `EndpointMode::Interactions` -- Gemini's default surface per §9.2,
//! per the task brief's own instruction. See
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md` for the
//! spec-verification record this codec (and the cassettes below) are built
//! against; every cassette's SSE event shapes are drawn from that fetched
//! spec's real schemas, not hand-invented to match the decoder.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::google_genai::encode::encode;
use roundhouse_provider::codec::google_genai::{EndpointMode, GoogleGenAiProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    CassetteTransport, ChatRequest, ChunkStrategy, HttpRequest, HttpResponseStream, HttpTransport,
    Provider, ProviderError, RequestCtx, TransportError,
};
use std::sync::Arc;

#[path = "support/google_genai_fixtures.rs"]
mod fixtures;

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/google-genai.toml")).unwrap()
}

fn cassette_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes/google_genai")
        .join(name)
}

/// The union of every flattened field path this codec's `encode` can put on
/// the wire (`EndpointMode::Interactions`) for the four success-path fixture
/// requests below, derived from `google-genai.toml`'s own `ParamsPolicy` per
/// REALITY-CORRECTIONS §12c -- `mode = "deny_list", fields = []` permits
/// every one of these (empirically enumerated via a throwaway probe against
/// each fixture's real encoded body, not guessed; the probe's `tools.
/// parameters.description` entry was a real snapshot bug this same run
/// caught -- a stray `///` doc comment on the fixture's `NoParams` struct --
/// fixed in `support/google_genai_fixtures.rs` rather than added to this
/// mask).
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let all_known: &[&str] = &[
        "model",
        "input",
        "stream",
        "input.type",
        "input.content",
        "input.content.type",
        "input.content.text",
        "tools",
        "tools.type",
        "tools.name",
        "tools.description",
        "tools.parameters",
        "tools.parameters.$schema",
        "tools.parameters.title",
        "tools.parameters.type",
        "generation_config",
        "generation_config.tool_choice",
        "generation_config.tool_choice.allowed_tools",
        "generation_config.tool_choice.allowed_tools.mode",
        "generation_config.tool_choice.allowed_tools.tools",
        "generation_config.thinking_level",
    ];
    SerializeOnlyMask {
        mandatory: vec!["model".into(), "input".into(), "stream".into()],
        allowed: profile.defaults.params.allowed_fields(all_known),
    }
}

struct GoogleGenAiSubject;

impl ConformanceSubject for GoogleGenAiSubject {
    type Provider = GoogleGenAiProvider;

    fn provider() -> Self::Provider {
        GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions)
    }

    fn cases() -> Vec<ConformanceCase> {
        let mask = mask(&fixture_profile());
        // `tools`/`parallel_tools`: the request's user-turn `Text` prompt is
        // never expected to survive into a ToolUse-only response -- declared,
        // not an undeclared drop (same pattern `openai_responses` established).
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
                mask,
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::Server { status: 500 })),
            },
        ]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &fixture_profile(), EndpointMode::Interactions)
            .expect("encode must succeed for this fixture profile")
    }
}

#[tokio::test]
async fn google_genai_is_conformant() {
    run::<GoogleGenAiSubject>().await.assert_green();
}

/// `Result::expect_err` needs `T: Debug`, and `ChatStream` deliberately
/// isn't -- matches `anthropic_provider_cassette.rs`'s/`openai_responses`'
/// existing precedent.
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
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::RateLimited { .. }),
        "expected RateLimited (google-genai.toml declares rate_limit_exceeded as \
         shed_concurrency), got {err:?}"
    );
}

/// §9.8: "never `?` on JSON parsing in the error path" -- a raw HTML 500 must
/// classify via the HTTP-status fallback tier, not panic on JSON decode.
#[tokio::test]
async fn error_500_cassette_classifies_as_server_error_without_panicking_on_an_html_body() {
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
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
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

/// `classify` (shared infra, `errors.rs`) hardcodes reading `/error/type` --
/// these tests exercise `classify` directly, so they build the body in the
/// shape it actually expects, matching `profile_errors_wiring_test.rs`'s
/// established `body_with_error_type` precedent. This is deliberately NOT
/// the real wire shape (`/error/code`, verified -- see the decision doc's
/// Divergence 4); `provider.rs`'s `remap_error_body_for_classify` is what
/// bridges the two on the real `stream_chat` path, covered separately by
/// `error_429_cassette_classifies_as_rate_limited` above (a real cassette
/// carrying the real `/error/code` shape, replayed through the full
/// `stream_chat` pipeline).
fn error_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": { "type": code, "message": "synthetic test body" }
    }))
    .unwrap()
}

/// These three tests prove `google-genai.toml`'s own `[errors]` table is
/// actually consulted (REALITY-CORRECTIONS §14g), deliberately at a status
/// (400) that carries none of these codes in `classify`'s own HTTP-status
/// fallback tier -- same isolating technique `profile_errors_wiring_test.rs`
/// and `conformance_openai_responses.rs` already established.
#[test]
fn google_genai_error_table_rate_limit_exceeded_maps_to_rate_limited() {
    let error_profile = fixture_profile().error_profile();
    let classified = roundhouse_provider::errors::classify(
        &error_profile,
        400,
        &error_body("rate_limit_exceeded"),
        &http::HeaderMap::new(),
    );
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}

#[test]
fn google_genai_error_table_service_unavailable_maps_to_overloaded() {
    let error_profile = fixture_profile().error_profile();
    let classified = roundhouse_provider::errors::classify(
        &error_profile,
        400,
        &error_body("service_unavailable"),
        &http::HeaderMap::new(),
    );
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn google_genai_error_table_quota_exceeded_maps_to_quota_exhausted() {
    let error_profile = fixture_profile().error_profile();
    let classified = roundhouse_provider::errors::classify(
        &error_profile,
        400,
        &error_body("quota_exceeded"),
        &http::HeaderMap::new(),
    );
    assert!(
        matches!(classified, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {classified:?}"
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
            "stream_chat must reject an Image/Document request before ever calling \
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
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
    let err = expect_err(provider.stream_chat(&req, &ctx).await);
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}
