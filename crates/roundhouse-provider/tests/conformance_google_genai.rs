//! `roundhouse-conformance` wiring for the `google-genai` codec (§9.10), run
//! against `EndpointMode::Interactions` -- Gemini's default surface per §9.2,
//! per the task brief's own instruction. See
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md` for the
//! spec-verification record this codec (and the cassettes below) are built
//! against; every cassette's SSE event shapes are drawn from that fetched
//! spec's real schemas, not hand-invented to match the decoder.

use roundhouse_conformance::{checks, run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
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

/// Loads a sibling profile by name -- used by the empty-`api_key` guard
/// tests below to exercise the `AuthKind::Bearer` arm (`vertex-gemini.toml`)
/// as well as this file's default `HeaderKey` profile.
fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
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

/// Task 12 (Cross-Cutting #2, Ruling R16): mandatory truncate-mid-stream
/// check -- this codec is in the "absence" truncation-signaling group
/// (`decode_guard.rs`'s module doc): it returns `Ok` without a `MessageStop`
/// when truncated before its real `interaction.completed` terminal, which
/// the check must accept (only a FABRICATED `MessageStop` fails it).
#[tokio::test]
async fn text_cassette_is_never_indistinguishable_from_a_clean_completion_when_truncated() {
    let failures = checks::check_truncate_mid_stream(
        &GoogleGenAiSubject::provider(),
        &fixtures::single_turn_text(),
        &cassette_path("text.cassette"),
        GoogleGenAiSubject::credentials(),
    )
    .await;
    assert!(
        failures.is_empty(),
        "google-genai must never report a clean completion for a stream truncated before its \
         real terminal: {failures:#?}"
    );
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

/// Fix-round-1 F3: exercised under BOTH endpoint modes, not just
/// Interactions -- the original version only proved the Interactions
/// fail-closed path was wired; the legacy `GenerateContent` path shares the
/// same `encode(...)?` propagation but had never actually been driven
/// through `stream_chat` at all before this fix round.
#[tokio::test]
async fn stream_chat_rejects_image_content_before_any_transport_call() {
    use roundhouse_provider::{ContentBlock, MediaSource, Message};
    for mode in [EndpointMode::Interactions, EndpointMode::GenerateContent] {
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
        let provider = GoogleGenAiProvider::new(fixture_profile(), mode);
        let err = expect_err(provider.stream_chat(&req, &ctx).await);
        assert!(
            matches!(err, ProviderError::Unsupported(_)),
            "expected Unsupported under {mode:?}, got {err:?}"
        );
    }
}

// ============================================================================
// Fix-round-1 F3: `EndpointMode::GenerateContent` integration coverage
//
// Before this fix round, `GoogleGenAiProvider::new(profile,
// EndpointMode::GenerateContent)` was never constructed in any test --
// its `stream_chat` URL building, auth attachment, and error classification
// (including the `/error/status` remap branch) had never run once, even
// against a synthetic cassette. Both reviewers independently concluded that
// well-formed synthetic unit-test frames can only confirm the decoder agrees
// with itself; F2's defect (an unconditional `MessageStop`) is the proof a
// cassette driven through the real `Provider::stream_chat` would have caught
// mechanically. These two tests are the minimum F3 asks for: one success
// cassette, one error cassette, both replayed through the real provider.
// Interactions correctly stays the canonical, fully-conformance-tested
// surface; a full second `ConformanceSubject` for this mode was judged not
// required.
//
// Per REALITY-CORRECTIONS §13b item 3 (state where cassette bytes came
// from): both cassettes below are hand-authored, not recorded against a live
// API. `generate_content_text.cassette`'s shape (two `data:` frames, each a
// partial `GenerateContentResponse` with no `event_type` discriminator, the
// second carrying `finishReason: "STOP"` and `usageMetadata`) is built from
// the verified schemas in `generate-content.md.txt`'s literal JSON-
// representation blocks (`Content`/`Part`/`Candidate`/`FinishReason`/
// `UsageMetadata`), not copied from a live response. Likewise the four
// Interactions-mode cassettes committed earlier in this task
// (`text`/`tools`/`parallel_tools`/`reasoning`) are hand-authored from
// `interactions.openapi.json`'s verified `event_type`/`step.type`/
// `delta.type` `const` values and the vendored tripwire lists, not recorded.
// `generate_content_error_429.cassette`'s body is the long-standing,
// corroborated-but-not-directly-fetched `google.rpc.Status` shape (see the
// decision doc) -- chosen specifically to exercise
// `remap_error_body_for_classify`'s `/error/status` fallback branch, since
// `/error/code` here is a JSON number, not a string.
// ============================================================================

#[tokio::test]
async fn generate_content_mode_text_cassette_decodes_via_real_stream_chat() {
    let transport = CassetteTransport::from_file(
        &cassette_path("generate_content_text.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("generate_content_text.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::GenerateContent);
    let stream = provider
        .stream_chat(&fixtures::single_turn_text(), &ctx)
        .await
        .expect("must decode successfully via the real stream_chat pipeline");
    let folded = roundhouse_conformance::checks::fold_stream(stream).await;

    let text: String = folded
        .blocks
        .iter()
        .filter_map(|b| match b {
            roundhouse_provider::ContentBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "4.");
    assert_eq!(folded.usage.input_tokens, 9);
    assert_eq!(folded.usage.output_tokens, 3);
    assert!(
        folded.loss_events.is_empty(),
        "no block should be left unterminated: {:?}",
        folded.loss_events
    );
}

/// Also proves URL construction and header attachment for this mode
/// actually work end to end (`build_endpoint_url`'s `:streamGenerateContent`
/// + `?alt=sse` path, `x-goog-api-key` header via the `AuthKind::HeaderKey`
/// fallback) -- `CassetteTransport` ignores the request it's given, but a
/// panic anywhere in `stream_chat` before `transport.send` (URL building,
/// serialization, auth) would still fail this test.
#[tokio::test]
async fn generate_content_mode_error_429_cassette_classifies_via_the_status_remap_branch() {
    let transport = CassetteTransport::from_file(
        &cassette_path("generate_content_error_429.cassette"),
        ChunkStrategy::WholeBody,
    )
    .expect("generate_content_error_429.cassette must parse");
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(transport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::GenerateContent);
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    // `RESOURCE_EXHAUSTED` is not a key in this profile's `[errors]` table
    // (that table targets the Interactions API's snake_case vocabulary,
    // deliberately -- see the decision doc's Divergence 4), so this falls
    // through to `classify`'s HTTP-status default tier for a bare 429. The
    // point of this test is not the specific `ProviderError` variant it
    // lands on -- it's that `remap_error_body_for_classify`'s `/error/status`
    // branch (the "corroborated but not directly fetched" shape) is
    // exercised for real, through the actual `stream_chat` pipeline, and
    // does not panic or misparse a numeric `/error/code`.
    assert!(
        matches!(err, ProviderError::RateLimited { .. }),
        "expected RateLimited via the HTTP-status default tier, got {err:?}"
    );
}

/// Fix round 4, Fix 1: an empty `api_key` with no `CredentialProvider` must
/// fail closed BEFORE any transport call for the `AuthKind::HeaderKey` arm
/// (this profile's `x-goog-api-key`), not silently send a header-shaped-
/// but-credential-less `x-goog-api-key: ` that only earns a remote 401.
/// Uses a transport that panics on `send` -- if this failed to fail closed,
/// it would panic there instead of returning the expected
/// `ProviderError::Unsupported`.
#[tokio::test]
async fn empty_api_key_with_no_credential_provider_fails_closed_header_key() {
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: String::new(),
        credentials: None,
    };
    let provider = GoogleGenAiProvider::new(fixture_profile(), EndpointMode::Interactions);
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

/// Same guarantee as above, for the `AuthKind::Bearer` arm -- `vertex-gemini`
/// is the codec's one Bearer profile (`vertex-gemini.toml`'s
/// `auth = { kind = "bearer" }`).
#[tokio::test]
async fn empty_api_key_with_no_credential_provider_fails_closed_bearer() {
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(PanicsIfCalledTransport),
        api_key: String::new(),
        credentials: None,
    };
    let provider = GoogleGenAiProvider::new(load("vertex-gemini"), EndpointMode::GenerateContent);
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
