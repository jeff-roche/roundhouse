//! `roundhouse-conformance` wiring for the `openai-responses` codec (§9.10).
//!
//! **Escalation, documented rather than worked around silently**: the
//! generic 4-`ChunkStrategy` `check_fold_determinism` path
//! (`roundhouse_conformance::checks`) calls `Provider::stream_chat` and
//! treats *any* `Err` result as a harness failure -- it has no way to express
//! "this cassette is supposed to produce an error." That fits every
//! *success*-path cassette (`text`/`tools`/`parallel_tools`/`reasoning`)
//! perfectly, but running `error_429`/`error_500` through
//! `ConformanceSubject::cases()` would make `assert_green()` fail for a
//! harness-shape reason unrelated to this codec's own correctness -- Task 3's
//! harness was built and self-tested only against success-path fixtures, and
//! this task is the first to need an error-status cassette at all.
//!
//! Both error cassettes still exist on disk (satisfying the "≥6 cassettes"
//! Definition of Done and the `every_profile_toml_has_at_least_one_cassette`
//! gate) and are still exercised by real tests below -- just directly against
//! `OpenAiResponsesProvider::stream_chat`, the same pattern
//! `anthropic_provider_cassette.rs`'s
//! `stream_chat_classifies_error_statuses_by_disposition` already established
//! for pinning a specific `ProviderError` disposition, rather than through
//! the generic per-`ChunkStrategy` replay loop.
//!
//! **A second, narrower gap found while writing these**: `error_429`/
//! `error_500`'s cassette-based tests below prove the full pipeline (cassette
//! bytes -> transport -> provider -> `classify`) produces the right
//! `ProviderError`, but 429 and 500 both already have their own entries in
//! `classify`'s generic HTTP-status fallback tier -- so those two tests would
//! still pass even if `openai-responses.toml`'s own `[errors]` table were
//! never consulted at all. The
//! `openai_responses_error_table_*_maps_to_*` tests below close that gap the
//! same way `profile_errors_wiring_test.rs` already does for `moonshot.toml`:
//! deliberately using status 400 (which carries none of these codes in its
//! own fallback mapping), so the only way to observe the expected
//! `ProviderError` variant is via this profile's own error-code
//! classification.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::openai_responses::encode::encode;
use roundhouse_provider::codec::openai_responses::OpenAiResponsesProvider;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::{
    CassetteTransport, ChatRequest, ChunkStrategy, Provider, ProviderError, RequestCtx,
};
use std::sync::Arc;

#[path = "support/openai_responses_fixtures.rs"]
mod fixtures;

fn fixture_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/openai-responses.toml")).unwrap()
}

fn cassette_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes/openai_responses")
        .join(name)
}

/// The union of every flattened field path this codec's `encode` can put on
/// the wire for the four success-path fixture requests below, derived from
/// `openai-responses.toml`'s own `ParamsPolicy` per REALITY-CORRECTIONS
/// §12c -- `mode = "deny_list", fields = []` permits every one of these
/// (empirically enumerated via `roundhouse_conformance::mask::flatten_object_keys`
/// against each fixture's real encoded body, not guessed).
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let all_known: &[&str] = &[
        "model",
        "input",
        "instructions",
        "tools",
        "tool_choice",
        "reasoning",
        "stream",
        "max_output_tokens",
        "stop",
        "input.type",
        "input.role",
        "input.content",
        "input.content.type",
        "input.content.text",
        "input.call_id",
        "input.name",
        "input.arguments",
        "input.output",
        "tools.type",
        "tools.name",
        "tools.description",
        "tools.parameters",
        "tools.parameters.$schema",
        "tools.parameters.title",
        "tools.parameters.type",
        "tool_choice.type",
        "tool_choice.name",
        "reasoning.effort",
    ];
    SerializeOnlyMask {
        mandatory: vec!["model".into(), "input".into(), "stream".into()],
        allowed: profile.defaults.params.allowed_fields(all_known),
    }
}

struct OpenAiResponsesSubject;

impl ConformanceSubject for OpenAiResponsesSubject {
    type Provider = OpenAiResponsesProvider;

    fn provider() -> Self::Provider {
        OpenAiResponsesProvider::new(fixture_profile())
    }

    fn cases() -> Vec<ConformanceCase> {
        let mask = mask(&fixture_profile());
        // `tools`/`parallel_tools`: the request's user-turn `Text` block is
        // never expected to survive into a ToolUse-only assistant response --
        // declared, not an undeclared drop (see this file's module doc for
        // why `error_429`/`error_500` are absent from this list).
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
            },
            ConformanceCase {
                name: "tools",
                request: fixtures::forced_tool_choice(),
                cassette_path: cassette_path("tools.cassette"),
                mask: mask.clone(),
                declared_loss_events: text_not_expected_in_a_tool_call_response.clone(),
            },
            ConformanceCase {
                name: "parallel_tools",
                request: fixtures::parallel_tool_calls(),
                cassette_path: cassette_path("parallel_tools.cassette"),
                mask: mask.clone(),
                declared_loss_events: text_not_expected_in_a_tool_call_response,
            },
            ConformanceCase {
                name: "reasoning",
                request: fixtures::reasoning_on(),
                cassette_path: cassette_path("reasoning.cassette"),
                mask,
                declared_loss_events: vec![],
            },
        ]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &fixture_profile())
    }
}

#[tokio::test]
async fn openai_responses_is_conformant() {
    run::<OpenAiResponsesSubject>().await.assert_green();
}

fn error_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": { "type": code, "message": "synthetic test body" }
    }))
    .unwrap()
}

/// These three tests prove `openai-responses.toml`'s own `[errors]` table is
/// actually consulted (REALITY-CORRECTIONS §14g) -- deliberately NOT status
/// 429/500/etc. (matches `profile_errors_wiring_test.rs`'s established
/// precedent): `classify`'s HTTP-status fallback tier would independently
/// produce the same `ProviderError` variant for those statuses regardless of
/// whether the profile table were ever read, which would make a same-status
/// test pass for the wrong reason. Status 400 carries none of these codes in
/// its own fallback mapping, so the only way to observe the expected variant
/// here is via this profile's own error-code classification.
#[test]
fn openai_responses_error_table_rate_limit_exceeded_maps_to_rate_limited() {
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
fn openai_responses_error_table_server_error_maps_to_overloaded() {
    let error_profile = fixture_profile().error_profile();
    let classified = roundhouse_provider::errors::classify(
        &error_profile,
        400,
        &error_body("server_error"),
        &http::HeaderMap::new(),
    );
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn openai_responses_error_table_insufficient_quota_maps_to_quota_exhausted() {
    let error_profile = fixture_profile().error_profile();
    let classified = roundhouse_provider::errors::classify(
        &error_profile,
        400,
        &error_body("insufficient_quota"),
        &http::HeaderMap::new(),
    );
    assert!(
        matches!(classified, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {classified:?}"
    );
}

/// `Result::expect_err` needs `T: Debug`, and `ChatStream` deliberately isn't
/// (it wraps a boxed stream) -- error-path tests unwrap through this instead,
/// matching `anthropic_provider_cassette.rs`'s existing precedent.
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
    let provider = OpenAiResponsesProvider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    assert!(
        matches!(err, ProviderError::RateLimited { .. }),
        "expected RateLimited (openai-responses.toml declares rate_limit_exceeded as \
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
    let provider = OpenAiResponsesProvider::new(fixture_profile());
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
