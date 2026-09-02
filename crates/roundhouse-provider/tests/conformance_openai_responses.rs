//! `roundhouse-conformance` wiring for the `openai-responses` codec (§9.10).
//!
//! **Fix-round-1 C7 update**: this file originally found and documented that
//! `check_fold_determinism` had no way to express "this cassette is supposed
//! to produce an error", so `error_429`/`error_500` were exercised only via
//! direct `stream_chat` calls, outside `ConformanceSubject::cases()`. That
//! gap is now closed additively in `roundhouse-conformance`
//! (`ConformanceCase::expected_error: Option<fn(&ProviderError) -> bool>`,
//! consulted by `check_fold_determinism`) — both error cassettes are now
//! real cases in `OpenAiResponsesSubject::cases()` below, replayed at all 4
//! `ChunkStrategy`s like every other case. The original direct tests are
//! kept too: they still add value the generic case can't (pinning the exact
//! wire pipeline end to end with a plain assertion, not a predicate).
//!
//! **A second, narrower gap found while writing the original direct tests**:
//! 429 and 500 both already have their own entries in `classify`'s generic
//! HTTP-status fallback tier, so a same-status test — cassette-based or via
//! `expected_error` — would pass even if `openai-responses.toml`'s own
//! `[errors]` table were never consulted at all. The
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
    CassetteTransport, ChatRequest, ChunkStrategy, ContentBlock, HttpRequest, HttpResponseStream,
    HttpTransport, MediaSource, Message, Provider, ProviderError, RequestCtx, TransportError,
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
            // Fix-round-1 C7: both error cassettes now run through the
            // generic harness via `expected_error`, at all 4 `ChunkStrategy`s
            // -- not just the direct tests below.
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
            // Fix-round-1 C2: `response.failed`/`response.incomplete`/`error`
            // arrive IN-BAND after a 200 -- these three cases prove
            // `decode_openai_responses_stream` surfaces them as an error
            // rather than a silently "successful" empty/truncated stream.
            // `response_failed`/`in_band_error` both carry a `code` that
            // matches one of this profile's own `[errors]` entries
            // (`server_error`/`rate_limit_exceeded`), so a mismatch here
            // would prove the code-table lookup wasn't reached (status 200
            // has no explicit branch of its own in `classify`'s fallback
            // tier, so there's no ambiguity the way there was for
            // `error_429`/`error_500`).
            ConformanceCase {
                name: "response_failed",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("response_failed.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::Overloaded)),
            },
            ConformanceCase {
                name: "response_incomplete",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("response_incomplete.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                // `response.incomplete` carries only a `reason` string, no
                // error `code` -- nothing in this profile's `[errors]` table
                // has "max_output_tokens" as a key, so this falls through to
                // `classify`'s HTTP-status default tier for the real 200
                // status this response actually had.
                expected_error: Some(|e| {
                    matches!(e, ProviderError::BadRequest { status: 200, .. })
                }),
            },
            ConformanceCase {
                name: "in_band_error",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("in_band_error.cassette"),
                mask: mask.clone(),
                declared_loss_events: vec![],
                expected_error: Some(|e| matches!(e, ProviderError::RateLimited { .. })),
            },
            // A non-terminal delta this codec previously dropped entirely --
            // now carried as `BlockDelta::Text` (the closest IR concept to
            // refusal content) rather than silently vanishing. Success path:
            // no `expected_error`.
            ConformanceCase {
                name: "refusal",
                request: fixtures::single_turn_text(),
                cassette_path: cassette_path("refusal.cassette"),
                mask,
                declared_loss_events: vec![],
                expected_error: None,
            },
        ]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &fixture_profile()).expect("encode must succeed for this fixture profile")
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

/// A transport that always fails with an error message shaped like a leaked
/// gateway API key -- the exact shape the fix-round-1 C5 reviewer traced
/// (`reqwest`'s `Display` appends `" for url ({url})"`, userinfo and query
/// string included, straight into `TransportError::Io`).
struct LeakyFailingTransport;

impl HttpTransport for LeakyFailingTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async {
            // Fix round 7, K3: the secret also sits in a path segment
            // (`gw-path-secret-...`) and a fragment (`gw-frag-secret-...`),
            // not just the query string and userinfo -- `record_base_url_
            // override` (`credential/host_only.rs`) reduces a URL to
            // `host[:port]` ONLY, dropping path/query/fragment entirely, so
            // this is the strongest fixture that can distinguish "redaction
            // reduces to host[:port]" from "redaction merely strips query
            // strings and userinfo" (which would still leak a path- or
            // fragment-embedded secret).
            Err(TransportError::Io(
                "error sending request for url \
                 (https://gwuser:gwpass@gateway.example.invalid/v1/responses/gw-path-secret-7a3f9c2e1b4d6a80\
                 ?key=gw-live-9f2b8c1d4e6a7b3c#gw-frag-secret-3c8e1a4f9d2b7601)"
                    .into(),
            ))
        })
    }
}

/// Fix-round-1 C5 introduced this test against plain `redact_error_body`,
/// whose `"[REDACTED-KEY]"` marker the second assertion below used to check
/// for literally. Fix round 5, H1 found that check gave false confidence:
/// `redact_error_body` alone does NOT strip a URL's query string or
/// userinfo (it only matches a labeled `api_key`/`access_token`/
/// `client_secret`-shaped field of >=16 chars against the RAW body text,
/// which happens to match `?api_key=...` here only because this fixture's
/// query param is literally named `api_key` -- a differently-named gateway
/// param, e.g. `?key=...` as `build_endpoint_url`'s own
/// `preserves_a_gateway_query_string` test uses, would NOT have matched and
/// would have leaked unredacted even though this test stayed green). This
/// sink now calls the stronger `redact_transport_error_text`, which reduces
/// the whole embedded URL to `host[:port]` before `redact_error_body` ever
/// runs -- the secret is gone via URL replacement, not via a labeled-field
/// match, so no `"[REDACTED-KEY]"` marker is left behind to assert on.
///
/// Fix round 6, J1: the fixture itself was still a second, independent
/// coincidence on top of the one above -- `sk-should-be-redacted-1234567890`
/// is *also* `sk-`-shaped, so `API_KEY_SHAPED` alone caught it even with
/// `redact_transport_error_text` reverted back to plain `redact_error_body`
/// (REALITY-CORRECTIONS §15). The fixture below uses a secret no other
/// matcher in `audit/redact.rs` recognizes on its own (no `sk-`/`pk-`/`rk-`
/// prefix, not a labeled `api_key`/`access_token`/`client_secret` field) and
/// puts it behind a URL carrying userinfo AND a differently-named query
/// param, so the only way this test can pass is via the URL-reduction
/// guarantee itself.
///
/// Fix round 7, K3: the fixture URL also embeds a secret in a PATH SEGMENT
/// and a FRAGMENT, neither of which the previous version of this fixture
/// covered. `record_base_url_override` (`credential/host_only.rs`) is
/// `host[:port]`-only -- it drops path, query, AND fragment unconditionally
/// -- so production behavior here was already correct; this only makes the
/// test capable of catching a regression that redacted the query string and
/// userinfo but left the path or fragment intact (a real, distinct way to
/// leak a URL-embedded secret that the pre-K3 fixture could not detect at
/// all, since it never put a secret in either place).
#[tokio::test]
async fn a_transport_failure_never_leaks_a_key_shaped_string_from_the_url() {
    const QUERY_SECRET: &str = "gw-live-9f2b8c1d4e6a7b3c";
    const PATH_SECRET: &str = "gw-path-secret-7a3f9c2e1b4d6a80";
    const FRAGMENT_SECRET: &str = "gw-frag-secret-3c8e1a4f9d2b7601";
    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(LeakyFailingTransport),
        api_key: "test-key".into(),
        credentials: None,
    };
    let provider = OpenAiResponsesProvider::new(fixture_profile());
    let err = expect_err(
        provider
            .stream_chat(&fixtures::single_turn_text(), &ctx)
            .await,
    );
    let rendered = format!("{err} / {err:?}");
    assert!(
        !rendered.contains(QUERY_SECRET),
        "the query-string-embedded secret leaked into a ProviderError unredacted: {rendered}"
    );
    assert!(
        !rendered.contains(PATH_SECRET),
        "the path-segment-embedded secret leaked into a ProviderError unredacted: {rendered}"
    );
    assert!(
        !rendered.contains(FRAGMENT_SECRET),
        "the fragment-embedded secret leaked into a ProviderError unredacted: {rendered}"
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

/// A transport that panics if `send` is ever called -- used to prove a
/// request is rejected before any network I/O is attempted, not merely
/// rejected eventually.
struct PanicsIfCalledTransport;

impl HttpTransport for PanicsIfCalledTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        panic!(
            "stream_chat must reject an Image/Document request before ever calling \
             HttpTransport::send -- fix-round-2 D1"
        )
    }
}

/// Fix-round-2 D1 (BLOCKER): fix-round-1 C6 put its Image/Document guard
/// only on `Provider::resolve`, which the review found has zero production
/// callers anywhere in this workspace -- every real path
/// (`roundhouse-engine`'s `chat.rs`/`compact.rs`, `fallback.rs`) calls
/// `stream_chat` directly. This is the test C6 should have had: it drives
/// the actual production entry point with an Image block and asserts the
/// rejection, using a transport that panics if `send` is ever reached, so a
/// regression that let the request through to the network would fail this
/// test even if the returned `Result` were somehow still `Err` for an
/// unrelated reason.
#[tokio::test]
async fn stream_chat_rejects_image_content_before_any_transport_call() {
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
    let provider = OpenAiResponsesProvider::new(fixture_profile());
    let err = expect_err(provider.stream_chat(&req, &ctx).await);
    assert!(
        matches!(err, ProviderError::Unsupported(_)),
        "expected Unsupported, got {err:?}"
    );
}
