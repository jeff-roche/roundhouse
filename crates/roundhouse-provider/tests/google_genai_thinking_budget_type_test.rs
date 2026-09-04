//! Task 17 addendum SS1 (Ruling P108) -- proves the `thinkingBudget`
//! fail-open fix at the `google_genai::encode::encode` level, independent of
//! any profile TOML file. `ProviderProfile` and its nested structs are all
//! plain public structs (`profile/schema.rs`), so a minimal fixture is built
//! directly here by struct literal rather than loading
//! `vertex-gemini.toml`/`gemini-generate-content-legacy.toml` (both are
//! covered end-to-end, through the real `Provider`, by
//! `tests/conformance_google_genai_batch.rs` -- this file tests the encoder
//! in isolation).
//!
//! This lives in its own integration-test file, calling the codec's public
//! `encode::encode` entry point, rather than as a `#[cfg(test)]` module
//! inside `encode.rs` -- an earlier draft did the latter and hit two real
//! problems worth recording: `clippy::items_after_test_module` rejects a
//! trailing `mod` followed by more top-level items (this crate denies
//! warnings), and `tests/google_genai_wire_literal_tripwire.rs`'s
//! `function_body` helper finds a scanned function's end by looking for the
//! next COLUMN-0 `fn` line -- a `#[cfg(test)] mod { .. }` block's nested,
//! indented `fn`s don't count as that boundary, so a trailing test module
//! silently got absorbed into `encode_generate_content_tool_config`'s
//! scanned body and every string literal in it (`"1024x"`, this file's own
//! test names, ...) was reported as an unvendored wire literal.

use roundhouse_provider::codec::google_genai::encode::{encode, EncodeError};
use roundhouse_provider::codec::google_genai::EndpointMode;
use roundhouse_provider::profile::{
    AuthKind, Defaults, ModelEntry, ParamsMode, ParamsPolicy, ProviderProfile, ReasoningControl,
    ReasoningKind, ReasoningValueType,
};
use roundhouse_provider::{
    ChatRequest, ContentBlock, Message, ModelId, Params, ProviderExt, ReasoningIntent,
    ReasoningRequest, RequestPolicy, ResponseFormat, Role, ToolChoice,
};
use std::collections::BTreeMap;

fn profile_with_reasoning(value_type: ReasoningValueType) -> ProviderProfile {
    ProviderProfile {
        id: "test-google-genai".into(),
        codec: "google-genai".into(),
        defaults: Defaults {
            allow_raw_extra: false,
            params: ParamsPolicy {
                mode: ParamsMode::DenyList,
                fields: vec![],
            },
            base_url: "https://generativelanguage.googleapis.com".into(),
            auth: AuthKind::HeaderKey {
                header: "x-goog-api-key".into(),
            },
        },
        model: vec![ModelEntry {
            match_globs: vec!["gemini-3.0*".into()],
            reasoning: Some(ReasoningControl {
                kind: ReasoningKind::Budget,
                field: "/generationConfig/thinkingConfig/thinkingBudget".into(),
                value_type,
                vocabulary: vec!["0".into(), "1024".into(), "8192".into(), "24576".into()],
                map: BTreeMap::from([
                    ("off".to_string(), "0".to_string()),
                    ("low".to_string(), "1024".to_string()),
                    ("medium".to_string(), "8192".to_string()),
                    ("high".to_string(), "24576".to_string()),
                    ("max".to_string(), "24576".to_string()),
                ]),
            }),
            endpoint_preference: vec![],
            azure_deployment: None,
        }],
        errors: BTreeMap::new(),
        error_pointer: "/error/type".into(),
    }
}

fn reasoning_high_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("gemini-3.0-pro".into()),
        system: vec![],
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "prove sqrt(2) is irrational".into(),
                cache: None,
                citations: vec![],
            }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Drop,
    }
}

/// The whole point of this fix round: `value_type = "number"` (what both
/// new batch profiles declare) makes `thinkingBudget` a genuine JSON
/// number, never a quoted string.
///
/// Revert-and-watch-it-fail (REALITY-CORRECTIONS SS15): with
/// `wire_value_to_json`'s float-to-i64 normalization temporarily removed
/// (`WireValue::Number(n) => json!(n)` unconditionally), this test failed
/// with `left: Number(24576.0), right: Number(24576)` -- confirmed during
/// implementation, restored immediately after. See the task report for the
/// captured failing output.
#[test]
fn budget_reaches_the_wire_as_a_json_number_not_a_quoted_string() {
    let profile = profile_with_reasoning(ReasoningValueType::Number);
    let body = encode(
        &reasoning_high_request(),
        &profile,
        EndpointMode::GenerateContent,
    )
    .expect("a value_type = \"number\" control with a mapped intent must encode");
    let budget = &body["generationConfig"]["thinkingConfig"]["thinkingBudget"];
    assert_eq!(
        budget,
        &serde_json::json!(24576),
        "expected the JSON *number* 24576 (not a float-formatted 24576.0, and not a string), \
         got {budget:?}"
    );
    assert!(
        !budget.is_string(),
        "thinkingBudget must never be a quoted string: {budget:?}"
    );
}

/// Companion to the test above: the SAME control, declared with the pre-fix
/// default `value_type` (`String` -- what every `google_genai` reasoning
/// control had before this task, since neither shipped profile ever set
/// it), proves the property above is not vacuous by exhibiting the real
/// pre-fix wire shape.
#[test]
fn a_string_typed_control_genuinely_serializes_the_budget_as_a_quoted_string() {
    let profile = profile_with_reasoning(ReasoningValueType::String);
    let body = encode(
        &reasoning_high_request(),
        &profile,
        EndpointMode::GenerateContent,
    )
    .expect("a value_type = \"string\" control with a mapped intent must still encode");
    let budget = &body["generationConfig"]["thinkingConfig"]["thinkingBudget"];
    assert!(
        budget.is_string(),
        "this documents the pre-fix failure mode this task's addendum describes: an \
         undeclared/`String`-typed reasoning control genuinely serializes thinkingBudget as a \
         quoted string via resolve_wire_value, got {budget:?}. This is exactly why both new \
         profiles MUST declare value_type = \"number\"."
    );
}

/// The other half of the addendum's fix, and the exact scenario the
/// addendum names: "a vocabulary typo like `1024x` builds clean, validates
/// clean" (because `value_type` defaulted to `String`, so
/// `validate_value_type` never attempted a numeric parse at build time),
/// "and then silently disables reasoning forever." Note this is
/// deliberately NOT an *unmapped* intent -- `ReasoningControl::resolve`
/// already hard-errors on that case regardless of this fix
/// (`UnmappedIntent`, checked before any parsing happens), so that scenario
/// would pass even against the old `.unwrap_or(0)` code and prove nothing
/// (confirmed during implementation: an earlier draft of this test used
/// exactly that scenario and stayed green with `.resolve(intent)?.parse()
/// .unwrap_or(0)` restored in place of the fix -- see the task report). The
/// real gap is a wire value that IS mapped and IS in the declared
/// vocabulary (so `resolve()` returns `Ok`), but does not parse as a number
/// -- exactly what a `value_type = "number"` control now catches via
/// `resolve_wire_value` instead of silently defaulting.
///
/// Revert-and-watch-it-fail (REALITY-CORRECTIONS SS15): with the production
/// code temporarily restored to `let budget: i64 = control.resolve(intent)?
/// .parse().unwrap_or(0); body[..] = json!(budget);`, this test failed --
/// `expect_err` panicked because the call returned `Ok` with a body
/// containing `"thinkingBudget": 0`, confirmed during implementation and
/// captured in the task report. Restored immediately after.
#[test]
fn an_unparseable_but_mapped_budget_fails_closed_instead_of_silently_encoding_a_zero_budget() {
    let mut profile = profile_with_reasoning(ReasoningValueType::Number);
    let control = profile.model[0]
        .reasoning
        .as_mut()
        .expect("test fixture always sets a reasoning control");
    // A self-consistent vocabulary typo: "1024x" is listed in BOTH
    // `vocabulary` and `map`, so `resolve()` (membership-only) succeeds --
    // the failure can only be caught by actually parsing the value under
    // the declared `value_type`, which `resolve_wire_value` does and bare
    // `resolve()`/`.parse().unwrap_or(0)` did not.
    control.vocabulary = vec!["0".into(), "1024x".into(), "8192".into(), "24576".into()];
    control.map.insert("high".to_string(), "1024x".to_string());

    let err = encode(
        &reasoning_high_request(),
        &profile,
        EndpointMode::GenerateContent,
    )
    .expect_err(
        "an unparseable-as-number wire value must be a hard error, not a silent budget of 0",
    );
    assert!(
        matches!(err, EncodeError::Reasoning(_)),
        "expected EncodeError::Reasoning(WireValueWrongType), got {err:?}"
    );
}
