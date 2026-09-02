//! Profile-deserialization shape tests for the six `openai-chat` batch-B
//! profiles (direct vendor APIs): Mistral, DeepSeek, Z.ai, xAI, NVIDIA NIM,
//! DeepInfra. REALITY-CORRECTIONS §10: `CARGO_MANIFEST_DIR` is already
//! `crates/roundhouse-provider`, so the path has no `../`.
//!
//! Vendor verification notes (dispatch requirement: verify enum VALUES, not
//! just names, and cite where looked):
//!
//! - **Mistral**: `docs.mistral.ai/api/` (fetched live, 2026-09) confirms
//!   base_url `https://api.mistral.ai/v1`, Bearer auth. No vendor-specific
//!   parameter quirk found; profile is a plain pass-through.
//! - **DeepSeek**: `api-docs.deepseek.com/api/create-chat-completion` and
//!   `.../quick_start/first_api_call` (fetched live, 2026-09) both give the
//!   base_url as the bare `https://api.deepseek.com` — NOT `.../v1` as the
//!   plan brief assumed. Both pages were fetched independently and agreed
//!   (neither mentions a `/v1` alias), so this profile corrects the brief's
//!   base_url to the currently-documented value. The same docs list the
//!   current model catalog as `deepseek-v4-flash`/`deepseek-v4-pro`/
//!   `deepseek-v4-flash-vision-exp` (no `deepseek-reasoner`/`deepseek-chat`
//!   split any more) and state `presence_penalty`/`frequency_penalty` are
//!   "no longer supported" API-wide (not reasoner-model-specific, as the
//!   brief assumed) — this profile denies both at `[defaults.params]`
//!   rather than per-model. `api-docs.deepseek.com/guides/reasoning_model`
//!   (fetched live) shows thinking is toggled via a nested `thinking:
//!   {"type": "enabled"}` object with depth controlled by a separate
//!   `reasoning_effort` field — this profile's `ReasoningControl` targets
//!   `reasoning_effort` (the effort vocabulary control our schema
//!   expresses), consistent with every other `openai-chat` profile's single
//!   effort-field shape.
//! - **Z.ai**: `docs.z.ai/api-reference/llm/chat-completion` (fetched live)
//!   shows `thinking.type` accepts only `"enabled"`/`"disabled"` — a binary
//!   switch, NOT the graduated `disabled`/`enabled`/`deep` vocabulary the
//!   plan brief assumed for glm-5.3, nor a 7-value vocabulary on that same
//!   field for glm-5.2. The real graduated-effort control is a *separate*
//!   top-level `reasoning_effort` parameter: glm-5.3/glm-5.3-flash accept
//!   exactly `["low", "high", "max"]` (3 values, matching the plan's own
//!   "glm-5.3: 3 values" claim), glm-5.2-and-above accept the full
//!   `["max", "xhigh", "high", "medium", "low", "minimal", "none"]` (7
//!   values, matching the plan's "glm-5.2: 7 values" claim) — same value
//!   counts the plan predicted, wrong field name. This profile's
//!   `ReasoningControl.field` is `/reasoning_effort` for both model entries,
//!   not `/thinking/type`.
//! - **xAI**: `docs.x.ai/docs/api-reference` confirms base_url
//!   `https://api.x.ai/v1`, Bearer auth, finish_reason `stop`/`length`.
//!   `docs.x.ai/docs/guides/reasoning` (fetched live) confirms a
//!   `reasoning_effort` parameter on `grok-4*` models accepting `"low"`,
//!   `"medium"`, `"high"` (default), `"xhigh"` — added to this profile
//!   though not required by the brief, since real vendor data was in hand.
//! - **NVIDIA NIM**: `docs.api.nvidia.com/nim/reference/llm-apis` confirms
//!   the base_url `https://integrate.api.nvidia.com` (path `/v1/chat/completions`,
//!   i.e. base_url `https://integrate.api.nvidia.com/v1`, matching the
//!   brief). NIM is a hosting layer for many third-party open models with
//!   no single vendor-specific request quirk, so no params/reasoning quirk
//!   is added; Bearer auth is the universal, well-established NIM pattern
//!   (auth docs were not reachable from the fetched page; this matches
//!   every publicly documented NIM/build.nvidia.com integration).
//! - **DeepInfra**: `docs.deepinfra.com/chat/overview` (redirect target of
//!   `deepinfra.com/docs/openai_api`, fetched live) confirms base_url
//!   `https://api.deepinfra.com/v1/openai` and Bearer auth verbatim
//!   (`Authorization: Bearer $DEEPINFRA_TOKEN`), matching the brief exactly.
//!   DeepInfra is also a multi-model hosting layer; no single quirk applies.
use roundhouse_provider::codec::openai_chat::encode_openai_chat;
use roundhouse_provider::profile::{AuthKind, ParamsMode, ProviderProfile};
use roundhouse_provider::{ChatRequest, ReasoningIntent, ReasoningRequest};

#[path = "support/openai_chat_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn mistral_profile_shape() {
    let p = load("mistral");
    assert_eq!(p.codec, "openai-chat");
    assert_eq!(p.defaults.base_url, "https://api.mistral.ai/v1");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
    assert_eq!(p.defaults.params.mode, ParamsMode::DenyList);
}

#[test]
fn deepseek_profile_denies_presence_and_frequency_penalty() {
    // DeepSeek's currently-documented API (api-docs.deepseek.com) states
    // presence_penalty/frequency_penalty are "no longer supported" across
    // its whole current model catalog, not a reasoner-model-specific
    // restriction as the plan brief assumed.
    let p = load("deepseek");
    assert_eq!(p.defaults.base_url, "https://api.deepseek.com");
    assert!(p
        .defaults
        .params
        .fields
        .iter()
        .any(|f| f == "presence_penalty"));
    assert!(p
        .defaults
        .params
        .fields
        .iter()
        .any(|f| f == "frequency_penalty"));
}

#[test]
fn deepseek_reasoning_effort_field_not_nested_thinking_type() {
    // api-docs.deepseek.com/guides/reasoning_model: depth is controlled by a
    // top-level `reasoning_effort` field, separate from the `thinking`
    // enable/disable toggle. Our schema expresses one effort control per
    // model; this profile targets `reasoning_effort`.
    let p = load("deepseek");
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "deepseek-v4*"))
        .expect("a deepseek-v4* entry must exist");
    let reasoning = model
        .reasoning
        .as_ref()
        .expect("reasoning control must be present");
    assert_eq!(reasoning.field, "/reasoning_effort");
}

#[test]
fn zai_profile_has_reasoning_control_for_glm() {
    // §9.5's motivating example, verbatim: the effort vocabulary itself
    // varies by model even within one provider (glm-5.3: 3 values; glm-5.2:
    // 7). Verified against docs.z.ai: the real field is `reasoning_effort`,
    // not `thinking/type` (see module doc above).
    let p = load("zai");
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "glm-5.3*"))
        .unwrap();
    assert!(model.reasoning.is_some());
}

#[test]
fn zai_glm_5_3_reasoning_effort_has_three_values() {
    let p = load("zai");
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "glm-5.3*"))
        .unwrap();
    let reasoning = model.reasoning.as_ref().unwrap();
    assert_eq!(reasoning.field, "/reasoning_effort");
    assert_eq!(reasoning.vocabulary.len(), 3);
    for v in ["low", "high", "max"] {
        assert!(reasoning.vocabulary.iter().any(|x| x == v));
    }
}

#[test]
fn zai_glm_5_2_reasoning_effort_has_seven_values() {
    let p = load("zai");
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "glm-5.2*"))
        .unwrap();
    let reasoning = model.reasoning.as_ref().unwrap();
    assert_eq!(reasoning.field, "/reasoning_effort");
    assert_eq!(reasoning.vocabulary.len(), 7);
    for v in ["max", "xhigh", "high", "medium", "low", "minimal", "none"] {
        assert!(reasoning.vocabulary.iter().any(|x| x == v));
    }
}

#[test]
fn xai_profile_shape() {
    let p = load("xai");
    assert_eq!(p.defaults.base_url, "https://api.x.ai/v1");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

#[test]
fn xai_grok_4_reasoning_effort_vocabulary() {
    // docs.x.ai/docs/guides/reasoning (fetched live): grok-4* accepts
    // low/medium/high/xhigh.
    let p = load("xai");
    let model = p
        .model
        .iter()
        .find(|m| m.match_globs.iter().any(|g| g == "grok-4*"))
        .expect("a grok-4* entry must exist");
    let reasoning = model
        .reasoning
        .as_ref()
        .expect("reasoning control must be present");
    assert_eq!(reasoning.field, "/reasoning_effort");
    for v in ["low", "medium", "high", "xhigh"] {
        assert!(reasoning.vocabulary.iter().any(|x| x == v));
    }
}

#[test]
fn nvidia_nim_profile_shape() {
    let p = load("nvidia-nim");
    assert_eq!(p.defaults.base_url, "https://integrate.api.nvidia.com/v1");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

#[test]
fn deepinfra_profile_shape() {
    let p = load("deepinfra");
    assert_eq!(p.defaults.base_url, "https://api.deepinfra.com/v1/openai");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

// ---------------------------------------------------------------------
// Round-8 review, M5: the tests above check `field`/`vocabulary` in
// isolation -- none call `encode_openai_chat` with a `ReasoningIntent` and
// assert the emitted wire body, so transposing `high` and `max` in any
// profile's `map` would pass every one of them. These call the real
// codec against the real, shipped profile and assert the exact emitted
// value for two intents whose mapped values genuinely differ (`high` !=
// `max`), which a transposition would flip.
// ---------------------------------------------------------------------

fn request_with_intent(model_id: &str, intent: ReasoningIntent) -> ChatRequest {
    ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(intent),
        },
        ..fixtures::single_turn_text(model_id)
    }
}

#[test]
fn zai_glm_5_3_encodes_high_and_max_to_their_distinct_mapped_values() {
    let profile = load("zai");
    let high_body = encode_openai_chat(
        &request_with_intent("glm-5.3", ReasoningIntent::High),
        &profile,
    );
    let max_body = encode_openai_chat(
        &request_with_intent("glm-5.3", ReasoningIntent::Max),
        &profile,
    );
    assert_eq!(high_body["reasoning_effort"], serde_json::json!("high"));
    assert_eq!(max_body["reasoning_effort"], serde_json::json!("max"));
}

#[test]
fn zai_glm_5_2_encodes_high_and_max_to_their_distinct_mapped_values() {
    let profile = load("zai");
    let high_body = encode_openai_chat(
        &request_with_intent("glm-5.2", ReasoningIntent::High),
        &profile,
    );
    let max_body = encode_openai_chat(
        &request_with_intent("glm-5.2", ReasoningIntent::Max),
        &profile,
    );
    assert_eq!(high_body["reasoning_effort"], serde_json::json!("high"));
    assert_eq!(max_body["reasoning_effort"], serde_json::json!("max"));
}

#[test]
fn xai_grok_4_encodes_high_and_max_to_their_distinct_mapped_values() {
    // grok-4's map sends `high -> "high"` but `max -> "xhigh"` -- the
    // profile's one genuinely three-way-distinct control among this
    // batch's reasoning-bearing profiles.
    let profile = load("xai");
    let high_body = encode_openai_chat(
        &request_with_intent("grok-4", ReasoningIntent::High),
        &profile,
    );
    let max_body = encode_openai_chat(
        &request_with_intent("grok-4", ReasoningIntent::Max),
        &profile,
    );
    assert_eq!(high_body["reasoning_effort"], serde_json::json!("high"));
    assert_eq!(max_body["reasoning_effort"], serde_json::json!("xhigh"));
}

#[test]
fn deepseek_v4_encodes_reasoning_effort_for_the_high_intent() {
    // deepseek-v4's map sends both `high` and `max` to the same wire value
    // ("high") -- a transposition of those two entries would be
    // undetectable at the wire (there is nothing to transpose *to* that
    // differs), so this asserts the one real, distinct emitted value
    // instead of a high-vs-max contrast.
    let profile = load("deepseek");
    let body = encode_openai_chat(
        &request_with_intent("deepseek-v4-pro", ReasoningIntent::High),
        &profile,
    );
    assert_eq!(body["reasoning_effort"], serde_json::json!("high"));
}
