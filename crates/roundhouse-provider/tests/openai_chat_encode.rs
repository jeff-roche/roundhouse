use roundhouse_provider::codec::openai_chat::encode_openai_chat;
use roundhouse_provider::profile::{
    AuthKind, Defaults, ModelEntry, ParamsMode, ParamsPolicy, ProviderProfile, ReasoningControl,
    ReasoningKind,
};
use roundhouse_provider::{
    tool_def_from_schema, ChatRequest, ContentBlock, IdOrigin, Message, ModelId, Params,
    ProviderExt, ReasoningIntent, ReasoningRequest, RequestPolicy, ResponseFormat, Role,
    SystemBlock, ToolCallId, ToolChoice, ToolResultPart,
};
use serde_json::json;
use std::collections::BTreeMap;

// Note: Snapshots in this crate are accepted via `INSTA_UPDATE=always cargo test` since
// `cargo-insta` CLI is not installed in this environment.

/// A minimal profile with no `[[model]]` entries -- used by the two
/// pre-existing snapshot tests below, which predate `encode_openai_chat`
/// taking a profile at all (fix round 1, P2) and exercise no reasoning
/// behavior, so their snapshots must stay byte-identical.
fn no_reasoning_profile() -> ProviderProfile {
    ProviderProfile {
        id: "test".into(),
        codec: "openai-chat".into(),
        defaults: Defaults {
            allow_raw_extra: false,
            params: ParamsPolicy {
                mode: ParamsMode::AllowAll,
                fields: vec![],
            },
            base_url: "https://example.invalid/v1".into(),
            auth: AuthKind::Bearer,
        },
        model: vec![],
        errors: BTreeMap::new(),
    }
}

/// A profile with one `[[model]]` entry matching `kimi-*`, carrying an
/// `effort`-kind `ReasoningControl` -- mirrors moonshot.toml's real,
/// shipped shape (`field = "/reasoning_effort"`, `off -> none`, `high ->
/// high`, `max -> high`).
fn reasoning_profile() -> ProviderProfile {
    ProviderProfile {
        model: vec![ModelEntry {
            match_globs: vec!["kimi-*".into()],
            reasoning: Some(ReasoningControl {
                kind: ReasoningKind::Effort,
                field: "/reasoning_effort".into(),
                vocabulary: vec!["none".into(), "low".into(), "medium".into(), "high".into()],
                map: BTreeMap::from([
                    ("off".into(), "none".into()),
                    ("low".into(), "low".into()),
                    ("medium".into(), "medium".into()),
                    ("high".into(), "high".into()),
                    ("max".into(), "high".into()),
                ]),
            }),
            endpoint_preference: vec![],
        }],
        ..no_reasoning_profile()
    }
}

/// Fix round 2: mirrors Z.ai's real, shipped `glm-5.3*` shape from Task
/// 11's brief -- `field = "/thinking/type"` (NESTED, unlike moonshot's
/// flat `/reasoning_effort`), `vocabulary = ["disabled", "enabled",
/// "deep"]`, `map = { off -> disabled, low/medium -> enabled, high/max ->
/// deep }`. Proves `set_json_pointer` actually creates the intermediate
/// `thinking` object rather than only handling flat keys.
fn zai_like_profile() -> ProviderProfile {
    ProviderProfile {
        model: vec![ModelEntry {
            match_globs: vec!["glm-5.3*".into()],
            reasoning: Some(ReasoningControl {
                kind: ReasoningKind::Effort,
                field: "/thinking/type".into(),
                vocabulary: vec!["disabled".into(), "enabled".into(), "deep".into()],
                map: BTreeMap::from([
                    ("off".into(), "disabled".into()),
                    ("low".into(), "enabled".into()),
                    ("medium".into(), "enabled".into()),
                    ("high".into(), "deep".into()),
                    ("max".into(), "deep".into()),
                ]),
            }),
            endpoint_preference: vec![],
        }],
        ..no_reasoning_profile()
    }
}

/// Fix round 2: mirrors Qwen's real, shipped `qwen3*` shape from Task 12's
/// brief -- `field = "/enable_thinking"` (flat, but a DIFFERENT key name
/// than moonshot's `/reasoning_effort`, proving the key itself is read from
/// `field` rather than a hardcoded literal), `vocabulary = ["false",
/// "true"]`, `map` sends every non-`off` intent to the string `"true"`.
fn qwen_like_profile() -> ProviderProfile {
    ProviderProfile {
        model: vec![ModelEntry {
            match_globs: vec!["qwen3*".into()],
            reasoning: Some(ReasoningControl {
                kind: ReasoningKind::Effort,
                field: "/enable_thinking".into(),
                vocabulary: vec!["false".into(), "true".into()],
                map: BTreeMap::from([
                    ("off".into(), "false".into()),
                    ("low".into(), "true".into()),
                    ("medium".into(), "true".into()),
                    ("high".into(), "true".into()),
                    ("max".into(), "true".into()),
                ]),
            }),
            endpoint_preference: vec![],
        }],
        ..no_reasoning_profile()
    }
}

/// Test params struct for the "read" tool.
#[derive(schemars::JsonSchema)]
struct ReadParams {
    #[allow(dead_code)]
    path: String,
}

#[test]
fn encodes_basic_tool_call_request() {
    let req = ChatRequest {
        model: ModelId("gpt-5.4".into()),
        system: vec![SystemBlock {
            text: "You are a careful coding agent.".into(),
            cache: None,
        }],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "Read main.rs".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: ToolCallId("call_1".into()),
                    id_origin: IdOrigin::Provider,
                    name: "read".into(),
                    input: json!({ "path": "main.rs" }),
                    cache: None,
                }],
            },
        ],
        tools: vec![tool_def_from_schema::<ReadParams>("read", "Read a file")],
        tool_choice: ToolChoice::Auto,
        // Params.stop is Option<Vec<String>> (audit finding 5 — the frozen "every field
        // Option" rule) and the max-tokens field is named max_output_tokens.
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: Some(1024),
            stop: None,
        },
        reasoning: ReasoningRequest::default(),
        // response_format/ext/extra/policy: unpopulated in Phase 1 (see Task 6's
        // deliberate-scoping note) — the type carries them since it's frozen/shared.
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_openai_chat(&req, &no_reasoning_profile());

    insta::assert_json_snapshot!("openai_chat_encode__basic_tool_call_request", body);
}

#[test]
fn encodes_tool_result_only_message() {
    // Test that a message containing only ToolResult blocks (no text, no tool calls)
    // produces exactly one message (the tool message), with no spurious empty role message.
    let req = ChatRequest {
        model: ModelId("gpt-5.4".into()),
        system: vec![],
        messages: vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "What's the time?".into(),
                    cache: None,
                    citations: vec![],
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: ToolCallId("call_42".into()),
                    id_origin: IdOrigin::Provider,
                    name: "get_time".into(),
                    input: json!({}),
                    cache: None,
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: ToolCallId("call_42".into()),
                    content: vec![ToolResultPart {
                        text: "It is 3:45 PM".into(),
                    }],
                    is_error: false,
                    cache: None,
                }],
            },
        ],
        tools: vec![],
        tool_choice: ToolChoice::None,
        params: Params {
            temperature: None,
            top_p: None,
            max_output_tokens: None,
            stop: None,
        },
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let body = encode_openai_chat(&req, &no_reasoning_profile());

    insta::assert_json_snapshot!("openai_chat_encode__tool_result_only_message", body);
}

fn no_reasoning_request(model: &str) -> ChatRequest {
    ChatRequest {
        model: ModelId(model.into()),
        system: vec![],
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hi".into(),
                cache: None,
                citations: vec![],
            }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// Fix round 1, P2: `[[model]].reasoning` was fully modeled and
/// deserialized (moonshot.toml ships one today) but `encode_openai_chat`
/// never read it at all -- dead configuration. This pins the fix: a
/// matching model + a non-`Off` intent must forward the resolved wire value
/// under the real OpenAI-compatible top-level `reasoning_effort` key.
#[test]
fn reasoning_effort_is_forwarded_when_intent_is_set_and_model_matches() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..no_reasoning_request("kimi-k3-8k")
    };

    let body = encode_openai_chat(&req, &reasoning_profile());

    assert_eq!(body["reasoning_effort"], json!("high"));
}

/// `max` maps to the same wire value as `high` in moonshot's real, shipped
/// map (`vocabulary` has no separate `"max"` entry) -- proves `resolve()`'s
/// mapping is actually consulted, not just intent-is-non-Off gating.
#[test]
fn reasoning_effort_max_intent_maps_through_the_profiles_declared_map() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Max),
        },
        ..no_reasoning_request("kimi-k3-8k")
    };

    let body = encode_openai_chat(&req, &reasoning_profile());

    assert_eq!(body["reasoning_effort"], json!("high"));
}

/// No `[[model]]` entry matches this model, so no `ReasoningControl` exists
/// for it -- the field must be omitted rather than guessed at, even with a
/// non-`Off` intent requested.
#[test]
fn reasoning_effort_is_omitted_when_no_model_entry_matches() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..no_reasoning_request("some-other-model")
    };

    let body = encode_openai_chat(&req, &reasoning_profile());

    assert!(body.get("reasoning_effort").is_none());
}

/// A matching model with `intent: Off` (the default) must not forward the
/// field either -- `Off` is a real, meaningful intent value, not merely "no
/// intent was set."
#[test]
fn reasoning_effort_is_omitted_when_intent_is_off() {
    let req = no_reasoning_request("kimi-k3-8k");

    let body = encode_openai_chat(&req, &reasoning_profile());

    assert!(body.get("reasoning_effort").is_none());
}

/// Fix round 2: `ReasoningControl.field` is a genuine JSON pointer, walked
/// (not hardcoded) so a NESTED path like Z.ai's real `/thinking/type`
/// produces a nested object, not a flat `thinking/type` string key or a
/// silently-wrong `reasoning_effort` key.
#[test]
fn a_nested_field_pointer_produces_a_nested_wire_object() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..no_reasoning_request("glm-5.3-turbo")
    };

    let body = encode_openai_chat(&req, &zai_like_profile());

    assert_eq!(body["thinking"]["type"], json!("deep"));
    // And nothing was written under the OLD fix-round-1 hardcoded key.
    assert!(body.get("reasoning_effort").is_none());
}

/// The `low`/`medium` intents both map to Z.ai's `"enabled"` wire value
/// (not `"deep"`) -- proves the map is genuinely consulted per-intent, not
/// just "any non-Off intent produces the same nested shape."
#[test]
fn a_nested_field_pointer_honors_the_profiles_intent_map() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::Medium),
        },
        ..no_reasoning_request("glm-5.3-turbo")
    };

    let body = encode_openai_chat(&req, &zai_like_profile());

    assert_eq!(body["thinking"]["type"], json!("enabled"));
}

/// Fix round 2: a flat field with a DIFFERENT key name than the fix-round-1
/// hardcoded `reasoning_effort` (Qwen's real `/enable_thinking`) must be
/// written under ITS OWN key, not silently dropped or misfiled under
/// `reasoning_effort`.
#[test]
fn a_differently_named_flat_field_pointer_uses_its_own_key() {
    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..no_reasoning_request("qwen3-14b")
    };

    let body = encode_openai_chat(&req, &qwen_like_profile());

    assert_eq!(body["enable_thinking"], json!("true"));
    assert!(body.get("reasoning_effort").is_none());
}
