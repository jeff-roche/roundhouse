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
