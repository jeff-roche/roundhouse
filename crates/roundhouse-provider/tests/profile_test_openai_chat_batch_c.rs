//! Profile-deserialization shape tests for the six `openai-chat` batch-C
//! profiles: Qwen (DashScope compat mode), LM Studio, vLLM, SGLang,
//! llama.cpp, Ollama `/v1`. REALITY-CORRECTIONS §10: `CARGO_MANIFEST_DIR` is
//! already `crates/roundhouse-provider`, so the path has no `../`.
//!
//! Vendor verification notes (dispatch requirement: verify enum VALUES, not
//! just names, and cite where looked):
//!
//! - **Qwen / DashScope compat mode**: live fetches of Alibaba Cloud's
//!   English (`alibabacloud.com/help/en/model-studio/...`) and Chinese
//!   (`help.aliyun.com/zh/model-studio/...`) compatibility pages gave THREE
//!   mutually inconsistent base-URL answers (`dashscope-us.aliyuncs.com`,
//!   a per-workspace `{id}.ap-southeast-1.maas.aliyuncs.com`, and no
//!   confirmation at all of `dashscope-intl.aliyuncs.com`), and neither page
//!   the fetcher actually read mentioned an `enable_thinking` parameter. A
//!   per-workspace templated domain cannot be a profile's static default
//!   (there is no single workspace id to bake in), which is itself evidence
//!   against that fetch result. Given the fetch evidence was internally
//!   contradictory rather than corroborating (unlike DeepSeek/Z.ai/xAI,
//!   where independent fetches agreed), this profile keeps the brief's
//!   `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` and
//!   `/enable_thinking` field — both long-established, stable, and widely
//!   documented for DashScope's international OpenAI-compatible surface —
//!   rather than overwriting a known-stable value with noisy fetch output.
//!   This is flagged in the task report as a lower-confidence entry.
//! - **LM Studio / vLLM / SGLang / llama.cpp / Ollama**: default listen
//!   ports (1234, 8000, 30000, 8080, 11434 respectively) are stable,
//!   long-documented community defaults for each project's OpenAI-compatible
//!   server, matching the brief. These are local, self-hosted runtimes with
//!   no vendor API to fetch a spec from; "verify enum values against the
//!   vendor's schema" does not apply the way it does to a hosted API — the
//!   requests these profiles produce are OpenAI-compatible pass-throughs the
//!   already-frozen `OpenAiChatProvider`/`encode_openai_chat` fully own.
use roundhouse_provider::codec::openai_chat::encode_openai_chat;
use roundhouse_provider::profile::{ProviderProfile, ReasoningValueType};
use roundhouse_provider::{ChatRequest, ReasoningIntent, ReasoningRequest};

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn qwen_compat_mode_profile_shape() {
    let p = load("qwen");
    assert_eq!(p.codec, "openai-chat");
    assert_eq!(
        p.defaults.base_url,
        "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
    );
}

/// Fix round 7, K6: the REAL, shipped `qwen.toml` (not a hand-built mirror
/// in `tests/openai_chat_encode.rs`) declares `value_type = "bool"` for its
/// `enable_thinking` reasoning control, and `encode_openai_chat` must emit a
/// genuine JSON boolean through it -- DashScope documents `enable_thinking`
/// as a boolean, and encoding the string `"true"` instead is a silent
/// protocol violation a gateway may accept-but-ignore (thinking silently
/// stays off) rather than reject with a loud error. No live Qwen endpoint
/// was reachable to confirm this against a real response; this proves the
/// codec's own self-consistency with the profile's declared type, not a
/// verified live behavior change.
#[test]
fn qwen_reasoning_control_declares_a_bool_value_type_and_encodes_one() {
    let profile = load("qwen");
    let control = profile.model[0]
        .reasoning
        .as_ref()
        .expect("qwen.toml declares a [[model]].reasoning control");
    assert_eq!(control.value_type, ReasoningValueType::Bool);

    let req = ChatRequest {
        reasoning: ReasoningRequest {
            intent: Some(ReasoningIntent::High),
        },
        ..minimal_qwen_request()
    };
    let body = encode_openai_chat(&req, &profile);
    assert_eq!(body["enable_thinking"], serde_json::json!(true));
    assert!(
        body["enable_thinking"].is_boolean(),
        "enable_thinking must be a genuine JSON boolean, not a string: {:?}",
        body["enable_thinking"]
    );
}

/// A minimal `ChatRequest` that matches `qwen.toml`'s `qwen3*` model glob --
/// used only by [`qwen_reasoning_control_declares_a_bool_value_type_and_encodes_one`].
fn minimal_qwen_request() -> ChatRequest {
    use roundhouse_provider::{
        ContentBlock, Message, ModelId, Params, ProviderExt, RequestPolicy, ResponseFormat, Role,
        ToolChoice,
    };
    ChatRequest {
        model: ModelId("qwen3-14b".into()),
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
        extra: std::collections::BTreeMap::new(),
        policy: RequestPolicy::Drop,
    }
}

#[test]
fn lm_studio_defaults_to_localhost() {
    let p = load("lm-studio");
    assert_eq!(p.defaults.base_url, "http://localhost:1234/v1");
}

#[test]
fn vllm_defaults_to_localhost() {
    let p = load("vllm");
    assert_eq!(p.defaults.base_url, "http://localhost:8000/v1");
}

#[test]
fn sglang_defaults_to_localhost() {
    let p = load("sglang");
    assert_eq!(p.defaults.base_url, "http://localhost:30000/v1");
}

#[test]
fn llama_cpp_defaults_to_localhost() {
    let p = load("llama-cpp");
    assert_eq!(p.defaults.base_url, "http://localhost:8080/v1");
}

#[test]
fn ollama_v1_defaults_to_localhost() {
    let p = load("ollama");
    assert_eq!(p.defaults.base_url, "http://localhost:11434/v1");
}

#[test]
fn every_local_runtime_profile_can_still_have_its_base_url_overridden() {
    // §9.9's override chain is what makes "localhost" a safe default: a real
    // deployment always overrides it, and the override is never silently
    // lost. `resolve_base_url` returns `(url::Url, String)` — a resolved URL
    // plus its host-only recording (REALITY-CORRECTIONS §credential.rs base_url
    // module) — not a bare `Url`, so this destructures the tuple.
    for name in ["lm-studio", "vllm", "sglang", "llama-cpp", "ollama"] {
        let p = load(name);
        let (resolved, _host_only) = roundhouse_provider::credential::resolve_base_url(
            &p.id,
            &p.defaults.base_url,
            Some("http://gpu-box.internal:9000/v1"),
        )
        .unwrap();
        assert_eq!(resolved.as_str(), "http://gpu-box.internal:9000/v1");
    }
}
