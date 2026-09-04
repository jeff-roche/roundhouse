//! `roundhouse-conformance` wiring for the six `openai-chat` batch-C
//! profiles: `qwen`, `lm-studio`, `vllm`, `sglang`, `llama-cpp`, `ollama`.
//!
//! Cassette provenance: every `testdata/cassettes/{qwen,lm_studio,vllm,
//! sglang,llama_cpp,ollama}/text.cassette` is HAND-AUTHORED. Per
//! REALITY-CORRECTIONS §13b item 3, this proves only that this codec's
//! decoder agrees with its own fiction, not that it matches any of these
//! runtimes' actual wire format. For the five local/self-hosted runtimes
//! (LM Studio, vLLM, SGLang, llama.cpp, Ollama) this limitation is closer to
//! moot than for a hosted vendor API: each project documents and tests
//! exact wire compatibility with OpenAI's own `/v1/chat/completions`
//! streaming shape (`data: {"choices":[{"delta":{...}}]}`,
//! `finish_reason: "stop"`, terminated by `data: [DONE]`) as their explicit
//! design goal, and that is exactly the shape these cassettes replay. For
//! Qwen (DashScope compat mode, a hosted vendor API), the same caveat as
//! any other hosted-vendor hand-authored cassette applies in full; see
//! `profile_test_openai_chat_batch_c.rs`'s module doc for the base_url/
//! enable_thinking verification notes and their confidence caveat. Every
//! cassette ends with a trailing blank line (REALITY-CORRECTIONS §13b item
//! 6), verified for the whole `testdata/cassettes/` tree by
//! `every_sse_cassette_has_a_terminator_test.rs`.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::openai_chat::{encode_openai_chat, OpenAiChatProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ChatRequest;
use std::path::PathBuf;

#[path = "support/openai_chat_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path(id: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes")
        .join(id)
        .join(name)
}

/// Every field `encode_openai_chat` can ever put on the wire that is
/// governed by a profile's `[defaults.params]` policy. None of these six
/// profiles deny anything beyond the four IR-backed fields (the five local
/// runtimes are `allow_all`; `qwen` is `deny_list` with an empty deny set),
/// so this list is the plain baseline, matching batch-A's/batch-B's
/// identical precedent.
const ALL_KNOWN_PARAM_FIELDS: &[&str] = &["temperature", "top_p", "max_output_tokens", "stop"];

fn params_wire_path(field: &str) -> &'static str {
    match field {
        "temperature" => "temperature",
        "top_p" => "top_p",
        "max_output_tokens" => "max_tokens",
        "stop" => "stop",
        other => panic!(
            "an openai-chat batch-C profile declares params field {other:?}, which this \
             test's wire-path translation table doesn't know about -- add it here"
        ),
    }
}

/// The mask for one profile, derived from that profile's own `ParamsPolicy`
/// (REALITY-CORRECTIONS §12c). Always permits `reasoning_effort` (qwen's
/// actual field name is `enable_thinking` -- also permitted, since it is
/// governed by `[[model]].reasoning`, not `[defaults.params]`, and none of
/// these `text` fixtures exercise it) and `enable_thinking` for the same
/// future-proofing reason batch-A permits `logprobs`/`n`.
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let mut allowed: Vec<String> = vec![
        "messages".into(),
        "messages.role".into(),
        "messages.content".into(),
        "stream".into(),
        "tools".into(),
        "tool_choice".into(),
        "reasoning_effort".into(),
        "enable_thinking".into(),
    ];
    for field in profile
        .defaults
        .params
        .allowed_fields(ALL_KNOWN_PARAM_FIELDS)
    {
        allowed.push(params_wire_path(&field).to_string());
    }
    SerializeOnlyMask {
        mandatory: vec!["model".into(), "messages".into()],
        allowed,
    }
}

macro_rules! openai_chat_profile_subject {
    ($subject:ident, $id:literal, $cassette_dir:literal) => {
        struct $subject;
        impl ConformanceSubject for $subject {
            type Provider = OpenAiChatProvider;
            fn provider() -> Self::Provider {
                OpenAiChatProvider::new(load($id))
            }
            fn cases() -> Vec<ConformanceCase> {
                vec![ConformanceCase {
                    name: "text",
                    request: fixtures::single_turn_text($id),
                    cassette_path: cassette_path($cassette_dir, "text.cassette"),
                    mask: mask(&load($id)),
                    declared_loss_events: vec![],
                    expected_error: None,
                }]
            }
            fn wire_body(req: &ChatRequest) -> serde_json::Value {
                encode_openai_chat(req, &load($id))
            }
        }
    };
}

openai_chat_profile_subject!(QwenSubject, "qwen", "qwen");
openai_chat_profile_subject!(LmStudioSubject, "lm-studio", "lm_studio");
openai_chat_profile_subject!(VllmSubject, "vllm", "vllm");
openai_chat_profile_subject!(SglangSubject, "sglang", "sglang");
openai_chat_profile_subject!(LlamaCppSubject, "llama-cpp", "llama_cpp");
openai_chat_profile_subject!(OllamaSubject, "ollama", "ollama");

#[tokio::test]
async fn qwen_is_conformant() {
    run::<QwenSubject>().await.assert_green();
}
#[tokio::test]
async fn lm_studio_is_conformant() {
    run::<LmStudioSubject>().await.assert_green();
}
#[tokio::test]
async fn vllm_is_conformant() {
    run::<VllmSubject>().await.assert_green();
}
#[tokio::test]
async fn sglang_is_conformant() {
    run::<SglangSubject>().await.assert_green();
}
#[tokio::test]
async fn llama_cpp_is_conformant() {
    run::<LlamaCppSubject>().await.assert_green();
}
#[tokio::test]
async fn ollama_is_conformant() {
    run::<OllamaSubject>().await.assert_green();
}
