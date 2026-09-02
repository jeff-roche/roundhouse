//! `roundhouse-conformance` wiring for the six `openai-chat` batch-B
//! profiles: `mistral`, `deepseek`, `zai`, `xai`, `nvidia-nim`, `deepinfra`.
//!
//! Cassette provenance: every `testdata/cassettes/{mistral,deepseek,zai,xai,
//! nvidia_nim,deepinfra}/text.cassette` is HAND-AUTHORED (no live credential
//! to record against). Per REALITY-CORRECTIONS §13b item 3, a hand-authored
//! cassette proves only that this codec's decoder agrees with its own
//! fiction — it is NOT evidence the codec matches any of these vendors'
//! actual wire format. What these cassettes DO establish: `finish_reason:
//! "stop"` is a verified-real value for every one of these six vendors
//! (Mistral's docs example, DeepSeek's documented enum, Z.ai's documented
//! enum, xAI's documented enum, and NVIDIA NIM/DeepInfra as bare OpenAI-
//! compatible pass-throughs all confirm `"stop"` — see
//! `profile_test_openai_chat_batch_b.rs`'s module doc for citations), so the
//! decode path this replays is at least matching a real, spec-confirmed
//! terminal value rather than an invented one. The chunk SHAPE itself
//! (`data: {"choices":[{"delta":{...}}]}`) is OpenAI's own widely-documented
//! `/v1/chat/completions` streaming shape, which every one of these six
//! vendors advertises exact wire compatibility with — this is the same
//! precedent `conformance_openai_chat_batch_a.rs` already established for
//! openrouter/together/fireworks/groq/cerebras. Every cassette ends with a
//! trailing blank line (REALITY-CORRECTIONS §13b item 6), verified for the
//! whole `testdata/cassettes/` tree by
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
/// governed by a profile's `[defaults.params]` policy, PLUS the two
/// vendor-specific params batch-B profiles deny
/// (`presence_penalty`/`frequency_penalty` for `deepseek`). None of these
/// six have a corresponding field on this crate's IR `Params` struct
/// (`temperature`/`top_p`/`max_output_tokens`/`stop` are the only ones
/// `encode_openai_chat` can ever emit), matching batch-A's identical
/// "permitted-but-never-emitted" precedent for `logprobs`/`n`.
const ALL_KNOWN_PARAM_FIELDS: &[&str] = &[
    "temperature",
    "top_p",
    "max_output_tokens",
    "stop",
    "presence_penalty",
    "frequency_penalty",
];

/// Maps a params-policy field identifier onto the actual wire-key
/// `encode_openai_chat` emits for it. Identity for every field except
/// `max_output_tokens`, which this codec emits under the wire key
/// `max_tokens`.
fn params_wire_path(field: &str) -> &'static str {
    match field {
        "temperature" => "temperature",
        "top_p" => "top_p",
        "max_output_tokens" => "max_tokens",
        "stop" => "stop",
        "presence_penalty" => "presence_penalty",
        "frequency_penalty" => "frequency_penalty",
        other => panic!(
            "an openai-chat batch-B profile declares params field {other:?}, which this \
             test's wire-path translation table doesn't know about -- add it here"
        ),
    }
}

/// The mask for one profile, derived from that profile's own `ParamsPolicy`
/// (REALITY-CORRECTIONS §12c) rather than a batch-wide constant. Also always
/// permits `reasoning_effort` (governed by `[[model]].reasoning`, not
/// `[defaults.params]` -- fix round 1, P2 precedent from batch-A) and
/// `enable_thinking`'s sibling field name doesn't apply to this batch (that's
/// batch-C's Qwen profile); none of these `text` fixtures set a reasoning
/// intent, so this is future-proofing, not something this cassette exercises.
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let mut allowed: Vec<String> = vec![
        "messages".into(),
        "messages.role".into(),
        "messages.content".into(),
        "stream".into(),
        "tools".into(),
        "tool_choice".into(),
        "reasoning_effort".into(),
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

/// One conformance subject per profile, all reusing the same
/// `OpenAiChatProvider` -- nothing here differs except which TOML file is
/// loaded and which cassette directory is read from.
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

openai_chat_profile_subject!(MistralSubject, "mistral", "mistral");
openai_chat_profile_subject!(DeepSeekSubject, "deepseek", "deepseek");
openai_chat_profile_subject!(ZaiSubject, "zai", "zai");
openai_chat_profile_subject!(XaiSubject, "xai", "xai");
openai_chat_profile_subject!(NvidiaNimSubject, "nvidia-nim", "nvidia_nim");
openai_chat_profile_subject!(DeepInfraSubject, "deepinfra", "deepinfra");

#[tokio::test]
async fn mistral_is_conformant() {
    run::<MistralSubject>().await.assert_green();
}
#[tokio::test]
async fn deepseek_is_conformant() {
    run::<DeepSeekSubject>().await.assert_green();
}
#[tokio::test]
async fn zai_is_conformant() {
    run::<ZaiSubject>().await.assert_green();
}
#[tokio::test]
async fn xai_is_conformant() {
    run::<XaiSubject>().await.assert_green();
}
#[tokio::test]
async fn nvidia_nim_is_conformant() {
    run::<NvidiaNimSubject>().await.assert_green();
}
#[tokio::test]
async fn deepinfra_is_conformant() {
    run::<DeepInfraSubject>().await.assert_green();
}
