//! `roundhouse-conformance` wiring for the five `openai-chat` batch-A
//! profiles (`openrouter`, `together`, `fireworks`, `groq`, `cerebras`) plus
//! the `moonshot` backfill (REALITY-CORRECTIONS's "Note on the moonshot
//! backfill": Task 4 built `moonshot.toml` but never gave it a cassette or a
//! conformance test before Task 3's `every_profile_toml_has_at_least_one_cassette`
//! gate existed).
//!
//! Cassette provenance: `testdata/cassettes/{openrouter,together,fireworks,
//! groq,cerebras}/text.cassette` are hand-authored (no live credential to
//! record against), copying the exact JSON chunk shape of the
//! already-shipped `testdata/cassettes/moonshot/text.cassette` (Task 4) --
//! `data: {"choices":[{"delta":{...}}]}` frames (a `role`+`content` delta, a
//! second `content` delta, a final empty-delta+`finish_reason`+`usage`
//! frame) terminated by `data: [DONE]`, matching OpenAI's real, widely-
//! documented `/v1/chat/completions` streaming shape. This IS a fresh
//! exercise of the `role`+`content` delta shape specifically: fix round 1,
//! P1 found that `decode_openai_chat_stream`'s `Delta` struct previously had
//! no `content` field at all, and the only pre-existing coverage
//! (`tests/openai_chat_decode.rs`) exercised solely the `tool_calls`/`usage`
//! path via a different fixture -- these `text` cases (and
//! `tests/openai_chat_decode.rs`'s new `decodes_streaming_text_content_into_block_events`
//! test, added in the same fix round) are what actually exercises the
//! `content` field end to end. Every cassette ends with a trailing blank
//! line (REALITY-CORRECTIONS §13b item 6), verified for the whole
//! `testdata/cassettes/` tree by `every_sse_cassette_has_a_terminator_test.rs`.

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
/// governed by a profile's `[defaults.params]` policy. Passed to
/// `ParamsPolicy::allowed_fields` (REALITY-CORRECTIONS §12c) so each
/// subject's mask is derived from that profile's OWN declared policy, not a
/// hardcoded mask shared across the batch -- the whole point being that
/// `groq`'s mask excludes `logprobs` and `cerebras`'s excludes `n`.
///
/// Fix round 1, P4: `logprobs` and `n` have no corresponding field on this
/// crate's IR `Params` at all (`ir.rs`'s `Params` struct only has
/// `temperature`/`top_p`/`max_output_tokens`/`stop`), so `encode_openai_chat`
/// can never actually emit them regardless of policy -- these two entries
/// are future-proofing, permitted-but-never-emitted mask slots (the same
/// shape as `cohere_v2`'s `k` precedent), not currently-exercised
/// differentiators. The mask-derivation mechanism itself is still real and
/// per-profile; it's specifically these two wire keys that are inert today.
const ALL_KNOWN_PARAM_FIELDS: &[&str] = &[
    "temperature",
    "top_p",
    "max_output_tokens",
    "stop",
    "logprobs",
    "n",
];

/// Maps a params-policy field identifier (as declared in a profile's
/// `[defaults.params] fields`) onto the actual wire-key `encode_openai_chat`
/// emits for it. Identity for every field except `max_output_tokens`, which
/// this codec emits under the wire key `max_tokens` (moonshot.toml's own
/// `allow_only` policy declares the IR-level name `max_output_tokens`, not
/// the wire name).
fn params_wire_path(field: &str) -> &'static str {
    match field {
        "temperature" => "temperature",
        "top_p" => "top_p",
        "max_output_tokens" => "max_tokens",
        "stop" => "stop",
        "logprobs" => "logprobs",
        "n" => "n",
        other => panic!(
            "an openai-chat batch-A profile declares params field {other:?}, which this \
             test's wire-path translation table doesn't know about -- add it here"
        ),
    }
}

/// The mask for one profile, derived from that profile's own
/// `ParamsPolicy` (REALITY-CORRECTIONS §12c) rather than a batch-wide
/// constant.
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let mut allowed: Vec<String> = vec![
        "messages".into(),
        "messages.role".into(),
        "messages.content".into(),
        "stream".into(),
        "tools".into(),
        "tool_choice".into(),
        // Independent of `[defaults.params]` -- governed by `[[model]].reasoning`
        // instead (fix round 1, P2). Not exercised by these `text` fixtures
        // (none set a reasoning intent), but permitted the same way
        // `logprobs`/`n` above are: a future case that does exercise it
        // shouldn't need a mask change.
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
/// `OpenAiChatProvider` -- the "provider is data" thesis made concrete:
/// nothing here differs except which TOML file is loaded and which cassette
/// directory is read from.
macro_rules! openai_chat_profile_subject {
    ($subject:ident, $id:literal) => {
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
                    cassette_path: cassette_path($id, "text.cassette"),
                    mask: mask(&load($id)),
                    // Fix round 1, P1: the decoder now genuinely decodes
                    // `delta.content`, so text really does round-trip -- no
                    // declared loss needed (and none should ever be added
                    // here again just to make a broken decoder pass; see
                    // this codec's `decode.rs` module history).
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

openai_chat_profile_subject!(OpenRouterSubject, "openrouter");
openai_chat_profile_subject!(TogetherSubject, "together");
openai_chat_profile_subject!(FireworksSubject, "fireworks");
openai_chat_profile_subject!(GroqSubject, "groq");
openai_chat_profile_subject!(CerebrasSubject, "cerebras");
// Backfill: moonshot (Task 4) never got a cassette or conformance test
// before Task 3's "every profile has >=1 cassette" gate existed (its own
// text.cassette was already shipped -- see this task's brief note).
openai_chat_profile_subject!(MoonshotSubject, "moonshot");

#[tokio::test]
async fn openrouter_is_conformant() {
    run::<OpenRouterSubject>().await.assert_green();
}
#[tokio::test]
async fn together_is_conformant() {
    run::<TogetherSubject>().await.assert_green();
}
#[tokio::test]
async fn fireworks_is_conformant() {
    run::<FireworksSubject>().await.assert_green();
}
#[tokio::test]
async fn groq_is_conformant() {
    run::<GroqSubject>().await.assert_green();
}
#[tokio::test]
async fn cerebras_is_conformant() {
    run::<CerebrasSubject>().await.assert_green();
}
#[tokio::test]
async fn moonshot_is_conformant() {
    run::<MoonshotSubject>().await.assert_green();
}
