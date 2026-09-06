//! Conformance wiring for the OpenAI first-party `openai` profile (Task 13:
//! the DEGRADED `openai-chat` path, §9.2/§9.4). Reuses `OpenAiChatProvider`
//! (Task 10) and `encode_openai_chat`/`decode_openai_chat_stream`
//! (Tasks 7/8) completely unchanged -- this task adds no new codec logic,
//! only profile data and the endpoint-preference facts pinned down in
//! `openai_endpoint_preference_test.rs`.
//!
//! `text.cassette` is HAND-AUTHORED (no live credential to record against),
//! copying the exact JSON chunk shape already established and exercised by
//! `testdata/cassettes/moonshot/text.cassette` (Task 4) and the batch-A/B/C
//! `openai-chat` cassettes: a `role`+`content` delta, a second `content`
//! delta, a final empty-delta+`finish_reason: "stop"`+`usage` frame,
//! terminated by `data: [DONE]` and a trailing blank line
//! (REALITY-CORRECTIONS §13b items 3/6, enforced crate-wide by
//! `every_sse_cassette_has_a_terminator_test.rs`). Per REALITY-CORRECTIONS
//! §13b item 3, this proves the (already-shipped, already-verified)
//! `openai-chat` decoder agrees with this recorded shape -- it is not
//! independent evidence about OpenAI's live wire format, which Tasks 7/8/10
//! already established.
//!
//! This case deliberately uses `gpt-4o`, NOT `gpt-5*`: it exercises the
//! (non-degraded, no-`endpoint_preference`) legacy path. The
//! degraded-frontier-model behavior is a pure-function fact already proven
//! by `openai_endpoint_preference_test.rs`'s four tests, not something a
//! cassette replay adds evidence for -- `OpenAiChatProvider` never reads
//! `endpoint_preference` at all (§9.2's design note: the real call site for
//! `resolve_endpoint_preference` is the agent loop, outside this crate).
use roundhouse_conformance::{checks, run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::openai_chat::{encode_openai_chat, OpenAiChatProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ChatRequest;
use std::path::PathBuf;

#[path = "support/openai_chat_fixtures.rs"]
mod fixtures;

fn load_profile() -> ProviderProfile {
    toml::from_str(include_str!("../profiles/openai.toml")).unwrap()
}

struct OpenAiChatSubject;
impl ConformanceSubject for OpenAiChatSubject {
    type Provider = OpenAiChatProvider;

    fn provider() -> Self::Provider {
        OpenAiChatProvider::new(load_profile())
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text("gpt-4o"),
            cassette_path: PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("testdata/cassettes/openai/text.cassette"),
            // `single_turn_text` sets no tools/params/reasoning, so
            // `encode_openai_chat` emits exactly {model, messages, stream}
            // -- `messages` is an array of {role, content} objects, which
            // `flatten_object_keys` walks down to `messages.role` /
            // `messages.content` leaf paths (mirrors
            // `conformance_openai_chat_batch_a.rs`'s identical mask shape).
            mask: SerializeOnlyMask {
                mandatory: vec!["model".into(), "messages".into()],
                allowed: vec![
                    "model".into(),
                    "messages".into(),
                    "messages.role".into(),
                    "messages.content".into(),
                    "stream".into(),
                    "tools".into(),
                    "tool_choice".into(),
                ],
            },
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode_openai_chat(req, &load_profile())
    }
}

#[tokio::test]
async fn openai_chat_is_conformant() {
    run::<OpenAiChatSubject>().await.assert_green();
}

/// Task 12 (Cross-Cutting #2, Ruling R16): mandatory truncate-mid-stream
/// check -- this codec is in the "strict" truncation-signaling group
/// (`decode_guard.rs`'s module doc): it must `Err`, never fabricate a
/// `MessageStop`, when truncated before its real `data: [DONE]` terminal.
#[tokio::test]
async fn text_cassette_is_never_indistinguishable_from_a_clean_completion_when_truncated() {
    let failures = checks::check_truncate_mid_stream(
        &OpenAiChatSubject::provider(),
        &fixtures::single_turn_text("gpt-4o"),
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/openai/text.cassette"),
        OpenAiChatSubject::credentials(),
    )
    .await;
    assert!(
        failures.is_empty(),
        "openai-chat must never report a clean completion for a stream truncated before its \
         real terminal: {failures:#?}"
    );
}
