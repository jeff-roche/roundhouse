//! `roundhouse-conformance` wiring for the `azure-openai` profile (Task 14,
//! audit finding 2).
//!
//! Cassette provenance: `testdata/cassettes/azure_openai/text.cassette` is
//! HAND-AUTHORED (no live Azure resource/credential to record against),
//! copying the exact `data: {"choices":[{"delta":{...}}]}` frame shape
//! already shipped in `testdata/cassettes/moonshot/text.cassette` and the
//! five batch-A cassettes (REALITY-CORRECTIONS §13b item 3: this proves the
//! decoder agrees with this cassette's bytes, not that it agrees with a live
//! Azure endpoint's bytes -- the same limitation those five hand-authored
//! cassettes already carry, and legitimate here for the same reason: this
//! task's whole premise, stated in the plan brief itself, is that "Azure's
//! request/response bodies are ordinary openai-chat shape" identical to the
//! wire shape those cassettes already exercise -- only the URL differs,
//! and that's covered by `azure_deployment_routing_test.rs`, not this file).
//! Terminated with a trailing blank line per REALITY-CORRECTIONS §13b item 6
//! (verified crate-wide by `every_sse_cassette_has_a_terminator_test.rs`).

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::openai_chat::{encode_openai_chat, AzureOpenAiProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ChatRequest;
use std::path::PathBuf;

#[path = "support/openai_chat_fixtures.rs"]
mod fixtures;

fn load() -> ProviderProfile {
    let path = format!("{}/profiles/azure-openai.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/azure_openai/text.cassette")
}

struct AzureOpenAiSubject;
impl ConformanceSubject for AzureOpenAiSubject {
    type Provider = AzureOpenAiProvider;

    fn provider() -> Self::Provider {
        AzureOpenAiProvider::new(load())
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            // "gpt-5.4" is the model id `azure-openai.toml` maps to the
            // `gpt-5-4-prod` deployment (the mapping under test in
            // `azure_deployment_routing_test.rs`); this codec's wire body
            // itself has no model-family-specific validation, so the exact
            // string doesn't matter for what `encode_openai_chat` exercises.
            request: fixtures::single_turn_text("gpt-5.4"),
            cassette_path: cassette_path(),
            mask: SerializeOnlyMask {
                mandatory: vec!["model".into(), "messages".into()],
                allowed: vec![
                    "model".into(),
                    "messages".into(),
                    "messages.role".into(),
                    "messages.content".into(),
                    "stream".into(),
                ],
            },
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode_openai_chat(req, &load())
    }
}

#[tokio::test]
async fn azure_openai_is_conformant() {
    run::<AzureOpenAiSubject>().await.assert_green();
}
