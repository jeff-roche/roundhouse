//! `roundhouse-conformance` wiring for Task 16's six `openai-responses`
//! batch profiles (NVIDIA, Vercel, OpenRouter, HuggingFace, Databricks,
//! AWS) -- unlike the `openai-chat`/`anthropic-messages` batches (Tasks
//! 10-15), no new `Provider` wrapper is needed here: `OpenAiResponsesProvider`
//! (Task 5) already takes a `ProviderProfile` in its constructor, so every
//! subject below reuses it directly, differing only in which TOML is
//! loaded, which cassette directory is read from, and (AWS only) which
//! credential is supplied.
//!
//! Cassette provenance: every `testdata/cassettes/{nvidia_open_responses,
//! vercel,openrouter_responses,huggingface,databricks,aws_open_responses}/
//! text.cassette` is a byte-for-byte copy of `testdata/cassettes/
//! openai_responses/text.cassette` -- the SAME SSE frame sequence Task 5
//! already verified against the real OpenAI Responses API spec (see that
//! codec's `decode.rs`/spec-verification note). Per REALITY-CORRECTIONS
//! §13b item 3, this proves the six profiles' decoding agrees with THIS
//! codec's own already-verified wire shape, not independent per-vendor wire
//! capture -- which is the entire premise of the audit finding this task
//! implements (§9.4: these six reuse Task 5's codec "exactly as built").
//! Every cassette ends with a trailing blank line (REALITY-CORRECTIONS §13b
//! item 1), verified for the whole `testdata/cassettes/` tree by
//! `every_sse_cassette_has_a_terminator_test.rs`.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::openai_responses::encode::encode;
use roundhouse_provider::codec::openai_responses::OpenAiResponsesProvider;
use roundhouse_provider::credential::CredentialProvider;
use roundhouse_provider::profile::{AuthKind, ProviderProfile};
use roundhouse_provider::ChatRequest;
use roundhouse_secrets::credential::SigV4Credential;
use roundhouse_secrets::secret::Secret;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "support/openai_responses_batch_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path(id: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes")
        .join(id.replace('-', "_"))
        .join(name)
}

/// A real `SigV4Credential` (fixed, obviously-fake test key material) --
/// `aws-open-responses` has no bare-`api_key` fallback that can sign an AWS
/// request (REALITY-CORRECTIONS §12b: SigV4 "applying" a credential IS
/// signing it), so the conformance run for that one profile must supply
/// one. Matches `conformance_anthropic_messages_batch.rs`'s/
/// `conformance_bedrock_converse.rs`'s identical precedent.
///
/// `service` is read from the profile's own declared `AuthKind::SigV4 {
/// service }` rather than a hand-written literal, so the profile's declared
/// value reaches the real `sigv4::sign()` signature path this credential's
/// `apply` calls -- proving the data is load-bearing, not merely re-asserted
/// by a test that reads the same TOML.
fn test_sigv4_credentials(profile: &ProviderProfile) -> Arc<dyn CredentialProvider> {
    let service = match &profile.defaults.auth {
        AuthKind::SigV4 { service } => service.clone(),
        other => panic!("expected SigV4 auth for {:?}, got {other:?}", profile.id),
    };
    Arc::new(SigV4Credential::new(
        "AKIAEXAMPLETESTKEY00000",
        Secret::new("wJalrXUtnFEMIexampleSECRETkey1234567890".to_string()),
        None,
        "us-east-1",
        service,
    ))
}

/// Every field `encode` (openai_responses) can put on the wire for the
/// plain single-turn-text fixture this batch shares -- the same known-field
/// union `conformance_openai_responses.rs`'s own `mask()` uses, restricted
/// to what a tool-less, reasoning-less, cache-less request can ever emit.
/// Passed to `ParamsPolicy::allowed_fields` (REALITY-CORRECTIONS §12c) so
/// each subject's mask is derived from that profile's OWN declared policy,
/// even though every profile in this batch happens to declare the same
/// `deny_list`-with-nothing-denied policy today -- the derivation is still
/// real and per-profile, not a shared hardcoded constant.
const ALL_KNOWN_PARAM_FIELDS: &[&str] = &[
    "model",
    "input",
    "instructions",
    "stream",
    "max_output_tokens",
    "stop",
    "input.type",
    "input.role",
    "input.content",
    "input.content.type",
    "input.content.text",
];

/// The mask for one profile, derived from that profile's own `ParamsPolicy`
/// (REALITY-CORRECTIONS §12c) -- there is no per-profile structural quirk
/// in this batch (unlike Vertex's `anthropic_version` swap in Task 15's
/// batch), so unlike that file's `mask()` this one needs no extra permitted
/// keys beyond what the shared policy union already covers.
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    SerializeOnlyMask {
        mandatory: vec!["model".into(), "input".into(), "stream".into()],
        allowed: profile
            .defaults
            .params
            .allowed_fields(ALL_KNOWN_PARAM_FIELDS),
    }
}

/// One conformance subject per profile, all reusing the same
/// `OpenAiResponsesProvider` -- the "provider is data" thesis made concrete:
/// nothing here differs except which TOML file is loaded and which cassette
/// directory is read from.
macro_rules! openai_responses_profile_subject {
    ($subject:ident, $id:literal, $model:literal) => {
        struct $subject;
        impl ConformanceSubject for $subject {
            type Provider = OpenAiResponsesProvider;
            fn provider() -> Self::Provider {
                OpenAiResponsesProvider::new(load($id))
            }
            fn cases() -> Vec<ConformanceCase> {
                vec![ConformanceCase {
                    name: "text",
                    request: fixtures::single_turn_text($model),
                    cassette_path: cassette_path($id, "text.cassette"),
                    mask: mask(&load($id)),
                    declared_loss_events: vec![],
                    expected_error: None,
                }]
            }
            fn wire_body(req: &ChatRequest) -> serde_json::Value {
                encode(req, &load($id)).expect("encode must succeed for this fixture profile")
            }
        }
    };
}

openai_responses_profile_subject!(
    NvidiaOpenResponsesSubject,
    "nvidia-open-responses",
    "meta/llama-4-scout"
);
openai_responses_profile_subject!(VercelSubject, "vercel", "openai/gpt-5.4");
openai_responses_profile_subject!(
    OpenRouterResponsesSubject,
    "openrouter-responses",
    "openai/gpt-5.4"
);
openai_responses_profile_subject!(
    HuggingFaceSubject,
    "huggingface",
    "openai/gpt-oss-120b:groq"
);
openai_responses_profile_subject!(DatabricksSubject, "databricks", "databricks-gpt-oss-120b");

struct AwsOpenResponsesSubject;
impl ConformanceSubject for AwsOpenResponsesSubject {
    type Provider = OpenAiResponsesProvider;
    fn provider() -> Self::Provider {
        OpenAiResponsesProvider::new(load("aws-open-responses"))
    }
    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text("openai.gpt-oss-120b"),
            cassette_path: cassette_path("aws-open-responses", "text.cassette"),
            mask: mask(&load("aws-open-responses")),
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }
    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &load("aws-open-responses"))
            .expect("encode must succeed for this fixture profile")
    }
    /// SigV4-only profile has no bare-`api_key` fallback, so this subject
    /// overrides the defaulted `credentials()` to supply a real one -- this
    /// is what lets `run::<AwsOpenResponsesSubject>()` reach
    /// `HttpTransport::send` at all instead of failing closed on a missing
    /// credential before ever touching the cassette transport.
    fn credentials() -> Option<Arc<dyn CredentialProvider>> {
        Some(test_sigv4_credentials(&load("aws-open-responses")))
    }
}

#[tokio::test]
async fn nvidia_open_responses_is_conformant() {
    run::<NvidiaOpenResponsesSubject>().await.assert_green();
}
#[tokio::test]
async fn vercel_is_conformant() {
    run::<VercelSubject>().await.assert_green();
}
#[tokio::test]
async fn openrouter_responses_is_conformant() {
    run::<OpenRouterResponsesSubject>().await.assert_green();
}
#[tokio::test]
async fn huggingface_is_conformant() {
    run::<HuggingFaceSubject>().await.assert_green();
}
#[tokio::test]
async fn databricks_is_conformant() {
    run::<DatabricksSubject>().await.assert_green();
}
#[tokio::test]
async fn aws_open_responses_is_conformant() {
    run::<AwsOpenResponsesSubject>().await.assert_green();
}

/// These three tests prove each corrected `error_pointer` is actually
/// consulted by `classify()` -- not merely declared in the TOML -- the same
/// concern `conformance_openai_responses.rs`'s own `openai_responses_error_
/// table_*_maps_to_*` tests exist to close (REALITY-CORRECTIONS §14g).
/// Deliberately status 400 (matching that file's established precedent):
/// `classify`'s HTTP-status fallback tier has its own, independent mapping
/// for 429/500/etc., so a same-status test would pass even if a profile's
/// own `[errors]` table (and, here, its `error_pointer`) were never
/// consulted at all. Status 400 carries none of these codes in the generic
/// fallback tier, so the only way to observe the expected `ProviderError`
/// variant is via this profile's own error-code classification at the
/// pointer it declares.
///
/// Per the task addendum §4 (REALITY-CORRECTIONS §15): the two pointer
/// corrections (openrouter-responses, databricks) were each confirmed by
/// temporarily deleting their profile's `error_pointer` line (falling back
/// to the codec's default `/error/type`, exactly what the brief's
/// un-corrected profile would have parsed to), re-running the matching test
/// here and watching it fail for this exact stated reason, then restoring
/// the line -- see this task's report file for the paired RED/GREEN
/// transcript. That revert is not present in this commit (it would ship a
/// broken profile); only its evidence is.
mod error_pointer_is_load_bearing {
    use super::load;
    use roundhouse_provider::ProviderError;

    fn error_profile(id: &str) -> roundhouse_provider::errors::ErrorProfile {
        load(id).error_profile()
    }

    /// openrouter-responses.toml declares `error_pointer = "/error_type"`
    /// (a top-level field) -- this body puts the matching code exactly
    /// there, nested `error.code` deliberately holds an UNRELATED value
    /// ("server_error", matching the real shape OpenRouter's own docs show:
    /// `{"error": {"code": "server_error", ...}, "error_type":
    /// "payment_required"}`) so this test can only pass if the profile's
    /// OWN corrected pointer -- not the codec's default `/error/type` --
    /// is what `classify()` actually walked.
    #[test]
    fn openrouter_responses_error_table_payment_required_maps_to_quota_exhausted() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error": { "code": "server_error", "message": "synthetic test body" },
            "error_type": "payment_required"
        }))
        .unwrap();
        let classified = roundhouse_provider::errors::classify(
            &error_profile("openrouter-responses"),
            400,
            &body,
            &http::HeaderMap::new(),
        );
        assert!(
            matches!(classified, ProviderError::QuotaExhausted),
            "expected QuotaExhausted (via error_pointer = /error_type), got {classified:?}"
        );
    }

    /// databricks.toml declares `error_pointer = "/error_code"` (a
    /// top-level field, the profile's default `/error/type` would find
    /// nothing here at all since there is no nested "error" object).
    #[test]
    fn databricks_error_table_resource_exhausted_maps_to_rate_limited() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error_code": "RESOURCE_EXHAUSTED",
            "message": "synthetic test body"
        }))
        .unwrap();
        let classified = roundhouse_provider::errors::classify(
            &error_profile("databricks"),
            400,
            &body,
            &http::HeaderMap::new(),
        );
        assert!(
            matches!(classified, ProviderError::RateLimited { .. }),
            "expected RateLimited (via error_pointer = /error_code), got {classified:?}"
        );
    }

    /// vercel.toml keeps the codec's default `/error/type` pointer (its
    /// documented error shape already nests the code there) -- covered here
    /// too so all three of this batch's evidenced [errors] tables get the
    /// same "actually consulted, not decorative" proof.
    #[test]
    fn vercel_error_table_quota_for_entity_exceeded_maps_to_quota_exhausted() {
        let body = serde_json::to_vec(&serde_json::json!({
            "error": { "type": "quota_for_entity_exceeded", "message": "synthetic test body" }
        }))
        .unwrap();
        let classified = roundhouse_provider::errors::classify(
            &error_profile("vercel"),
            400,
            &body,
            &http::HeaderMap::new(),
        );
        assert!(
            matches!(classified, ProviderError::QuotaExhausted),
            "expected QuotaExhausted, got {classified:?}"
        );
    }
}
