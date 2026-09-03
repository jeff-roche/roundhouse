//! Task 17 -- `roundhouse-conformance` wiring for the two `google-genai`
//! batch profiles, both run under `EndpointMode::GenerateContent` (Vertex
//! Gemini does not speak the Interactions API -- see `vertex-gemini.toml`'s
//! own citation; the legacy first-party profile is explicitly the
//! GenerateContent surface by design). Mirrors
//! `conformance_google_genai.rs`'s (Task 6's) shape and
//! REALITY-CORRECTIONS §12c: each mask is derived from that profile's own
//! `ParamsPolicy::allowed_fields()`, never a shared/hardcoded one.
//!
//! Cassette provenance (REALITY-CORRECTIONS §13b item 3): both cassettes'
//! bytes are copied verbatim from `testdata/cassettes/google_genai/
//! generate_content_text.cassette` (Task 6's own, built from the verified
//! `generate-content.md.txt` schemas -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md`) -- the
//! wire *content* shape these two profiles produce is byte-identical to
//! first-party GenerateContent mode's (`encode_generate_content` needs no
//! per-profile changes; only the request envelope/URL/auth differ, and
//! those are exercised by `stream_chat`, not by cassette replay). Both
//! terminate with the required trailing blank line.

use roundhouse_conformance::{run, ConformanceCase, ConformanceSubject, SerializeOnlyMask};
use roundhouse_provider::codec::google_genai::encode::encode;
use roundhouse_provider::codec::google_genai::{EndpointMode, GoogleGenAiProvider};
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ChatRequest;

#[path = "support/google_genai_fixtures.rs"]
mod fixtures;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cassette_path(dir: &str, name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/cassettes")
        .join(dir)
        .join(name)
}

/// REALITY-CORRECTIONS §12c: the mask for `single_turn_text()`'s encoded
/// wire body under `EndpointMode::GenerateContent`
/// (`{"contents":[{"role":"user","parts":[{"text":"..."}]}]}` -- verified
/// directly via a throwaway probe against `encode(&fixtures::
/// single_turn_text(), &profile, EndpointMode::GenerateContent)`, not
/// guessed), derived per profile from that profile's own `ParamsPolicy`.
/// Both batch profiles declare `params = { mode = "deny_list", fields = []
/// }` (deny nothing), so `allowed_fields` is the full `all_known` list
/// either way -- the mechanism is still exercised per profile, not shared
/// as one hardcoded constant, matching Tasks 15/16.
fn mask(profile: &ProviderProfile) -> SerializeOnlyMask {
    let all_known: &[&str] = &[
        "contents",
        "contents.role",
        "contents.parts",
        "contents.parts.text",
    ];
    SerializeOnlyMask {
        mandatory: vec!["contents".into()],
        allowed: profile.defaults.params.allowed_fields(all_known),
    }
}

struct VertexGeminiSubject;

impl ConformanceSubject for VertexGeminiSubject {
    type Provider = GoogleGenAiProvider;

    fn provider() -> Self::Provider {
        GoogleGenAiProvider::new(load("vertex-gemini"), EndpointMode::GenerateContent)
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text(),
            cassette_path: cassette_path("vertex_gemini", "text.cassette"),
            mask: mask(&load("vertex-gemini")),
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(req, &load("vertex-gemini"), EndpointMode::GenerateContent)
            .expect("encode must succeed for this fixture profile")
    }
}

struct GenerateContentLegacySubject;

impl ConformanceSubject for GenerateContentLegacySubject {
    type Provider = GoogleGenAiProvider;

    fn provider() -> Self::Provider {
        GoogleGenAiProvider::new(
            load("gemini-generate-content-legacy"),
            EndpointMode::GenerateContent,
        )
    }

    fn cases() -> Vec<ConformanceCase> {
        vec![ConformanceCase {
            name: "text",
            request: fixtures::single_turn_text(),
            cassette_path: cassette_path("gemini_generate_content_legacy", "text.cassette"),
            mask: mask(&load("gemini-generate-content-legacy")),
            declared_loss_events: vec![],
            expected_error: None,
        }]
    }

    fn wire_body(req: &ChatRequest) -> serde_json::Value {
        encode(
            req,
            &load("gemini-generate-content-legacy"),
            EndpointMode::GenerateContent,
        )
        .expect("encode must succeed for this fixture profile")
    }
}

#[tokio::test]
async fn vertex_gemini_is_conformant() {
    run::<VertexGeminiSubject>().await.assert_green();
}

#[tokio::test]
async fn generate_content_legacy_is_conformant() {
    run::<GenerateContentLegacySubject>().await.assert_green();
}
