//! Task 17 -- deserialization/shape tests for the two `google-genai` batch
//! profiles: `vertex-gemini` (Vertex AI's Gemini via the classic
//! `generateContent`/`streamGenerateContent` surface, Bearer/OAuth auth) and
//! `gemini-generate-content-legacy` (first-party Gemini, same surface,
//! `x-goog-api-key` header auth). Mirrors Tasks 15/16's own
//! `profile_test_*_batch*.rs` files.

use roundhouse_provider::profile::{AuthKind, ProviderProfile};

fn load(name: &str) -> ProviderProfile {
    // REALITY-CORRECTIONS §10: `CARGO_MANIFEST_DIR` for this crate's tests
    // is `crates/roundhouse-provider` -- no `../` (the brief's own helper
    // had one, which resolves to `crates/profiles/` and is wrong).
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

#[test]
fn vertex_gemini_profile_uses_google_oauth_bearer_not_the_api_key_header() {
    // Vertex resolves auth via Google OAuth (service account / ADC), unlike
    // first-party google-genai.toml's x-goog-api-key header (Task 4/6).
    let p = load("vertex-gemini");
    assert_eq!(p.codec, "google-genai");
    assert!(matches!(p.defaults.auth, AuthKind::Bearer));
}

/// The brief's own draft base_url (`.../locations/us-east5/...`) would have
/// produced a valid-looking but wrong-shaped host under a regional endpoint;
/// this profile uses the documented global endpoint instead (see the TOML's
/// own citation) -- assert the properties that matter regardless of which
/// region/endpoint choice: the real Vertex host and the real
/// `publishers/google/models` resource path (not first-party's host, and
/// not a bare "/models" without the publisher segment).
#[test]
fn vertex_gemini_profile_uses_the_real_vertex_publisher_model_resource_path() {
    let p = load("vertex-gemini");
    assert!(p.defaults.base_url.contains("aiplatform.googleapis.com"));
    assert!(p.defaults.base_url.contains("/publishers/google/models"));
    assert!(
        !p.defaults.base_url.contains("v1beta"),
        "Vertex's real REST path has no v1beta segment (verified) -- \
         base_url = {:?}",
        p.defaults.base_url
    );
}

#[test]
fn generate_content_legacy_profile_shape() {
    let p = load("gemini-generate-content-legacy");
    assert_eq!(p.codec, "google-genai");
    assert!(p
        .defaults
        .base_url
        .contains("generativelanguage.googleapis.com"));
    assert!(matches!(p.defaults.auth, AuthKind::HeaderKey { .. }));
}

/// The exact bug this profile's own module comment reports as a divergence
/// from the brief: the brief's sample `base_url` was
/// "https://generativelanguage.googleapis.com/v1beta", which -- combined
/// with `build_endpoint_url`'s own hardcoded "/v1beta/models/{model}:..."
/// suffix for `EndpointMode::GenerateContent` -- would have produced a
/// double "v1beta/v1beta" path. Pin the real, correct value directly so a
/// future edit can't silently reintroduce the "/v1beta" suffix.
#[test]
fn generate_content_legacy_base_url_is_the_bare_host_not_pre_suffixed_with_v1beta() {
    let p = load("gemini-generate-content-legacy");
    assert_eq!(
        p.defaults.base_url, "https://generativelanguage.googleapis.com",
        "base_url must be the bare host -- build_endpoint_url's GenerateContent branch already \
         appends /v1beta/models/{{model}}:streamGenerateContent itself; pre-appending /v1beta \
         here would double it"
    );
}

/// Both profiles' reasoning tables must declare `value_type = "number"`
/// (Task 17 addendum SS1 / Ruling P108) -- `thinkingBudget` is a genuine
/// JSON number on the wire, and the default `value_type` (`"string"`) would
/// silently regress the resolved value to a quoted string once the encoder
/// routes through `resolve_wire_value`. `build.rs`'s
/// `validate_value_type`/codec guard already enforce a consistent,
/// non-vacuous declaration at build time (a profile that got this wrong
/// would fail `cargo build` outright) -- this test additionally pins the
/// deserialized runtime value, since a build-time-only guarantee is easy to
/// lose track of when reading the shipped profile alone.
#[test]
fn both_batch_profiles_declare_a_numeric_thinking_budget_value_type() {
    use roundhouse_provider::profile::ReasoningValueType;
    for name in ["vertex-gemini", "gemini-generate-content-legacy"] {
        let p = load(name);
        let control = p.model[0]
            .reasoning
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: expected a [[model]].reasoning table"));
        assert_eq!(
            control.value_type,
            ReasoningValueType::Number,
            "{name}: expected value_type = \"number\""
        );
    }
}
