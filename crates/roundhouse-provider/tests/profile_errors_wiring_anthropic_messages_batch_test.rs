//! REALITY-CORRECTIONS §14g / this task's addendum §3 (the M1 lesson):
//! proves each of Task 15's six `anthropic-messages` batch profiles'
//! `[errors]` table is actually consulted by `crate::errors::classify`, not
//! merely deserialized and ignored -- and that an empty table (qwen-anthropic,
//! deepinfra-anthropic) is genuinely empty, not silently populated by a
//! default.
//!
//! Every populated-table test below deliberately uses a NON-matching HTTP
//! status (never the status `classify()`'s own generic fallback tier would
//! independently produce the same `ProviderError` for), matching
//! `profile_errors_wiring_batch_c_test.rs`'s established technique -- this
//! isolates whether the profile's own table genuinely fired, not a
//! coincidental agreement with the fallback tier.

use roundhouse_provider::errors::classify;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ProviderError;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

// ---------------------------------------------------------------------
// vertex-anthropic — google.rpc.Status shape, error_pointer = "/error/status".
// ---------------------------------------------------------------------

fn vertex_body(status_code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": {
            "code": 400,
            "message": "synthetic test body",
            "status": status_code,
        }
    }))
    .unwrap()
}

#[test]
fn vertex_resource_exhausted_classifies_as_rate_limited_not_fatal() {
    // Deliberately NOT status 429 -- isolates the table's own effect.
    let error_profile = load("vertex-anthropic").error_profile();
    let body = vertex_body("RESOURCE_EXHAUSTED");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
    // Ruling P106: never fatal for a throttling-shaped code.
    assert_ne!(
        roundhouse_provider::retry::disposition(&classified),
        roundhouse_provider::retry::Disposition::Fatal,
        "RESOURCE_EXHAUSTED must be retryable"
    );
}

#[test]
fn vertex_unavailable_classifies_as_overloaded() {
    // Deliberately NOT status 503 -- isolates the table's own effect.
    let error_profile = load("vertex-anthropic").error_profile();
    let body = vertex_body("UNAVAILABLE");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn vertex_permission_denied_is_not_in_the_table_and_falls_back_to_status_default() {
    // AIP-193: PERMISSION_DENIED is a genuine, permanent auth failure that
    // does not map to QuotaExhausted or ModelNotFound (the only two
    // ProviderErrorKind variants a `fatal` entry can express) -- deliberately
    // left out of vertex-anthropic.toml rather than guessed onto one of them.
    let error_profile = load("vertex-anthropic").error_profile();
    assert!(
        !error_profile.code_table.contains_key("PERMISSION_DENIED"),
        "the vertex-anthropic profile's [errors] table must not classify \
         PERMISSION_DENIED -- see the comment above that key's deliberate \
         absence in vertex-anthropic.toml"
    );
    let body = vertex_body("PERMISSION_DENIED");
    let classified = classify(&error_profile, 403, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::BadRequest { status: 403, .. }),
        "expected the generic HTTP-status fallback, got {classified:?}"
    );
}

#[test]
fn vertex_without_the_error_pointer_override_the_default_pointer_never_matches() {
    // Proves /error/status (not this codec's default /error/type) is what
    // actually resolves Vertex's error codes.
    use roundhouse_provider::errors::ErrorProfile;
    let mut wrong_pointer = ErrorProfile::empty();
    wrong_pointer.error_pointer = "/error/type".to_string();
    let body = vertex_body("RESOURCE_EXHAUSTED");
    let classified = classify(&wrong_pointer, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::BadRequest { status: 400, .. }),
        "expected the /error/type-keyed lookup to miss, got {classified:?}"
    );
}

// ---------------------------------------------------------------------
// microsoft-foundry — Anthropic-native shape, default error_pointer.
// ---------------------------------------------------------------------

fn anthropic_native_body(error_type: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "type": "error",
        "error": {
            "type": error_type,
            "message": "synthetic test body",
        }
    }))
    .unwrap()
}

#[test]
fn microsoft_foundry_overloaded_error_classifies_as_overloaded() {
    let error_profile = load("microsoft-foundry").error_profile();
    let body = anthropic_native_body("overloaded_error");
    // Deliberately not 529 (Anthropic's real overloaded status) -- isolates
    // the table's own effect.
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn microsoft_foundry_rate_limit_error_classifies_as_rate_limited() {
    let error_profile = load("microsoft-foundry").error_profile();
    let body = anthropic_native_body("rate_limit_error");
    // Deliberately not 429 -- isolates the table's own effect.
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}

// ---------------------------------------------------------------------
// qwen-anthropic — deliberately empty table.
// ---------------------------------------------------------------------

#[test]
fn qwen_anthropic_error_table_is_deliberately_empty() {
    let error_profile = load("qwen-anthropic").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "qwen-anthropic.toml's own comment explains why: the only documented \
         DashScope error codes found are for a DIFFERENT compat surface, and \
         no live-captured or vendor-documented shape exists for this specific \
         Anthropic-compat endpoint"
    );
}

// ---------------------------------------------------------------------
// openrouter-anthropic — Anthropic-native shape (OpenRouter's own
// documented Anthropic-endpoint error mapping), default error_pointer.
// ---------------------------------------------------------------------

#[test]
fn openrouter_anthropic_rate_limit_error_classifies_as_rate_limited() {
    let error_profile = load("openrouter-anthropic").error_profile();
    let body = anthropic_native_body("rate_limit_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}

#[test]
fn openrouter_anthropic_overloaded_error_classifies_as_overloaded() {
    let error_profile = load("openrouter-anthropic").error_profile();
    let body = anthropic_native_body("overloaded_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn openrouter_anthropic_billing_error_classifies_as_quota_exhausted() {
    let error_profile = load("openrouter-anthropic").error_profile();
    let body = anthropic_native_body("billing_error");
    // Deliberately not 402 (OpenRouter's real payment_required status) --
    // isolates the table's own effect.
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {classified:?}"
    );
    // A genuine billing block IS fatal -- the opposite direction from
    // RESOURCE_EXHAUSTED/rate_limit_error above, and correctly so.
    assert_eq!(
        roundhouse_provider::retry::disposition(&classified),
        roundhouse_provider::retry::Disposition::Fatal
    );
}

// ---------------------------------------------------------------------
// deepinfra-anthropic — deliberately empty table.
// ---------------------------------------------------------------------

#[test]
fn deepinfra_anthropic_error_table_is_deliberately_empty() {
    let error_profile = load("deepinfra-anthropic").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "deepinfra-anthropic.toml's own comment explains why: DeepInfra's \
         docs document no error response shape or codes at all"
    );
}

// ---------------------------------------------------------------------
// bedrock-anthropic-messages — Anthropic-native shape, default error_pointer.
// ---------------------------------------------------------------------

#[test]
fn bedrock_anthropic_messages_overloaded_error_classifies_as_overloaded() {
    let error_profile = load("bedrock-anthropic-messages").error_profile();
    let body = anthropic_native_body("overloaded_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn bedrock_anthropic_messages_rate_limit_error_classifies_as_rate_limited() {
    let error_profile = load("bedrock-anthropic-messages").error_profile();
    let body = anthropic_native_body("rate_limit_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}
