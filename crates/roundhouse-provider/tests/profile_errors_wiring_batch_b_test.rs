//! Round-8 review, M1/M2: `profile_errors_wiring_test.rs` proves the
//! `[errors]` -> `classify()` wiring works for moonshot (whose real error
//! body already happened to match the hardcoded `/error/type` default).
//! This file proves it for Task 11's six batch-B `openai-chat` profiles
//! (Mistral, DeepSeek, Z.ai, xAI, NVIDIA NIM, DeepInfra), whose real error
//! bodies mostly do NOT match that default — exercising the actual
//! `error_pointer` field this round's fix adds. Each profile's TOML module
//! comment cites where its real error shape was verified; these tests feed
//! that verified shape through `classify()` and assert the resulting
//! `ProviderError`, per M2's requirement (do not just assert the profile
//! parses).

use roundhouse_provider::errors::classify;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ProviderError;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

// ---------------------------------------------------------------------
// Mistral — flat `{"object":"error","message":...,"type":...,"param":...,
// "code":...}`, error_pointer = "/type".
// ---------------------------------------------------------------------

fn mistral_body(error_type: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "object": "error",
        "message": "synthetic test body",
        "type": error_type,
        "param": null,
        "code": null,
    }))
    .unwrap()
}

#[test]
fn mistral_server_error_classifies_as_overloaded() {
    let error_profile = load("mistral").error_profile();
    // Deliberately not a 5xx status: the HTTP-status fallback tier would
    // also produce `Server{status}` for a bare 5xx (a DIFFERENT variant
    // than `Overloaded`, but proving the table fires needs a status the
    // fallback tier maps to something else entirely -- 400 makes the only
    // way to observe `Overloaded` the profile's own classification).
    let body = mistral_body("server_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn mistral_rate_limit_error_classifies_as_rate_limited() {
    let error_profile = load("mistral").error_profile();
    let body = mistral_body("rate_limit_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}

#[test]
fn mistral_authentication_error_is_not_asserted_as_quota_exhausted() {
    // Mistral's glossary documents no distinct billing/quota error type --
    // `authentication_error` means "your key is wrong", not "you're out of
    // quota". This profile deliberately does not map it to anything.
    let error_profile = load("mistral").error_profile();
    let body = mistral_body("authentication_error");
    let classified = classify(&error_profile, 401, &body, &http::HeaderMap::new());
    assert!(
        !matches!(classified, ProviderError::QuotaExhausted),
        "authentication_error must not be asserted as QuotaExhausted: {classified:?}"
    );
}

/// The default `/error/type` pointer never resolves against Mistral's flat
/// shape -- without the profile's `error_pointer = "/type"` override, the
/// same body would fall through to the HTTP-status default instead.
#[test]
fn mistral_without_the_error_pointer_override_the_same_body_falls_back_to_status_default() {
    use roundhouse_provider::errors::ErrorProfile;
    let empty = ErrorProfile::empty(); // error_pointer defaults to "/error/type"
    let body = mistral_body("server_error");
    let classified = classify(&empty, 503, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Server { status: 503 }),
        "expected the HTTP-status fallback (Server{{503}}), got {classified:?}"
    );
}

// ---------------------------------------------------------------------
// DeepSeek — deliberately empty table (unmatchable flat `error` string).
// ---------------------------------------------------------------------

#[test]
fn deepseek_error_table_is_deliberately_empty() {
    let error_profile = load("deepseek").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "DeepSeek's real error body is an unstructured string with no \
         matchable code field -- the table must stay empty rather than \
         match on message text"
    );
}

#[test]
fn deepseek_real_shaped_body_still_falls_back_to_the_http_status_tier() {
    let error_profile = load("deepseek").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": "429 Too Many Requests",
        "message": "Rate limit exceeded. Please retry later.",
    }))
    .unwrap();
    let classified = classify(&error_profile, 429, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::RateLimited { .. }));
}

// ---------------------------------------------------------------------
// Z.ai — nested `{"error":{"code":"XXXX","message":...}}`, error_pointer
// = "/error/code".
// ---------------------------------------------------------------------

fn zai_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": { "code": code, "message": "synthetic test body" }
    }))
    .unwrap()
}

#[test]
fn zai_rate_limit_reached_classifies_as_rate_limited() {
    // Deliberately NOT status 429: the HTTP-status fallback tier would
    // also produce `RateLimited` for a bare 429, which would make this
    // test pass even if the profile's code table were never consulted.
    let error_profile = load("zai").error_profile();
    let body = zai_body("1302");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::RateLimited { .. }));
}

#[test]
fn zai_temporarily_overloaded_classifies_as_overloaded_not_rate_limited() {
    // 1305 and 1302 share the same real HTTP status (429): only the
    // profile's own code table -- not the HTTP-status fallback -- can
    // distinguish "overloaded" (1305) from "rate limited" (1302).
    let error_profile = load("zai").error_profile();
    let body = zai_body("1305");
    let classified = classify(&error_profile, 429, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn zai_insufficient_balance_classifies_as_quota_exhausted_not_rate_limited() {
    // The exact "billing masquerading as a 429" shape errors.rs's module
    // doc calls out: without the profile's own code table, a bare 429
    // fallback would (wrongly) call this retryable.
    let error_profile = load("zai").error_profile();
    let body = zai_body("1113");
    let classified = classify(&error_profile, 429, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {classified:?}"
    );
}

#[test]
fn zai_content_policy_code_is_not_in_the_table() {
    // 1301 (content-safety rejection) maps to none of the four
    // ProviderErrorKind variants and must not have been guessed into one.
    let error_profile = load("zai").error_profile();
    assert!(!error_profile.code_table.contains_key("1301"));
}

// ---------------------------------------------------------------------
// xAI — flat `{"code": "...", "error": "..."}`, error_pointer = "/code".
// ---------------------------------------------------------------------

#[test]
fn xai_service_unavailable_code_classifies_as_overloaded() {
    let error_profile = load("xai").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "code": "The service is currently unavailable",
        "error": "Timed out waiting for first token",
    }))
    .unwrap();
    // Deliberately not a 5xx: proves the profile's own table fired, not
    // the HTTP-status fallback tier (which would give Server{400}, a
    // different variant than Overloaded).
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn xai_without_the_error_pointer_override_the_same_body_falls_back_to_status_default() {
    use roundhouse_provider::errors::ErrorProfile;
    let empty = ErrorProfile::empty();
    let body = serde_json::to_vec(&serde_json::json!({
        "code": "The service is currently unavailable",
        "error": "Timed out waiting for first token",
    }))
    .unwrap();
    let classified = classify(&empty, 503, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::Server { status: 503 }));
}

// ---------------------------------------------------------------------
// NVIDIA NIM — deliberately empty table (title mirrors HTTP status 1:1).
// ---------------------------------------------------------------------

#[test]
fn nvidia_nim_error_table_is_deliberately_empty() {
    let error_profile = load("nvidia-nim").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "NIM's RFC 7807 `title` field carries no information beyond the \
         raw HTTP status the fallback tier already uses"
    );
}

#[test]
fn nvidia_nim_real_shaped_body_still_falls_back_to_the_http_status_tier() {
    let error_profile = load("nvidia-nim").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "status": 429,
        "title": "Too Many Requests",
    }))
    .unwrap();
    let classified = classify(&error_profile, 429, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::RateLimited { .. }));
}

// ---------------------------------------------------------------------
// DeepInfra — deliberately empty table (only reachable code doesn't map
// to any ProviderErrorKind), error_pointer = "/error/code".
// ---------------------------------------------------------------------

#[test]
fn deepinfra_error_table_is_deliberately_empty() {
    let error_profile = load("deepinfra").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "the only DeepInfra code observed live (invalid_api_key) is an \
         auth failure, not one of the four ProviderErrorKind conditions"
    );
}

#[test]
fn deepinfra_real_captured_auth_failure_body_falls_back_to_status_default() {
    // The exact body captured live from api.deepinfra.com (2026-09, see
    // deepinfra.toml's module comment).
    let error_profile = load("deepinfra").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "User is not authorized to access this resource",
            "type": "invalid_request_error",
            "param": null,
            "code": "invalid_api_key",
        }
    }))
    .unwrap();
    let classified = classify(&error_profile, 401, &body, &http::HeaderMap::new());
    assert!(matches!(
        classified,
        ProviderError::BadRequest { status: 401, .. }
    ));
}
