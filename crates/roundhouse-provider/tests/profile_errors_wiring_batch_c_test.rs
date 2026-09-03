//! Round-8 review, M1/M2: same purpose as `profile_errors_wiring_batch_b_test.rs`,
//! covering Task 12's six batch-C `openai-chat` profiles (Qwen compat mode,
//! LM Studio, vLLM, SGLang, llama.cpp, Ollama `/v1`).

use roundhouse_provider::errors::classify;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ProviderError;

fn load(name: &str) -> ProviderProfile {
    let path = format!("{}/profiles/{name}.toml", env!("CARGO_MANIFEST_DIR"));
    toml::from_str(&std::fs::read_to_string(path).unwrap()).expect("valid profile must deserialize")
}

// ---------------------------------------------------------------------
// Qwen (DashScope compat mode) — nested `{"error":{"code":...,"type":...}}`,
// error_pointer = "/error/code".
// ---------------------------------------------------------------------

fn qwen_body(code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "synthetic test body",
            "type": "invalid_request_error",
            "param": null,
            "code": code,
        },
        "request_id": "test-request-id",
    }))
    .unwrap()
}

#[test]
fn qwen_limit_requests_classifies_as_rate_limited() {
    // Deliberately NOT status 429: the HTTP-status fallback tier would
    // also produce `RateLimited` for a bare 429, which would make this
    // test pass even if the profile's `/error/code` table were never
    // consulted (this is exactly what the pointer-mutation check below
    // catches at status 400 instead).
    let error_profile = load("qwen").error_profile();
    let body = qwen_body("limit_requests");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::RateLimited { .. }));
}

#[test]
fn qwen_insufficient_quota_is_not_in_the_table_and_falls_back_to_retryable_rate_limited() {
    // Ruling P106: DashScope's "429-Throttling.AllocationQuota" (compat-mode
    // code `insufficient_quota`) is a throughput cap, not a permanent billing
    // block -- the vendor code name says "Throttling", and Alibaba's own
    // error docs give the remedy as adjusting call rate / requesting a
    // temporary TPM increase. A `fatal`/QuotaExhausted entry for this code
    // was an unevidenced guess and a behavioural regression versus the
    // pre-entry fallback, so it was removed from qwen.toml rather than
    // reclassified.
    let error_profile = load("qwen").error_profile();

    // Part 1: prove the table is genuinely silent on this code -- not
    // merely agreeing by coincidence with whatever classify() returns below.
    // This assertion is false the instant the entry is re-added under any
    // disposition, which is the whole point.
    assert!(
        !error_profile.code_table.contains_key("insufficient_quota"),
        "the qwen profile's [errors] table must not classify insufficient_quota -- \
         see the comment above that key's deliberate absence in qwen.toml"
    );

    // Part 2: with the table silent, the SAME real HTTP status (429) that
    // limit_requests uses above now hits the HTTP-429 fallback tier in
    // classify(), which is RateLimited -- restoring the pre-entry behaviour.
    let body = qwen_body("insufficient_quota");
    let classified = classify(&error_profile, 429, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited via the HTTP-429 fallback tier, got {classified:?}"
    );

    // Part 3: assert the property that actually matters -- retry.rs will
    // retry this, not just that the enum variant happens to be RateLimited.
    // QuotaExhausted (the old, wrong classification) is Fatal in
    // retry::disposition; RateLimited never is.
    assert_ne!(
        roundhouse_provider::retry::disposition(&classified),
        roundhouse_provider::retry::Disposition::Fatal,
        "insufficient_quota must be retryable now that the qwen profile's error \
         table does not classify it as QuotaExhausted"
    );
}

#[test]
fn qwen_model_not_supported_classifies_as_model_not_found() {
    let error_profile = load("qwen").error_profile();
    let body = qwen_body("model_not_supported");
    // Deliberately not 404: proves the table fired, not the HTTP-status
    // fallback (a real DashScope "unsupported model" response is 404, but
    // using a different status here isolates the table's own effect).
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::ModelNotFound));
}

#[test]
fn qwen_without_the_error_pointer_override_the_generic_type_bucket_does_not_distinguish_codes() {
    // The default `/error/type` pointer resolves to the coarse
    // "invalid_request_error" bucket shared by every one of these bodies --
    // proving `/error/code` (not `/error/type`) is what actually
    // distinguishes them.
    use roundhouse_provider::errors::ErrorProfile;
    let mut wrong_pointer = ErrorProfile::empty();
    wrong_pointer.error_pointer = "/error/type".to_string();
    for kind in [
        "limit_requests",
        "insufficient_quota",
        "model_not_supported",
    ] {
        let body = qwen_body(kind);
        let classified = classify(&wrong_pointer, 400, &body, &http::HeaderMap::new());
        assert!(
            matches!(classified, ProviderError::BadRequest { status: 400, .. }),
            "expected the /error/type-keyed lookup to miss for {kind:?}, got {classified:?}"
        );
    }
}

// ---------------------------------------------------------------------
// LM Studio — deliberately empty table (code is null, type is a shared
// generic bucket).
// ---------------------------------------------------------------------

#[test]
fn lm_studio_error_table_is_deliberately_empty() {
    let error_profile = load("lm-studio").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "LM Studio's real 'no model loaded' body has code: null and a \
         shared generic type bucket -- nothing to key a code_table on"
    );
}

#[test]
fn lm_studio_real_shaped_no_model_loaded_body_falls_back_to_status_default() {
    let error_profile = load("lm-studio").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "No models loaded. Please load a model in the developer page or use the 'lms load' command.",
            "type": "invalid_request_error",
            "param": "model",
            "code": null,
        }
    }))
    .unwrap();
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(matches!(
        classified,
        ProviderError::BadRequest { status: 400, .. }
    ));
}

// ---------------------------------------------------------------------
// vLLM — nested `{"error":{"type":...}}` (default pointer resolves).
// ---------------------------------------------------------------------

#[test]
fn vllm_service_unavailable_classifies_as_overloaded_not_a_generic_server_error() {
    let error_profile = load("vllm").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "The engine is currently busy and cannot accept new requests.",
            "type": "Service Unavailable",
            "param": null,
            "code": 503,
        }
    }))
    .unwrap();
    let classified = classify(&error_profile, 503, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded (not the generic Server{{503}} fallback), got {classified:?}"
    );
}

#[test]
fn vllm_without_the_table_the_same_body_is_a_generic_server_error() {
    use roundhouse_provider::errors::ErrorProfile;
    let empty = ErrorProfile::empty();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "The engine is currently busy and cannot accept new requests.",
            "type": "Service Unavailable",
            "param": null,
            "code": 503,
        }
    }))
    .unwrap();
    let classified = classify(&empty, 503, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::Server { status: 503 }));
}

// ---------------------------------------------------------------------
// SGLang — deliberately empty table (flat shape, ambiguous type buckets).
// ---------------------------------------------------------------------

#[test]
fn sglang_error_table_is_deliberately_empty() {
    let error_profile = load("sglang").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "SGLang's real 'InternalServerError'/'BadRequest' buckets cover \
         both genuine bugs and capacity conditions alike -- no confident \
         mapping to a single ProviderErrorKind exists"
    );
}

#[test]
fn sglang_real_shaped_internal_server_error_body_falls_back_to_status_default() {
    let error_profile = load("sglang").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "object": "error",
        "message": "synthetic test body",
        "type": "InternalServerError",
        "param": null,
        "code": 500,
    }))
    .unwrap();
    let classified = classify(&error_profile, 500, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::Server { status: 500 }));
}

// ---------------------------------------------------------------------
// llama.cpp — deliberately empty table (default-200 "no slot" shape).
// ---------------------------------------------------------------------

#[test]
fn llama_cpp_error_table_is_deliberately_empty() {
    let error_profile = load("llama-cpp").error_profile();
    assert!(
        error_profile.code_table.is_empty(),
        "llama.cpp's 'no slot available' body arrives at HTTP 200 by \
         default; the codec does not opt into fail_on_no_slot, so no \
         reliable non-2xx signal exists to key a code_table on"
    );
}

// ---------------------------------------------------------------------
// Ollama — nested `{"error":{"type":...}}` (default pointer resolves).
// ---------------------------------------------------------------------

#[test]
fn ollama_not_found_error_classifies_as_model_not_found() {
    let error_profile = load("ollama").error_profile();
    let body = serde_json::to_vec(&serde_json::json!({
        "error": {
            "message": "model 'nonexistent' not found",
            "type": "not_found_error",
            "param": null,
            "code": null,
        }
    }))
    .unwrap();
    // Deliberately not 404: proves the table fired, not the HTTP-status
    // fallback (which would also give ModelNotFound for a bare 404 --
    // using 400 here isolates the table's own effect).
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(matches!(classified, ProviderError::ModelNotFound));
}

#[test]
fn ollama_api_error_bucket_is_not_in_the_table() {
    // Ollama's third, catch-all bucket ("api_error") covers both genuine
    // rate limiting and unrelated failures alike -- must not be guessed.
    let error_profile = load("ollama").error_profile();
    assert!(!error_profile.code_table.contains_key("api_error"));
}
