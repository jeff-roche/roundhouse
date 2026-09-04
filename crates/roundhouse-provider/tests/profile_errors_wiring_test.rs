//! REALITY-CORRECTIONS §14g: every profile TOML carries an `[errors]` table,
//! but nothing in the plan ever reads it — `ProviderProfile::error_profile()`
//! wires it into the real §9.8 classification path (`crate::errors::classify`)
//! so a profile's declared error codes actually change how a response body
//! carrying that code gets classified.

use roundhouse_provider::errors::classify;
use roundhouse_provider::profile::ProviderProfile;
use roundhouse_provider::ProviderError;

const MOONSHOT_TOML: &str = include_str!("../profiles/moonshot.toml");

fn moonshot_profile() -> ProviderProfile {
    toml::from_str(MOONSHOT_TOML).expect("valid profile must deserialize")
}

fn body_with_error_type(code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "error": { "type": code, "message": "synthetic test body" }
    }))
    .unwrap()
}

#[test]
fn retry_backoff_disposition_classifies_as_overloaded() {
    let error_profile = moonshot_profile().error_profile();
    let body = body_with_error_type("engine_overloaded_error");
    let classified = classify(&error_profile, 503, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Overloaded),
        "expected Overloaded, got {classified:?}"
    );
}

#[test]
fn shed_concurrency_disposition_classifies_as_rate_limited() {
    // Deliberately NOT status 429: the HTTP-status fallback tier (§9.8's
    // third tier) would also produce `RateLimited` for a bare 429, which
    // would make this test pass even if the profile's error table were
    // never consulted at all. Using 400 here means the only way to observe
    // `RateLimited` is via the profile's own error-code classification.
    let error_profile = moonshot_profile().error_profile();
    let body = body_with_error_type("rate_limit_reached_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::RateLimited { .. }),
        "expected RateLimited, got {classified:?}"
    );
}

#[test]
fn fatal_quota_disposition_classifies_as_quota_exhausted() {
    let error_profile = moonshot_profile().error_profile();
    let body = body_with_error_type("exceeded_current_quota_error");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::QuotaExhausted),
        "expected QuotaExhausted, got {classified:?}"
    );
}

/// Without the profile's error table, the same body falls through to the
/// HTTP-status default (§9.8's third tier) instead of the provider-specific
/// classification — this is the "before" case that proves the wiring, not
/// just the codec's status-code fallback, is what changed the outcome above.
#[test]
fn without_the_profile_error_table_the_same_body_falls_back_to_status_default() {
    use roundhouse_provider::errors::ErrorProfile;
    let empty = ErrorProfile::empty();
    let body = body_with_error_type("engine_overloaded_error");
    let classified = classify(&empty, 503, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::Server { status: 503 }),
        "expected the HTTP-status fallback (Server{{503}}), got {classified:?}"
    );
}

/// Builds a minimal, otherwise-valid `ProviderProfile` whose only interesting
/// content is the `[errors.*]` table(s) supplied by `errors_toml` — lets the
/// two fix-round-1 (E1) tests below exercise a `Fatal` disposition shape that
/// `moonshot.toml` doesn't have (moonshot's one `Fatal` entry is always
/// `category = "quota"`, an exact-fit case).
fn profile_with_errors(errors_toml: &str) -> ProviderProfile {
    let toml_src = format!(
        r#"
        id = "fixture"
        codec = "openai-chat"

        [defaults]
        allow_raw_extra = false
        base_url = "https://example.invalid"

        [defaults.params]
        mode = "allow_only"
        fields = []

        [defaults.auth]
        kind = "bearer"

        {errors_toml}
        "#
    );
    toml::from_str(&toml_src).expect("fixture profile must deserialize")
}

/// Fix round 1, E1: an unrecognized-`Fatal` code must NOT be asserted as
/// `QuotaExhausted` — that would be a confidently wrong, actionable claim
/// about billing state for what might be a permanent auth failure or a
/// content-policy rejection. `error_kind()` returns `None` for this shape,
/// `error_profile()` skips it entirely, and `classify()` falls through to
/// its existing, already-tested HTTP-status tier.
#[test]
fn fatal_disposition_with_an_unrecognized_category_falls_through_to_status_default() {
    let profile = profile_with_errors(
        r#"
        [errors.content_policy_violation]
        disposition = "fatal"
        category = "content_policy"
        "#,
    );
    let error_profile = profile.error_profile();
    let body = body_with_error_type("content_policy_violation");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::BadRequest { status: 400, .. }),
        "an unrecognized Fatal category must fall through to the HTTP-status \
         default, not assert a specific ProviderErrorKind — got {classified:?}"
    );
}

/// Same as above, for the even more common real shape: `disposition =
/// "fatal"` with no `category` key at all.
#[test]
fn fatal_disposition_with_no_category_at_all_falls_through_to_status_default() {
    let profile = profile_with_errors(
        r#"
        [errors.some_fatal_code]
        disposition = "fatal"
        "#,
    );
    let error_profile = profile.error_profile();
    let body = body_with_error_type("some_fatal_code");
    let classified = classify(&error_profile, 400, &body, &http::HeaderMap::new());
    assert!(
        matches!(classified, ProviderError::BadRequest { status: 400, .. }),
        "a Fatal entry with no category at all must fall through to the \
         HTTP-status default — got {classified:?}"
    );
}
