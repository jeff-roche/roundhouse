//! §9.9 hardening triad, parts 2-3: host-only base-URL override recording,
//! allow-list header capture for the audit log, and error-body redaction.

use roundhouse_provider::audit::{capture_headers_for_audit, redact_error_body};
use roundhouse_provider::credential::record_base_url_override;

#[test]
fn base_url_override_is_recorded_as_host_only_never_full_url_with_query() {
    // §9.9: "an override is recorded on the task as host only, never a full URL
    // with query string (some gateways put keys in query params)."
    let recorded = record_base_url_override(
        "https://gateway.example.com/v1/chat?api_key=sk-should-never-appear",
    );
    assert_eq!(recorded, "gateway.example.com");
    assert!(
        !recorded.contains("api_key"),
        "recorded override must never carry the query string"
    );
    assert!(
        !recorded.contains("/v1/chat"),
        "recorded override must never carry the path"
    );
}

#[test]
fn header_capture_is_allow_list_only() {
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("x-request-id".to_string(), "req-123".to_string()),
        (
            "authorization".to_string(),
            "Bearer sk-should-never-be-captured".to_string(),
        ),
        (
            "x-api-key".to_string(),
            "should-never-be-captured-either".to_string(),
        ),
    ];
    let captured = capture_headers_for_audit(&headers);
    assert!(captured.iter().any(|(k, _)| k == "content-type"));
    assert!(captured.iter().any(|(k, _)| k == "x-request-id"));
    assert!(
        !captured.iter().any(|(k, _)| k == "authorization"),
        "authorization is never allow-listed, regardless of its value"
    );
    assert!(
        !captured.iter().any(|(k, _)| k == "x-api-key"),
        "x-api-key is never allow-listed, regardless of its value"
    );
}

#[test]
fn error_body_redaction_catches_api_keys_bearer_tokens_and_jwts() {
    let body = r#"{"error":"invalid request","hint":"your key sk-live-abcdEFGH12345678ijklMNOP was rejected","auth":"Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("sk-live-abcdEFGH12345678ijklMNOP"),
        "API-key-shaped string must be redacted"
    );
    assert!(
        !redacted.contains("Bearer eyJhbGciOiJIUzI1NiJ9"),
        "bearer token must be redacted"
    );
    assert!(
        !redacted.contains("eyJzdWIiOiIxMjM0NTY3ODkwIn0"),
        "JWT segment must be redacted"
    );
    assert!(
        redacted.contains("invalid request"),
        "non-secret content must survive redaction"
    );
}

#[test]
fn error_body_redaction_catches_a_jwt_whose_payload_segment_does_not_start_with_eyj() {
    // A9: only a JWT's header segment is guaranteed to start `eyJ`; the
    // payload segment's leading bytes depend on its own first claim and are
    // not. This payload segment ("eyIxMjM0NTY3ODkwIn0" decodes to something
    // whose base64 does not happen to start `eyJ`) would have been missed by
    // a pattern requiring both segments to start `eyJ`.
    let body = r#"{"auth":"Bearer eyJhbGciOiJIUzI1NiJ9.c3ViOjEyMzQ1Njc4OTA.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("c3ViOjEyMzQ1Njc4OTA"),
        "JWT payload segment must be redacted even when it doesn't itself start `eyJ`: {redacted}"
    );
}

#[test]
fn error_body_redaction_catches_aws_and_google_key_shapes_and_labeled_secrets() {
    // A9: the earlier version of this redactor covered only sk-/pk-/rk-
    // prefixed keys, bearer tokens, and JWTs — missing most of what the six
    // credential mechanisms this phase built actually carry.
    let body = r#"{"error":"bad request","access_key_id":"AKIAABCDEFGHIJKLMNOP","google_key":"AIzaSyD-1234567890abcdefghijklmnopqrstu","client_secret":"Tn8Q~1a2B3c4D5e6F7g8H9i0Jk"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("AKIAABCDEFGHIJKLMNOP"),
        "AWS access key ID must be redacted: {redacted}"
    );
    assert!(
        !redacted.contains("AIzaSyD-1234567890abcdefghijklmnopqrstu"),
        "Google API key must be redacted: {redacted}"
    );
    assert!(
        !redacted.contains("Tn8Q~1a2B3c4D5e6F7g8H9i0Jk"),
        "labeled client_secret value must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("bad request"),
        "non-secret content must survive redaction"
    );
}

#[test]
fn error_body_redaction_consumes_the_full_labeled_secret_value_past_punctuation() {
    // B4 (fix-round-2): the labeled-secret pattern's value class stops at
    // the first character outside `[A-Za-z0-9/_+.~-]`, so a value
    // containing punctuation used to redact only its first 16 characters
    // and leave the rest sitting in the persisted body untouched.
    let body = r#"{"client_secret":"abcdefghijklmnop!QRSTUVWX"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("abcdefghijklmnop"),
        "the matched prefix must be redacted: {redacted}"
    );
    assert!(
        !redacted.contains("!QRSTUVWX"),
        "the tail past the first punctuation character must also be redacted, not left \
         behind: {redacted}"
    );
}

#[test]
fn error_body_redaction_does_not_destroy_fields_after_a_labeled_secret_json() {
    // C3 (fix-round-3): B4's fix (`\S*`) is unbounded — it stops only at
    // whitespace or end-of-string. Real provider error bodies are compact
    // JSON with no whitespace between fields, so on a body like this one
    // `\S*` ran clean off the end of the string, destroying
    // `other_field`'s visible, non-secret value. This is fail-safe in
    // direction (over-redaction, never a miss) but destroys exactly the
    // diagnostic content this function exists to preserve. It shipped
    // untested because the round-2 fixture happened to put the labeled
    // secret last, where "eat to end of string" and "eat the tail" are
    // indistinguishable — this fixture puts another field after it.
    let body = r#"{"client_secret":"abcdefghijklmnop!QRSTUVWX","other_field":"visible-value-should-stay"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("abcdefghijklmnop"),
        "the labeled secret must still be redacted: {redacted}"
    );
    assert!(
        redacted.contains("visible-value-should-stay"),
        "a field AFTER the labeled secret must survive redaction, not be swallowed by an \
         unbounded tail match: {redacted}"
    );
    assert!(
        redacted.contains("other_field"),
        "the following field's own key must survive too: {redacted}"
    );
}

#[test]
fn error_body_redaction_does_not_destroy_fields_after_a_labeled_secret_form_encoded() {
    // C3 (fix-round-3): same defect, form-encoded shape (the actual wire
    // shape OAuthRefreshCredential's token request uses, per this task's
    // own A2 fix).
    let body = "grant_type=client_credentials&client_secret=Tn8Q1a2B3c4D5e6F7g8H&client_id=my-app&scope=https://example.com/.default";
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("Tn8Q1a2B3c4D5e6F7g8H"),
        "the labeled secret must still be redacted: {redacted}"
    );
    assert!(
        redacted.contains("client_id=my-app"),
        "fields AFTER the labeled secret must survive: {redacted}"
    );
    assert!(
        redacted.contains("scope=https://example.com/.default"),
        "fields AFTER the labeled secret must survive: {redacted}"
    );
}

/// Audit L4: `API_KEY_SHAPED` used to cover only `sk-`/`pk-`/`rk-`. A
/// provider's own free-prose 401 body (no `label=`/`label:` anchor for
/// `LABELED_SECRET_VALUE`, no `Bearer ` prefix for `BEARER_TOKEN`) echoing a
/// rejected key back verbatim is exactly the shape demonstrated in the
/// audit finding:
/// `"Incorrect API key provided: gsk_ABCDEFGH..."` used to survive
/// redaction untouched.
#[test]
fn error_body_redaction_catches_the_five_newly_added_provider_key_prefixes() {
    let cases = [
        ("Groq", "gsk_wJ3pQ7mN2xK9vR5tL8yH4cA6bD1fE0g"),
        ("Cerebras", "csk-4f8a2b1c9d7e6f5a4b3c2d1e0f9a8b7c"),
        ("Fireworks", "fw_3c8a5b2d1e9f4a7b6c5d4e3f2a1b0c9d"),
        ("xAI", "xai-8f7e6d5c4b3a2918f7e6d5c4b3a29187"),
        ("NVIDIA NIM", "nvapi-a1b2c3d4e5f60718293a4b5c6d7e8f90"),
    ];
    for (vendor, key) in cases {
        let body = format!("Incorrect API key provided: {key}");
        let redacted = redact_error_body(&body);
        assert!(
            !redacted.contains(key),
            "{vendor}'s key-shaped string must be redacted: {redacted}"
        );
        assert!(
            redacted.contains("[REDACTED-KEY]"),
            "{vendor}'s key must be replaced with the redaction marker: {redacted}"
        );
    }
}

/// Audit L4b: this is the residual gap `API_KEY_SHAPED`'s doc comment states
/// deliberately, not one silently forgotten. Mistral, DeepInfra, and Z.ai
/// issue bare opaque tokens with no distinguishing prefix -- in a free-prose
/// 401 with no `label=`/`label:` anchor and no `Bearer ` prefix, nothing in
/// this module matches a bare token, and a generic length-based fallback was
/// deliberately rejected (it would also redact commit SHAs, request IDs, and
/// trace IDs throughout every persisted error body). This test pins that gap
/// down: if it ever starts failing because the string below stops surviving
/// redaction, that's a signal this module's coverage changed, not that this
/// test rotted.
#[test]
fn a_bare_token_key_with_no_prefix_label_or_bearer_anchor_is_not_redacted_a_known_gap() {
    let body = "Incorrect API key provided: yZ4qT9wL2mN7pR5vX8kH1cA6bD3fE0gJ";
    let redacted = redact_error_body(body);
    assert!(
        redacted.contains("yZ4qT9wL2mN7pR5vX8kH1cA6bD3fE0gJ"),
        "a bare-token key with no prefix, label, or Bearer anchor is a known, \
         documented gap in this module's coverage -- it is NOT expected to be \
         redacted here: {redacted}"
    );
}

/// Phase 7 Task 16: `LABELED_SECRET_VALUE`'s alternation had no bare `key`
/// label -- only `client_secret`/`secret_access_key`/`api_key`/
/// `access_token`. A gateway or provider that echoes a bare `key=<value>`
/// (not one of the four existing labels) back in an error body survived
/// redaction untouched until this alternative was added.
#[test]
fn a_bare_key_equals_label_is_redacted() {
    // Deliberately NOT `sk-`/`pk-`/etc.-prefixed -- this must be caught by
    // `LABELED_SECRET_VALUE`'s new bare-`key` alternative, not incidentally
    // by `API_KEY_SHAPED`.
    let body = r#"{"error":"request failed","key":"zQ7mN2xK9vR5tL8yH4cA6bD1fE0g"}"#;
    let redacted = redact_error_body(body);
    assert!(
        !redacted.contains("zQ7mN2xK9vR5tL8yH4cA6bD1fE0g"),
        "a bare `key=`/`key:`-labeled secret must be redacted: {redacted}"
    );
    assert!(
        redacted.contains("request failed"),
        "non-secret content must survive redaction: {redacted}"
    );
}

/// Phase 7 Task 16, the stated trap: `LABELED_SECRET_VALUE` is `(?i)` with no
/// leading word boundary, so naively adding `key` to the alternation would
/// also fire inside `monkey=`, `pubkey=`, `hostkey=` -- words that merely
/// *end* in `key`, not the bare label itself. The fix must anchor `key` on a
/// word boundary so these are left alone.
#[test]
fn a_word_merely_ending_in_key_is_not_mangled() {
    let body = concat!(
        r#"{"monkey":"1234567890123456","#,
        r#""pubkey":"abcdefghijklmnopqrst","#,
        r#""hostkey":"zyxwvutsrqponmlkjihg"}"#
    );
    let redacted = redact_error_body(body);
    assert_eq!(
        redacted, body,
        "a label that merely ends in `key` (monkey/pubkey/hostkey) must not be treated as \
         the bare `key` label: {redacted}"
    );
}
