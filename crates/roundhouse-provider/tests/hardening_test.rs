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
