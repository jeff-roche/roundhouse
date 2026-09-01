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
