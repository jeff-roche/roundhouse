use http::HeaderMap;
use roundhouse_provider::errors::{classify, ErrorProfile};
use roundhouse_provider::ProviderError;

#[test]
fn html_body_on_5xx_never_panics_and_classifies_as_server_error() {
    let profile = ErrorProfile::empty();
    // Moonshot's real failure mode: a 900s gateway timeout returns raw HTML, not JSON.
    let body = b"<html><body>504 Gateway Time-out</body></html>";
    let result = classify(&profile, 504, body, &HeaderMap::new());
    assert!(matches!(result, ProviderError::Server { status: 504 }));
}

#[test]
fn provider_error_code_table_takes_precedence_over_http_status() {
    let profile = ErrorProfile::anthropic_like();
    let body = br#"{"type":"error","error":{"type":"rate_limit_error","message":"..."}}"#;
    let result = classify(&profile, 429, body, &HeaderMap::new());
    assert!(matches!(result, ProviderError::RateLimited { .. }));
}

#[test]
fn quota_exhausted_is_never_retryable_by_classification() {
    let profile = ErrorProfile::anthropic_like();
    let body = br#"{"type":"error","error":{"type":"invalid_request_error","message":"credit balance too low"}}"#;
    let result = classify(&profile, 400, body, &HeaderMap::new());
    assert!(matches!(result, ProviderError::QuotaExhausted));
}
