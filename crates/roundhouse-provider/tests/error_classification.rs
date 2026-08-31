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
    // Anthropic's real, verbatim error text (not a synthetic substring):
    // "Your credit balance is too low to access the Anthropic API."
    let body = br#"{"type":"error","error":{"type":"invalid_request_error","message":"Your credit balance is too low to access the Anthropic API."}}"#;
    let result = classify(&profile, 400, body, &HeaderMap::new());
    assert!(matches!(result, ProviderError::QuotaExhausted));
}

#[test]
fn retry_after_header_is_clamped_to_a_sane_ceiling() {
    let profile = ErrorProfile::empty();
    let mut headers = HeaderMap::new();
    // A hostile or buggy provider sending an enormous Retry-After must not
    // produce an effectively-infinite (or overflow-prone) wait.
    headers.insert("retry-after", "18446744073709551615".parse().unwrap());
    let result = classify(&profile, 429, b"{}", &headers);
    match result {
        ProviderError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(5 * 60)));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
fn echoed_request_content_does_not_steer_classification_away_from_the_structured_message() {
    let profile = ErrorProfile::anthropic_like();
    // The structured `/error/message` field carries an unrelated message,
    // but the provider has echoed request/context content elsewhere in the
    // body that happens to contain the quota-exhausted pattern string. The
    // regex tier must only look at the structured field, not the whole body,
    // or an agent's own file/web content could steer classification.
    let body = br#"{"type":"error","error":{"type":"invalid_request_error","message":"nothing relevant here"},"echoed_request":"the user asked about: credit balance is too low"}"#;
    let result = classify(&profile, 400, body, &HeaderMap::new());
    assert!(
        !matches!(result, ProviderError::QuotaExhausted),
        "echoed body content incorrectly steered classification: {result:?}"
    );
    assert!(matches!(
        result,
        ProviderError::BadRequest { status: 400, .. }
    ));
}

#[test]
fn retry_after_header_is_parsed_on_default_429_path() {
    let profile = ErrorProfile::empty();
    let mut headers = HeaderMap::new();
    headers.insert("retry-after", "30".parse().unwrap());
    let result = classify(&profile, 429, b"{}", &headers);
    match result {
        ProviderError::RateLimited { retry_after } => {
            assert_eq!(retry_after, Some(std::time::Duration::from_secs(30)));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
}

#[test]
fn bad_request_never_carries_a_body_snippet() {
    let profile = ErrorProfile::empty();
    // A provider echoing the request back, secret and all — §9.9's exact
    // warning. `BadRequest.body_snippet` flows into `ProviderError`'s
    // `Display`/`Debug`, which lands in the append-only, unscrubbable
    // `events` table — no redaction pass exists yet, so the safe amount of
    // unredacted body to persist is none.
    let body = br#"{"echoed_key":"sk-ant-super-secret-value"}"#;
    let result = classify(&profile, 400, body, &HeaderMap::new());
    match result {
        ProviderError::BadRequest {
            status,
            body_snippet,
        } => {
            assert_eq!(status, 400);
            assert_eq!(body_snippet, "");
        }
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn non_utf8_body_never_panics_and_falls_back_to_status_default() {
    let profile = ErrorProfile::empty();
    // Invalid UTF-8 and invalid JSON — must not panic in the error path.
    let body: &[u8] = &[0xff, 0xfe, 0xfd, 0x00, 0x01];
    let result = classify(&profile, 502, body, &HeaderMap::new());
    assert!(matches!(result, ProviderError::Server { status: 502 }));
}
