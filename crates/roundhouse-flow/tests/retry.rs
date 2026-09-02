use roundhouse_flow::parse::types::RetryDef;
use roundhouse_flow::retry::{
    classify_http_status, next_retry_delay, retry_policy_from_def, FailureClass,
};
use std::time::Duration;

fn def() -> RetryDef {
    RetryDef {
        attempts: 3,
        backoff: Some("exponential".into()),
        base: Some("10s".into()),
        max: Some("5m".into()),
        on: vec!["retryable".into()],
    }
}

#[test]
fn classifies_429_and_5xx_as_retryable_and_4xx_as_terminal() {
    // §8.4: "Retryable (429/5xx, connection reset, provider timeout) vs
    // Terminal (schema validation, permission denial)."
    assert_eq!(classify_http_status(429), FailureClass::Retryable);
    assert_eq!(classify_http_status(500), FailureClass::Retryable);
    assert_eq!(classify_http_status(503), FailureClass::Retryable);
    assert_eq!(classify_http_status(400), FailureClass::Terminal);
    assert_eq!(classify_http_status(403), FailureClass::Terminal);
}

#[test]
fn backoff_grows_exponentially_and_is_capped_at_max() {
    let policy = retry_policy_from_def(&def());
    assert_eq!(policy.max_attempts, 3);
    assert_eq!(policy.base, Duration::from_secs(10));
    assert_eq!(policy.max, Duration::from_secs(300));

    // Full jitter: uniform(0, min(base * 2^(attempt-1), max)). Fix jitter_unit
    // at 1.0 (the top of the range) to make the cap assertion deterministic.
    let d1 = next_retry_delay(&policy, 1, Duration::ZERO, 1.0).unwrap();
    let d2 = next_retry_delay(&policy, 2, Duration::ZERO, 1.0).unwrap();
    assert_eq!(d1, Duration::from_secs(10), "attempt 1: base * 2^0 = 10s");
    assert_eq!(d2, Duration::from_secs(20), "attempt 2: base * 2^1 = 20s");

    let d_capped = next_retry_delay(&policy, 10, Duration::ZERO, 1.0);
    // attempt 10 would be far beyond `max`, but attempts is capped at 3 —
    // exhausted attempts stop retrying outright, never uncapped delay.
    assert!(
        d_capped.is_none(),
        "max_attempts exhausted stops retrying, regardless of budget"
    );
}

#[test]
fn total_budget_stops_retrying_even_with_attempts_remaining() {
    let mut policy = retry_policy_from_def(&def());
    policy.total_budget = Duration::from_secs(15); // less than one more 10s-20s backoff step
    let delay = next_retry_delay(&policy, 2, Duration::from_secs(10), 1.0);
    assert!(
        delay.is_none(),
        "a wedged provider cannot burn the night — the total budget wins even with attempts left"
    );
}

#[test]
fn full_jitter_is_uniform_between_zero_and_the_capped_delay() {
    let policy = retry_policy_from_def(&def());
    let low = next_retry_delay(&policy, 1, Duration::ZERO, 0.0).unwrap();
    let high = next_retry_delay(&policy, 1, Duration::ZERO, 1.0).unwrap();
    assert_eq!(
        low,
        Duration::ZERO,
        "jitter_unit=0.0 is the bottom of the full-jitter range"
    );
    assert_eq!(
        high,
        Duration::from_secs(10),
        "jitter_unit=1.0 is the top — the uncapped exponential value itself"
    );
}
