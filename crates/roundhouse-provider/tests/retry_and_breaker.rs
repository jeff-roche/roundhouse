use roundhouse_provider::retry::{retry_with_policy, AimdSemaphore, BreakerState, CircuitBreaker};
use roundhouse_provider::{ModelId, ProviderError, ProviderId};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

#[tokio::test(start_paused = true)]
async fn retry_after_header_is_honored_exactly_not_jittered() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    let calls = AtomicU32::new(0);

    let start = tokio::time::Instant::now();
    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(ProviderError::RateLimited {
                        retry_after: Some(Duration::from_secs(3)),
                    })
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_secs(3),
        "must sleep exactly Retry-After, no jitter added on top"
    );
}

#[tokio::test(start_paused = true)]
async fn breaker_opens_after_5_consecutive_failures_within_30s_and_half_opens_after_10s() {
    let breaker = CircuitBreaker::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    assert_eq!(breaker.state(key.clone()), BreakerState::Open);

    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);
}

#[tokio::test(start_paused = true)]
async fn quota_exhausted_is_attempted_exactly_once_never_retried() {
    // Regression for audit finding 8: this used to call `attempt` a second time despite
    // the comment saying "never retry," double-billing a quota-exhausted request.
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    let calls = AtomicU32::new(0);

    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(ProviderError::QuotaExhausted) }
        })
        .await;

    assert!(matches!(result, Err(ProviderError::QuotaExhausted)));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a fatal disposition must short-circuit without a second attempt"
    );
}

#[tokio::test(start_paused = true)]
async fn rate_limited_with_no_retry_after_is_still_retried_with_backoff() {
    // Regression for audit finding 9: RateLimited{retry_after: None} previously fell
    // through to the catchall `Err(e) => return Err(e)` and was never retried at all.
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));
    let calls = AtomicU32::new(0);

    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(ProviderError::RateLimited { retry_after: None })
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "must retry with backoff even with no Retry-After header"
    );
}

#[test]
fn aimd_semaphore_halves_on_shed_and_grows_additively_on_sustained_success() {
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    assert_eq!(
        semaphore.current_limit(&key),
        8,
        "starts at the initial concurrency limit"
    );

    semaphore.shed(&key);
    assert_eq!(
        semaphore.current_limit(&key),
        4,
        "shed-concurrency halves the limit — multiplicative decrease"
    );

    for _ in 0..10 {
        semaphore.on_success(&key);
    }
    assert_eq!(
        semaphore.current_limit(&key),
        5,
        "sustained success grows the limit by exactly one at a time — additive increase, not a snap back to full"
    );
}
