use roundhouse_provider::retry::{
    disposition, retry_with_policy, AimdSemaphore, BreakerState, CircuitBreaker, Disposition,
};
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

// ---------------------------------------------------------------------
// Post-review fix round (2026-08-29): regression tests for the six issues
// docs/security audits found in commit d5b5936.
// ---------------------------------------------------------------------

// Finding 1: disposition() had Overloaded and RateLimited backwards relative to
// ir.rs's own doc comments / §9.8. These three tests exercise the corrected
// routing end-to-end through retry_with_policy (not just disposition() in
// isolation), since the bug that mattered was in what actually got shed.

#[tokio::test(start_paused = true)]
async fn rate_limited_with_exact_retry_after_sheds_concurrency() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    let calls = AtomicU32::new(0);

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(ProviderError::RateLimited {
                        retry_after: Some(Duration::from_secs(1)),
                    })
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(
        semaphore.current_limit(&key),
        4,
        "RateLimited always means 'your rate' (ir.rs's own doc comment on the variant) — \
         it must shed concurrency even when it comes with an exact Retry-After"
    );
}

#[tokio::test(start_paused = true)]
async fn rate_limited_with_no_retry_after_sheds_concurrency() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));
    let calls = AtomicU32::new(0);

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |attempt| {
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
        semaphore.current_limit(&key),
        4,
        "RateLimited{{None}} must shed too — same reasoning, just without exact timing"
    );
}

#[tokio::test(start_paused = true)]
async fn overloaded_does_not_shed_concurrency() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    let calls = AtomicU32::new(0);

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |attempt| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n == 0 {
                    Err(ProviderError::Overloaded)
                } else {
                    Ok(attempt)
                }
            }
        })
        .await;

    assert_eq!(result.unwrap(), 1);
    assert_eq!(
        semaphore.current_limit(&key),
        8,
        "Overloaded is 'capacity, not your fault' per ir.rs's doc comment — it must NOT \
         shed this key's concurrency ceiling"
    );
}

// Finding 2: shed() under real load (permits actually checked out) silently failed to
// shed and let the real ceiling ratchet upward. This is the exact test the security
// audit named as missing: acquire everything, shed, release, check *real* availability.

#[tokio::test]
async fn shed_under_full_load_reduces_real_availability_once_outstanding_permits_return() {
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    // Acquire every currently-granted permit — the exact "provider is overloaded, every
    // permit is in flight" scenario shed() must still handle correctly.
    let mut permits = Vec::new();
    for _ in 0..8 {
        permits.push(semaphore.acquire(&key).await);
    }
    assert_eq!(semaphore.available_permits(&key), 0);

    semaphore.shed(&key);
    assert_eq!(
        semaphore.current_limit(&key),
        4,
        "current_limit's bookkeeping should reflect the shed immediately"
    );

    // Release every outstanding permit.
    drop(permits);

    assert_eq!(
        semaphore.available_permits(&key),
        4,
        "a shed under full load must actually reduce REAL capacity once outstanding \
         permits return, not just current_limit()'s bookkeeping — otherwise the shed is \
         silently lost and repeated shed/recover cycles ratchet the true ceiling upward"
    );
}

#[tokio::test]
async fn on_success_growth_does_not_re_add_a_permit_while_shed_debt_is_still_unpaid() {
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    let mut permits = Vec::new();
    for _ in 0..8 {
        permits.push(semaphore.acquire(&key).await);
    }
    semaphore.shed(&key); // current_limit 8 -> 4, all 4 forgets deferred as debt (nothing available)

    // Grow past the shed while the debt is still outstanding (permits not yet returned).
    for _ in 0..10 {
        semaphore.on_success(&key);
    }
    assert_eq!(semaphore.current_limit(&key), 5);

    drop(permits);

    assert_eq!(
        semaphore.available_permits(&key),
        5,
        "growth while debt is outstanding must cancel a unit of debt rather than minting a \
         brand-new real permit on top of it, or the real semaphore ends up above current_limit \
         once the debted permits are returned"
    );
}

// Finding 3: breaker-open/exhaustion paths returned ProviderError::Overloaded, which this
// module's own disposition() classifies as retryable — self-contradictory for a "stop
// calling this" signal.

#[tokio::test(start_paused = true)]
async fn attempt_exhaustion_returns_the_last_real_error_not_a_generic_overloaded() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |_attempt| async move {
            Err(ProviderError::Timeout)
        })
        .await;

    assert!(
        matches!(result, Err(ProviderError::Timeout)),
        "exhausting all attempts must surface the LAST real provider error ({:?}), not an \
         invented generic Overloaded that would itself misleadingly self-classify as \
         retryable via this module's own disposition()",
        result
    );
}

// Finding 4: HalfOpen was declared but never enforced — every concurrent caller passed
// through simultaneously, stampeding a still-recovering provider.

#[tokio::test(start_paused = true)]
async fn try_enter_half_open_trial_admits_exactly_one_caller() {
    let breaker = CircuitBreaker::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);

    let admitted = (0..5)
        .filter(|_| breaker.try_enter_half_open_trial(key.clone()))
        .count();
    assert_eq!(
        admitted, 1,
        "exactly one caller may become the half-open trial, no matter how many race for it — \
         the check-and-set is guarded by the same lock as the state read, so this holds \
         regardless of call order or true thread interleaving"
    );
}

#[tokio::test(start_paused = true)]
async fn half_open_refuses_second_caller_while_a_trial_is_already_in_flight() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);

    // Simulate a concurrent caller that already won the trial slot.
    assert!(
        breaker.try_enter_half_open_trial(key.clone()),
        "test setup: the first caller should win the trial"
    );

    let calls = AtomicU32::new(0);
    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(0u32) }
        })
        .await;

    assert!(
        result.is_err(),
        "a second caller must be refused while the half-open trial is in flight"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "the refused caller must never invoke `attempt` at all — no thundering herd through \
         a half-open breaker"
    );
    assert_eq!(
        disposition(&result.unwrap_err()),
        Disposition::Fatal,
        "the refusal must not self-classify as retryable via this module's own disposition(), \
         or a caller using it to decide what to do next would loop forever"
    );
}

// Finding 5: the RetryAfter arm was missing the MAX_ATTEMPTS guard the other two backoff
// arms already had, and the sleep site didn't clamp against MAX_RETRY_AFTER independently
// of parse_retry_after.

#[tokio::test(start_paused = true)]
async fn retry_after_arm_stops_at_max_attempts_and_caps_each_sleep() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );
    let calls = AtomicU32::new(0);

    let start = tokio::time::Instant::now();
    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move {
                Err(ProviderError::RateLimited {
                    retry_after: Some(Duration::from_secs(3600)), // 1 hour — way past the cap
                })
            }
        })
        .await;

    assert!(
        matches!(result, Err(ProviderError::RateLimited { .. })),
        "must return the real RateLimited error on exhaustion, not a generic placeholder"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        5,
        "must stop after MAX_ATTEMPTS — the same guard the other backoff arms already had"
    );
    // 4 sleeps between the 5 attempts, each clamped to errors::MAX_RETRY_AFTER (5 minutes)
    // even though the provider asked for a full hour.
    assert_eq!(
        tokio::time::Instant::now() - start,
        Duration::from_secs(5 * 60 * 4),
        "each Retry-After sleep must be clamped at the sleep site too, not obeyed uncapped"
    );
}
