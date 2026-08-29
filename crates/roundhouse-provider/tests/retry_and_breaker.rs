use roundhouse_provider::retry::{
    disposition, retry_with_policy, AimdSemaphore, BreakerState, CircuitBreaker, Disposition,
};
use roundhouse_provider::{ModelId, ProviderError, ProviderId};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
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
        .filter(|_| breaker.try_enter_half_open_trial(key.clone()).is_some())
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
        breaker.try_enter_half_open_trial(key.clone()).is_some(),
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

// ---------------------------------------------------------------------
// Round-2 post-review fix round (2026-08-29): the round-1 fix (commit
// 7147c6b) introduced 2 new Critical regressions and 1 new Important
// regression while fixing the round-1 findings. Regression tests below.
// ---------------------------------------------------------------------

// New finding 1 (Critical regression): moving Overloaded/Server off the
// shedding arm (round-1 finding 1's fix) accidentally also moved them off
// the only code path that called breaker.record_failure, so the breaker
// could no longer trip on its spec-mandated "overloaded/5xx" trigger at
// all -- while RateLimited (moved onto a shedding arm) started tripping it
// for a condition §9.8 never lists as a breaker trigger.

#[tokio::test(start_paused = true)]
async fn breaker_trips_on_five_consecutive_overloaded_even_though_overloaded_does_not_shed() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |_attempt| async move {
            Err(ProviderError::Overloaded)
        })
        .await;

    assert!(result.is_err());
    assert_eq!(
        breaker.state(key),
        BreakerState::Open,
        "5 consecutive Overloaded is §9.8's literal breaker-open trigger — it must trip the \
         breaker even though Overloaded (correctly, per round-1's finding 1) no longer sheds \
         concurrency; 'does this shed' and 'does this trip the breaker' are independent \
         decisions"
    );
}

#[tokio::test(start_paused = true)]
async fn breaker_trips_on_five_consecutive_server_errors() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |_attempt| async move {
            Err(ProviderError::Server { status: 503 })
        })
        .await;

    assert!(result.is_err());
    assert_eq!(
        breaker.state(key),
        BreakerState::Open,
        "5 consecutive Server{{503}} must trip the breaker per §9.8's 'overloaded/5xx' trigger"
    );
}

#[tokio::test(start_paused = true)]
async fn breaker_does_not_trip_on_five_consecutive_rate_limited() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |_attempt| async move {
            Err(ProviderError::RateLimited { retry_after: None })
        })
        .await;

    assert!(result.is_err());
    assert_eq!(
        breaker.state(key),
        BreakerState::Closed,
        "RateLimited is not a §9.8 breaker trigger — even 5 consecutive rate-limits inside a \
         single call must not trip the breaker, even though (correctly) they do shed \
         concurrency"
    );
}

// New finding 2 (Critical regression): try_enter_half_open_trial's flag was only ever
// cleared by record_success/record_failure -- but the Fatal and RetryWithBackoff exit
// arms called neither, so a single Timeout/BadRequest/etc. during a trial wedged that
// key's half-open slot permanently (state() reports HalfOpen forever, every subsequent
// caller refused forever, attempt never invoked again for that key).

#[tokio::test(start_paused = true)]
async fn a_failed_half_open_trial_does_not_permanently_wedge_the_key() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);

    // The trial fails with Timeout -- NOT a breaker trigger (is_breaker_trigger), so
    // record_failure never runs for it. Before this fix, nothing else ever cleared
    // half_open_trial_in_flight on this exit path, and the key would be wedged forever.
    let trial_result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |_attempt| async move {
            Err(ProviderError::Timeout)
        })
        .await;
    assert!(
        trial_result.is_err(),
        "test setup: the trial must actually fail"
    );

    // Simulate a long time passing (well past any plausible re-open window) and then a
    // fresh, independent, unrelated call for the same key -- it must be allowed to
    // attempt, not permanently rejected as Fatal by a leaked trial flag.
    tokio::time::advance(Duration::from_secs(3600)).await;

    let calls = AtomicU32::new(0);
    let result: Result<u32, ProviderError> =
        retry_with_policy(key, &breaker, &semaphore, |attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(attempt) }
        })
        .await;

    assert!(
        result.is_ok(),
        "a single failed half-open trial must not permanently wedge this (provider, model) \
         key: {:?}",
        result
    );
    assert!(
        calls.load(Ordering::SeqCst) > 0,
        "the subsequent call must actually invoke `attempt`, not get silently rejected forever"
    );
}

// New finding 3 (Important regression, round 2): the trial holder re-checked/re-acquired
// the trial slot on every loop iteration of its OWN call, so its own second attempt would
// see the flag IT ITSELF set on the first iteration and reject itself -- discarding its own
// real error (e.g. a genuine Timeout silently replaced by a generic breaker-rejection error).
//
// Round 3 superseded this test's original expectations: fixing round 3's finding 2 (ANY
// failure during a held trial must reopen the breaker immediately, not just
// is_breaker_trigger ones) means a held trial is now a strict one-shot probe --
// retry_with_policy returns immediately on its first Ok/Err while holding one, rather than
// looping internally. This still satisfies finding 3's core requirement (the trial holder
// never re-checks/re-acquires the slot against itself, because it never reaches a later
// loop iteration at all while holding a trial) while also fixing finding 2: the failure is
// returned as this call's own real error (not masked by a self-rejection), AND the breaker
// reopens immediately.

#[tokio::test(start_paused = true)]
async fn half_open_trial_failure_returns_the_real_error_immediately_without_self_rejecting() {
    let breaker = CircuitBreaker::new();
    let semaphore = AimdSemaphore::new();
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);

    let calls = AtomicU32::new(0);
    let result: Result<u32, ProviderError> =
        retry_with_policy(key.clone(), &breaker, &semaphore, |_attempt| {
            calls.fetch_add(1, Ordering::SeqCst);
            async move { Err(ProviderError::Timeout) } // not Fatal, not a breaker trigger
        })
        .await;

    assert!(
        matches!(result, Err(ProviderError::Timeout)),
        "the trial's own real error ({:?}) must be returned directly -- not masked by a \
         self-inflicted breaker-rejection from the call re-checking its own trial slot",
        result
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "a held trial is a one-shot probe: exactly one attempt, no further retries within \
         the same call, regardless of error type"
    );
    assert_eq!(
        breaker.state(key),
        BreakerState::Open,
        "ANY failure during an active trial reopens the breaker immediately, even a \
         non-is_breaker_trigger error like Timeout (finding 2, round 3)"
    );
}

// New finding 1 (Critical regression, round 3): a bare bool flag can't distinguish "my
// trial" from "a different, later trial" -- an ABA bug. Round 2's design let a stale guard
// from an old trial clear a NEWER trial's slot out from under it, reopening the exact
// thundering-herd hole this mechanism exists to close. None of the previous tests used
// genuinely concurrent tokio tasks racing for the SAME key's trial slot -- that's exactly
// why this bug wasn't caught by round 2's test suite. This test uses real spawned tasks and
// a `Notify` to force genuine overlap: the winner blocks mid-`attempt` (deliberately, so it
// cannot possibly resolve before the other racers have had a chance to run), while multiple
// concurrent racers attempt the same key at the same time.

#[tokio::test(start_paused = true)]
async fn only_one_of_several_concurrent_callers_is_admitted_as_the_half_open_trial() {
    let breaker = Arc::new(CircuitBreaker::new());
    let semaphore = Arc::new(AimdSemaphore::new());
    let key = (
        ProviderId("anthropic".into()),
        ModelId("claude-test".into()),
    );

    for _ in 0..5 {
        breaker.record_failure(key.clone());
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(breaker.state(key.clone()), BreakerState::HalfOpen);

    // The winner blocks here until explicitly released, guaranteeing every other
    // concurrently-spawned racer gets a chance to run (and be refused) while the winner
    // is still genuinely holding the trial -- not just sequentially, one after another.
    let release = Arc::new(tokio::sync::Notify::new());
    let admitted_into_attempt = Arc::new(AtomicU32::new(0));

    const RACERS: usize = 6;
    let mut handles = Vec::with_capacity(RACERS);
    for _ in 0..RACERS {
        let breaker = breaker.clone();
        let semaphore = semaphore.clone();
        let key = key.clone();
        let release = release.clone();
        let admitted_into_attempt = admitted_into_attempt.clone();
        handles.push(tokio::spawn(async move {
            retry_with_policy(key, &breaker, &semaphore, |_attempt| {
                let release = release.clone();
                let admitted_into_attempt = admitted_into_attempt.clone();
                async move {
                    admitted_into_attempt.fetch_add(1, Ordering::SeqCst);
                    release.notified().await;
                    Ok::<u32, ProviderError>(0)
                }
            })
            .await
        }));
    }

    // Let every spawned task run until it either blocks inside `attempt` (the winner) or
    // returns having been refused (everyone else) -- paused-clock `yield_now` round-trips
    // are enough to drain the whole batch on tokio's current-thread test executor since
    // none of the refusal paths await anything.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    assert_eq!(
        admitted_into_attempt.load(Ordering::SeqCst),
        1,
        "of {RACERS} genuinely concurrent callers racing for the same key's half-open \
         trial, exactly one may be admitted into `attempt` at a time -- the rest must be \
         refused outright without ever calling it"
    );

    // Release the winner and collect every racer's result.
    release.notify_waiters();
    let mut ok_count = 0;
    let mut refused_count = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => ok_count += 1,
            Err(_) => refused_count += 1,
        }
    }
    assert_eq!(
        ok_count, 1,
        "exactly one racer wins and succeeds as the trial"
    );
    assert_eq!(
        refused_count,
        RACERS - 1,
        "every other racer is refused, never silently admitted alongside the winner"
    );
    assert_eq!(
        breaker.state(key),
        BreakerState::Closed,
        "the winning trial's success must fully close the breaker"
    );
}

// Same ABA-prevention mechanism, exercised across TWO successive trial cycles: after the
// first trial concludes (successfully) and the breaker later reopens and returns to
// HalfOpen again, a fresh set of concurrent racers must again admit exactly one NEW winner
// -- proving the generation/ticket correctly advances and a completed old trial can never
// interfere with a later one, not just within a single cycle but across repeated cycles.

#[tokio::test(start_paused = true)]
async fn concurrent_racing_admits_exactly_one_winner_on_each_successive_half_open_cycle() {
    let breaker = Arc::new(CircuitBreaker::new());
    let semaphore = Arc::new(AimdSemaphore::new());
    let key = (ProviderId("openai".into()), ModelId("gpt-test".into()));

    for cycle in 0..2 {
        for _ in 0..5 {
            breaker.record_failure(key.clone());
        }
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(
            breaker.state(key.clone()),
            BreakerState::HalfOpen,
            "cycle {cycle}: breaker must be half-open before this cycle's race"
        );

        let release = Arc::new(tokio::sync::Notify::new());
        let admitted_into_attempt = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let breaker = breaker.clone();
            let semaphore = semaphore.clone();
            let key = key.clone();
            let release = release.clone();
            let admitted_into_attempt = admitted_into_attempt.clone();
            handles.push(tokio::spawn(async move {
                retry_with_policy(key, &breaker, &semaphore, |_attempt| {
                    let release = release.clone();
                    let admitted_into_attempt = admitted_into_attempt.clone();
                    async move {
                        admitted_into_attempt.fetch_add(1, Ordering::SeqCst);
                        release.notified().await;
                        // Fail this cycle's trial so the breaker reopens and a further
                        // cycle can be exercised the same way.
                        Err::<u32, ProviderError>(ProviderError::Timeout)
                    }
                })
                .await
            }));
        }

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            admitted_into_attempt.load(Ordering::SeqCst),
            1,
            "cycle {cycle}: exactly one of the concurrent racers may be admitted"
        );

        release.notify_waiters();
        for h in handles {
            let _ = h.await.unwrap();
        }

        assert_eq!(
            breaker.state(key.clone()),
            BreakerState::Open,
            "cycle {cycle}: the failed trial must reopen the breaker so the next cycle \
             starts from a clean, fully-open state"
        );
    }
}
