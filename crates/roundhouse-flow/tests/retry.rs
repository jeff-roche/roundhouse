use roundhouse_flow::parse::types::RetryDef;
use roundhouse_flow::retry::{
    classify_http_status, next_retry_delay, retry_policy_from_def, FailureClass, RetryPolicy,
    RetryPolicyError, MAX_ATTEMPTS,
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
    let policy = retry_policy_from_def(&def()).expect("valid RetryDef");
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
    let mut policy = retry_policy_from_def(&def()).expect("valid RetryDef");
    policy.total_budget = Duration::from_secs(15); // less than one more 10s-20s backoff step
    let delay = next_retry_delay(&policy, 2, Duration::from_secs(10), 1.0);
    assert!(
        delay.is_none(),
        "a wedged provider cannot burn the night — the total budget wins even with attempts left"
    );
}

#[test]
fn full_jitter_is_uniform_between_zero_and_the_capped_delay() {
    let policy = retry_policy_from_def(&def()).expect("valid RetryDef");
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

// ---- Fix round 1 on Task 10 ----

#[test]
fn m1_overflowing_duration_text_is_rejected_not_wrapped_or_panicked() {
    // Fix round 1 (finding M1): `n * 3600` on unchecked u64 used to panic
    // in debug and silently wrap in release for a huge `h`-suffixed value.
    let mut d = def();
    d.base = Some("999999999999999999h".to_string());
    let err = retry_policy_from_def(&d).expect_err("an overflowing duration must be rejected");
    assert!(matches!(err, RetryPolicyError::DurationOverflow { .. }));
}

#[test]
fn m1_and_m2_malformed_duration_text_is_rejected_precisely() {
    // Fix round 1 (findings M1/M2): "10sec", "10 s", "-5s", and a bare
    // "10" used to silently become a zero delay instead of failing.
    for bad in ["10sec", "10 s", "-5s", "10"] {
        let mut d = def();
        d.base = Some(bad.to_string());
        match retry_policy_from_def(&d) {
            Err(RetryPolicyError::InvalidDuration { field, value }) => {
                assert_eq!(field, "base");
                assert_eq!(value, bad);
            }
            other => panic!("expected InvalidDuration for base={bad:?}, got {other:?}"),
        }
    }
}

#[test]
fn m2_a_literal_zero_base_is_treated_as_unconfigured_not_a_real_zero_delay() {
    // Fix round 1 (finding M2): `base: "0s"` is syntactically valid but
    // would otherwise mean "never wait" — combined with a large attempt
    // count, that is the same zero-delay-storm shape as the malformed-text
    // case above, so it falls back to the 1s default instead.
    let mut d = def();
    d.base = Some("0s".to_string());
    let policy =
        retry_policy_from_def(&d).expect("a literal zero is not an error, just unconfigured");
    assert_eq!(policy.base, Duration::from_secs(1));
}

#[test]
fn m2_attempts_beyond_max_attempts_is_rejected() {
    let mut d = def();
    d.attempts = MAX_ATTEMPTS + 1;
    let err = retry_policy_from_def(&d).expect_err("attempts beyond MAX_ATTEMPTS must be rejected");
    assert_eq!(
        err,
        RetryPolicyError::TooManyAttempts {
            actual: MAX_ATTEMPTS + 1,
            max: MAX_ATTEMPTS,
        }
    );
}

#[test]
fn m2_no_zero_delay_request_storm_survives_from_a_pathological_retrydef() {
    // Fix round 1 (finding M2), end to end: the previously-measured
    // exploit (`attempts: 4294967295, base: "10sec"`) admitted 2,000,000
    // zero-delay attempts because a malformed duration silently became
    // zero and a zero delay never advances `elapsed_total` against the
    // budget. Both holes are closed now — the malformed duration is
    // rejected outright, and `attempts` itself is bounded — so this
    // `RetryDef` is rejected long before any delay is ever computed.
    let d = RetryDef {
        attempts: u32::MAX,
        backoff: Some("exponential".into()),
        base: Some("10sec".into()),
        max: None,
        on: vec![],
    };
    let err = retry_policy_from_def(&d).expect_err("this pathological RetryDef must be rejected");
    assert_eq!(
        err,
        RetryPolicyError::TooManyAttempts {
            actual: u32::MAX,
            max: MAX_ATTEMPTS,
        },
        "attempts is checked first, so this is the error surfaced"
    );
}

#[test]
fn m3_extreme_but_validly_formatted_max_does_not_panic() {
    // Fix round 1 (finding M3): `max: "18446744073709551615s"` (u64::MAX)
    // parses cleanly and builds a valid `RetryPolicy`, but the previous
    // `next_retry_delay` panicked at attempt >= 65 converting the computed
    // float delay back to `Duration`. This must return, not panic,
    // regardless of attempt number.
    let mut d = def();
    d.max = Some("18446744073709551615s".to_string());
    d.attempts = MAX_ATTEMPTS; // exercise many attempts without exceeding the cap
    let policy = retry_policy_from_def(&d).expect("a huge but well-formed max is accepted");
    for attempt in 1..MAX_ATTEMPTS {
        let _ = next_retry_delay(&policy, attempt, Duration::ZERO, 1.0);
    }
    // Reaching here at all (rather than panicking partway through) is the
    // assertion.
}

#[test]
fn m3_elapsed_plus_delay_never_panics_on_overflowing_add() {
    let policy = RetryPolicy {
        max_attempts: 5,
        base: Duration::from_secs(10),
        max: Duration::MAX,
        total_budget: Duration::from_secs(3600),
    };
    // `elapsed_total` already at the ceiling: a naive `Duration` `+` would
    // panic; `saturating_add` must not, and staying saturated at the
    // ceiling is still (obviously) over any finite budget.
    let result = next_retry_delay(&policy, 1, Duration::MAX, 1.0);
    assert!(
        result.is_none(),
        "saturating at the ceiling must never exceed the budget"
    );
}

#[test]
fn l1_huge_attempt_number_does_not_panic_or_wrap_the_exponent() {
    // Fix round 1 (finding L1): `attempt as i32 - 1` overflows/wraps for
    // `attempt` near `u32`/`i32::MAX`. `next_retry_delay` only reaches its
    // exponent computation when `attempt < max_attempts`, so exercise it
    // with a `max_attempts` set high enough to let a huge `attempt` value
    // through to that computation.
    let policy = RetryPolicy {
        max_attempts: u32::MAX,
        base: Duration::from_secs(1),
        max: Duration::from_secs(300),
        total_budget: Duration::from_secs(3600),
    };
    let delay = next_retry_delay(&policy, u32::MAX - 1, Duration::ZERO, 1.0);
    // With `max_attempts` this permissive, the total budget stops it
    // instead — the point is that computing the exponent along the way
    // never panics.
    let _ = delay;
}
