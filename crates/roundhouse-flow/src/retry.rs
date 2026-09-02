//! §8.4's real two-tier retry computation: "Retries are two-tier —
//! step-level inside workflows, run-level for infrastructure faults — both
//! classified `Retryable` ... vs `Terminal` ..., with exponential backoff
//! plus full jitter and a total retry budget so a wedged provider cannot
//! burn the night." This module is the policy computation only — deciding
//! *whether* and *how long* to wait before the next attempt. The actual
//! sleep-and-retry wrapper around a step's tool/provider call is the
//! executor's integration point (Workflows Task 5, `Executor::dispatch_step`)
//! and `roundhouse-engine`'s run-level retry loop; both are daemon-owned
//! wiring outside this crate's scope, same class as this plan's other
//! daemon-owned integration points.

use crate::parse::types::RetryDef;
use std::time::Duration;
use thiserror::Error;

/// §8.4: "Retryable (429/5xx, connection reset, provider timeout) vs
/// Terminal (schema validation, permission denial)."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Retryable,
    Terminal,
}

/// §8.4: "Retryable (429/5xx, connection reset, provider timeout) vs
/// Terminal (schema validation, permission denial)."
///
/// The exact boundary for codes §8.4 doesn't name explicitly — this
/// classifies `408` (Request Timeout) and `425` (Too Early) as `Terminal`
/// by falling into the catch-all arm below. That specific choice was
/// inherited verbatim from this task's brief rather than independently
/// re-derived against §8.4's "429/5xx" wording; noted here (fix round 1 on
/// Task 10) so a later reader doesn't assume it was re-litigated.
pub fn classify_http_status(status: u16) -> FailureClass {
    match status {
        429 | 500..=599 => FailureClass::Retryable,
        _ => FailureClass::Terminal,
    }
}

/// Schema-validation and permission-denial failures are always Terminal —
/// retrying them burns budget on a failure mode retrying cannot fix.
pub fn classify_schema_or_permission_error() -> FailureClass {
    FailureClass::Terminal
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base: Duration,
    pub max: Duration,
    pub total_budget: Duration,
}

/// Why [`retry_policy_from_def`] rejected a [`RetryDef`]. Untrusted input:
/// `base`/`max` come straight from workflow YAML, so this type exists to
/// let the caller reject a malformed or degenerate value rather than
/// silently guessing one (fix round 1 on Task 10, findings M1/M2).
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RetryPolicyError {
    #[error(
        "{field} duration {value:?} is not a valid duration — expected a non-negative integer followed by one of h/m/s/d (e.g. \"10s\", \"5m\")"
    )]
    InvalidDuration { field: &'static str, value: String },
    #[error("{field} duration {value:?} overflows when converted to seconds")]
    DurationOverflow { field: &'static str, value: String },
    #[error("retry.attempts is {actual}, exceeding the limit of {max}")]
    TooManyAttempts { actual: u32, max: u32 },
    #[error(
        "{field} is an explicit zero duration ({value:?}), which would mean \"never wait\"/\"cap every backoff at zero\" — omit {field} entirely to use its default instead"
    )]
    ZeroDuration { field: &'static str, value: String },
}

/// No real retry policy needs more than a handful of attempts — §8.4's own
/// `total_budget` already bounds wall-clock time regardless, but an
/// unbounded `attempts` count combined with a degenerate (near-zero) delay
/// admits an attempt-count-bounded-only-by-CPU-time retry storm that never
/// meaningfully advances `elapsed_total` (fix round 1 on Task 10, finding
/// M2). Generous relative to `RetryDef`'s own fixture value of 3.
pub const MAX_ATTEMPTS: u32 = 20;

/// Minimal, strict parser for the subset of duration text used in workflow
/// YAML: a non-negative integer followed by exactly one unit character
/// (`s`, `m`, `h`, `d`), no surrounding content, no sign, no fractional
/// part. Deliberately local and small rather than a general duration
/// parser — this crate's workflow YAML never needs anything richer.
///
/// Fix round 1 on Task 10 (finding M1/M2): an earlier version of this
/// function accepted any text, using unrecognised or malformed input
/// (`"10sec"`, `"10 s"`, `"-5s"`, a bare `"10"`) as a signal to silently
/// fall back to a zero duration, and computed `n * <multiplier>` on
/// unchecked `u64` arithmetic (panicking in debug, wrapping in release, on
/// e.g. `"999999999999999999h"`). This version rejects anything that
/// isn't exactly the strict shape above, and uses `checked_mul` so an
/// overflowing value is a rejection rather than a silently wrapped one.
fn parse_duration_str(field: &'static str, s: &str) -> Result<Duration, RetryPolicyError> {
    let invalid = || RetryPolicyError::InvalidDuration {
        field,
        value: s.to_string(),
    };
    if s.is_empty() {
        return Err(invalid());
    }
    let mut chars = s.chars();
    let unit = chars.next_back().ok_or_else(invalid)?;
    let digits = chars.as_str();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    let n: u64 = digits.parse().map_err(|_| invalid())?;
    let multiplier: u64 = match unit {
        'h' => 3600,
        'm' => 60,
        's' => 1,
        'd' => 86400,
        _ => return Err(invalid()),
    };
    let secs = n
        .checked_mul(multiplier)
        .ok_or_else(|| RetryPolicyError::DurationOverflow {
            field,
            value: s.to_string(),
        })?;
    Ok(Duration::from_secs(secs))
}

/// Resolves an optional YAML duration field to a `Duration`, applying
/// `default` when the field is absent, and rejecting it outright when
/// present but parsed to exactly zero.
///
/// Fix round 1 on Task 10 (finding M2) originally treated a literal
/// `base: 0s` as "unconfigured" and silently substituted `default` — on
/// the same reasoning as this round's M1/M2 fixes, that a malformed
/// duration should never silently become a guessed value. Fix round 2
/// pointed out the contradiction directly: a *validly parsed* `0s` is
/// just as explicit an author statement as any other duration, so
/// silently overriding it was exactly the silent-normalization pattern
/// this whole module was written to stop doing. It is now rejected with
/// [`RetryPolicyError::ZeroDuration`] instead, consistent with every other
/// malformed/degenerate input this function's siblings reject.
fn resolve_duration(
    field: &'static str,
    raw: Option<&str>,
    default: Duration,
) -> Result<Duration, RetryPolicyError> {
    match raw {
        None => Ok(default),
        Some(s) => {
            let parsed = parse_duration_str(field, s)?;
            if parsed.is_zero() {
                Err(RetryPolicyError::ZeroDuration {
                    field,
                    value: s.to_string(),
                })
            } else {
                Ok(parsed)
            }
        }
    }
}

/// 1 hour — a wedged provider gets one hour of the night, not all of it.
const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_secs(3600);

/// Builds a [`RetryPolicy`] from a workflow's declared [`RetryDef`],
/// rejecting anything malformed, overflowing, or pathological rather than
/// silently normalizing it (fix round 1 on Task 10 folded `Result` into
/// this signature for exactly that reason — the brief's original signature
/// returned `RetryPolicy` unconditionally, which cannot reject bad input).
pub fn retry_policy_from_def(def: &RetryDef) -> Result<RetryPolicy, RetryPolicyError> {
    if def.attempts > MAX_ATTEMPTS {
        return Err(RetryPolicyError::TooManyAttempts {
            actual: def.attempts,
            max: MAX_ATTEMPTS,
        });
    }
    Ok(RetryPolicy {
        max_attempts: def.attempts.max(1),
        base: resolve_duration("base", def.base.as_deref(), Duration::from_secs(1))?,
        max: resolve_duration("max", def.max.as_deref(), Duration::from_secs(300))?,
        total_budget: DEFAULT_TOTAL_BUDGET,
    })
}

/// §8.4's real retry-loop computation: exponential backoff (`base *
/// 2^(attempt-1)`, capped at `max`) with **full jitter** (`uniform(0,
/// capped)`, per the well-known AWS full-jitter algorithm — minimizes
/// retry-storm correlation far better than "backoff ± a little noise"),
/// stopping outright once either `max_attempts` is exhausted or
/// `elapsed_total` plus the computed delay would exceed `total_budget`.
/// `jitter_unit` is injected in `[0.0, 1.0]` for deterministic tests; the
/// real caller uses `rand::random::<f64>()`.
///
/// Fix round 1 on Task 10 (findings M3/L1): an earlier version computed
/// the exponent as `attempt as i32 - 1` (overflows/wraps for `attempt`
/// near `i32::MAX`) and converted the final delay with the panicking
/// `Duration::from_secs_f64` plus `Duration`'s panicking `Add` (both
/// reachable from an ordinarily-valid but extreme `RetryPolicy`, e.g.
/// `max: "18446744073709551615s"`). This version saturates the exponent,
/// uses `Duration::try_from_secs_f64` with a safe fallback, and uses
/// `Duration::saturating_add` — every input this function accepts now
/// returns a `Duration` or `None`, never panics.
pub fn next_retry_delay(
    policy: &RetryPolicy,
    attempt: u32,
    elapsed_total: Duration,
    jitter_unit: f64,
) -> Option<Duration> {
    if attempt >= policy.max_attempts {
        return None;
    }
    // `2^64` already vastly exceeds any representable `Duration`, so
    // capping the exponent here (rather than computing `attempt - 1` in
    // `i32`, which overflows/wraps well before `attempt` reaches even
    // `i32::MAX`) is exact for every attempt count `next_retry_delay` can
    // actually be called with and never changes the result `.min(max)`
    // would produce anyway.
    let exponent = attempt.saturating_sub(1).min(64);
    let exp_secs = policy.base.as_secs_f64() * 2f64.powi(exponent as i32);
    let capped_secs = exp_secs.min(policy.max.as_secs_f64());
    let jittered_secs = (capped_secs * jitter_unit.clamp(0.0, 1.0)).max(0.0);
    // `try_from_secs_f64` returns `Err` only at the extreme edge of what
    // `Duration` can represent (e.g. float rounding pushing a
    // near-`u64::MAX`-second value a hair over) — falling back to
    // `policy.max` is safe because `capped_secs` was already `.min()`-ed
    // against it.
    let delay = Duration::try_from_secs_f64(jittered_secs).unwrap_or(policy.max);
    if elapsed_total.saturating_add(delay) > policy.total_budget {
        return None;
    }
    Some(delay)
}
