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

/// §8.4: "Retryable (429/5xx, connection reset, provider timeout) vs
/// Terminal (schema validation, permission denial)."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    Retryable,
    Terminal,
}

/// §8.4: "Retryable (429/5xx, connection reset, provider timeout) vs
/// Terminal (schema validation, permission denial)."
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

/// Minimal parser for the subset of duration text used in workflow YAML:
/// a non-negative integer followed by a single unit character (`s`, `m`,
/// `h`, `d`). Deliberately local and small rather than a general duration
/// parser — this crate's workflow YAML never needs anything richer, and a
/// malformed/unrecognised value falls back to zero rather than panicking
/// (parsing itself never fails here; callers that need a hard error over a
/// malformed duration string should validate before calling this).
fn parse_duration_str(s: &str) -> Duration {
    let s = s.trim();
    if s.is_empty() {
        return Duration::ZERO;
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num.parse().unwrap_or(0);
    match unit {
        "h" => Duration::from_secs(n * 3600),
        "m" => Duration::from_secs(n * 60),
        "s" => Duration::from_secs(n),
        "d" => Duration::from_secs(n * 86400),
        _ => Duration::from_secs(0),
    }
}

/// 1 hour — a wedged provider gets one hour of the night, not all of it.
const DEFAULT_TOTAL_BUDGET: Duration = Duration::from_secs(3600);

pub fn retry_policy_from_def(def: &RetryDef) -> RetryPolicy {
    RetryPolicy {
        max_attempts: def.attempts.max(1),
        base: def
            .base
            .as_deref()
            .map(parse_duration_str)
            .unwrap_or(Duration::from_secs(1)),
        max: def
            .max
            .as_deref()
            .map(parse_duration_str)
            .unwrap_or(Duration::from_secs(300)),
        total_budget: DEFAULT_TOTAL_BUDGET,
    }
}

/// §8.4's real retry-loop computation: exponential backoff (`base *
/// 2^(attempt-1)`, capped at `max`) with **full jitter** (`uniform(0,
/// capped)`, per the well-known AWS full-jitter algorithm — minimizes
/// retry-storm correlation far better than "backoff ± a little noise"),
/// stopping outright once either `max_attempts` is exhausted or
/// `elapsed_total` plus the computed delay would exceed `total_budget`.
/// `jitter_unit` is injected in `[0.0, 1.0]` for deterministic tests; the
/// real caller uses `rand::random::<f64>()`.
pub fn next_retry_delay(
    policy: &RetryPolicy,
    attempt: u32,
    elapsed_total: Duration,
    jitter_unit: f64,
) -> Option<Duration> {
    if attempt >= policy.max_attempts {
        return None;
    }
    let exp_secs = policy.base.as_secs_f64() * 2f64.powi(attempt as i32 - 1);
    let capped_secs = exp_secs.min(policy.max.as_secs_f64());
    let jittered_secs = capped_secs * jitter_unit.clamp(0.0, 1.0);
    let delay = Duration::from_secs_f64(jittered_secs.max(0.0));
    if elapsed_total + delay > policy.total_budget {
        return None;
    }
    Some(delay)
}
