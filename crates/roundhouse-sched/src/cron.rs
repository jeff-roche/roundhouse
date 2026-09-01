//! Cron next-fire computation with a required IANA timezone and explicit
//! DST gap / ambiguous-time handling.
//!
//! Phase 5, Subsystem A, Task 2. Consumes `TriggerSpec::Cron`'s fields
//! (Task 1) and is in turn consumed by the scheduler heap (Task 3) and
//! catch-up (Task 4). See `docs/architecture/05-scheduling-and-workflows.md`.
use crate::trigger::{DstAmbiguous, DstGap};
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use chrono_tz::Tz;
use cron::Schedule;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CronError {
    #[error("invalid cron expression '{0}': {1}")]
    InvalidExpr(String, String),
    #[error("cron schedule '{0}' has no future occurrences")]
    Exhausted(String),
}

/// The pinned `cron` crate's real API (`cron = "0.15"`): there is no
/// `after_naive` method anywhere on `Schedule`, and no way to iterate bare
/// `NaiveDateTime` candidates directly — only `Schedule::after<Z:
/// chrono::TimeZone>(&self, after: &DateTime<Z>) -> impl Iterator<Item =
/// DateTime<Z>>` and `Schedule::upcoming<Z>`. To get the naive-time walk
/// DST resolution needs, feed the wall-clock digits to `Schedule::after`
/// labeled as `Utc` (`Utc::from_utc_datetime` never produces
/// `Ambiguous`/`None` — `Utc` has no DST), so `cron`'s own arithmetic runs
/// purely on the naive wall-clock numbers with zero timezone reasoning of
/// its own; `naive_utc()` on each yielded candidate then recovers those
/// digits (which are actually the wall-clock-in-`tz` value, mislabeled as
/// UTC), and *that* naive value is resolved against the real `tz` via
/// `TimeZone::from_local_datetime` — which is where `dst_gap`/
/// `dst_ambiguous` actually get applied.
fn naive_candidates(
    schedule: &Schedule,
    after_local_naive: chrono::NaiveDateTime,
) -> impl Iterator<Item = chrono::NaiveDateTime> + '_ {
    let after_as_utc = Utc.from_utc_datetime(&after_local_naive);
    schedule.after(&after_as_utc).map(|dt| dt.naive_utc())
}

/// Computes the next fire instant strictly after `after`, in UTC, honoring
/// the binding's declared DST policy and applying a deterministic jitter
/// offset. `expr` is a standard 5-field cron expression (`min hour dom
/// month dow`) evaluated against wall-clock time in `tz`.
pub fn next_fire_after(
    expr: &str,
    tz: Tz,
    after: DateTime<Utc>,
    dst_gap: &DstGap,
    dst_ambiguous: &DstAmbiguous,
    jitter: Duration,
) -> Result<DateTime<Utc>, CronError> {
    let schedule = Schedule::from_str(&format!("0 {expr}"))
        .map_err(|e| CronError::InvalidExpr(expr.to_string(), e.to_string()))?;
    let after_local = after.with_timezone(&tz).naive_local();

    for naive_candidate in naive_candidates(&schedule, after_local).take(366 * 2) {
        let resolved = match tz.from_local_datetime(&naive_candidate) {
            LocalResult::Single(dt) => Some(dt.with_timezone(&Utc)),
            LocalResult::Ambiguous(first, second) => {
                let chosen = match dst_ambiguous {
                    DstAmbiguous::First => first,
                    DstAmbiguous::Second => second,
                    // `Both` is admission-time fan-out: the caller (scheduler
                    // admission, Task 3) fires the binding twice via
                    // `fire_all_ambiguous`. For the single-instant contract
                    // of `next_fire_after`, the first occurrence is the
                    // correct "next" instant.
                    DstAmbiguous::Both => first,
                };
                Some(chosen.with_timezone(&Utc))
            }
            LocalResult::None => match dst_gap {
                DstGap::Skip => None,
                DstGap::FireAtGapEnd => {
                    // Walk forward minute-by-minute to the first valid local
                    // instant after the gap — bounded because a DST gap is
                    // at most a few hours.
                    let mut probe = naive_candidate;
                    let mut found = None;
                    for _ in 0..6 * 60 {
                        probe += chrono::Duration::minutes(1);
                        if let LocalResult::Single(dt) = tz.from_local_datetime(&probe) {
                            found = Some(dt.with_timezone(&Utc));
                            break;
                        }
                    }
                    found
                }
            },
        };
        if let Some(base) = resolved {
            let offset =
                chrono::Duration::from_std(deterministic_jitter(base, jitter)).unwrap_or_default();
            return Ok(base + offset);
        }
    }
    Err(CronError::Exhausted(expr.to_string()))
}

/// A deterministic offset in `[0, jitter)`, derived from a hash of the
/// un-jittered candidate instant. Deterministic on purpose: recomputing the
/// same binding from the same base instant (e.g. after Task 3's
/// drift-triggered recompute) must land on the *same* jittered fire time,
/// not re-roll a new one every recompute — otherwise "when will this
/// actually fire" has no stable answer.
fn deterministic_jitter(base: DateTime<Utc>, jitter: Duration) -> Duration {
    let jitter_nanos = jitter.as_nanos();
    if jitter_nanos == 0 {
        return Duration::ZERO;
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    base.timestamp_nanos_opt().unwrap_or(0).hash(&mut hasher);
    let offset_nanos = (hasher.finish() as u128) % jitter_nanos;
    Duration::from_nanos(offset_nanos as u64)
}

/// For `DstAmbiguous::Both`, the caller (scheduler admission, Task 3) fires
/// the binding twice for the one ambiguous wall-clock instant: once at each
/// UTC instant the doubled local hour actually corresponds to.
pub fn fire_all_ambiguous(
    expr: &str,
    tz: Tz,
    after: DateTime<Utc>,
) -> Result<Vec<DateTime<Utc>>, CronError> {
    let schedule = Schedule::from_str(&format!("0 {expr}"))
        .map_err(|e| CronError::InvalidExpr(expr.to_string(), e.to_string()))?;
    let after_local = after.with_timezone(&tz).naive_local();
    for naive_candidate in naive_candidates(&schedule, after_local).take(366 * 2) {
        if let LocalResult::Ambiguous(first, second) = tz.from_local_datetime(&naive_candidate) {
            return Ok(vec![first.with_timezone(&Utc), second.with_timezone(&Utc)]);
        }
    }
    Ok(vec![])
}
