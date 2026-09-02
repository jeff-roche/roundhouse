//! Cron next-fire computation with a required IANA timezone and explicit
//! DST gap / ambiguous-time handling.
//!
//! Phase 5, Subsystem A, Task 2. Consumes `TriggerSpec::Cron`'s fields
//! (Task 1) and is in turn consumed by the scheduler heap (Task 3) and
//! catch-up (Task 4). See `docs/architecture/05-scheduling-and-workflows.md`.
use crate::trigger::{DstAmbiguous, DstGap};
use chrono::{DateTime, LocalResult, NaiveDateTime, TimeZone, Utc};
use chrono_tz::Tz;
use cron::Schedule;
use std::str::FromStr;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CronError {
    #[error("invalid cron expression '{0}': {1}")]
    InvalidExpr(String, String),
    #[error("cron schedule '{0}' has no future occurrences")]
    Exhausted(String),
    /// M5 fold-in: `TriggerSpec::Interval { every: Duration::ZERO, .. }`
    /// makes the scheduler's `occurrences_after` return `after` unchanged
    /// forever (`after + 0`), which without this guard hangs `Scheduler::
    /// tick`'s `while` loop on a single malformed binding. Validated and
    /// refused here so `Scheduler::add_binding` fails fast at registration
    /// time instead of silently accepting a binding that can never
    /// meaningfully schedule.
    #[error("interval trigger's `every` duration must be greater than zero")]
    ZeroInterval,
    /// NEW-2 (fix round 2): `ZeroInterval`'s `is_zero()` guard missed two
    /// non-zero degenerate magnitudes, both confirmed against pinned chrono
    /// 0.4.45: `every > chrono::TimeDelta::MAX` (~9.22e15s) makes
    /// `chrono::Duration::from_std` return `Err`, which the old
    /// `unwrap_or_default()` silently turned into `TimeDelta::zero()` —
    /// bit-for-bit the same degenerate behavior `ZeroInterval` exists to
    /// prevent; and roughly 8.3e12s <= `every` <= `TimeDelta::MAX` makes
    /// `from_std` succeed but the later `DateTime<Utc> + TimeDelta`
    /// overflow chrono's representable year range (max year 262143) and
    /// panic, which no `if let Ok(..)` call site can catch. Both are
    /// refused by one sane upper bound on interval length — no real
    /// interval trigger fires less often than once a century.
    #[error("interval trigger's `every` duration of {0:?} is too large to schedule")]
    IntervalTooLarge(Duration),
    /// Fold-in fix (parity with `IntervalTooLarge`, same defect class): the
    /// old `chrono::Duration::from_std(deterministic_jitter(base,
    /// jitter)).unwrap_or_default()` silently turned a `jitter` beyond
    /// `chrono::TimeDelta::MAX` (~9.22e15s) into a zero offset instead of
    /// reporting it, and a `jitter` large enough to produce an offset that
    /// overflows `DateTime<Utc> + TimeDelta`'s representable year range
    /// (~8.3e12s and up) would have panicked via the bare `base + offset`
    /// that followed. `jitter` reaches [`next_fire_after`] straight from a
    /// deserialized `TriggerSpec::Cron`, so a corrupted or malicious
    /// persisted binding could otherwise reach either failure mode with
    /// nothing in between to validate it — the same gap `MAX_INTERVAL`
    /// closed for `TriggerSpec::Interval::every`, but on the jitter path,
    /// which that bound does not cover.
    #[error("cron trigger's jitter duration of {0:?} is too large to schedule")]
    JitterTooLarge(Duration),
}

/// Sane ceiling on `TriggerSpec::Cron`'s `jitter` field — parity with
/// [`crate::scheduler::MAX_INTERVAL`]'s reasoning, applied to the jitter
/// path instead of the interval path. A cron binding's jitter exists to
/// spread near-simultaneous fires apart by at most a few minutes, nowhere
/// near this bound, but nothing upstream of [`next_fire_after`] validated
/// the value before it reached `chrono::Duration::from_std`/
/// `checked_add_signed` — exactly the gap `MAX_INTERVAL` closed for
/// `Interval::every`. Chosen comfortably below both the
/// `chrono::Duration::from_std` failure threshold (~9.22e15s,
/// `TimeDelta::MAX`) and the `DateTime<Utc> + TimeDelta` panic threshold
/// (~8.3e12s, chrono's representable year range) confirmed against pinned
/// chrono 0.4.45, while comfortably above any jitter window a real
/// deployment would legitimately configure.
pub const MAX_JITTER: Duration = Duration::from_secs(24 * 60 * 60);

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
///
/// **Contract for `DstAmbiguous::Both` (Ruling P16):** this function's
/// return type is a single `DateTime<Utc>`, so it cannot express "fires
/// twice." When `dst_ambiguous` is `Both`, the value returned here is only
/// the first of the two occurrences — a caller whose binding policy is
/// `Both` MUST call [`fire_all_ambiguous`] instead (or in addition) to get
/// both fire instants; otherwise the second occurrence is silently dropped.
/// Use [`is_ambiguous_local`] to detect, ahead of time, whether the next
/// occurrence for a given wall-clock candidate falls in a fold at all.
pub fn next_fire_after(
    expr: &str,
    tz: Tz,
    after: DateTime<Utc>,
    dst_gap: &DstGap,
    dst_ambiguous: &DstAmbiguous,
    jitter: Duration,
) -> Result<DateTime<Utc>, CronError> {
    // Fold-in fix: refuse an out-of-range jitter up front, at the same
    // "fail fast at the boundary" point `Scheduler::add_binding`'s
    // `*every > MAX_INTERVAL` check uses for `Interval` — see
    // `CronError::JitterTooLarge`'s doc comment for why this matters.
    if jitter > MAX_JITTER {
        return Err(CronError::JitterTooLarge(jitter));
    }
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
                    // `Both` is admission-time fan-out (see this function's
                    // doc comment, Ruling P16): the caller MUST use
                    // `fire_all_ambiguous` to get the real double-fire. This
                    // arm exists only so `next_fire_after` still returns
                    // *a* valid instant (the first occurrence) rather than
                    // panicking or erroring when called with `Both`.
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
            // Fold-in fix: the early `jitter > MAX_JITTER` guard above
            // means `deterministic_jitter`'s `[0, jitter)` output can never
            // actually be large enough to fail `from_std` or overflow
            // `checked_add_signed` at this point — but both are still
            // propagated as `CronError::JitterTooLarge`, not
            // `unwrap_or_default()`/a bare `+`, so a future change to the
            // bound (or to `deterministic_jitter` itself) fails closed
            // instead of silently degrading to a zero offset or panicking.
            let offset = chrono::Duration::from_std(deterministic_jitter(base, jitter))
                .map_err(|_| CronError::JitterTooLarge(jitter))?;
            return base
                .checked_add_signed(offset)
                .ok_or(CronError::JitterTooLarge(jitter));
        }
    }
    Err(CronError::Exhausted(expr.to_string()))
}

/// FNV-1a (64-bit), a fixed, publicly-documented, non-cryptographic hash
/// algorithm (see the FNV spec, `isthe.com/chongo/tech/comp/fnv/`) — chosen
/// over `std::collections::hash_map::DefaultHasher` specifically because
/// `DefaultHasher`'s own documentation disclaims algorithm stability across
/// standard-library releases. `deterministic_jitter` below needs a hash
/// whose bit pattern is fixed by *this crate's own code*, not by whichever
/// toolchain built it, so that a daemon rebuilt on a newer Rust never
/// silently shifts every binding's fire instant.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// A deterministic offset in `[0, jitter)`, derived from a fixed-algorithm
/// hash ([`fnv1a64`]) of the un-jittered candidate instant's nanosecond
/// timestamp. Deterministic on purpose: recomputing the same binding from
/// the same base instant (e.g. after Task 3's drift-triggered recompute)
/// must land on the *same* jittered fire time, not re-roll a new one every
/// recompute — otherwise "when will this actually fire" has no stable
/// answer. Pinned to `fnv1a64` rather than `DefaultHasher` so that answer
/// is also stable across Rust toolchain/std upgrades, not just within one
/// compiled binary.
fn deterministic_jitter(base: DateTime<Utc>, jitter: Duration) -> Duration {
    let jitter_nanos = jitter.as_nanos();
    if jitter_nanos == 0 {
        return Duration::ZERO;
    }
    let nanos = base.timestamp_nanos_opt().unwrap_or(0);
    let hash = fnv1a64(&nanos.to_le_bytes());
    let offset_nanos = (hash as u128) % jitter_nanos;
    Duration::from_nanos(offset_nanos as u64)
}

/// Reports whether the given wall-clock instant `naive`, interpreted in
/// `tz`, falls in a DST fold — i.e. whether it is one of the doubled local
/// times that occurs during a fall-back transition. Lets a caller (Task 3's
/// scheduler admission) check a candidate ahead of time to decide whether
/// [`fire_all_ambiguous`] needs to be consulted for a `DstAmbiguous::Both`
/// binding, without having to pattern-match `chrono`'s `LocalResult`
/// itself.
pub fn is_ambiguous_local(tz: Tz, naive: NaiveDateTime) -> bool {
    matches!(tz.from_local_datetime(&naive), LocalResult::Ambiguous(_, _))
}

/// The real double-fire entry point for `DstAmbiguous::Both` (Ruling P16):
/// finds the next wall-clock candidate (strictly after `after`) that falls
/// in a DST fold for `tz`, and returns **both** UTC instants the doubled
/// local time actually corresponds to — first the earlier-offset (e.g.
/// daylight-time) occurrence, then the later-offset (standard-time) one.
/// Returns an empty `Vec` if no ambiguous occurrence exists within the
/// search window (most schedules never hit a fold at all). A caller whose
/// binding policy is `Both` MUST call this function to get the real
/// double-fire semantics — [`next_fire_after`] alone only ever returns the
/// first occurrence for an ambiguous candidate.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// FNV-1a's own published test vector: the hash of the empty byte
    /// string is defined to be the offset basis itself. Verifies `fnv1a64`
    /// against the algorithm's spec, independent of anything in this crate.
    #[test]
    fn fnv1a64_matches_the_published_empty_input_test_vector() {
        assert_eq!(fnv1a64(&[]), 0xcbf29ce484222325);
    }

    /// A second published FNV-1a (64-bit) test vector, for the single byte
    /// 'a' (0x61): offset_basis XOR 0x61, then multiplied by the FNV prime.
    #[test]
    fn fnv1a64_matches_the_published_single_byte_test_vector() {
        assert_eq!(fnv1a64(b"a"), 0xaf63dc4c8601ec8c);
    }

    /// Pins `deterministic_jitter`'s output for a known input to a
    /// hard-coded value, so a future accidental change to the hash
    /// algorithm or the offset formula is caught by the suite rather than
    /// silently shifting every binding's fire instant.
    #[test]
    fn deterministic_jitter_is_pinned_for_a_known_input() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap();
        let jitter = Duration::from_secs(300);
        let offset = deterministic_jitter(base, jitter);
        assert!(offset < jitter, "offset must stay within [0, jitter)");
        // Computed once from the fixed fnv1a64 algorithm above and pinned
        // here; a change to either the hash or the modulo/scale formula
        // must be a deliberate, reviewed edit to this constant.
        assert_eq!(offset, Duration::from_nanos(223_571_448_879));
    }

    #[test]
    fn deterministic_jitter_is_zero_when_jitter_window_is_zero() {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 2, 0, 0).unwrap();
        assert_eq!(deterministic_jitter(base, Duration::ZERO), Duration::ZERO);
    }

    /// Fold-in fix, first magnitude (parity with
    /// `adding_an_interval_binding_beyond_chronos_representable_range_is_rejected`):
    /// a `jitter` beyond `chrono::TimeDelta::MAX` (~9.22e15s), where the old
    /// `unwrap_or_default()` would have silently turned `from_std`'s `Err`
    /// into a zero offset. Confirmed this is rejected (not silently
    /// accepted, and not a panic).
    #[test]
    fn next_fire_after_rejects_jitter_beyond_chronos_representable_range() {
        let err = next_fire_after(
            "* * * * *",
            Tz::UTC,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            &DstGap::FireAtGapEnd,
            &DstAmbiguous::First,
            Duration::from_secs(u64::MAX),
        )
        .unwrap_err();
        assert!(matches!(err, CronError::JitterTooLarge(_)));
    }

    /// Fold-in fix, second magnitude (parity with
    /// `adding_an_interval_binding_that_would_overflow_datetime_arithmetic_is_rejected`):
    /// roughly 8.3e12s <= `jitter` <= `TimeDelta::MAX`, where `from_std`
    /// would have succeeded but the old bare `base + offset` could overflow
    /// chrono's representable year range and panic. Confirmed this
    /// magnitude is rejected too, by the same `MAX_JITTER` bound, rather
    /// than reaching the panicking addition.
    #[test]
    fn next_fire_after_rejects_jitter_that_would_overflow_datetime_arithmetic() {
        let err = next_fire_after(
            "* * * * *",
            Tz::UTC,
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            &DstGap::FireAtGapEnd,
            &DstAmbiguous::First,
            // ~9e12 seconds: from_std would succeed at this magnitude, but
            // the resulting DateTime addition would overflow chrono's range.
            Duration::from_secs(9_000_000_000_000),
        )
        .unwrap_err();
        assert!(matches!(err, CronError::JitterTooLarge(_)));
    }
}
