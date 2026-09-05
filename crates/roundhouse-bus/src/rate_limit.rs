use crate::types::BusError;
use roundhouse_core::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// §7.7 per-session default: 20/min, burst 10.
pub const DEFAULT_RATE_PER_MIN: u32 = 20;
pub const DEFAULT_BURST: u32 = 10;

/// §7.7's "plus a global cap" — a single token bucket, a field on `RateLimiter`
/// which is itself a field of `LocalBus` — so this is **per-`LocalBus` instance**,
/// not process-scoped. (A process hosting more than one `LocalBus` gets one of
/// these per bus.) It is checked in the same `try_acquire` call as the per-session
/// bucket, at `LocalBus::send`'s chokepoint, and bounds *aggregate* message volume
/// across every session sharing this bus, catching a flood spread across many
/// senders that no single per-session bucket would ever see.
///
/// Sizing arithmetic (deliberately generous, so a single busy session never trips
/// this on its own): `MAX_TEAM_SIZE` (`limits.rs`) is 32, the largest population of
/// distinct senders *one team* expects to share a bus — but a single `LocalBus` can
/// and does host more than one team, including across different workspaces (see
/// `team_workspace_scoping_tests`, which puts two workspaces' teams on one
/// `LocalBus`), so the real population sharing this bucket is `workspaces × 32`,
/// unbounded by anything in this crate. `GLOBAL_BURST`/`GLOBAL_RATE_PER_MIN` are set
/// to *twice* "every member of a full team bursting simultaneously at full
/// per-session burst/rate" — i.e. `2 * 32 * 10 = 640` burst and `2 * 32 * 20 =
/// 1280`/min sustained. That leaves a single session's entire per-session budget
/// (burst 10, sustained 20/min) at under 1/32 of the global ceiling on either axis,
/// so a lone session can never reach the global cap without every other session on
/// the bus also being simultaneously active near their own limits — but a second
/// (or third) team's worth of simultaneously-active sessions absolutely can, and
/// that headroom is the arithmetic's actual margin of safety, not a hard guarantee.
pub const GLOBAL_BURST: u32 = 2 * crate::limits::MAX_TEAM_SIZE * DEFAULT_BURST;
pub const GLOBAL_RATE_PER_MIN: u32 = 2 * crate::limits::MAX_TEAM_SIZE * DEFAULT_RATE_PER_MIN;

/// Per-session token bucket, plus a per-`LocalBus`-instance global bucket, not
/// process-scoped (see `GLOBAL_RATE_PER_MIN`/`GLOBAL_BURST` above). §7.7: "Message rate cap — token
/// bucket per session (default 20/min, burst 10) plus a global cap; exceeding
/// returns Refused, never silently queues."
///
/// Tokens refill continuously at `rate_per_min / 60.0` tokens per second and are
/// capped at `burst`. Time is monotonic (`Instant`), so wall-clock changes and NTP
/// adjustments cannot grant or revoke tokens.
pub struct RateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<SessionId, BucketState>>,
    global_rate_per_sec: f64,
    global_burst: f64,
    /// Lazily initialized on the first `try_acquire` call, using that call's `now` —
    /// mirroring how each per-session `BucketState` is lazily seeded on first use.
    global: Mutex<Option<BucketState>>,
}

struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Takes only the per-session numbers; the global cap is always installed at
    /// the `GLOBAL_RATE_PER_MIN`/`GLOBAL_BURST` defaults above. Use
    /// `new_with_global` to override the global numbers too (e.g. in tests).
    pub fn new(rate_per_min: u32, burst: u32) -> Self {
        Self::new_with_global(rate_per_min, burst, GLOBAL_RATE_PER_MIN, GLOBAL_BURST)
    }

    pub fn new_with_global(
        rate_per_min: u32,
        burst: u32,
        global_rate_per_min: u32,
        global_burst: u32,
    ) -> Self {
        Self {
            rate_per_sec: rate_per_min as f64 / 60.0,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::new()),
            global_rate_per_sec: global_rate_per_min as f64 / 60.0,
            global_burst: global_burst as f64,
            global: Mutex::new(None),
        }
    }

    /// Consumes one token from `session`'s bucket *and* the global bucket if both
    /// have room after refilling up to their respective bursts; consumes neither
    /// otherwise. Returns `BusError::RateLimited` carrying `session` and a real
    /// `retry_after_ms` for whichever bucket was the one that refused — the
    /// per-session bucket is checked first, so an abusive session is always
    /// attributed to itself rather than blamed on (or allowed to starve) the shared
    /// global bucket.
    pub fn try_acquire(&self, session: SessionId, now: Instant) -> Result<(), BusError> {
        self.try_acquire_inner(session, now, false)
    }

    /// Like [`try_acquire`](Self::try_acquire), but checks and consumes only the
    /// per-session bucket — the global bucket is left untouched. A1: this is the
    /// human-originated-send path. The global bucket is a shared, per-`LocalBus`
    /// resource (see `GLOBAL_RATE_PER_MIN`'s doc comment) that agent-generated
    /// traffic can drive to zero; a human operator's break-glass send must not be
    /// refused because of load generated by the very agents the operator is trying
    /// to interrupt. The per-session bucket still applies to humans (unchanged
    /// 20/min, burst 10) — this only ever exempts the *global* half, never the
    /// per-session half, so a human sender is still individually metered and
    /// attributable.
    pub fn try_acquire_session_only(
        &self,
        session: SessionId,
        now: Instant,
    ) -> Result<(), BusError> {
        self.try_acquire_inner(session, now, true)
    }

    fn try_acquire_inner(
        &self,
        session: SessionId,
        now: Instant,
        skip_global: bool,
    ) -> Result<(), BusError> {
        let mut buckets = self
            .buckets
            .lock()
            .expect("rate limiter bucket mutex poisoned");
        let state = buckets.entry(session).or_insert(BucketState {
            tokens: self.burst,
            last_refill: now,
        });

        let elapsed = now
            .saturating_duration_since(state.last_refill)
            .as_secs_f64();
        state.tokens = (state.tokens + elapsed * self.rate_per_sec).min(self.burst);
        state.last_refill = now;

        if state.tokens < 1.0 {
            let retry_after_ms = ((1.0 - state.tokens) / self.rate_per_sec * 1000.0).ceil() as u64;
            return Err(BusError::RateLimited {
                session,
                retry_after_ms,
            });
        }

        if skip_global {
            state.tokens -= 1.0;
            return Ok(());
        }

        let mut global = self
            .global
            .lock()
            .expect("rate limiter global mutex poisoned");
        let g = global.get_or_insert(BucketState {
            tokens: self.global_burst,
            last_refill: now,
        });
        let g_elapsed = now.saturating_duration_since(g.last_refill).as_secs_f64();
        g.tokens = (g.tokens + g_elapsed * self.global_rate_per_sec).min(self.global_burst);
        g.last_refill = now;

        if g.tokens < 1.0 {
            // A6: the raw arithmetic retry_after_ms for the global bucket at its
            // sustained refill rate (1000 / (1280/60) ≈ 47ms) reads, to a looping
            // agent, as "retry immediately" — which keeps the bucket pinned at zero
            // and burns CPU spinning on this function's two mutexes instead of
            // backing off. Floor it so a caller that actually honors
            // `retry_after_ms` gives the global bucket real room to refill.
            const GLOBAL_RETRY_AFTER_FLOOR_MS: u64 = 250;
            let retry_after_ms = (((1.0 - g.tokens) / self.global_rate_per_sec * 1000.0).ceil()
                as u64)
                .max(GLOBAL_RETRY_AFTER_FLOOR_MS);
            // Same `BusError::RateLimited` variant as the per-session case (no new
            // variant — see this crate's cross-lane contract on `BusError`), but
            // distinguishable in tracing output via the `cap = "global"` field.
            // A5: `debug!`, not `warn!` — under the sustained flood this cap exists
            // to catch, this line fires dozens of times per second; the comparable
            // duplicate-drop path (`send`, above) already logs at `debug!`.
            tracing::debug!(
                ?session,
                retry_after_ms,
                cap = "global",
                "global message-volume rate cap tripped"
            );
            return Err(BusError::RateLimited {
                session,
                retry_after_ms,
            });
        }

        state.tokens -= 1.0;
        g.tokens -= 1.0;
        Ok(())
    }
}

impl Default for RateLimiter {
    /// §7.7 default: 20/min, burst 10 per session, plus the global cap above.
    fn default() -> Self {
        Self::new(DEFAULT_RATE_PER_MIN, DEFAULT_BURST)
    }
}

/// §7.7: "Repetition damper — ≥3 sends with identical (from, to, subject) and no
/// state change between refuses the 4th. Cheap livelock kill." Keying on `from` too
/// means no single session can permanently jam a (recipient, subject) pair — each
/// (sender, recipient, subject) triple gets its own streak.
pub struct RepetitionDamper {
    counts: HashMap<(SessionId, SessionId, String), u32>,
}

impl RepetitionDamper {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn check_and_record(
        &mut self,
        from: SessionId,
        to: SessionId,
        subject: &str,
    ) -> Result<(), BusError> {
        let key = (from, to, subject.to_string());
        let count = self.counts.entry(key).or_insert(0);
        if *count >= 3 {
            return Err(BusError::Repetitive {
                to,
                subject: subject.to_string(),
            });
        }
        *count += 1;
        Ok(())
    }

    /// Called by the caller whenever it can observe that something changed as a
    /// result of a send (e.g. the recipient's state moved, or a reply carried new
    /// information) — resets the streak for that `(from, to, subject)`.
    pub fn note_state_change(&mut self, from: SessionId, to: SessionId, subject: &str) {
        self.counts.remove(&(from, to, subject.to_string()));
    }
}

impl Default for RepetitionDamper {
    fn default() -> Self {
        Self::new()
    }
}

/// §7.7: "ttl_hops (default 8) decremented per relay." Decrements the remaining hop
/// count; refuses synchronously once it reaches zero so an envelope can never
/// circulate forever.
pub fn decrement_ttl(current: u8) -> Result<u8, BusError> {
    current.checked_sub(1).ok_or(BusError::TtlExpired)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::SessionId;
    use std::time::{Duration, Instant};

    #[test]
    fn token_bucket_allows_burst_then_throttles() {
        let limiter = RateLimiter::new(20, 10); // 20/min, burst 10
        let sid = SessionId::new();
        let t0 = Instant::now();

        for _ in 0..10 {
            assert!(limiter.try_acquire(sid, t0).is_ok());
        }
        // 11th immediate send exceeds the burst allowance.
        let err = limiter.try_acquire(sid, t0).unwrap_err();
        assert!(matches!(err, BusError::RateLimited { session, .. } if session == sid));
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = RateLimiter::new(60, 1); // 60/min == 1/sec, burst 1
        let sid = SessionId::new();
        let t0 = Instant::now();

        assert!(limiter.try_acquire(sid, t0).is_ok());
        assert!(limiter.try_acquire(sid, t0).is_err());
        // One second later, one more token has refilled.
        assert!(limiter
            .try_acquire(sid, t0 + Duration::from_secs(1))
            .is_ok());
    }

    #[test]
    fn repetition_damper_refuses_the_fourth_identical_send() {
        let mut damper = RepetitionDamper::new();
        let from = SessionId::new();
        let to = SessionId::new();
        let subject = "status-check".to_string();
        assert!(damper.check_and_record(from, to, &subject).is_ok());
        assert!(damper.check_and_record(from, to, &subject).is_ok());
        assert!(damper.check_and_record(from, to, &subject).is_ok());
        assert!(damper.check_and_record(from, to, &subject).is_err());
    }

    #[test]
    fn repetition_damper_resets_on_state_change() {
        let mut damper = RepetitionDamper::new();
        let from = SessionId::new();
        let to = SessionId::new();
        let subject = "status-check".to_string();
        damper.check_and_record(from, to, &subject).unwrap();
        damper.check_and_record(from, to, &subject).unwrap();
        damper.note_state_change(from, to, &subject);
        damper.check_and_record(from, to, &subject).unwrap();
        damper.check_and_record(from, to, &subject).unwrap();
        assert!(damper.check_and_record(from, to, &subject).is_ok());
    }

    #[test]
    fn ttl_hops_decrements_and_expires_at_zero() {
        assert_eq!(decrement_ttl(1).unwrap(), 0);
        assert!(decrement_ttl(0).is_err());
    }

    #[test]
    fn global_cap_trips_across_many_distinct_senders_not_one() {
        // Global burst of 5, effectively-infinite rate so elapsed==0 refill is a
        // no-op within this test's single instant `t0`.
        let limiter = RateLimiter::new_with_global(20, 10, 6000, 5);
        let t0 = Instant::now();
        for _ in 0..5 {
            let sid = SessionId::new();
            assert!(limiter.try_acquire(sid, t0).is_ok());
        }
        // A 6th, brand-new sender — its own per-session bucket (burst 10) is
        // untouched — still gets refused because the *global* pool is empty.
        let sixth = SessionId::new();
        let err = limiter.try_acquire(sixth, t0).unwrap_err();
        assert!(matches!(err, BusError::RateLimited { session, .. } if session == sixth));
    }

    #[test]
    fn one_session_at_full_per_session_rate_never_trips_the_global_cap() {
        // The global cap is sized specifically so a single busy session, even
        // running flat-out at its own per-session ceiling forever, never reaches
        // it (see the arithmetic in GLOBAL_RATE_PER_MIN/GLOBAL_BURST's doc comment).
        let limiter = RateLimiter::default();
        let sid = SessionId::new();
        let mut t = Instant::now();
        for _ in 0..10 {
            assert!(limiter.try_acquire(sid, t).is_ok());
        }
        // Sustain exactly at the per-session refill rate (1 token / 3s == 20/min)
        // for far longer than it would take to exhaust the global burst if the
        // global bucket were ever the actual constraint here.
        for _ in 0..100 {
            t += Duration::from_secs(3);
            assert!(limiter.try_acquire(sid, t).is_ok());
        }
    }

    #[test]
    fn global_bucket_refills_over_time() {
        let limiter = RateLimiter::new_with_global(20, 10, 60, 1); // global: 60/min == 1/sec, burst 1
        let t0 = Instant::now();
        let a = SessionId::new();
        let b = SessionId::new();

        assert!(limiter.try_acquire(a, t0).is_ok()); // consumes the sole global token
        assert!(limiter.try_acquire(b, t0).is_err()); // global empty; b's own bucket is untouched
        assert!(limiter.try_acquire(b, t0 + Duration::from_secs(1)).is_ok()); // one second later, the global bucket has refilled
    }
}
