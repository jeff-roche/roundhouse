use crate::types::BusError;
use roundhouse_core::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Per-session token bucket. §7.7: "Message rate cap — token bucket per session
/// (default 20/min, burst 10) plus a global cap; exceeding returns Refused, never
/// silently queues."
///
/// Tokens refill continuously at `rate_per_min / 60.0` tokens per second and are
/// capped at `burst`. Time is monotonic (`Instant`), so wall-clock changes and NTP
/// adjustments cannot grant or revoke tokens.
pub struct RateLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets: Mutex<HashMap<SessionId, BucketState>>,
}

struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(rate_per_min: u32, burst: u32) -> Self {
        Self {
            rate_per_sec: rate_per_min as f64 / 60.0,
            burst: burst as f64,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Consumes one token for `session` if any are available after refilling up to
    /// the burst. Returns `BusError::RateLimited` otherwise, carrying the number of
    /// milliseconds until the next token is expected.
    pub fn try_acquire(&self, session: SessionId, now: Instant) -> Result<(), BusError> {
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

        if state.tokens >= 1.0 {
            state.tokens -= 1.0;
            Ok(())
        } else {
            let retry_after_ms = ((1.0 - state.tokens) / self.rate_per_sec * 1000.0).ceil() as u64;
            Err(BusError::RateLimited {
                session,
                retry_after_ms,
            })
        }
    }
}

/// §7.7: "Repetition damper — ≥3 sends with identical (to, subject) and no state
/// change between refuses the 4th. Cheap livelock kill."
pub struct RepetitionDamper {
    counts: HashMap<(SessionId, String), u32>,
}

impl RepetitionDamper {
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    pub fn check_and_record(&mut self, to: SessionId, subject: &str) -> Result<(), BusError> {
        let key = (to, subject.to_string());
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
    /// information) — resets the streak for that `(to, subject)`.
    pub fn note_state_change(&mut self, to: SessionId, subject: &str) {
        self.counts.remove(&(to, subject.to_string()));
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
        let to = SessionId::new();
        let subject = "status-check".to_string();
        assert!(damper.check_and_record(to, &subject).is_ok());
        assert!(damper.check_and_record(to, &subject).is_ok());
        assert!(damper.check_and_record(to, &subject).is_ok());
        assert!(damper.check_and_record(to, &subject).is_err());
    }

    #[test]
    fn repetition_damper_resets_on_state_change() {
        let mut damper = RepetitionDamper::new();
        let to = SessionId::new();
        let subject = "status-check".to_string();
        damper.check_and_record(to, &subject).unwrap();
        damper.check_and_record(to, &subject).unwrap();
        damper.note_state_change(to, &subject);
        damper.check_and_record(to, &subject).unwrap();
        damper.check_and_record(to, &subject).unwrap();
        assert!(damper.check_and_record(to, &subject).is_ok());
    }

    #[test]
    fn ttl_hops_decrements_and_expires_at_zero() {
        assert_eq!(decrement_ttl(1).unwrap(), 0);
        assert!(decrement_ttl(0).is_err());
    }
}
