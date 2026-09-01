use crate::types::{BusError, Envelope};
use roundhouse_core::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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

/// Per-recipient subject tracker. §7.7: "Repetition damper — a send with the same
/// (to, subject) within the window is refused." This is the cheap livelock kill:
/// an agent that loops `message` to the same recipient with an unchanging subject
/// is stopped at the second send, not after burning a full relay cycle.
pub struct RepetitionDamper {
    window: Duration,
    last_seen: Mutex<HashMap<(SessionId, String), Instant>>,
}

impl RepetitionDamper {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last_seen: Mutex::new(HashMap::new()),
        }
    }

    /// Refuses with `BusError::Repetitive` if `(to, subject)` was last seen within
    /// `window`. Records the current `now` as the last-seen timestamp otherwise.
    /// Stale entries (older than `window`) are lazily evicted on each check.
    pub fn check(&self, to: SessionId, subject: &str, now: Instant) -> Result<(), BusError> {
        let mut last_seen = self
            .last_seen
            .lock()
            .expect("repetition damper mutex poisoned");

        // Lazy eviction: drop every pair whose last sighting is outside the window.
        last_seen.retain(|_, seen| now.duration_since(*seen) < self.window);

        let key = (to, subject.to_string());
        if last_seen.contains_key(&key) {
            return Err(BusError::Repetitive {
                to,
                subject: subject.to_string(),
            });
        }

        last_seen.insert(key, now);
        Ok(())
    }
}

/// §7.7: "ttl_hops (default 8) decremented per relay." Decrements the envelope's
/// remaining hop count in place; refuses synchronously once it reaches zero so an
/// envelope can never circulate forever.
pub fn decrement_ttl(envelope: &mut Envelope) -> Result<(), BusError> {
    if envelope.ttl_hops == 0 {
        return Err(BusError::TtlExpired);
    }
    envelope.ttl_hops -= 1;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    fn envelope_with_ttl(ttl_hops: u8) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from: SessionId::new(),
            to: SessionId::new(),
            to_requested: Address::Session {
                id: SessionId::new(),
            },
            subject: "ping".into(),
            body: "hi".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

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
    fn repetition_damper_rejects_same_subject_within_window() {
        let damper = RepetitionDamper::new(Duration::from_secs(10));
        let to = SessionId::new();
        let subject = "status-check";
        let t0 = Instant::now();

        assert!(damper.check(to, subject, t0).is_ok());
        let err = damper
            .check(to, subject, t0 + Duration::from_secs(5))
            .unwrap_err();
        assert!(
            matches!(err, BusError::Repetitive { to: t, subject: s } if t == to && s == "status-check")
        );
    }

    #[test]
    fn repetition_damper_allows_different_subjects() {
        let damper = RepetitionDamper::new(Duration::from_secs(10));
        let to = SessionId::new();
        let t0 = Instant::now();

        assert!(damper.check(to, "one", t0).is_ok());
        assert!(damper.check(to, "two", t0).is_ok());
    }

    #[test]
    fn repetition_damper_allows_after_window_expires() {
        let damper = RepetitionDamper::new(Duration::from_secs(10));
        let to = SessionId::new();
        let subject = "status-check";
        let t0 = Instant::now();

        assert!(damper.check(to, subject, t0).is_ok());
        assert!(damper
            .check(to, subject, t0 + Duration::from_secs(11))
            .is_ok());
    }

    #[test]
    fn ttl_hops_zero_is_refused_synchronously() {
        let mut env = envelope_with_ttl(0);
        assert!(matches!(decrement_ttl(&mut env), Err(BusError::TtlExpired)));
    }

    #[test]
    fn ttl_hops_decrements_on_each_hop() {
        let mut env = envelope_with_ttl(3);
        assert!(decrement_ttl(&mut env).is_ok());
        assert_eq!(env.ttl_hops, 2);
        assert!(decrement_ttl(&mut env).is_ok());
        assert_eq!(env.ttl_hops, 1);
        assert!(decrement_ttl(&mut env).is_ok());
        assert_eq!(env.ttl_hops, 0);
        assert!(matches!(decrement_ttl(&mut env), Err(BusError::TtlExpired)));
    }
}
