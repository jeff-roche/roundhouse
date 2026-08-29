//! §9.8's retry/circuit-breaker/shed-concurrency machinery, built on top of
//! Task 5's `ProviderError` classification.
//!
//! Fixes audit finding 8 (a "never retry" comment was contradicted by code
//! that called `attempt` a second time on `QuotaExhausted`/`BadRequest`,
//! double-billing on quota exhaustion) and finding 9 (no shed-concurrency/
//! AIMD semaphore existed anywhere, and `RateLimited{retry_after: None}`
//! fell through to a bare `return Err(e)` with zero retries).
use crate::{ModelId, ProviderError, ProviderId}; // real types from ir.rs — do not redeclare
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
// `tokio::time::Instant`, not `std::time::Instant`: this breaker's `Open`→`HalfOpen`
// transition is exercised under `#[tokio::test(start_paused = true)]` with
// `tokio::time::advance`, which only moves tokio's mocked clock. `std::time::Instant::now()`
// is real wall-clock time and does not observe `advance()` at all, so the breaker would
// never see the simulated 10 seconds pass — `tokio::time::Instant::now()` does.
use tokio::time::{sleep, Instant};

pub type BreakerKey = (ProviderId, ModelId); // requires Hash on both — see the ir.rs edit above

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

struct BreakerEntry {
    consecutive_failures: Vec<Instant>, // timestamps of consecutive overloaded/5xx failures
    opened_at: Option<Instant>,
    half_open_trial_in_flight: bool,
}

pub struct CircuitBreaker {
    entries: Mutex<HashMap<BreakerKey, BreakerEntry>>,
}

const FAILURE_THRESHOLD: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(30);
const OPEN_DURATION: Duration = Duration::from_secs(10);

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl CircuitBreaker {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn record_failure(&self, key: BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key).or_insert_with(|| BreakerEntry {
            consecutive_failures: Vec::new(),
            opened_at: None,
            half_open_trial_in_flight: false,
        });
        let now = Instant::now();
        entry
            .consecutive_failures
            .retain(|t| now.duration_since(*t) <= FAILURE_WINDOW);
        entry.consecutive_failures.push(now);
        if entry.consecutive_failures.len() >= FAILURE_THRESHOLD {
            entry.opened_at = Some(now);
        }
    }

    pub fn record_success(&self, key: BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(&key) {
            entry.consecutive_failures.clear();
            entry.opened_at = None;
            entry.half_open_trial_in_flight = false;
        }
    }

    pub fn state(&self, key: BreakerKey) -> BreakerState {
        let entries = self.entries.lock().unwrap();
        match entries.get(&key).and_then(|e| e.opened_at) {
            None => BreakerState::Closed,
            Some(opened_at) if Instant::now().duration_since(opened_at) >= OPEN_DURATION => {
                BreakerState::HalfOpen
            }
            Some(_) => BreakerState::Open,
        }
    }
}

/// §9.8's disposition table, made an explicit type so the retry loop below cannot
/// silently mis-route an error kind the way the previous draft did for two separate
/// bugs (findings 8 and 9). `QuotaExhausted`/`BadRequest`/`ModelNotFound` are fatal —
/// the request is malformed or the account is out of credit, and no amount of retrying
/// changes that. `RateLimited` is always retryable, exactly-timed when the provider
/// gives a `Retry-After`, backed off otherwise. `Overloaded`/`Server`/`Timeout`/
/// `Transport` are shed-and-retry: back off AND shrink this key's concurrency ceiling,
/// since a flood of concurrent requests is often what caused the overload in the first
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    Fatal,
    RetryAfter,
    RetryWithBackoff,
    ShedAndRetry,
}

pub fn disposition(e: &ProviderError) -> Disposition {
    match e {
        ProviderError::QuotaExhausted
        | ProviderError::BadRequest { .. }
        | ProviderError::ModelNotFound => Disposition::Fatal,
        ProviderError::RateLimited {
            retry_after: Some(_),
        } => Disposition::RetryAfter,
        ProviderError::RateLimited { retry_after: None } => Disposition::RetryWithBackoff,
        ProviderError::Overloaded | ProviderError::Server { .. } => Disposition::ShedAndRetry,
        ProviderError::Timeout | ProviderError::Transport(_) => Disposition::RetryWithBackoff,
        // Added 2026-08-28: these two are Phase 0's original placeholder
        // variants, now merged into this same `ProviderError` (see
        // `roundhouse-provider`'s `ir.rs` for the merge note).
        // `Unsupported` means the request asked for a
        // capability this adapter/model doesn't have — retrying the exact
        // same request changes nothing, so it's fatal from this retry
        // loop's perspective (the *caller* may still choose to fall back to
        // a different provider/model, which is a separate decision from
        // "should this exact attempt be retried"). `StreamInterrupted` is
        // explicitly the agent loop's decision per §9.4 ("a transport
        // failure after the first token... the *agent loop* decides —
        // resuming means re-sending a prefix, which changes billing and
        // discards reasoning-model state") — never something this generic
        // retry loop should transparently retry on its own.
        ProviderError::Unsupported(_) | ProviderError::StreamInterrupted { .. } => {
            Disposition::Fatal
        }
    }
}

const INITIAL_PERMITS: usize = 8;
const MIN_PERMITS: usize = 1;
const MAX_PERMITS: usize = 64;
const SUCCESSES_PER_INCREASE: u32 = 10;

struct AimdEntry {
    semaphore: Arc<Semaphore>,
    current_limit: usize,
    consecutive_successes: u32,
}

impl AimdEntry {
    fn new() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(INITIAL_PERMITS)),
            current_limit: INITIAL_PERMITS,
            consecutive_successes: 0,
        }
    }
}

/// §9.8's shed-concurrency/AIMD semaphore, per `(provider, model)` — did not exist at
/// all before this fix (audit finding 9). Halves on a shed-concurrency disposition
/// (multiplicative decrease, reacts fast to real overload); grows by one permit per
/// `SUCCESSES_PER_INCREASE` consecutive successes (additive increase, recovers slowly
/// and doesn't immediately re-trigger the same overload).
pub struct AimdSemaphore {
    entries: Mutex<HashMap<BreakerKey, AimdEntry>>,
}

impl Default for AimdSemaphore {
    fn default() -> Self {
        Self::new()
    }
}

impl AimdSemaphore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn semaphore_for(&self, key: &BreakerKey) -> Arc<Semaphore> {
        let mut entries = self.entries.lock().unwrap();
        entries
            .entry(key.clone())
            .or_insert_with(AimdEntry::new)
            .semaphore
            .clone()
    }

    pub async fn acquire(&self, key: &BreakerKey) -> OwnedSemaphorePermit {
        let sem = self.semaphore_for(key);
        sem.acquire_owned()
            .await
            .expect("semaphore is never closed")
    }

    pub fn shed(&self, key: &BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key.clone()).or_insert_with(AimdEntry::new);
        let new_limit = (entry.current_limit / 2).max(MIN_PERMITS);
        let to_forget = entry.current_limit.saturating_sub(new_limit);
        entry.semaphore.forget_permits(to_forget);
        entry.current_limit = new_limit;
        entry.consecutive_successes = 0;
    }

    pub fn on_success(&self, key: &BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key.clone()).or_insert_with(AimdEntry::new);
        entry.consecutive_successes += 1;
        if entry.consecutive_successes >= SUCCESSES_PER_INCREASE
            && entry.current_limit < MAX_PERMITS
        {
            entry.semaphore.add_permits(1);
            entry.current_limit += 1;
            entry.consecutive_successes = 0;
        }
    }

    pub fn current_limit(&self, key: &BreakerKey) -> usize {
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .map(|e| e.current_limit)
            .unwrap_or(INITIAL_PERMITS)
    }
}

/// Honors an exact Retry-After when the provider gives one; falls back to full-jitter
/// backoff otherwise — including for `RateLimited{retry_after: None}`, which previously
/// fell through to the catchall arm and was never retried (finding 9). Never adds jitter
/// on top of an explicit Retry-After — that header is the provider telling us precisely
/// when capacity returns (S-PROV-3). Every attempt acquires an AIMD permit first, so a
/// shed-concurrency disposition's effect (a smaller ceiling) is enforced on the very
/// next attempt, not just logged.
pub async fn retry_with_policy<F, Fut, T>(
    key: BreakerKey,
    breaker: &CircuitBreaker,
    semaphore: &AimdSemaphore,
    attempt: F,
) -> Result<T, ProviderError>
where
    F: Fn(u32) -> Fut,
    Fut: Future<Output = Result<T, ProviderError>>,
{
    const MAX_ATTEMPTS: u32 = 5;
    for n in 0..MAX_ATTEMPTS {
        if breaker.state(key.clone()) == BreakerState::Open {
            return Err(ProviderError::Overloaded);
        }
        let _permit = semaphore.acquire(&key).await;
        let result = attempt(n).await;
        drop(_permit);

        match result {
            Ok(v) => {
                breaker.record_success(key.clone());
                semaphore.on_success(&key);
                return Ok(v);
            }
            Err(e) => match disposition(&e) {
                // Fixes finding 8: Fatal returns immediately, no second `attempt` call.
                Disposition::Fatal => return Err(e),
                Disposition::RetryAfter => {
                    if let ProviderError::RateLimited {
                        retry_after: Some(d),
                    } = &e
                    {
                        sleep(*d).await;
                    }
                }
                // Fixes finding 9: RateLimited{None}/Timeout/Transport now retry with backoff
                // instead of falling through to an unconditional Err(e).
                Disposition::RetryWithBackoff => {
                    if n + 1 == MAX_ATTEMPTS {
                        return Err(e);
                    }
                    sleep(Duration::from_millis(100 * 2u64.pow(n)) + jitter()).await;
                }
                Disposition::ShedAndRetry => {
                    breaker.record_failure(key.clone());
                    semaphore.shed(&key);
                    if n + 1 == MAX_ATTEMPTS {
                        return Err(e);
                    }
                    sleep(Duration::from_millis(100 * 2u64.pow(n)) + jitter()).await;
                }
            },
        }
    }
    Err(ProviderError::Overloaded)
}

fn jitter() -> Duration {
    Duration::from_millis(rand::random::<u64>() % 100)
}
