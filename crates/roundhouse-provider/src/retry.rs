//! §9.8's retry/circuit-breaker/shed-concurrency machinery, built on top of
//! Task 5's `ProviderError` classification.
//!
//! Fixes audit finding 8 (a "never retry" comment was contradicted by code
//! that called `attempt` a second time on `QuotaExhausted`/`BadRequest`,
//! double-billing on quota exhaustion) and finding 9 (no shed-concurrency/
//! AIMD semaphore existed anywhere, and `RateLimited{retry_after: None}`
//! fell through to a bare `return Err(e)` with zero retries).
//!
//! Post-review fix round (2026-08-29): the first pass of this module
//! inherited the plan document's shown code without reconciling it against
//! `ir.rs`'s own adjacent doc comments on `ProviderError::Overloaded`/
//! `RateLimited` (which already stated the correct §9.8 routing), silently
//! got the shed-vs-no-shed routing backwards as a result, dropped shed
//! debt under load, left the circuit breaker's `HalfOpen` state
//! unenforced, and returned a self-contradictory `Overloaded` (a
//! `disposition()`-retryable error!) from the breaker-open/exhaustion
//! paths. All fixed below; see each item's comment for specifics.
use crate::{ModelId, ProviderError, ProviderId}; // real types from ir.rs — do not redeclare
use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
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
    // Set by `try_enter_half_open_trial` for the one caller admitted while
    // `HalfOpen`; read by that same method to refuse every other concurrent
    // caller. Cleared by `record_success`/`record_failure` when either fires
    // for this key, and — unconditionally, on every exit path, so it can
    // never leak — by the `HalfOpenTrial` RAII guard `retry_with_policy`
    // holds for the lifetime of the call that won the trial.
    half_open_trial_in_flight: bool,
}

impl BreakerEntry {
    fn new() -> Self {
        Self {
            consecutive_failures: Vec::new(),
            opened_at: None,
            half_open_trial_in_flight: false,
        }
    }
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
        let entry = entries.entry(key.clone()).or_insert_with(BreakerEntry::new);
        let now = Instant::now();
        // A failed half-open trial reopens the breaker immediately,
        // regardless of the accumulated-failure threshold below — the whole
        // point of the trial was "is this key healthy again," and it just
        // answered no.
        let trial_failed = entry.half_open_trial_in_flight;
        entry
            .consecutive_failures
            .retain(|t| now.duration_since(*t) <= FAILURE_WINDOW);
        entry.consecutive_failures.push(now);
        if trial_failed || entry.consecutive_failures.len() >= FAILURE_THRESHOLD {
            if entry.opened_at.is_none() {
                tracing::warn!(
                    provider = %key.0 .0,
                    model = %key.1 .0,
                    "circuit breaker tripped open"
                );
            }
            entry.opened_at = Some(now);
        }
        entry.half_open_trial_in_flight = false;
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

    /// Atomic check-and-set admission for the `HalfOpen` state: re-checks
    /// (under the same lock) that the key is actually still half-open, and
    /// if so and no trial is already in flight, claims the trial slot and
    /// returns `true`. Every other concurrent caller — whether it arrives
    /// before or after the winner — sees `half_open_trial_in_flight` already
    /// set and gets `false`. Without this, every caller's separate `state()`
    /// read would observe `HalfOpen` independently and all would proceed at
    /// once, stampeding a provider that's still recovering (the classic
    /// half-open thundering herd this mechanism exists to prevent).
    pub fn try_enter_half_open_trial(&self, key: BreakerKey) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let Some(entry) = entries.get_mut(&key) else {
            return false;
        };
        let now = Instant::now();
        let is_half_open = matches!(
            entry.opened_at,
            Some(opened_at) if now.duration_since(opened_at) >= OPEN_DURATION
        );
        if is_half_open && !entry.half_open_trial_in_flight {
            entry.half_open_trial_in_flight = true;
            true
        } else {
            false
        }
    }

    /// Releases a claimed half-open trial slot. Idempotent — safe to call
    /// even if `record_success`/`record_failure` already cleared the flag
    /// through the breaker's normal state transition (setting `false` to
    /// `false` again is a no-op). Called by `HalfOpenTrial`'s `Drop` impl so
    /// a trial slot can never leak past the `retry_with_policy` call that
    /// claimed it, regardless of which exit path that call takes (post-review
    /// fix, 2026-08-29 — see `HalfOpenTrial`'s doc comment for the bug this
    /// closes).
    fn clear_half_open_trial(&self, key: BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(entry) = entries.get_mut(&key) {
            entry.half_open_trial_in_flight = false;
        }
    }
}

/// RAII guard for a claimed half-open trial slot, held by `retry_with_policy`
/// for the lifetime of the call that won it via `try_enter_half_open_trial`.
///
/// Before this existed, only `record_success`/`record_failure` ever cleared
/// `half_open_trial_in_flight` — but `retry_with_policy`'s `Fatal` arm and
/// `RetryWithBackoff` arm (and, by construction, a dropped/cancelled
/// `attempt` future or a panic inside one) called neither. A single
/// `Timeout`/`BadRequest`/etc. during a trial would leak the flag
/// permanently: `opened_at` never clears without `record_success`, so
/// `state()` reports `HalfOpen` forever and `try_enter_half_open_trial`
/// refuses every subsequent caller forever — a permanent per-key denial of
/// service, strictly worse than the thundering-herd bug this mechanism
/// exists to prevent. Wrapping the claimed slot in this guard means its
/// `Drop` impl clears the flag on *every* exit path — success, any
/// disposition, an early return, a cancelled future, or a panicking
/// `attempt` closure — with no way to forget.
struct HalfOpenTrial<'a> {
    breaker: &'a CircuitBreaker,
    key: BreakerKey,
}

impl Drop for HalfOpenTrial<'_> {
    fn drop(&mut self) {
        self.breaker.clear_half_open_trial(self.key.clone());
    }
}

/// §9.8's disposition table, made an explicit type so the retry loop below cannot
/// silently mis-route an error kind the way the previous draft did for two separate
/// bugs (findings 8 and 9). `QuotaExhausted`/`BadRequest`/`ModelNotFound` are fatal —
/// the request is malformed or the account is out of credit, and no amount of retrying
/// changes that.
///
/// `RateLimited` (both variants) is "your rate" per §9.8 and `ir.rs`'s own doc comment
/// on the variant — it always sheds concurrency, exactly-timed when the provider gives
/// a `Retry-After` (`RetryAfter`), backed off otherwise (`ShedAndRetry`). `Overloaded`
/// is "capacity, not your fault" per the same spec section and `ir.rs` comment — it
/// retries with full-jitter backoff but does **not** shed (a flood of concurrent
/// requests isn't necessarily what caused it, so punishing this key's ceiling isn't
/// warranted). `Server`/`Timeout`/`Transport` are the 5xx/timeout/transport family:
/// retry, capped attempts, no shed either.
///
/// (Post-review note: an earlier version of this table had `Overloaded` shedding and
/// `RateLimited` never shedding — exactly backwards relative to the two paragraphs
/// above, which were already sitting right next to `ProviderError`'s definition in
/// `ir.rs` when that version was written.)
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
        // "Your rate" per ir.rs's own doc comment on this variant — sheds concurrency
        // even without an exact Retry-After to honor (finding 1).
        ProviderError::RateLimited { retry_after: None } => Disposition::ShedAndRetry,
        // "Capacity, not your fault" per ir.rs — retries, but does NOT shed (finding 1).
        ProviderError::Overloaded => Disposition::RetryWithBackoff,
        ProviderError::Server { .. } | ProviderError::Timeout | ProviderError::Transport(_) => {
            Disposition::RetryWithBackoff
        }
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

/// Whether an error should count toward the circuit breaker's failure
/// threshold — a decision §9.8 makes independently of `disposition()`'s
/// "should this shed concurrency" decision, and one this function keeps
/// structurally separate on purpose (post-review fix, 2026-08-29): an
/// earlier version derived "call `record_failure`" from *which disposition
/// arm* an error routed through, which conflated the two questions and
/// regressed both directions at once — `Overloaded`/`Server{..}` (moved
/// off the shedding arm by finding 1's fix) silently stopped tripping the
/// breaker at all, its exact spec-mandated trigger, while `RateLimited`
/// (moved *onto* a shedding arm) started tripping it for a condition §9.8
/// never lists as a breaker trigger. Checking the concrete `ProviderError`
/// variant here, called independently of `disposition()`, makes it
/// impossible for a future change to the shed routing to silently change
/// the breaker-trigger set again.
///
/// Only `Overloaded`/`Server{..}` trigger it, matching §9.8's literal
/// "overloaded/5xx" breaker-open language. `RateLimited` never does — rate
/// limiting isn't a breaker trigger per spec, even though it does shed
/// concurrency. `Timeout`/`Transport` also don't: §9.8's retry-disposition
/// row bundles "5xx/timeout" together, but the breaker-open wording only
/// says "overloaded/5xx" — lacking stronger evidence that a timeout should
/// count the same as a 5xx for breaker purposes, this leans conservative
/// and excludes it (a network hiccup on our end/in transit isn't
/// necessarily evidence the *provider* is unhealthy the way a 5xx is).
///
/// Deliberately an exhaustive `match`, not a `matches!` with an implicit
/// "else false" — mirroring `disposition()`'s own structure above, so a
/// future new `ProviderError` variant forces a compile error here instead
/// of silently defaulting to "not a breaker trigger."
fn is_breaker_trigger(e: &ProviderError) -> bool {
    match e {
        ProviderError::Overloaded | ProviderError::Server { .. } => true,
        ProviderError::RateLimited { .. }
        | ProviderError::Timeout
        | ProviderError::Transport(_)
        | ProviderError::QuotaExhausted
        | ProviderError::BadRequest { .. }
        | ProviderError::ModelNotFound
        | ProviderError::Unsupported(_)
        | ProviderError::StreamInterrupted { .. } => false,
    }
}

const INITIAL_PERMITS: usize = 8;
const MIN_PERMITS: usize = 1;
const MAX_PERMITS: usize = 64;
const SUCCESSES_PER_INCREASE: u32 = 10;

/// Per-key state shared between `AimdSemaphore` and every outstanding
/// `AimdPermit` issued for that key — an `Arc` so a permit can outlive the
/// `acquire()` call that created it (held across awaits, moved into a
/// future) while still being able to report its return to the right key's
/// debt counter on drop.
struct AimdKeyState {
    semaphore: Arc<Semaphore>,
    // Permits that a `shed()` call wanted to remove from circulation but
    // couldn't yet because they were checked out at the time (the exact
    // "provider is overloaded, all permits are in flight" scenario this
    // limiter exists for). Paid down as those permits are returned: an
    // `AimdPermit::drop` with debt outstanding calls `.forget()` on the real
    // permit (removing it from the semaphore for good) instead of letting it
    // return, and decrements debt by one. See `AimdSemaphore::shed`.
    debt: Mutex<usize>,
}

struct AimdEntry {
    state: Arc<AimdKeyState>,
    current_limit: usize,
    consecutive_successes: u32,
}

impl AimdEntry {
    fn new() -> Self {
        Self {
            state: Arc::new(AimdKeyState {
                semaphore: Arc::new(Semaphore::new(INITIAL_PERMITS)),
                debt: Mutex::new(0),
            }),
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

/// An acquired AIMD permit. Behaves like `tokio::sync::OwnedSemaphorePermit`
/// (hold it, drop it to release) but, unlike a raw permit, checks this key's
/// shed debt on drop: if `shed()` reduced `current_limit` while this permit
/// was checked out and couldn't immediately reclaim it, this drop pays that
/// debt down by forgetting the permit outright instead of returning it to
/// the semaphore. Without this, a shed under full load (every permit
/// outstanding) would update `current_limit`'s bookkeeping but never
/// actually shrink the real semaphore once those permits came back —
/// silently discarding the shed and, after enough shed/recover cycles,
/// ratcheting the *real* concurrency ceiling past `MAX_PERMITS` (the
/// security-audit finding this type exists to close).
pub struct AimdPermit {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    state: Arc<AimdKeyState>,
}

impl Drop for AimdPermit {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        let mut debt = self.state.debt.lock().unwrap();
        if *debt > 0 {
            *debt -= 1;
            permit.forget();
        }
        // else: no outstanding debt, drop the real permit normally — it
        // returns to the semaphore's available pool, exactly as a raw
        // `OwnedSemaphorePermit` would.
    }
}

impl AimdSemaphore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn state_for(&self, key: &BreakerKey) -> Arc<AimdKeyState> {
        let mut entries = self.entries.lock().unwrap();
        entries
            .entry(key.clone())
            .or_insert_with(AimdEntry::new)
            .state
            .clone()
    }

    pub async fn acquire(&self, key: &BreakerKey) -> AimdPermit {
        let state = self.state_for(key);
        let permit = state
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore is never closed");
        AimdPermit {
            permit: Some(permit),
            state,
        }
    }

    /// Multiplicative decrease: halves `current_limit` (floor `MIN_PERMITS`).
    /// Forgets as many currently-*available* permits as it can immediately;
    /// anything it can't reach yet (because it's checked out right now —
    /// the overload scenario) becomes debt, collected by `AimdPermit::drop`
    /// as those permits are returned. `current_limit` always reflects the
    /// intended ceiling; the real semaphore catches up as outstanding
    /// permits come back.
    ///
    /// Deferred debt is computed from `forget_permits`'s own return value
    /// (the actual number it forgot), not from a separately-read
    /// `available_permits()` beforehand (post-review fix, 2026-08-29): those
    /// were two non-atomic reads of the same counter, so a concurrent
    /// `acquire` landing in the gap between them could grab a permit this
    /// call had already counted as "available to forget," making
    /// `forget_permits` forget fewer than `want_to_forget` while the stale
    /// `available` count silently ate the difference instead of it becoming
    /// debt — the same class of lost-shed bug this whole debt mechanism
    /// exists to close, just narrowed to a smaller window.
    pub fn shed(&self, key: &BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key.clone()).or_insert_with(AimdEntry::new);
        let new_limit = (entry.current_limit / 2).max(MIN_PERMITS);
        let want_to_forget = entry.current_limit.saturating_sub(new_limit);
        let forgotten = entry.state.semaphore.forget_permits(want_to_forget);
        let deferred = want_to_forget - forgotten;
        if deferred > 0 {
            *entry.state.debt.lock().unwrap() += deferred;
        }
        entry.current_limit = new_limit;
        entry.consecutive_successes = 0;
    }

    /// Additive increase: after `SUCCESSES_PER_INCREASE` consecutive
    /// successes, raises `current_limit` by exactly one (ceiling
    /// `MAX_PERMITS`). If a `shed()` still has unpaid debt outstanding for
    /// this key (permits it wanted to remove but hasn't reclaimed yet),
    /// growth cancels one unit of that debt instead of minting a new real
    /// permit — otherwise the real semaphore would end up with both the
    /// shed's in-flight permits *and* a freshly added one once everything
    /// settles, silently exceeding `current_limit`.
    pub fn on_success(&self, key: &BreakerKey) {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.entry(key.clone()).or_insert_with(AimdEntry::new);
        entry.consecutive_successes += 1;
        if entry.consecutive_successes >= SUCCESSES_PER_INCREASE
            && entry.current_limit < MAX_PERMITS
        {
            let mut debt = entry.state.debt.lock().unwrap();
            if *debt > 0 {
                *debt -= 1;
            } else {
                drop(debt);
                entry.state.semaphore.add_permits(1);
            }
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

    /// The semaphore's *real* available-permit count, as opposed to
    /// `current_limit`'s bookkeeping — used by tests to verify a `shed()`
    /// under load actually reduces real capacity once outstanding permits
    /// are returned, not just the reported limit.
    pub fn available_permits(&self, key: &BreakerKey) -> usize {
        self.entries
            .lock()
            .unwrap()
            .get(key)
            .map(|e| e.state.semaphore.available_permits())
            .unwrap_or(INITIAL_PERMITS)
    }
}

/// A circuit-breaker rejection (breaker `Open`, or `HalfOpen` with another
/// trial already in flight) is deliberately *not* `ProviderError::Overloaded`
/// — `Overloaded` is exactly what this module's own `disposition()` classifies
/// as retryable. A caller that fed a breaker rejection back through
/// `disposition()` to decide what to do next would see "retry this," the
/// opposite of what a tripped breaker means. `Unsupported` classifies as
/// `Fatal`, correctly signaling "don't retry this exact call" without
/// inventing a new `ProviderError` variant for it.
fn breaker_rejection(key: &BreakerKey, reason: &str) -> ProviderError {
    ProviderError::Unsupported(format!(
        "circuit breaker rejected request for provider={} model={}: {reason}",
        key.0 .0, key.1 .0
    ))
}

/// Honors an exact Retry-After when the provider gives one; falls back to full-jitter
/// backoff otherwise — including for `RateLimited{retry_after: None}`, which previously
/// fell through to the catchall arm and was never retried (finding 9). Never adds jitter
/// on top of an explicit Retry-After — that header is the provider telling us precisely
/// when capacity returns (S-PROV-3) — but does clamp it against the same
/// `errors::MAX_RETRY_AFTER` ceiling `parse_retry_after` already enforces, belt-and-braces,
/// since a `RateLimited` value can in principle be constructed directly rather than only
/// via that parser. Every attempt acquires an AIMD permit first, so a shed-concurrency
/// disposition's effect (a smaller ceiling) is enforced on the very next attempt, not just
/// logged. A tripped or half-open-and-already-trialing breaker refuses the call outright
/// (see `breaker_rejection`) rather than silently returning a retryable-looking error, and
/// on final attempt exhaustion the *last real* provider error is returned instead of a
/// generic placeholder.
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
    let mut last_err: Option<ProviderError> = None;
    // Set once, the first time this call observes `HalfOpen` and wins the
    // trial slot; `Some` for every remaining iteration of *this* call's own
    // loop after that. Declared outside the loop and dropped only when this
    // function returns (any exit path — success, `Fatal`, exhaustion,
    // cancellation, panic), so the slot it holds can never leak (finding 2)
    // and this call never re-checks/re-acquires it against itself on a later
    // iteration (finding 3 — without this, a call's own second attempt would
    // see the flag it itself set and reject its own retry).
    let mut trial: Option<HalfOpenTrial<'_>> = None;
    for n in 0..MAX_ATTEMPTS {
        if trial.is_none() {
            match breaker.state(key.clone()) {
                BreakerState::Open => {
                    tracing::warn!(
                        provider = %key.0 .0,
                        model = %key.1 .0,
                        "refusing attempt: circuit breaker open"
                    );
                    return Err(breaker_rejection(&key, "breaker open"));
                }
                BreakerState::HalfOpen => {
                    if breaker.try_enter_half_open_trial(key.clone()) {
                        trial = Some(HalfOpenTrial {
                            breaker,
                            key: key.clone(),
                        });
                    } else {
                        tracing::warn!(
                            provider = %key.0 .0,
                            model = %key.1 .0,
                            "refusing attempt: half-open trial already in flight"
                        );
                        return Err(breaker_rejection(&key, "half-open trial already in flight"));
                    }
                }
                BreakerState::Closed => {}
            }
        }
        // else: this call already won the trial slot on an earlier iteration
        // of its own loop — proceed without re-checking breaker state at all.

        let _permit = semaphore.acquire(&key).await;
        let result = attempt(n).await;
        drop(_permit);

        match result {
            Ok(v) => {
                breaker.record_success(key.clone());
                semaphore.on_success(&key);
                return Ok(v);
            }
            Err(e) => {
                last_err = Some(e.clone());
                // Finding 1 (post-review): "should this trip the breaker" and "should
                // this shed concurrency" are independent §9.8 decisions — checked here
                // via the concrete error variant, not derived from which `Disposition`
                // arm below happens to run, so they can't get re-coupled by a future
                // change to the shed routing.
                if is_breaker_trigger(&e) {
                    breaker.record_failure(key.clone());
                    tracing::warn!(
                        provider = %key.0 .0,
                        model = %key.1 .0,
                        "breaker failure recorded (overloaded/5xx)"
                    );
                }
                match disposition(&e) {
                    // Fixes finding 8: Fatal returns immediately, no second `attempt` call.
                    Disposition::Fatal => return Err(e),
                    Disposition::RetryAfter => {
                        // Finding 1: RateLimited always means "your rate," regardless of
                        // whether the provider gave an exact retry-after value — shed here
                        // too (but does NOT trip the breaker — see is_breaker_trigger above).
                        semaphore.shed(&key);
                        tracing::warn!(
                            provider = %key.0 .0,
                            model = %key.1 .0,
                            "rate limited (exact retry-after); shedding concurrency"
                        );
                        // Finding 5: this arm was missing the same attempt-exhaustion guard
                        // the other two backoff arms already had.
                        if n + 1 == MAX_ATTEMPTS {
                            return Err(e);
                        }
                        if let ProviderError::RateLimited {
                            retry_after: Some(d),
                        } = &e
                        {
                            // Finding 5: clamp at the sleep site too, belt-and-braces —
                            // `parse_retry_after` already caps parsed headers, but a
                            // hand-constructed `RateLimited` would bypass that.
                            sleep((*d).min(crate::errors::MAX_RETRY_AFTER)).await;
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
                        // Finding 1: sheds, but does NOT trip the breaker (RateLimited{None}
                        // is not a breaker trigger — see is_breaker_trigger above).
                        semaphore.shed(&key);
                        tracing::warn!(
                            provider = %key.0 .0,
                            model = %key.1 .0,
                            "shedding concurrency after overload/error"
                        );
                        if n + 1 == MAX_ATTEMPTS {
                            return Err(e);
                        }
                        sleep(Duration::from_millis(100 * 2u64.pow(n)) + jitter()).await;
                    }
                }
            }
        }
    }
    tracing::error!(
        provider = %key.0 .0,
        model = %key.1 .0,
        "retry attempts exhausted"
    );
    // Finding 3: return the last real error, not a generic Overloaded that would
    // itself misleadingly classify as retryable via this module's own disposition().
    Err(last_err.unwrap_or(ProviderError::Overloaded))
}

fn jitter() -> Duration {
    Duration::from_millis(rand::random::<u64>() % 100)
}
