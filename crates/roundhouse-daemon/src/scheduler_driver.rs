//! The scheduler background service (Phase 8, L3, Task 5): the daemon-side
//! driver that turns persisted `trigger_binding` rows into a live
//! [`Scheduler`] and feeds every occurrence that scheduler fires through
//! [`accept_occurrence`], which durably records the `trigger_event`, runs the
//! overlap-policy admission gate, and (for an admitting decision) creates the
//! `ready` `trigger_delivery` row.
//!
//! # What this module deliberately does NOT do
//!
//! It starts no run and creates no session. A `Fire` processed here stops at
//! the durable `trigger_delivery` row; picking that row up, reserving a run
//! and constructing the headless session is the *next* task's job. That is
//! why [`InMemoryRunRegistry`] below is honest about its own limits rather
//! than pretending to be a complete run tracker (see its doc comment).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use roundhouse_core::{BindingId, JobId, WorkspaceId};
use roundhouse_sched::admission::{CancellationOutcome, RegistryError, RunRegistry};
use roundhouse_sched::scheduler::{
    ClockSource, ScheduledOccurrence, Scheduler, SchedulerEvent, SystemClock,
};
use roundhouse_sched::store::accept_occurrence;
use roundhouse_sched::trigger::{Binding, OverlapPolicy, StoredBinding, TriggerSpec};
use roundhouse_store::StorePool;
use rusqlite::Connection;
use uuid::Uuid;

use crate::session_bootstrap::{BackgroundServiceContext, BackgroundServiceError};

/// How often the driver asks the scheduler what is due. One second is the
/// finest granularity any `TriggerSpec` this scheduler heaps can express
/// (`cron`'s tightest practical cadence is a minute; `Interval`'s `every` is
/// a `Duration` but nothing downstream promises sub-second delivery), so a
/// one-second heartbeat bounds the lateness of a fire to the heartbeat
/// itself without polling the clock in a tight loop.
const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(1);

/// How far back a restored binding's persisted fire cursor may reach when it
/// seeds that binding's catch-up baseline at boot.
///
/// `Scheduler`'s own `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` bounds a
/// backlog *per tick*, not in total, and one of the two heap-scheduled specs
/// has nothing that collapses it: `TriggerSpec::Interval` has no `CatchUp`
/// policy, so `drain_due` takes its identity branch and fires every missed
/// occurrence. A one-second `Interval` whose daemon was down for a week
/// therefore owes 604,800 occurrences and would replay them at 100 per tick —
/// roughly 1.7 hours of continuous `trigger_event` writes after boot, nearly
/// all of which become `SkipDueToOverlap` anyway. That is the default
/// non-cron path, not an exotic configuration.
///
/// Clamping the *baseline* rather than the per-tick count is what bounds it
/// in total: a binding is never replayed from further back than this,
/// however stale its persisted cursor actually is. Twenty-four hours matches
/// the catch-up philosophy `docs/architecture/05-scheduling-and-workflows.md`
/// already states — one report this morning, not eight.
///
/// **This lives here, in the daemon, deliberately.** `Scheduler::add_binding`
/// is a general-purpose mechanism ("seed from this baseline"); *how far back
/// to replay* is a policy decision, and belongs to the caller that decides
/// what baseline to hand it.
const MAX_CATCH_UP_LOOKBACK: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Boot-load failures that abort daemon startup.
///
/// Deliberately static `Display` strings with the real cause carried as a
/// `#[source]`/log line rather than interpolated here: this error is
/// stringified into [`BackgroundServiceError`], which is rendered through
/// `tracing`, and this crate's manifest records the binding invariant that
/// no operator- or repository-controlled bytes may reach a `tracing` field
/// or message.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerDriverError {
    #[error("could not check out a store connection for the trigger-binding boot load")]
    StoreConnection,
    #[error("the trigger_binding boot-load query failed")]
    BootLoadQuery,
}

/// A [`ClockSource`] pinned to one already-taken wall-clock reading.
///
/// [`Scheduler::tick`] reads the clock itself and hands the reading back to
/// nobody, but `accept_occurrence` needs the *same* reading as this tick's
/// `fired_at` — otherwise the durable `trigger_event.fired_at` is a second
/// reading taken some microseconds later, which is a different value on
/// every retry and makes "when did this tick decide to fire" unreconstructable
/// from the row. Reading the clock once per tick and ticking against this
/// makes the two provably identical rather than merely close.
struct FixedClock(DateTime<Utc>);

impl ClockSource for FixedClock {
    fn wall_now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// Per-binding run-concurrency counters, held in memory for the lifetime of
/// the daemon process.
///
/// This is the first non-test [`RunRegistry`] in the workspace: before this
/// task every implementation was a test fixture. It is deliberately the
/// smallest thing that satisfies the trait's documented contract —
/// `&self` + interior mutability, every mutation visible to the matching
/// read before the call returns, and `checked_add`/`checked_sub` reporting
/// [`RegistryError::CounterOutOfRange`] rather than wrapping (a wrapping
/// `+= 1` at `u32::MAX` silently becomes `0`, the exact fail-open mode the
/// admission gate exists to prevent).
///
/// # Two limits a reader must not mistake for bugs
///
/// 1. **`cancel_active` always reports `Unconfirmed`.** This driver starts
///    no runs yet, so there is no process, task, or run handle for it to
///    terminate — and [`RunRegistry::cancel_active`]'s contract forbids
///    blocking to find out. Reporting `Confirmed` would be a lie that lets
///    `decide_admission` admit a replacement on top of a predecessor it
///    never actually stopped. `Unconfirmed` makes `OverlapPolicy::CancelPrevious`
///    fail closed instead, which is the correct behaviour for a daemon that
///    cannot yet cancel anything.
/// 2. **Nothing calls [`RunRegistry::note_finished`] yet.** `accept_occurrence`
///    calls `note_admitted` for every admitted occurrence, and the only
///    thing that could ever balance it is the run-completion path a later
///    task adds. Until then an `OverlapPolicy::Skip` binding (the default
///    for `Cron`/`Interval`) fires once and then reports
///    `SkipDueToOverlap` for every subsequent occurrence, because its
///    active count never returns to zero. That is a known, bounded
///    consequence of this task stopping at the `trigger_delivery` row, not
///    an accounting bug here: the release side belongs with the code that
///    actually runs and completes a delivery.
///
/// Counters are per-process and per-`InMemoryRunRegistry` value — a daemon
/// restart starts from zero. That matches this state's nature (it describes
/// runs *of this process*), not a durability gap.
///
/// # Why this is not wrapped in `SharedRegistry`
///
/// `roundhouse_sched::admission::SharedRegistry` is the crate's supported
/// way to share one registry across *concurrent* callers, and it cannot be
/// used here: `accept_occurrence` calls `decide_admission` itself, through a
/// `&dyn RunRegistry` it is handed, so there is no seam for `SharedRegistry`
/// to interpose its per-binding lock on. The race that wrapper exists to
/// close is closed differently here — this registry has exactly one caller,
/// [`run`]'s heartbeat loop, which processes a tick's occurrences strictly
/// one after another on a single blocking `interact` call. If a second
/// caller is ever added, that reasoning stops holding and this needs the
/// per-binding locking discipline back, not merely its own `Mutex`.
#[derive(Debug, Default)]
pub struct InMemoryRunRegistry {
    counts: Mutex<HashMap<BindingId, Counts>>,
}

#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    active: u32,
    queued: u32,
}

impl InMemoryRunRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Runs `f` against `binding_id`'s counters with the registry lock held.
    /// A poisoned lock fails closed (`RegistryError::Poisoned`) rather than
    /// recovering the guard: the counters a panicking holder left behind
    /// cannot be trusted, and an untrustworthy count is exactly what an
    /// admission gate must not admit against.
    fn with_counts<T>(
        &self,
        binding_id: BindingId,
        f: impl FnOnce(&mut Counts) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let mut counts = self.counts.lock().map_err(|_| {
            tracing::error!(
                binding_id = %binding_id,
                "the scheduler driver's run-registry lock is poisoned; admission is denied \
                 for every binding until the daemon is restarted"
            );
            RegistryError::Poisoned { binding_id }
        })?;
        f(counts.entry(binding_id).or_default())
    }
}

impl RunRegistry for InMemoryRunRegistry {
    fn active_run_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        self.with_counts(binding_id, |counts| Ok(counts.active))
    }

    fn queued_count(&self, binding_id: BindingId) -> Result<u32, RegistryError> {
        self.with_counts(binding_id, |counts| Ok(counts.queued))
    }

    fn cancel_active(&self, _binding_id: BindingId) -> Result<CancellationOutcome, RegistryError> {
        // See this type's doc comment, limit 1: nothing here can terminate a
        // run, so nothing here may claim one terminated.
        Ok(CancellationOutcome::Unconfirmed)
    }

    fn note_admitted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_counts(binding_id, |counts| {
            counts.active = counts
                .active
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        })
    }

    fn note_queued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_counts(binding_id, |counts| {
            counts.queued = counts
                .queued
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        })
    }

    fn note_finished(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_counts(binding_id, |counts| {
            counts.active = counts
                .active
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        })
    }

    fn note_dequeued(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        self.with_counts(binding_id, |counts| {
            counts.queued = counts
                .queued
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            Ok(())
        })
    }

    fn note_promoted(&self, binding_id: BindingId) -> Result<(), RegistryError> {
        // Both counters move under one acquisition of the same lock, which is
        // what `note_promoted`'s "visible together" contract requires — a
        // reader cannot observe the decremented queue before the incremented
        // active count.
        self.with_counts(binding_id, |counts| {
            let queued = counts
                .queued
                .checked_sub(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            let active = counts
                .active
                .checked_add(1)
                .ok_or(RegistryError::CounterOutOfRange { binding_id })?;
            counts.queued = queued;
            counts.active = active;
            Ok(())
        })
    }
}

/// One `trigger_binding` row as SQLite hands it back, before the fallible
/// UUID/JSON decoding that cannot happen inside a `rusqlite` row-mapping
/// closure (which must return `rusqlite::Result`).
struct RawBindingRow {
    binding_id: String,
    workspace_id: String,
    job_id: String,
    spec_json: String,
    overlap_json: String,
    last_fired_for: Option<i64>,
}

/// Loads every enabled `trigger_binding`, paired with its persisted
/// `trigger_binding_cursor.last_fired_for`, as the [`StoredBinding`]s both
/// the [`Scheduler`] and [`accept_occurrence`] need.
///
/// `now` is the boot instant this load is reckoned against — taken once by
/// the caller and passed in rather than read here, both so the whole boot
/// sequence agrees on one reading and so the [`MAX_CATCH_UP_LOOKBACK`] clamp
/// each restored cursor passes through
/// ([`clamp_catch_up_baseline`]) is testable without a real clock.
///
/// Disabled rows (`enabled = 0`) are excluded by the query, not filtered
/// afterwards, so a disabled binding never becomes a `Binding` in the first
/// place.
///
/// # One bad row does not fail the load
///
/// A row whose ids or JSON cannot be decoded is logged and skipped; only a
/// connection or query failure aborts the load (and therefore daemon boot).
/// The alternative — refusing to boot at all — takes down every session on
/// the daemon because one trigger row is corrupt, which is a far worse
/// outcome than that one trigger not firing. The skip is logged at `error`
/// so it is not silent.
pub async fn load_enabled_bindings(
    store: &StorePool,
    now: DateTime<Utc>,
) -> Result<Vec<StoredBinding>, SchedulerDriverError> {
    let conn = store.pool.get().await.map_err(|error| {
        tracing::error!(error = %error, "could not check out a store connection");
        SchedulerDriverError::StoreConnection
    })?;
    let rows = conn
        .interact(
            |connection| -> Result<Vec<RawBindingRow>, rusqlite::Error> {
                let mut statement = connection.prepare(
                    "SELECT b.binding_id, b.workspace_id, b.job_id, b.spec_json, b.overlap_json, \
                        c.last_fired_for \
                 FROM trigger_binding b \
                 LEFT JOIN trigger_binding_cursor c ON c.binding_id = b.binding_id \
                 WHERE b.enabled = 1 \
                 ORDER BY b.created_at, b.binding_id",
                )?;
                let rows = statement
                    .query_map([], |row| {
                        Ok(RawBindingRow {
                            binding_id: row.get(0)?,
                            workspace_id: row.get(1)?,
                            job_id: row.get(2)?,
                            spec_json: row.get(3)?,
                            overlap_json: row.get(4)?,
                            last_fired_for: row.get(5)?,
                        })
                    })?
                    .collect();
                rows
            },
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "the trigger_binding boot-load query panicked");
            SchedulerDriverError::BootLoadQuery
        })?
        .map_err(|error| {
            tracing::error!(error = %error, "the trigger_binding boot-load query failed");
            SchedulerDriverError::BootLoadQuery
        })?;

    Ok(rows
        .into_iter()
        .filter_map(|raw| decode_binding_row(raw, now))
        .collect())
}

/// The effective catch-up baseline for a restored cursor: never further back
/// than [`MAX_CATCH_UP_LOOKBACK`] before `now`.
///
/// A cursor already inside the window is returned untouched; only a staler
/// one is pulled forward. `None` (a binding that has never fired) stays
/// `None`, so the scheduler falls back to its own wall-clock reading and the
/// binding has no backlog at all.
///
/// This clamps the *replay baseline*, not the persisted record: the
/// `trigger_binding_cursor` row still holds the true historical value, and
/// `accept_occurrence` still advances it monotonically. A binding down longer
/// than the window simply does not replay everything it missed — by design,
/// and reported at `warn` so the discarded span is visible rather than
/// inferred.
fn clamp_catch_up_baseline(
    last_fired_for: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    binding_id: BindingId,
) -> Option<DateTime<Utc>> {
    let cursor = last_fired_for?;
    // `MAX_CATCH_UP_LOOKBACK` is a fixed 24h constant, so this conversion
    // cannot fail; `checked_sub_signed` guards the (unreachable) case of
    // `now` sitting within a day of chrono's representable minimum rather
    // than panicking on the subtraction.
    let Some(earliest) = chrono::Duration::from_std(MAX_CATCH_UP_LOOKBACK)
        .ok()
        .and_then(|window| now.checked_sub_signed(window))
    else {
        return Some(cursor);
    };
    if cursor >= earliest {
        return Some(cursor);
    }
    tracing::warn!(
        binding_id = %binding_id,
        lookback_hours = MAX_CATCH_UP_LOOKBACK.as_secs() / 3600,
        "this binding's persisted fire cursor is older than the catch-up lookback window; \
         replaying only the window and discarding the rest of the missed span"
    );
    Some(earliest)
}

/// Decodes one raw row, returning `None` (with an `error` log) for a row
/// this daemon cannot make sense of. See [`load_enabled_bindings`] for why a
/// bad row is skipped rather than fatal.
fn decode_binding_row(raw: RawBindingRow, now: DateTime<Utc>) -> Option<StoredBinding> {
    let binding_id = match Uuid::parse_str(&raw.binding_id) {
        Ok(id) => BindingId::from_uuid(id),
        Err(_) => {
            // The malformed value itself is deliberately NOT logged: it is
            // the one field of this row that is definitely not a UUID, and
            // therefore the one field that could carry arbitrary bytes into
            // a `tracing` field.
            tracing::error!(
                "skipping a trigger_binding row whose binding_id is not a UUID; this \
                 binding will not fire until the row is repaired"
            );
            return None;
        }
    };
    let workspace = match Uuid::parse_str(&raw.workspace_id) {
        Ok(id) => WorkspaceId::from_uuid(id),
        Err(_) => {
            tracing::error!(
                binding_id = %binding_id,
                "skipping a trigger_binding row whose workspace_id is not a UUID"
            );
            return None;
        }
    };
    let job_id = match Uuid::parse_str(&raw.job_id) {
        Ok(id) => JobId::from_uuid(id),
        Err(_) => {
            tracing::error!(
                binding_id = %binding_id,
                "skipping a trigger_binding row whose job_id is not a UUID"
            );
            return None;
        }
    };
    let spec: TriggerSpec = match serde_json::from_str(&raw.spec_json) {
        Ok(spec) => spec,
        Err(error) => {
            // `line`/`column` are integers and the error's `classify` is a
            // fixed vocabulary, so this says where the parse failed without
            // echoing any byte of the stored JSON back into a log field.
            tracing::error!(
                binding_id = %binding_id,
                line = error.line(),
                column = error.column(),
                category = ?error.classify(),
                "skipping a trigger_binding row whose spec_json does not parse as a TriggerSpec"
            );
            return None;
        }
    };
    let overlap: OverlapPolicy = match serde_json::from_str(&raw.overlap_json) {
        Ok(overlap) => overlap,
        Err(error) => {
            tracing::error!(
                binding_id = %binding_id,
                line = error.line(),
                column = error.column(),
                category = ?error.classify(),
                "skipping a trigger_binding row whose overlap_json does not parse as an \
                 OverlapPolicy"
            );
            return None;
        }
    };

    Some(StoredBinding {
        workspace,
        binding: Binding {
            id: binding_id,
            job_id,
            spec,
            overlap,
            // The *effective* replay baseline, clamped to the catch-up
            // lookback window — not necessarily the historical cursor the
            // row holds. See `clamp_catch_up_baseline`.
            last_fired_for: clamp_catch_up_baseline(
                raw.last_fired_for.map(DateTime::from_timestamp_nanos),
                now,
                binding_id,
            ),
            // Always `None`: `Scheduler::add_binding` overwrites this field
            // itself (via its own `push_occurrences`) from the occurrences it
            // computes, so any value restored here would be discarded on the
            // next line anyway. Persisting it would also be wrong — migration
            // 0013 deliberately keeps `next_fire_at` out of
            // `trigger_binding_cursor`, because it is derived state, not a
            // fact about what happened.
            next_fire_at: None,
            // The query already restricted to `enabled = 1`.
            enabled: true,
        },
    })
}

/// Resolves each [`SchedulerEvent`] to the [`StoredBinding`] whose workspace
/// and overlap policy [`accept_occurrence`] needs.
///
/// An occurrence naming a binding this driver has no snapshot of is logged
/// and dropped rather than fired blind — `accept_occurrence` would reject it
/// anyway (`StoreError::BindingIdentityMismatch`), and there is no honest
/// `StoredBinding` to invent for it.
fn pair_with_bindings(
    bindings: &HashMap<BindingId, StoredBinding>,
    events: Vec<SchedulerEvent>,
) -> Vec<(StoredBinding, ScheduledOccurrence)> {
    events
        .into_iter()
        .filter_map(|event| {
            let SchedulerEvent::Fire(occurrence) = event;
            match bindings.get(&occurrence.binding_id) {
                Some(stored) => Some((stored.clone(), occurrence)),
                None => {
                    tracing::error!(
                        binding_id = %occurrence.binding_id,
                        "the scheduler fired an occurrence for a binding this driver has no \
                         snapshot of; dropping it"
                    );
                    None
                }
            }
        })
        .collect()
}

/// Runs [`accept_occurrence`] for each due occurrence.
///
/// One occurrence's failure is logged and skipped, never propagated: a
/// single binding whose acceptance fails (a `SQLITE_BUSY` that outlasted the
/// busy handler, a registry counter at its ceiling) must not stop the other
/// bindings due in the same tick, and must not terminate the driver — a
/// background service that returns `Err` takes the whole daemon down with
/// it.
fn accept_due_occurrences(
    conn: &mut Connection,
    due: &[(StoredBinding, ScheduledOccurrence)],
    fired_at: DateTime<Utc>,
    registry: &dyn RunRegistry,
) {
    for (stored, occurrence) in due {
        match accept_occurrence(conn, stored, occurrence, fired_at, registry) {
            Ok(acceptance) => tracing::debug!(
                binding_id = %occurrence.binding_id,
                is_catch_up = occurrence.is_catch_up,
                ?acceptance,
                "accepted a scheduled occurrence"
            ),
            Err(error) => tracing::error!(
                binding_id = %occurrence.binding_id,
                error = %error,
                "failed to accept a scheduled occurrence; this occurrence is dropped, other \
                 bindings are unaffected"
            ),
        }
    }
}

/// The scheduler background service.
///
/// Boot order is load -> schedule -> signal readiness -> heartbeat, and
/// [`BackgroundServiceContext::signal_ready`] is called exactly once, after
/// the load has succeeded: the daemon's startup contract is that a service
/// returning or failing before readiness aborts boot, so signalling earlier
/// would report a scheduler that is not yet scheduling anything.
///
/// # The binding snapshot is taken once, at boot
///
/// [`Scheduler`] exposes no lookup from `BindingId` back to a `Binding`, so
/// this driver keeps its own `HashMap<BindingId, StoredBinding>` — populated
/// by the same boot load that seeds the scheduler — to resolve each `Fire`
/// back to the workspace and overlap policy `accept_occurrence` needs.
///
/// **That snapshot is never refreshed.** A binding created, enabled,
/// disabled, or deleted after boot is not picked up by a running driver; it
/// takes effect on the next daemon restart. That is a known limitation of
/// this task's scope rather than an oversight: no binding CRUD or lifecycle
/// API exists yet for this driver to observe. When one lands it needs a
/// channel into this loop that updates both the scheduler and this map
/// together.
///
/// # The restored cursor replays the downtime backlog
///
/// `trigger_binding_cursor.last_fired_for` is restored onto each `Binding`
/// by [`load_enabled_bindings`], and `Scheduler::add_binding` seeds that
/// binding's first heap entry from it — so occurrences a binding missed
/// while this daemon was down are still due on the first tick after boot,
/// rather than being skipped in favour of "next occurrence after now."
///
/// That backlog is bounded in two independent ways, and both matter:
///
/// - **Per tick**, by `drain_due`: at most
///   `MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK` (100) occurrences per
///   binding per tick, further reduced by the binding's own `CatchUp` policy
///   (`Latest` collapses the window to one fire, `None` drops it, `All`
///   drains progressively).
/// - **In total**, by [`MAX_CATCH_UP_LOOKBACK`] (24 hours): the baseline this
///   driver hands the scheduler is clamped, so a binding down longer than
///   the window **will not replay everything it missed — by design**.
///
/// The per-tick cap alone is not enough. It bounds the rate, not the total,
/// and `TriggerSpec::Interval` has no `CatchUp` policy to collapse a backlog
/// (`drain_due` takes its identity branch), so a one-second `Interval` down
/// for a week would otherwise replay 604,800 occurrences at 100 a tick —
/// about 1.7 hours of continuous `trigger_event` writes after boot. The
/// lookback clamp is what makes that finite.
///
/// On top of both, `accept_occurrence` dedupes on
/// `(binding_id, scheduled_for)` so a replayed occurrence cannot produce a
/// second `trigger_event`, and the cursor advance is monotonic, so a
/// replayed occurrence can never rewind the record.
///
/// A binding with no cursor row (never fired) seeds from the boot instant
/// instead and has no backlog at all.
pub async fn run(mut ctx: BackgroundServiceContext) -> Result<(), BackgroundServiceError> {
    let system_clock = SystemClock;
    // One wall-clock reading for the whole boot sequence: the same instant
    // clamps every restored cursor and seeds every never-fired binding, so
    // the two cannot disagree about when "boot" was.
    let boot = system_clock.wall_now();
    let stored = load_enabled_bindings(&ctx.store, boot)
        .await
        .map_err(|error| BackgroundServiceError(error.to_string()))?;

    let mut scheduler = Scheduler::new();
    let mut bindings: HashMap<BindingId, StoredBinding> = HashMap::new();
    for stored_binding in stored {
        let binding_id = stored_binding.binding.id;
        // A binding whose spec cannot be scheduled (a malformed cron
        // expression, a zero or degenerate interval) is refused by
        // `add_binding`. Skipping it — rather than failing the whole boot —
        // is the same judgement `decode_binding_row` makes for a corrupt
        // row, for the same reason.
        match scheduler.add_binding(stored_binding.binding.clone(), &FixedClock(boot)) {
            Ok(()) => {
                bindings.insert(binding_id, stored_binding);
            }
            Err(error) => tracing::error!(
                binding_id = %binding_id,
                error = %error,
                "a persisted trigger binding could not be scheduled; it will not fire"
            ),
        }
    }
    tracing::info!(
        bindings = bindings.len(),
        "scheduler driver loaded its enabled trigger bindings"
    );

    let registry = Arc::new(InMemoryRunRegistry::new());

    ctx.signal_ready().await?;

    let mut heartbeat = tokio::time::interval(HEARTBEAT);
    // A tick missed because a previous tick's acceptance work ran long must
    // not be repaid as a burst of back-to-back ticks — the scheduler's own
    // catch-up machinery already handles a late tick correctly, so the
    // heartbeat only needs to resume its cadence.
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // The cancellation result is carried out of the `select!` rather than
        // handled inside it: the arm's future holds `&mut ctx.cancelled` for
        // as long as the macro's scope lives, so reading `ctx.cancelled`
        // again has to happen after that scope ends.
        let cancellation = tokio::select! {
            _ = heartbeat.tick() => None,
            changed = ctx.cancelled.changed() => Some(changed),
        };

        if let Some(changed) = cancellation {
            // `Err` means the daemon dropped the cancellation channel, which
            // only happens as it goes away — the same orderly exit, not a
            // failure to report.
            if changed.is_err() || *ctx.cancelled.borrow() {
                tracing::debug!("scheduler driver stopping on cancellation");
                return Ok(());
            }
            continue;
        }

        let fired_at = system_clock.wall_now();
        let events = scheduler.tick(&FixedClock(fired_at));
        let due = pair_with_bindings(&bindings, events);
        if due.is_empty() {
            continue;
        }

        // `accept_occurrence` is synchronous and owns its own `BEGIN
        // IMMEDIATE` transaction, so it runs on the pool's blocking thread
        // via `interact` rather than on this async task. A checkout or
        // interact failure costs this tick's occurrences and nothing more:
        // the scheduler has already advanced past them, so they are dropped
        // rather than retried, and the driver keeps running.
        let conn = match ctx.store.pool.get().await {
            Ok(conn) => conn,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    due = due.len(),
                    "could not check out a store connection for this tick's occurrences"
                );
                continue;
            }
        };
        let tick_registry = Arc::clone(&registry);
        let interact = conn
            .interact(move |connection| {
                accept_due_occurrences(connection, &due, fired_at, tick_registry.as_ref());
            })
            .await;
        if let Err(error) = interact {
            tracing::error!(
                error = %error,
                "accepting this tick's occurrences failed on the store's blocking thread"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_store::StorePool;
    use std::time::Duration;

    /// The fixed instant every test in this module treats as "now" — the
    /// boot reading `run` takes once and threads through the whole boot
    /// sequence. A constant, not `Utc::now()`: the catch-up lookback clamp is
    /// defined relative to "now", so a test that read the real clock would be
    /// asserting against whatever today's date happens to be.
    fn boot_instant() -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(1_700_000_000_000_000_000)
    }

    async fn store(dir: &std::path::Path) -> StorePool {
        roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap()
    }

    /// Seeds one `trigger_binding` row (and, when `last_fired_for` is set,
    /// its cursor row) exactly the way a future binding-CRUD API would.
    async fn seed_binding(
        store: &StorePool,
        stored: &StoredBinding,
        enabled: bool,
        last_fired_for: Option<i64>,
    ) {
        let binding_id = stored.binding.id.to_string();
        let workspace_id = stored.workspace.to_string();
        let job_id = stored.binding.job_id.to_string();
        let spec_json = serde_json::to_string(&stored.binding.spec).unwrap();
        let overlap_json = serde_json::to_string(&stored.binding.overlap).unwrap();
        let conn = store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            connection
                .execute(
                    "INSERT INTO trigger_binding
                        (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                    rusqlite::params![
                        binding_id,
                        workspace_id,
                        job_id,
                        spec_json,
                        overlap_json,
                        enabled as i64,
                    ],
                )
                .unwrap();
            if let Some(nanos) = last_fired_for {
                connection
                    .execute(
                        "INSERT INTO trigger_binding_cursor (binding_id, last_fired_for)
                         VALUES (?1, ?2)",
                        rusqlite::params![binding_id, nanos],
                    )
                    .unwrap();
            }
        })
        .await
        .unwrap();
    }

    async fn delivery_count(store: &StorePool) -> i64 {
        let conn = store.pool.get().await.unwrap();
        conn.interact(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM trigger_delivery", [], |row| {
                    row.get(0)
                })
                .unwrap()
        })
        .await
        .unwrap()
    }

    fn interval_binding(every: Duration) -> StoredBinding {
        StoredBinding {
            workspace: WorkspaceId::new(),
            binding: Binding::new(
                JobId::new(),
                TriggerSpec::Interval {
                    every,
                    align: false,
                    anchor: None,
                },
            ),
        }
    }

    /// A `TriggerSpec::Cron` built through the *same* serde representation
    /// `trigger_binding.spec_json` stores, so this crate needs no `chrono-tz`
    /// dependency of its own just to name the `tz` field's type.
    fn cron_binding(expr: &str) -> StoredBinding {
        let spec: TriggerSpec = serde_json::from_value(serde_json::json!({
            "Cron": {
                "expr": expr,
                "tz": "UTC",
                "catch_up": "Latest",
                "jitter": { "secs": 0, "nanos": 0 },
                "dst_gap": "FireAtGapEnd",
                "dst_ambiguous": "First",
            }
        }))
        .expect("the cron spec fixture matches TriggerSpec's serde shape");
        StoredBinding {
            workspace: WorkspaceId::new(),
            binding: Binding::new(JobId::new(), spec),
        }
    }

    #[tokio::test]
    async fn the_boot_load_restores_enabled_bindings_with_their_persisted_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let enabled = interval_binding(Duration::from_secs(60));
        let last_fired_for = 1_700_000_000_000_000_000_i64;
        seed_binding(&store, &enabled, true, Some(last_fired_for)).await;

        let never_fired = interval_binding(Duration::from_secs(90));
        seed_binding(&store, &never_fired, true, None).await;

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();

        let restored = loaded
            .iter()
            .find(|stored| stored.binding.id == enabled.binding.id)
            .expect("the enabled binding must be restored");
        assert_eq!(restored.workspace, enabled.workspace);
        assert_eq!(restored.binding.job_id, enabled.binding.job_id);
        assert_eq!(restored.binding.spec, enabled.binding.spec);
        assert_eq!(restored.binding.overlap, enabled.binding.overlap);
        assert!(restored.binding.enabled);
        assert_eq!(
            restored.binding.last_fired_for,
            Some(DateTime::from_timestamp_nanos(last_fired_for)),
            "the persisted cursor must be restored onto the binding"
        );
        assert_eq!(
            restored.binding.next_fire_at, None,
            "next_fire_at is derived state the scheduler recomputes; it must not be restored"
        );

        let cursorless = loaded
            .iter()
            .find(|stored| stored.binding.id == never_fired.binding.id)
            .expect("a binding with no cursor row must still be restored");
        assert_eq!(
            cursorless.binding.last_fired_for, None,
            "a binding that has never fired must restore with no cursor, not a fabricated one"
        );
    }

    #[tokio::test]
    async fn the_boot_load_excludes_disabled_bindings() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let disabled = interval_binding(Duration::from_secs(60));
        seed_binding(&store, &disabled, false, Some(1_700_000_000_000_000_000)).await;

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        assert!(
            loaded.is_empty(),
            "a disabled binding must never reach the scheduler, got {loaded:?}"
        );
    }

    /// A corrupt row must cost exactly one binding, not the daemon's boot.
    #[tokio::test]
    async fn the_boot_load_skips_an_undecodable_row_without_failing_the_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let good = interval_binding(Duration::from_secs(60));
        seed_binding(&store, &good, true, None).await;

        let conn = store.pool.get().await.unwrap();
        conn.interact(|connection| {
            connection
                .execute(
                    "INSERT INTO trigger_binding
                        (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
                     VALUES ('not-a-uuid', 'also-not-a-uuid', 'nope', '{', 'nonsense', 1, 1)",
                    [],
                )
                .unwrap();
        })
        .await
        .unwrap();

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].binding.id, good.binding.id);
    }

    /// The bridge this task exists to build: a binding that is due produces a
    /// `Fire`, and that `Fire` becomes a durable `ready` `trigger_delivery`
    /// row. Driven through a [`FixedClock`] rather than a real one-second
    /// wait, so the "now" every step sees is chosen by the test.
    #[tokio::test]
    async fn a_due_binding_ticks_through_to_a_trigger_delivery_row() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let stored = interval_binding(Duration::from_secs(1));
        seed_binding(&store, &stored, true, None).await;

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        let mut scheduler = Scheduler::new();
        let boot = boot_instant();
        let mut bindings = HashMap::new();
        for stored_binding in loaded {
            scheduler
                .add_binding(stored_binding.binding.clone(), &FixedClock(boot))
                .unwrap();
            bindings.insert(stored_binding.binding.id, stored_binding);
        }

        assert_eq!(
            delivery_count(&store).await,
            0,
            "nothing is due yet, so nothing may have been delivered"
        );

        let fired_at = boot + chrono::Duration::seconds(1);
        let events = scheduler.tick(&FixedClock(fired_at));
        let due = pair_with_bindings(&bindings, events);
        assert_eq!(due.len(), 1, "the binding is due, so it must fire");
        assert_eq!(due[0].1.binding_id, stored.binding.id);
        assert!(
            !due[0].1.is_catch_up,
            "a single on-time occurrence is not a catch-up pass"
        );

        let registry = InMemoryRunRegistry::new();
        let conn = store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &due, fired_at, &registry);
        })
        .await
        .unwrap();

        assert_eq!(
            delivery_count(&store).await,
            1,
            "an admitted occurrence must leave exactly one trigger_delivery row"
        );

        let cursor: Option<i64> = {
            let conn = store.pool.get().await.unwrap();
            let binding_id = stored.binding.id.to_string();
            conn.interact(move |connection| {
                connection
                    .query_row(
                        "SELECT last_fired_for FROM trigger_binding_cursor WHERE binding_id = ?1",
                        rusqlite::params![binding_id],
                        |row| row.get(0),
                    )
                    .unwrap()
            })
            .await
            .unwrap()
        };
        assert!(
            cursor.is_some(),
            "accepting an occurrence must advance the persisted fire cursor"
        );
    }

    /// Fix round 1: the end-to-end proof of what the boot cursor is *for*.
    /// A binding whose persisted `last_fired_for` predates boot has the
    /// occurrences it missed while the daemon was down drained on its first
    /// tick and turned into a real `trigger_delivery` row — the whole point
    /// of persisting the cursor. Before the `Scheduler::add_binding` fix this
    /// tick produced nothing at all: the binding was seeded from the boot
    /// instant and the entire downtime window vanished silently.
    ///
    /// Driven through [`FixedClock`] at both boot and tick, so "how long the
    /// daemon was down" is chosen by the test rather than by the host.
    #[tokio::test]
    async fn a_binding_restored_from_its_cursor_delivers_the_occurrences_it_missed() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let stored = interval_binding(Duration::from_secs(60));
        let boot = boot_instant();
        // The cursor says this binding last fired ten minutes before boot, so
        // ten one-minute occurrences were missed while the daemon was down.
        let cursor = boot - chrono::Duration::minutes(10);
        seed_binding(
            &store,
            &stored,
            true,
            Some(cursor.timestamp_nanos_opt().unwrap()),
        )
        .await;

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        assert_eq!(
            loaded[0].binding.last_fired_for,
            Some(cursor),
            "the boot load must hand the persisted cursor to the scheduler; this test \
             proves nothing if it arrives as None"
        );

        let mut scheduler = Scheduler::new();
        let mut bindings = HashMap::new();
        for stored_binding in loaded {
            scheduler
                .add_binding(stored_binding.binding.clone(), &FixedClock(boot))
                .unwrap();
            bindings.insert(stored_binding.binding.id, stored_binding);
        }

        // The very first tick after boot, at the boot instant itself — no
        // time has passed, so anything that fires here is backlog, not a
        // newly-due occurrence.
        let events = scheduler.tick(&FixedClock(boot));
        let due = pair_with_bindings(&bindings, events);
        assert!(
            !due.is_empty(),
            "the occurrences missed during downtime must still be due at boot"
        );
        assert!(
            due.iter().all(|(_, occurrence)| occurrence.is_catch_up
                && occurrence.scheduled_for > cursor
                && occurrence.scheduled_for <= boot),
            "every drained occurrence must come from the missed window and be reported \
             as a catch-up fire: {due:?}"
        );

        let registry = InMemoryRunRegistry::new();
        let conn = store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &due, boot, &registry);
        })
        .await
        .unwrap();

        assert_eq!(
            delivery_count(&store).await,
            1,
            "the missed window must reach a real trigger_delivery row (one, because \
             OverlapPolicy::Skip admits the first occurrence only)"
        );
    }

    /// Fix round 2 (review Important finding): the per-tick cap bounds the
    /// *rate* of a replay, not its total. `TriggerSpec::Interval` has no
    /// `CatchUp` policy to collapse a backlog, so without a lookback clamp a
    /// one-second interval whose daemon was down for a week would replay
    /// 604,800 occurrences at 100 a tick — about 1.7 hours of continuous
    /// `trigger_event` writes after boot.
    ///
    /// This pins the clamp at the boot load: a week-old cursor must arrive as
    /// the 24-hour baseline, not as the true historical value.
    #[tokio::test]
    async fn a_cursor_older_than_the_lookback_window_is_clamped_at_the_boot_load() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let boot = boot_instant();

        let stored = interval_binding(Duration::from_secs(1));
        let a_week_ago = boot - chrono::Duration::days(7);
        seed_binding(
            &store,
            &stored,
            true,
            Some(a_week_ago.timestamp_nanos_opt().unwrap()),
        )
        .await;

        let loaded = load_enabled_bindings(&store, boot).await.unwrap();
        assert_eq!(
            loaded[0].binding.last_fired_for,
            Some(boot - chrono::Duration::hours(24)),
            "a cursor older than MAX_CATCH_UP_LOOKBACK must be pulled forward to the \
             window's edge, not replayed from where it actually sat"
        );
    }

    /// The mirror that stops the clamp from being a blunt instrument: a
    /// cursor already inside the window is handed through untouched. Without
    /// this, a clamp that simply returned `now - 24h` unconditionally — and
    /// so discarded every real recent cursor — would pass the test above.
    #[tokio::test]
    async fn a_cursor_inside_the_lookback_window_is_left_exactly_as_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let boot = boot_instant();

        let stored = interval_binding(Duration::from_secs(60));
        let recent = boot - chrono::Duration::hours(3);
        seed_binding(
            &store,
            &stored,
            true,
            Some(recent.timestamp_nanos_opt().unwrap()),
        )
        .await;

        let loaded = load_enabled_bindings(&store, boot).await.unwrap();
        assert_eq!(
            loaded[0].binding.last_fired_for,
            Some(recent),
            "a cursor inside the window must survive the clamp unchanged"
        );
    }

    /// The behavioural half of the clamp, and the one that actually bounds
    /// the work: a week-stale one-second `Interval` must not walk back into
    /// the week. Every occurrence its first tick produces has to sit inside
    /// the 24-hour window, and the tick itself must still respect the
    /// per-tick cap — the two bounds compose rather than replacing one
    /// another.
    #[tokio::test]
    async fn a_week_stale_binding_replays_only_inside_the_lookback_window() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;
        let boot = boot_instant();

        let stored = interval_binding(Duration::from_secs(1));
        let a_week_ago = boot - chrono::Duration::days(7);
        seed_binding(
            &store,
            &stored,
            true,
            Some(a_week_ago.timestamp_nanos_opt().unwrap()),
        )
        .await;

        let loaded = load_enabled_bindings(&store, boot).await.unwrap();
        let mut scheduler = Scheduler::new();
        let mut bindings = HashMap::new();
        for stored_binding in loaded {
            scheduler
                .add_binding(stored_binding.binding.clone(), &FixedClock(boot))
                .unwrap();
            bindings.insert(stored_binding.binding.id, stored_binding);
        }

        let due = pair_with_bindings(&bindings, scheduler.tick(&FixedClock(boot)));
        assert!(!due.is_empty(), "the clamped window must still drain");

        let window_start = boot - chrono::Duration::hours(24);
        assert!(
            due.iter()
                .all(|(_, occurrence)| occurrence.scheduled_for > window_start),
            "no occurrence may come from before the lookback window — the week-old \
             backlog must never be walked at all"
        );
        assert!(
            due.len() <= roundhouse_sched::scheduler::MAX_CATCH_UP_OCCURRENCES_PER_BINDING_PER_TICK,
            "the per-tick cap still applies on top of the lookback clamp, got {}",
            due.len()
        );
    }

    /// A late tick hands the driver a whole catch-up backlog at once, and
    /// the overlap policy — not the driver — is what decides how much of it
    /// becomes a delivery. This also pins the known limit described on
    /// [`InMemoryRunRegistry`]: nothing calls `note_finished` yet, so the
    /// first admitted occurrence keeps this `Skip` binding's active count at
    /// one and every later occurrence is suppressed. When the run-completion
    /// path lands, this expectation changes with it — deliberately, and
    /// visibly here.
    #[tokio::test]
    async fn a_catch_up_backlog_is_bounded_by_the_bindings_overlap_policy() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let stored = interval_binding(Duration::from_secs(1));
        assert_eq!(
            stored.binding.overlap,
            OverlapPolicy::Skip,
            "this test is about Skip specifically; it proves nothing if the default changed"
        );
        seed_binding(&store, &stored, true, None).await;

        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        let mut scheduler = Scheduler::new();
        let boot = boot_instant();
        let mut bindings = HashMap::new();
        for stored_binding in loaded {
            scheduler
                .add_binding(stored_binding.binding.clone(), &FixedClock(boot))
                .unwrap();
            bindings.insert(stored_binding.binding.id, stored_binding);
        }

        let fired_at = boot + chrono::Duration::seconds(3);
        let events = scheduler.tick(&FixedClock(fired_at));
        let due = pair_with_bindings(&bindings, events);
        assert_eq!(
            due.len(),
            3,
            "a three-second-late tick on a one-second interval owes three occurrences"
        );
        assert!(
            due.iter().all(|(_, occurrence)| occurrence.is_catch_up),
            "every occurrence of a real backlog is a catch-up fire"
        );

        let registry = InMemoryRunRegistry::new();
        let conn = store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &due, fired_at, &registry);
        })
        .await
        .unwrap();

        assert_eq!(
            delivery_count(&store).await,
            1,
            "OverlapPolicy::Skip admits the first occurrence and suppresses the rest"
        );
    }

    /// The same occurrence arriving twice (a crash-and-retry, or a scheduler
    /// that re-fires an instant) must not create a second delivery — proof
    /// this driver inherits `accept_occurrence`'s dedupe rather than
    /// bypassing it.
    #[tokio::test]
    async fn re_accepting_the_same_occurrence_creates_no_second_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let stored = interval_binding(Duration::from_secs(1));
        let fired_at = DateTime::from_timestamp_nanos(1_700_000_000_000_000_000);
        let occurrence = ScheduledOccurrence {
            binding_id: stored.binding.id,
            scheduled_for: fired_at,
            is_catch_up: false,
        };
        let due = vec![(stored.clone(), occurrence)];

        let registry = InMemoryRunRegistry::new();
        let conn = store.pool.get().await.unwrap();
        let repeated = due.clone();
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &repeated, fired_at, &registry);
            accept_due_occurrences(connection, &repeated, fired_at, &registry);
        })
        .await
        .unwrap();

        assert_eq!(delivery_count(&store).await, 1);
    }

    /// One failing occurrence must not stop the others in the same tick. The
    /// failure is a real one `accept_occurrence` itself raises: an occurrence
    /// whose `binding_id` does not match the `StoredBinding` it is paired
    /// with (`StoreError::BindingIdentityMismatch`).
    #[tokio::test]
    async fn one_failing_occurrence_does_not_stop_the_rest_of_the_tick() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let good = interval_binding(Duration::from_secs(1));
        let mismatched = interval_binding(Duration::from_secs(1));
        let fired_at = DateTime::from_timestamp_nanos(1_700_000_000_000_000_000);

        let due = vec![
            (
                mismatched.clone(),
                ScheduledOccurrence {
                    // Deliberately not `mismatched`'s own id.
                    binding_id: good.binding.id,
                    scheduled_for: fired_at,
                    is_catch_up: false,
                },
            ),
            (
                good.clone(),
                ScheduledOccurrence {
                    binding_id: good.binding.id,
                    scheduled_for: fired_at,
                    is_catch_up: false,
                },
            ),
        ];

        let registry = InMemoryRunRegistry::new();
        let conn = store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            accept_due_occurrences(connection, &due, fired_at, &registry);
        })
        .await
        .unwrap();

        assert_eq!(
            delivery_count(&store).await,
            1,
            "the well-formed occurrence must still have been accepted"
        );
    }

    #[test]
    fn an_occurrence_for_an_unknown_binding_is_dropped_rather_than_fired_blind() {
        let bindings: HashMap<BindingId, StoredBinding> = HashMap::new();
        let due = pair_with_bindings(
            &bindings,
            vec![SchedulerEvent::Fire(ScheduledOccurrence {
                binding_id: BindingId::new(),
                scheduled_for: DateTime::from_timestamp_nanos(0),
                is_catch_up: false,
            })],
        );
        assert!(due.is_empty());
    }

    #[test]
    fn the_run_registry_counts_admissions_and_releases_per_binding() {
        let registry = InMemoryRunRegistry::new();
        let a = BindingId::new();
        let b = BindingId::new();

        assert_eq!(registry.active_run_count(a).unwrap(), 0);
        registry.note_admitted(a).unwrap();
        registry.note_admitted(a).unwrap();
        assert_eq!(registry.active_run_count(a).unwrap(), 2);
        assert_eq!(
            registry.active_run_count(b).unwrap(),
            0,
            "one binding's runs must not count against another's"
        );

        registry.note_finished(a).unwrap();
        assert_eq!(registry.active_run_count(a).unwrap(), 1);

        registry.note_queued(a).unwrap();
        assert_eq!(registry.queued_count(a).unwrap(), 1);
        registry.note_promoted(a).unwrap();
        assert_eq!(registry.queued_count(a).unwrap(), 0);
        assert_eq!(registry.active_run_count(a).unwrap(), 2);
        registry.note_dequeued(a).unwrap_err();
    }

    /// Underflow must be reported, never wrapped — a wrapping `-= 1` on a
    /// zero counter becomes `u32::MAX`, which is the fail-open mode the
    /// admission gate exists to prevent.
    #[test]
    fn the_run_registry_reports_underflow_rather_than_wrapping() {
        let registry = InMemoryRunRegistry::new();
        let binding_id = BindingId::new();
        assert_eq!(
            registry.note_finished(binding_id).unwrap_err(),
            RegistryError::CounterOutOfRange { binding_id }
        );
        assert_eq!(registry.active_run_count(binding_id).unwrap(), 0);
    }

    /// This driver cannot terminate a run, so `CancelPrevious` must fail
    /// closed rather than admit a replacement over a predecessor nothing
    /// actually stopped.
    #[test]
    fn cancel_active_never_claims_an_unstoppable_run_was_stopped() {
        let registry = InMemoryRunRegistry::new();
        let binding_id = BindingId::new();
        registry.note_admitted(binding_id).unwrap();
        assert_eq!(
            registry.cancel_active(binding_id).unwrap(),
            CancellationOutcome::Unconfirmed
        );
        assert_eq!(
            registry.active_run_count(binding_id).unwrap(),
            1,
            "an unconfirmed cancellation must not fabricate the predecessor away"
        );
    }

    /// A cron binding whose expression is malformed must cost only that
    /// binding: `Scheduler::add_binding` refuses it and the driver skips it.
    #[tokio::test]
    async fn a_binding_whose_spec_cannot_be_scheduled_is_skipped_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path()).await;

        let broken = cron_binding("this is not a cron expression");
        seed_binding(&store, &broken, true, None).await;

        // The row itself decodes fine — it is the scheduling that fails.
        let loaded = load_enabled_bindings(&store, boot_instant()).await.unwrap();
        assert_eq!(loaded.len(), 1);

        let mut scheduler = Scheduler::new();
        let clock = FixedClock(DateTime::from_timestamp_nanos(1_700_000_000_000_000_000));
        assert!(
            scheduler
                .add_binding(loaded[0].binding.clone(), &clock)
                .is_err(),
            "a malformed cron expression must be refused by the scheduler, not silently heaped"
        );
    }
}
