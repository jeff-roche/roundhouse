//! The scheduler background service (Phase 8, L3, Tasks 5 and 6): the
//! daemon-side driver that turns persisted `trigger_binding` rows into a live
//! [`Scheduler`], feeds every occurrence that scheduler fires through
//! [`accept_occurrence`] (which durably records the `trigger_event`, runs the
//! overlap-policy admission gate, and — for an admitting decision — creates
//! the `ready` `trigger_delivery` row), and then **claims those `ready` rows
//! and actually runs them**: reserve a `SessionId`/`RunId`, insert the
//! `workflow_run` row that *is* the reservation, construct a headless
//! session, drive [`run_workflow_from_storage`], and complete or fail the
//! delivery — releasing the admission-registry slot on either terminal path.
//!
//! # The binding invariant every `tracing` call here honours
//!
//! No operator- or repository-controlled bytes may reach a `tracing` field or
//! message (see this crate's manifest). Delivery failures therefore carry
//! their detail in [`DeliveryError`]'s `Display` — which is rendered into
//! `trigger_delivery.last_error`, a *database column* — while the log line
//! carries only [`DeliveryError::kind`]'s static category. The same split
//! `CreateRealSessionError::kind` already established.
//!
//! # What this module still deliberately does NOT do
//!
//! - **It never transitions a `workflow_run` row itself.** `finish_run` (in
//!   `roundhouse-flow`'s run loop) is the workspace's only writer of
//!   `Completed`/`Failed`/`Cancelled`, and it is what discharges ruling
//!   P112's "exactly one report on every terminal path". A run whose
//!   `run_workflow_from_storage` call returned `Err` therefore stays
//!   `Running` on the row even though its *delivery* correctly reaches
//!   `failed`. Reconciling those is §8.11's reaper, not this driver's to
//!   invent.
//! - **It never closes a session it created.** Nothing in this workspace
//!   drives a `SessionActor` to `SessionState::Closed` yet (see
//!   `session_manager::spawn_session_reaper`'s own doc comment), so a
//!   scheduled run's headless session stays registered for the daemon's
//!   life. With `max_sessions` bounded, a long-lived daemon running many
//!   deliveries will eventually fill the registry — a real limit, recorded
//!   rather than papered over, and closable the moment a terminal session
//!   transition exists.
//! - **It resolves no secrets and no `env()` names.** See
//!   [`DeliveryExecutor::run_claimed_delivery`] for both.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{
    BindingId, EventPayload, JobId, OnDegrade, SessionId, SessionSpec, TaskId, TaskKind,
    TaskRunner, Tier, Timestamp, WorkspaceId,
};
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::durability::{insert_workflow_run, RunState, WorkflowRun};
use roundhouse_flow::exec::run_loop::RunOutcome;
use roundhouse_flow::exec::{RunContext, RunId, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::job::content_hash;
use roundhouse_flow::job_store::resolve_latest_by_job_id;
use roundhouse_flow::production::{run_workflow_from_storage, SqliteWorkflowHost};
use roundhouse_flow::worktree::SandboxWorktreeProvider;
use roundhouse_sched::admission::{CancellationOutcome, RegistryError, RunRegistry};
use roundhouse_sched::delivery::TriggerDelivery;
use roundhouse_sched::scheduler::{
    ClockSource, ScheduledOccurrence, Scheduler, SchedulerEvent, SystemClock,
};
use roundhouse_sched::store::{
    accept_occurrence, complete_delivery, fail_delivery, fetch_trigger_event_outcome,
    lease_delivery, list_ready_deliveries, mark_delivery_running, reserve_delivery,
};
use roundhouse_sched::trigger::{
    Binding, OverlapPolicy, StoredBinding, TriggerEventOutcome, TriggerSpec,
};
use roundhouse_store::StorePool;
use rusqlite::Connection;
use uuid::Uuid;

use crate::session_bootstrap::{BackgroundServiceContext, BackgroundServiceError, DaemonResources};
use crate::session_manager::{create_headless_session, CreateHeadlessSessionError};
use crate::session_registry::SessionRegistry;
use crate::workflow_host::WorkflowSessionTree;

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
/// 1. **`cancel_active` always reports `Unconfirmed`.** This registry holds
///    counts, not handles: nothing here retains the `tokio` task or `RunId`
///    of a delivery in flight, so there is nothing for it to terminate — and
///    [`RunRegistry::cancel_active`]'s contract forbids blocking to find
///    out. (§8.13's cancel is cooperative and lives on
///    `roundhouse_flow::control::cancel`; wiring it to a *binding's*
///    in-flight run needs a durable run handle this driver does not keep.)
///    Reporting `Confirmed` would be a lie that lets
///    `decide_admission` admit a replacement on top of a predecessor it
///    never actually stopped. `Unconfirmed` makes `OverlapPolicy::CancelPrevious`
///    fail closed instead, which is the correct behaviour for a daemon that
///    cannot yet cancel anything.
/// 2. **The release side is per-process, like the counts themselves.**
///    [`DeliveryExecutor`] calls [`RunRegistry::note_finished`] on every
///    terminal delivery path (Task 6), so a `Skip` binding no longer fires
///    exactly once per daemon lifetime — but a delivery whose executing task
///    is lost to a daemon crash leaves its slot held until restart, when
///    these counters start from zero again.
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
/// to interpose its per-binding lock on.
///
/// **Task 6 added a second caller, and the reasoning below is why that is
/// still safe rather than why the note above went stale.** The race
/// `SharedRegistry` exists to close is a torn *read-then-write* inside
/// `decide_admission` — `active_run_count`, then `note_admitted` — which
/// two concurrent `decide_admission` callers could interleave into two
/// admissions over one slot. There is still exactly one `decide_admission`
/// caller: [`run`]'s heartbeat loop, which processes a tick's occurrences
/// strictly one after another inside a single blocking `interact` call. The
/// new caller is [`DeliveryExecutor`], and it only ever calls the
/// *mutations* `note_promoted`/`note_finished`, never the read-then-write
/// sequence. Each of those is a single `with_counts` critical section, so
/// interleaving one with `decide_admission` can move a count only in the
/// conservative direction: a `note_finished` landing between
/// `active_run_count` and `note_admitted` makes this occurrence skip when it
/// could have run (a missed fire, recovered on the next tick), never admit
/// when it should not have. The fail-open direction — two admissions over
/// one slot — still needs two concurrent `decide_admission` callers, and
/// there are none. A second `decide_admission` caller is what would
/// re-open this; a second mutator is not.
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

// ───────────────────────── delivery claim and execution ─────────────────────

/// How many `ready` deliveries one heartbeat tick may claim.
///
/// Each claim becomes its own spawned task holding a store connection for the
/// length of a whole workflow run, so this is really a bound on how fast the
/// driver may convert a backlog into concurrent long-lived connection
/// holders. Eight is comfortably below any sane pool size while still being
/// more than one tick's realistic admissions — the overlap policies are what
/// bound admissions per binding, and a tick that finds more than eight
/// leaves the rest `ready` for the next tick a second later, which is the
/// correct backpressure rather than a loss.
const MAX_DELIVERY_CLAIMS_PER_TICK: usize = 8;

/// How long a claim's `ready -> leased` lease is stamped for.
///
/// The lease covers only the window between winning `lease_delivery` and
/// winning `reserve_delivery` — once a delivery is `reserved` no reclaimer
/// consults `lease_expires_at` at all (`reclaim_expired_lease` is
/// predecessor-constrained on `state = 'leased'`). That window is a handful
/// of store round-trips, so five minutes is generous by orders of magnitude
/// while still being finite for a claimer that dies inside it.
const DELIVERY_LEASE: std::time::Duration = std::time::Duration::from_secs(300);

/// The `schema_v` every event this driver appends carries. Matches
/// `workflow_host::WorkflowSessionTree::persist_child_session`, the other
/// daemon-side minter of workflow-related events.
const EVENT_SCHEMA_V: u16 = 1;

/// Why one delivery could not be carried through to a completed run.
///
/// **`Display` is written for `trigger_delivery.last_error`, not for a log
/// line.** Some variants interpolate text this daemon does not control (a
/// workflow file's parse error, a job store's message), which is exactly
/// what this crate's manifest forbids reaching a `tracing` field. Log
/// [`Self::kind`] instead — the same split `CreateRealSessionError::kind`
/// already established.
#[derive(Debug, thiserror::Error)]
enum DeliveryError {
    #[error("the store connection pool refused a connection")]
    StoreConnection,
    #[error("a store operation failed on the pool's blocking thread")]
    Interact,
    #[error("a trigger_delivery state transition failed: {0}")]
    Transition(String),
    #[error(
        "this daemon has no workspace registry, so a scheduled run cannot resolve a \
         workspace root to run in"
    )]
    NoWorkspaceRegistry,
    #[error("the binding's workspace could not be resolved: {0}")]
    Workspace(String),
    #[error("no job is registered under this binding's job id in this workspace")]
    JobNotRegistered,
    #[error("the binding's job could not be resolved: {0}")]
    JobUnresolvable(String),
    #[error("the workflow_run row could not be created: {0}")]
    RunRow(String),
    #[error("this delivery's headless session could not be constructed: {0}")]
    Session(&'static str),
    /// Won the lease, then lost the `leased -> reserved` transition — the row
    /// moved underneath this claimer (a reclaimed lease, a cancellation
    /// request). Not an error to shout about; the delivery is simply no
    /// longer ours.
    #[error("this delivery's state changed after it was leased")]
    LostClaim,
}

impl DeliveryError {
    /// A static diagnostic category, safe to render into a `tracing` field.
    /// See this type's own doc comment for why `Display` is not.
    fn kind(&self) -> &'static str {
        match self {
            Self::StoreConnection => "store_connection",
            Self::Interact => "store_interact",
            Self::Transition(_) => "delivery_transition",
            Self::NoWorkspaceRegistry => "no_workspace_registry",
            Self::Workspace(_) => "workspace_unresolvable",
            Self::JobNotRegistered => "job_not_registered",
            Self::JobUnresolvable(_) => "job_unresolvable",
            Self::RunRow(_) => "run_row",
            Self::Session(_) => "session_construction",
            Self::LostClaim => "lost_claim",
        }
    }
}

/// What driving one claimed delivery's workflow actually produced.
enum RunConclusion {
    /// The run reached `RunState::Completed`.
    Completed,
    /// The run reached a terminal state that is not `Completed`, or the run
    /// loop refused to drive it. The `String` is written to
    /// `trigger_delivery.last_error` (a column, never a log field).
    Failed(String),
    /// A `gate:` parked the run on a human. **Not terminal**, so the delivery
    /// stays `running` and the registry slot stays held — see
    /// [`DeliveryExecutor::claim_and_run`].
    Parked,
}

/// The first production [`TaskSink`] in the workspace: buffers every task
/// event a run emits and writes them to the run's own session log once, at
/// the end, in one transaction.
///
/// # Why buffered rather than streaming
///
/// `run_workflow_from_storage` borrows the `&mut Connection` for the whole
/// run, so a sink cannot hold one too. The alternatives were each worse: a
/// *second* pooled connection writing while the run's own connection holds a
/// `BEGIN IMMEDIATE` is a same-process `SQLITE_BUSY` the busy handler cannot
/// resolve (the holder is blocked on us), and a channel into
/// `EventWriter` would have this blocking thread waiting on a writer task
/// that may itself be waiting for a pool connection this run is holding.
/// Buffering keeps every write on the one connection that is already ours.
///
/// **The cost, stated plainly:** a run's tasks become visible in the session
/// log when the run ends, not as it runs, and a daemon that dies mid-run
/// loses them. What it does *not* lose is the run's own durable state — the
/// `workflow_run`/`workflow_step_run` rows are written by the run loop
/// itself, on that same connection, as it goes.
///
/// `parent` and `kind` are dropped rather than stored: for a `TaskCreated`
/// payload both are already inside the payload, and for every other payload
/// they are not part of the event at all.
#[derive(Default)]
struct BufferedTaskSink {
    emitted: Vec<(TaskId, EventPayload)>,
}

impl TaskSink for BufferedTaskSink {
    fn emit(
        &mut self,
        task_id: TaskId,
        _parent: Option<TaskId>,
        _kind: TaskKind,
        payload: EventPayload,
    ) {
        self.emitted.push((task_id, payload));
    }
}

/// Appends a [`BufferedTaskSink`]'s events to `session_id`'s log.
///
/// Every event is minted through [`TaskRunner`], never constructed directly —
/// `Event`'s constructor is sealed inside `roundhouse-core` precisely so that
/// S-LOG-1's "exactly one authority mints task records" is structural. The
/// `seq` passed in is ignored by `append_event_in_transaction`, which assigns
/// the next per-session sequence itself; `0` is what
/// `WorkflowSessionTree::persist_child_session` passes for the same reason.
///
/// A payload this function has no `record_*` method for is logged and
/// dropped rather than silently skipped. The run loop emits only
/// `TaskCreated`/`TaskCompleted` today, so this arm is unreachable — it
/// exists so that a future emit of a different payload is *loud* rather than
/// invisible.
fn flush_task_events(
    conn: &mut Connection,
    runner: &'static TaskRunner,
    session_id: SessionId,
    now: Timestamp,
    sink: BufferedTaskSink,
) -> Result<(), roundhouse_store::StoreError> {
    if sink.emitted.is_empty() {
        return Ok(());
    }
    let txn = roundhouse_store::begin_immediate(conn)?;
    // No needles: this run's `RunContext.secrets` is empty (see
    // `run_claimed_delivery`), so there is no live secret value for a
    // redactor to match. When secret resolution lands, this is the call site
    // that must be handed the same values.
    let redactor = roundhouse_store::redact::Redactor::build(&[]);
    for (task_id, payload) in sink.emitted {
        let event = match payload {
            EventPayload::TaskCreated {
                kind,
                parent,
                origin,
                input,
            } => runner.record_task_created(
                session_id,
                0,
                now,
                task_id,
                kind,
                parent,
                origin,
                input,
                EVENT_SCHEMA_V,
            ),
            EventPayload::TaskCompleted { output, usage } => runner.record_task_completed(
                session_id,
                0,
                now,
                task_id,
                output,
                usage,
                EVENT_SCHEMA_V,
            ),
            EventPayload::TaskFailed { error, retryable } => runner.record_task_failed(
                session_id,
                0,
                now,
                task_id,
                error,
                retryable,
                EVENT_SCHEMA_V,
            ),
            _ => {
                tracing::error!(
                    session_id = %session_id,
                    "a workflow run emitted a task payload this driver cannot mint an event \
                     for; it is dropped rather than persisted"
                );
                continue;
            }
        };
        roundhouse_store::append_event_in_transaction(&txn, &event, &redactor)?;
    }
    txn.commit()?;
    Ok(())
}

/// Everything one claimed delivery needs to become a real, running workflow.
///
/// Cloned into each spawned per-delivery task, so every field is a handle
/// rather than a value: one store pool, one `DaemonResources`, one session
/// registry, one admission registry, one spawn tree for the whole daemon.
#[derive(Clone)]
pub(crate) struct DeliveryExecutor {
    store: StorePool,
    resources: Arc<DaemonResources>,
    sessions: Arc<SessionRegistry>,
    registry: Arc<InMemoryRunRegistry>,
    /// The daemon's runtime workflow spawn tree. Created here because this is
    /// the workspace's first production `SqliteWorkflowHost` and therefore
    /// the first thing that needs one; if a second owner ever appears it must
    /// share *this* tree rather than minting a second (the tree is what
    /// `MAX_DIRECT_CHILD_CALLS` fan-out admission is counted against).
    spawn_tree: Arc<SpawnTree>,
    /// Injected rather than read from `Utc::now()` inside the executor, so
    /// every timestamp a delivery writes is chosen by the caller — which is
    /// what makes this path testable without a real clock.
    clock: Arc<dyn ClockSource + Send + Sync>,
}

impl DeliveryExecutor {
    pub(crate) fn new(
        store: StorePool,
        resources: Arc<DaemonResources>,
        sessions: Arc<SessionRegistry>,
        registry: Arc<InMemoryRunRegistry>,
        clock: Arc<dyn ClockSource + Send + Sync>,
    ) -> Self {
        Self {
            store,
            resources,
            sessions,
            registry,
            spawn_tree: Arc::new(SpawnTree::new()),
            clock,
        }
    }

    fn now(&self) -> Timestamp {
        // The only way `timestamp_nanos_opt` returns `None` is a `DateTime`
        // outside chrono's representable nanosecond range (year ~1677-2262),
        // which no real wall clock is — the same fallback
        // `roundhouse_sched::store`'s own `timestamp_from_datetime` takes.
        Timestamp::from_unix_nanos(self.clock.wall_now().timestamp_nanos_opt().unwrap_or(0))
    }

    /// Runs `f` against a pooled connection on the pool's blocking thread.
    ///
    /// Every store call on this path goes through here, including
    /// `run_workflow_from_storage` itself — it is synchronous and takes
    /// `&mut Connection`, so running it on the async reactor would block a
    /// runtime worker for the length of a whole workflow.
    async fn with_connection<T, F>(&self, f: F) -> Result<T, DeliveryError>
    where
        F: FnOnce(&mut Connection) -> T + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.store.pool.get().await.map_err(|error| {
            tracing::error!(
                error = %error,
                "could not check out a store connection for a trigger delivery"
            );
            DeliveryError::StoreConnection
        })?;
        conn.interact(f).await.map_err(|error| {
            tracing::error!(
                error = %error,
                "a trigger-delivery store operation failed on the pool's blocking thread"
            );
            DeliveryError::Interact
        })
    }

    /// Claims one `ready` delivery and drives it to a terminal delivery
    /// state.
    ///
    /// # The release invariant
    ///
    /// `accept_occurrence` charged exactly one registry slot for this
    /// delivery — an *active* one for `Admit`/`CancelledPreviousAndAdmit`, a
    /// *queued* one for `QueueAt`. Every path below that reaches
    /// `delivered`/`failed` answers that with exactly one
    /// [`RunRegistry::note_finished`], **including the failure path**: a
    /// failed run that kept its slot would wedge its binding shut exactly
    /// like the un-released case, and a binding silently never firing again
    /// is a far worse failure than one failed run.
    ///
    /// The one deliberate exception is [`RunConclusion::Parked`]. A parked
    /// run is *not* terminal — `roundhouse-flow` will drive it to completion
    /// when a human answers its gate — so completing or failing the delivery
    /// there would be a lie, and releasing the slot would let the same
    /// binding start a second run on top of one that is still live. Nothing
    /// in these tasks resumes a parked scheduled run, so such a delivery
    /// holds its slot until the daemon restarts; that is a known limitation
    /// with a named owner (human-in-the-loop resumption), not an oversight.
    pub(crate) async fn claim_and_run(&self, delivery: TriggerDelivery, stored: StoredBinding) {
        let now = self.now();
        let binding_id = stored.binding.id;
        let delivery_id = delivery.delivery_id.clone();

        if !self.lease(&delivery_id, now).await {
            return;
        }
        // The claim is ours from here. A queued delivery holds a *queued*
        // slot; running it is a promotion, and without this the
        // `note_finished` below would underflow `active` and strand `queued`.
        self.promote_if_queued(&delivery, binding_id).await;

        match self.run_claimed_delivery(&delivery, &stored, now).await {
            Ok(RunConclusion::Completed) => {
                let finished = self.now();
                self.transition(&delivery_id, move |conn, id| {
                    complete_delivery(conn, id, finished)
                })
                .await;
                self.release(binding_id);
            }
            Ok(RunConclusion::Parked) => {
                tracing::info!(
                    binding_id = %binding_id,
                    "a scheduled run parked on a human gate; its delivery stays `running` and \
                     its admission slot stays held until the run is resumed"
                );
            }
            Ok(RunConclusion::Failed(reason)) => {
                self.fail(&delivery_id, binding_id, "workflow_failed", reason)
                    .await;
            }
            Err(error) => {
                self.fail(&delivery_id, binding_id, error.kind(), error.to_string())
                    .await;
            }
        }
    }

    /// `ready -> leased`. `false` means this delivery is not ours — either
    /// another claimer won it or its state changed — which is an ordinary
    /// no-op, not an error.
    async fn lease(&self, delivery_id: &str, now: Timestamp) -> bool {
        let lease_nanos = i64::try_from(DELIVERY_LEASE.as_nanos()).unwrap_or(i64::MAX);
        let expires = Timestamp::from_unix_nanos(now.as_unix_nanos().saturating_add(lease_nanos));
        let id = delivery_id.to_string();
        match self
            .with_connection(move |conn| {
                lease_delivery(conn, &id, expires, now).map_err(|error| error.to_string())
            })
            .await
        {
            Ok(Ok(true)) => true,
            Ok(Ok(false)) => {
                tracing::debug!(
                    "a ready delivery was already claimed by the time this tick got to it"
                );
                false
            }
            Ok(Err(_)) | Err(_) => {
                // `with_connection` already logged pool/interact failures; a
                // lease failure costs this delivery this tick and nothing
                // more — the row stays `ready` and the next tick retries it.
                tracing::error!("leasing a ready trigger delivery failed; it stays ready");
                false
            }
        }
    }

    /// Moves a delivery created by an `OverlapPolicy::Queue` decision from
    /// its queued slot into an active one, so the `note_finished` at the end
    /// of [`Self::claim_and_run`] balances the `note_queued`
    /// `decide_admission` charged for it.
    ///
    /// Everything else — an `Admit` or a `CancelledPreviousAndAdmit` — was
    /// already charged an active slot by `note_admitted` and needs no
    /// promotion. An outcome that cannot be read back (a crash between
    /// recording the event and deciding admission) is treated as
    /// already-active: that is the conservative reading, since the
    /// alternative promotes a slot nothing queued.
    async fn promote_if_queued(&self, delivery: &TriggerDelivery, binding_id: BindingId) {
        let trigger_event_id = delivery.trigger_event_id;
        let outcome = self
            .with_connection(move |conn| {
                fetch_trigger_event_outcome(conn, trigger_event_id).map_err(|e| e.to_string())
            })
            .await;
        let queued = matches!(outcome, Ok(Ok(Some(TriggerEventOutcome::Queued))));
        if !queued {
            return;
        }
        if let Err(error) = self.registry.note_promoted(binding_id) {
            tracing::error!(
                binding_id = %binding_id,
                error = %error,
                "could not promote a queued delivery into an active admission slot"
            );
        }
    }

    /// Steps (b) through (i): reserve identities, resolve the job, create the
    /// reservation row and the session, and drive the workflow.
    ///
    /// # Two `RunContext` fields this cannot populate honestly
    ///
    /// - **`env_allowlist` is deny-all.** `EnvAllowlist` is built from an
    ///   operator-authored list of readable variable names, and no such
    ///   configuration surface exists anywhere in `roundhouse-config` yet
    ///   (checked: nothing in the workspace constructs an `EnvAllowlist` from
    ///   config). Every `env()` call in a scheduled run therefore denies
    ///   every name — the fail-closed direction, and the same default
    ///   `RunContext::env_allowlist`'s own doc comment names as correct while
    ///   that plumbing is outstanding.
    /// - **`secrets` is empty.** Resolving a `SecretRef` through
    ///   `roundhouse-secrets` for a *binding* has no wiring — a binding
    ///   declares no secrets and a job version's `SessionTemplate` carries
    ///   none — so a scheduled run's `${{ secrets.X }}` resolves to nothing
    ///   rather than to a fabricated value. [`flush_task_events`] builds its
    ///   `Redactor` with no needles for exactly this reason; both must change
    ///   together.
    ///
    /// `worktree_provider` *is* wired: `SandboxWorktreeProvider` takes a
    /// plain `repo_root`, and this delivery has resolved a real workspace
    /// root, which is precisely the value `roundhouse_flow::worktree`'s
    /// module doc says is the daemon's to supply. It is not validated to be
    /// a git repository here — the provider's own contract is that the first
    /// `materialize` surfaces that, and validating it eagerly would fail
    /// every non-`worktree` workflow in a non-git workspace for nothing.
    async fn run_claimed_delivery(
        &self,
        delivery: &TriggerDelivery,
        stored: &StoredBinding,
        now: Timestamp,
    ) -> Result<RunConclusion, DeliveryError> {
        let session_id = SessionId::new();
        let run_id = RunId::new();

        // **Reserved before anything fallible, deliberately — not in the
        // resolve-then-reserve order the brief sketched.** `fail_delivery` is
        // predecessor-constrained on `state IN ('running', 'reserved')`, so a
        // claim that dies while still `leased` cannot record why it failed:
        // the row sits `leased` with no owner, and nothing calls
        // `reclaim_expired_lease` yet. Reserving first puts every fallible
        // step below inside a state `fail_delivery` accepts. Widening
        // `fail_delivery` to accept `leased` was the alternative and is
        // *wrong*: a lease that expires is meant to return to `ready` for
        // another claimer, not to be burned as a permanent failure.
        //
        // The residual window is lease-success to reserve-success — one store
        // round-trip with no logic in it. A claimer that dies there leaves a
        // `leased` row that only a lease reaper (`reclaim_expired_lease`,
        // which has no caller yet) can return to `ready`. That is what the
        // lease column is *for*; wiring the reaper is a separate task.
        let reserved = self
            .transition_checked(&delivery.delivery_id, {
                let run_text = run_id.as_uuid().to_string();
                move |conn, id| reserve_delivery(conn, id, &run_text, session_id, now)
            })
            .await?;
        if !reserved {
            return Err(DeliveryError::LostClaim);
        }

        let registry = self
            .resources
            .workspace_registry
            .as_ref()
            .ok_or(DeliveryError::NoWorkspaceRegistry)?;
        let workspace = registry
            .resolve_by_id(stored.workspace)
            .map_err(|error| DeliveryError::Workspace(error.to_string()))?;
        let workspace_root = workspace.root.clone();

        let job_id = stored.binding.job_id;
        let root_for_job = workspace_root.clone();
        let resolved = self
            .with_connection(move |conn| {
                resolve_latest_by_job_id(conn, &root_for_job, job_id).map_err(|e| e.to_string())
            })
            .await?
            .map_err(DeliveryError::JobUnresolvable)?
            .ok_or(DeliveryError::JobNotRegistered)?;
        let version = resolved.job.latest();

        // The row's existence IS the reservation: `run_workflow` fails
        // `RunNotFound` without it, and flow has no separate reserve API.
        let run = WorkflowRun {
            id: run_id,
            job_id,
            job_version: version.version(),
            // The pinned hash, taken from the *same* `JobVersion` value this
            // run is being created against — `resolve_run_definition` will
            // re-derive it from storage and refuse the run if the two ever
            // disagree.
            content_hash: content_hash(version),
            session_id,
            binding_id: Some(stored.binding.id),
            trigger_event_id: Some(delivery.trigger_event_id),
            state: RunState::Running,
            parent_run_id: None,
            forked_from_run_id: None,
            awaiting_until: None,
            checkpoint_ref: None,
            checkpoint_blob_ref: None,
            started_at: now,
            ended_at: None,
            // A root run, never `None`: `admit_call_from_run` refuses a run
            // whose depth was never recorded, and `LedgerError::CapsNotRecorded`
            // refuses one whose caps were not — either would make this run
            // inert rather than merely unbudgeted.
            session_depth: Some(0),
            caps: Some(ResourceCaps::default()),
        };
        self.with_connection(move |conn| {
            insert_workflow_run(conn, &run).map_err(|error| error.to_string())
        })
        .await?
        .map_err(DeliveryError::RunRow)?;

        let spec = SessionSpec {
            workspace: stored.workspace,
            name: Some(workspace.name.clone()),
            // Ruling W1-R95's reasoning, applied to an *unattended* session:
            // `Tier::Sandbox` is the same tier the socket path requests, but
            // `OnDegrade::Refuse` is used unconditionally rather than
            // `resources.default_on_degrade`. The operator's
            // `--allow-degraded-to` flag is a human decision made for
            // sessions a human is present for; a scheduled run has nobody
            // watching it degrade, and §6.5 requires a downgrade be an
            // explicit human decision at creation. Refusing to run
            // unattended work unsandboxed is the conservative reading, and
            // the one this driver takes.
            requested_tier: Tier::Sandbox,
            on_degrade: OnDegrade::Refuse,
        };
        create_headless_session(
            &self.resources,
            &self.sessions,
            session_id,
            spec.clone(),
            workspace_root.clone(),
            workspace.root_device,
            workspace.root_inode,
        )
        .await
        .map_err(|error| DeliveryError::Session(headless_session_error_kind(&error)))?;

        let running = self
            .transition_checked(&delivery.delivery_id, move |conn, id| {
                mark_delivery_running(conn, id, now)
            })
            .await?;
        if !running {
            return Err(DeliveryError::LostClaim);
        }

        let run_ctx = RunContext {
            inputs: serde_json::Value::Null,
            vars: serde_json::Value::Null,
            secrets: HashMap::new(),
            run_id,
            // `defaults.carry_over.last_report` is not honoured for scheduled
            // runs yet: finding the previous run is
            // `durability::previous_run_for_binding`, but loading *its
            // report* is a `tasks`/`events` query nothing on this path makes.
            previous_report: None,
            env_allowlist: EnvAllowlist::deny_all(),
            worktree_provider: Some(Arc::new(SandboxWorktreeProvider::new(
                workspace_root.clone(),
            ))),
        };

        let runner = self.resources.runner;
        let spawn_tree = Arc::clone(&self.spawn_tree);
        self.with_connection(move |conn| {
            let mut sink = BufferedTaskSink::default();
            let mut host = SqliteWorkflowHost::with_session_tree(
                workspace_root,
                Box::new(WorkflowSessionTree::new(spawn_tree, runner, spec)),
            );
            let outcome =
                run_workflow_from_storage(conn, run_id, &mut sink, &mut host, run_ctx, now, None);
            if let Err(error) = flush_task_events(conn, runner, session_id, now, sink) {
                tracing::error!(
                    session_id = %session_id,
                    error = %error,
                    "a scheduled run's task events could not be appended to its session log"
                );
            }
            conclusion_for(outcome)
        })
        .await
    }

    /// Applies a delivery transition whose `false` (lost race) the caller
    /// wants to inspect.
    async fn transition_checked<F>(
        &self,
        delivery_id: &str,
        transition: F,
    ) -> Result<bool, DeliveryError>
    where
        F: FnOnce(&mut Connection, &str) -> Result<bool, roundhouse_sched::store::StoreError>
            + Send
            + 'static,
    {
        let id = delivery_id.to_string();
        self.with_connection(move |conn| transition(conn, &id).map_err(|error| error.to_string()))
            .await?
            .map_err(DeliveryError::Transition)
    }

    /// Applies a terminal delivery transition, logging rather than
    /// propagating: there is nothing further to do with a failure here, and
    /// the registry slot must still be released.
    async fn transition<F>(&self, delivery_id: &str, transition: F)
    where
        F: FnOnce(&mut Connection, &str) -> Result<bool, roundhouse_sched::store::StoreError>
            + Send
            + 'static,
    {
        match self.transition_checked(delivery_id, transition).await {
            Ok(true) => {}
            Ok(false) => tracing::warn!(
                "a trigger delivery's terminal transition found the row in another state; \
                 leaving it as it is"
            ),
            Err(error) => tracing::error!(
                kind = error.kind(),
                "a trigger delivery's terminal transition failed"
            ),
        }
    }

    /// `running|reserved -> failed`, recording `reason` in `last_error`, then
    /// releasing the admission slot. `reason` is written to a database
    /// column; only `kind` is logged.
    async fn fail(
        &self,
        delivery_id: &str,
        binding_id: BindingId,
        kind: &'static str,
        reason: String,
    ) {
        tracing::error!(
            binding_id = %binding_id,
            kind,
            "a scheduled trigger delivery failed; its admission slot is released so the \
             binding can fire again"
        );
        let failed = self.now();
        self.transition(delivery_id, move |conn, id| {
            fail_delivery(conn, id, &reason, failed)
        })
        .await;
        self.release(binding_id);
    }

    /// The one release call. Kept as its own method so every terminal path
    /// reads identically and a future path cannot quietly skip it.
    fn release(&self, binding_id: BindingId) {
        if let Err(error) = self.registry.note_finished(binding_id) {
            tracing::error!(
                binding_id = %binding_id,
                error = %error,
                "could not release this binding's admission slot; it may not fire again until \
                 the daemon restarts"
            );
        }
    }
}

/// [`CreateHeadlessSessionError`] as a static category — see
/// [`DeliveryError`]'s doc comment for why the `Display` is not used.
fn headless_session_error_kind(error: &CreateHeadlessSessionError) -> &'static str {
    match error {
        CreateHeadlessSessionError::Session(inner) => inner.kind(),
        CreateHeadlessSessionError::RegistryFull => "session_registry_full",
    }
}

/// Maps a run loop result onto the three delivery-visible conclusions.
///
/// A `Failed`/`Cancelled` terminal state is a *workflow* outcome, not a
/// driver error — but it is still a delivery that did not deliver, so it
/// fails the delivery rather than completing it.
fn conclusion_for(
    outcome: Result<RunOutcome, roundhouse_flow::exec::run_loop::RunLoopError>,
) -> RunConclusion {
    match outcome {
        Ok(RunOutcome::Terminal {
            state: RunState::Completed,
            ..
        }) => RunConclusion::Completed,
        Ok(RunOutcome::Terminal { state, .. }) => RunConclusion::Failed(format!(
            "the workflow run ended in state `{}`",
            state.wire_name()
        )),
        Ok(RunOutcome::Parked(_)) => RunConclusion::Parked,
        Err(error) => {
            RunConclusion::Failed(format!("the workflow run could not be driven: {error}"))
        }
    }
}

/// Discovers `ready` deliveries and spawns one task per delivery to claim and
/// run it.
///
/// Spawned rather than awaited inline for the obvious reason: a workflow run
/// can take hours, and the heartbeat has to keep ticking (and other
/// deliveries have to keep starting) while one runs. Each spawned task
/// contains its own failures — it returns `()` and every error inside it is
/// logged, so one bad delivery can neither crash the driver nor block
/// another.
///
/// A delivery whose binding is not in this driver's boot snapshot is left
/// `ready`: there is no honest `StoredBinding` to run it against, and
/// leaving the row alone means a daemon restart (which reloads the snapshot)
/// picks it up rather than losing it. Logged at `debug` because a tick
/// happens every second and this state persists across all of them.
async fn dispatch_ready_deliveries(
    executor: &DeliveryExecutor,
    bindings: &HashMap<BindingId, StoredBinding>,
) {
    let ready = match executor
        .with_connection(|conn| {
            list_ready_deliveries(conn, MAX_DELIVERY_CLAIMS_PER_TICK).map_err(|e| e.to_string())
        })
        .await
    {
        Ok(Ok(ready)) => ready,
        Ok(Err(_)) => {
            tracing::error!("listing ready trigger deliveries failed; retrying on the next tick");
            return;
        }
        // Pool/interact failures are already logged by `with_connection`.
        Err(_) => return,
    };

    for delivery in ready {
        let Some(stored) = bindings.get(&delivery.binding_id).cloned() else {
            tracing::debug!(
                binding_id = %delivery.binding_id,
                "a ready delivery names a binding this driver has no snapshot of; leaving it \
                 ready for a daemon that does"
            );
            continue;
        };
        let executor = executor.clone();
        tokio::spawn(async move {
            executor.claim_and_run(delivery, stored).await;
        });
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
    let executor = DeliveryExecutor::new(
        ctx.store.clone(),
        Arc::clone(&ctx.resources),
        Arc::clone(&ctx.sessions),
        Arc::clone(&registry),
        Arc::new(SystemClock),
    );

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

        if !due.is_empty() {
            // `accept_occurrence` is synchronous and owns its own `BEGIN
            // IMMEDIATE` transaction, so it runs on the pool's blocking
            // thread via `interact` rather than on this async task. A
            // checkout or interact failure costs this tick's occurrences and
            // nothing more: the scheduler has already advanced past them, so
            // they are dropped rather than retried, and the driver keeps
            // running.
            match ctx.store.pool.get().await {
                Ok(conn) => {
                    let tick_registry = Arc::clone(&registry);
                    let interact = conn
                        .interact(move |connection| {
                            accept_due_occurrences(
                                connection,
                                &due,
                                fired_at,
                                tick_registry.as_ref(),
                            );
                        })
                        .await;
                    if let Err(error) = interact {
                        tracing::error!(
                            error = %error,
                            "accepting this tick's occurrences failed on the store's blocking \
                             thread"
                        );
                    }
                }
                Err(error) => tracing::error!(
                    error = %error,
                    due = due.len(),
                    "could not check out a store connection for this tick's occurrences"
                ),
            }
        }

        // Runs on **every** tick, not only ticks that fired something: the
        // `ready` rows this picks up include the ones just created above (so
        // a freshly-admitted occurrence needs no special case) *and* any
        // left over from an earlier tick whose claim lost a race or whose
        // binding was not yet known. Skipping this when `due` is empty would
        // strand exactly the latter.
        dispatch_ready_deliveries(&executor, &bindings).await;
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
    /// becomes a delivery. This test drives `accept_due_occurrences` alone,
    /// with nothing claiming or completing the delivery it creates, so the
    /// first admitted occurrence keeps this `Skip` binding's active count at
    /// one and every later occurrence in the same tick is suppressed — which
    /// is the overlap policy working, not the missing-release limitation it
    /// used to pin (`DeliveryExecutor` releases the slot now; see
    /// `delivery_tests`).
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

/// End-to-end coverage for Task 6's claim-and-execute path: a `ready`
/// `trigger_delivery` becomes a real `workflow_run` in a real headless
/// session, and reaches `delivered` or `failed` with its admission slot
/// released either way.
///
/// **No real-clock timing anywhere.** Every timestamp comes from the
/// [`FixedClock`] the harness injects into [`DeliveryExecutor`], and the one
/// place a test waits (the parked case's spawned task) is driven by awaiting
/// the call directly rather than sleeping.
#[cfg(test)]
mod delivery_tests {
    use super::*;
    use crate::session_registry::SessionRegistry;
    use crate::test_support::daemon_resources;
    use crate::workspace_registry::{WorkspaceRegistration, WorkspaceRegistry};
    use roundhouse_core::Tier;
    use roundhouse_flow::durability::recover_run;
    use roundhouse_flow::job::SessionTemplate;
    use roundhouse_flow::job_store::register_workflow_file;
    use roundhouse_sched::delivery::DeliveryState;
    use roundhouse_sched::store::fetch_delivery;
    use roundhouse_store::StorePool;
    use std::path::PathBuf;
    use std::time::Duration;

    /// The one instant every delivery test reckons against.
    fn instant() -> DateTime<Utc> {
        DateTime::from_timestamp_nanos(1_700_000_000_000_000_000)
    }

    fn template() -> SessionTemplate {
        SessionTemplate {
            provider: "test".into(),
            model: "test-model".into(),
            cwd: "/tmp".into(),
            tools: vec![],
            isolation: Tier::Sandbox,
            permission_policy_ref: "default".into(),
        }
    }

    /// A workflow whose single step completes with no dispatch of any kind.
    fn completing_workflow() -> String {
        "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: result\n    emit: { value: ready }\n"
            .to_string()
    }

    /// A workflow whose step fails: `no_such_fn` is not a function the
    /// expression evaluator knows, so the step (and therefore the run) fails
    /// — the same fixture `roundhouse-flow`'s own run-loop tests use.
    fn failing_workflow() -> String {
        "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: broken\n    emit: \"${{ no_such_fn(1) }}\"\n"
            .to_string()
    }

    /// A workflow that parks on a human gate — a real, valid non-terminal
    /// outcome this driver deliberately does not resolve.
    fn parking_workflow() -> String {
        "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
         escalate: fail\nsteps:\n  - id: approve\n    gate:\n      title: approve\n      \
         form: { approved: { type: boolean } }\n      timeout: 1h\n      on_timeout: deny\n"
            .to_string()
    }

    struct Harness {
        _dir: tempfile::TempDir,
        store: StorePool,
        sessions: Arc<SessionRegistry>,
        executor: DeliveryExecutor,
        registry: Arc<InMemoryRunRegistry>,
        stored: StoredBinding,
        delivery: TriggerDelivery,
        workspace_root: PathBuf,
    }

    impl Harness {
        async fn delivery_row(&self) -> TriggerDelivery {
            let id = self.delivery.delivery_id.clone();
            let conn = self.store.pool.get().await.unwrap();
            conn.interact(move |connection| fetch_delivery(connection, &id).unwrap().unwrap())
                .await
                .unwrap()
        }

        fn active(&self) -> u32 {
            self.registry
                .active_run_count(self.stored.binding.id)
                .unwrap()
        }

        async fn session_event_count(&self, session_id: SessionId) -> i64 {
            let conn = self.store.pool.get().await.unwrap();
            conn.interact(move |connection| {
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM events WHERE session_id = ?1",
                        rusqlite::params![session_id.to_string()],
                        |row| row.get(0),
                    )
                    .unwrap()
            })
            .await
            .unwrap()
        }
    }

    /// Builds a real workspace, a real registered job, a real `ready`
    /// delivery (through `accept_occurrence`, so the admission slot is
    /// genuinely charged), and an executor wired to all of it.
    async fn harness(workflow_yaml: String) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let workspace_root = dir.path().join("workspace");
        std::fs::create_dir(&workspace_root).unwrap();
        let source = workspace_root.join("workflow.yaml");
        std::fs::write(&source, workflow_yaml).unwrap();

        let store = roundhouse_store::open(&dir.path().join("events.db"))
            .await
            .unwrap();
        let workspaces = Arc::new(
            WorkspaceRegistry::open(
                roundhouse_store::open(&dir.path().join("events.db"))
                    .await
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        let workspace = workspaces
            .register(WorkspaceRegistration::new(
                "scheduled-workspace",
                workspace_root.clone(),
            ))
            .await
            .unwrap();
        // The canonical root the registry resolved, not the raw tempdir path
        // — `register_workflow_file` canonicalizes both sides and would
        // otherwise reject the source as outside the workspace on a platform
        // whose temp directory is a symlink.
        let workspace_root = workspace.root.clone();
        let source = workspace_root.join("workflow.yaml");

        let job_id = {
            let conn = store.pool.get().await.unwrap();
            let root = workspace_root.clone();
            conn.interact(move |connection| {
                register_workflow_file(connection, &root, &source, template())
                    .unwrap()
                    .job
                    .id()
            })
            .await
            .unwrap()
        };

        let stored = StoredBinding {
            workspace: workspace.id,
            binding: Binding::new(
                job_id,
                TriggerSpec::Interval {
                    every: Duration::from_secs(60),
                    align: false,
                    anchor: None,
                },
            ),
        };

        let registry = Arc::new(InMemoryRunRegistry::new());
        let due = vec![(
            stored.clone(),
            ScheduledOccurrence {
                binding_id: stored.binding.id,
                scheduled_for: instant(),
                is_catch_up: false,
            },
        )];
        {
            let conn = store.pool.get().await.unwrap();
            let tick_registry = Arc::clone(&registry);
            conn.interact(move |connection| {
                accept_due_occurrences(connection, &due, instant(), tick_registry.as_ref());
            })
            .await
            .unwrap();
        }
        let delivery = {
            let conn = store.pool.get().await.unwrap();
            conn.interact(|connection| list_ready_deliveries(connection, 10).unwrap())
                .await
                .unwrap()
                .pop()
                .expect("accept_occurrence must have created one ready delivery")
        };
        assert_eq!(
            registry.active_run_count(stored.binding.id).unwrap(),
            1,
            "this harness proves nothing about release unless the slot was really charged"
        );

        let sessions = Arc::new(SessionRegistry::new());
        let resources = Arc::new(daemon_resources(dir.path(), Some(Arc::clone(&workspaces))).await);
        let executor = DeliveryExecutor::new(
            store.clone(),
            resources,
            Arc::clone(&sessions),
            Arc::clone(&registry),
            Arc::new(FixedClock(instant())),
        );

        Harness {
            _dir: dir,
            store,
            sessions,
            executor,
            registry,
            stored,
            delivery,
            workspace_root,
        }
    }

    #[tokio::test]
    async fn a_ready_delivery_runs_its_workflow_and_releases_its_admission_slot() {
        let harness = harness(completing_workflow()).await;

        harness
            .executor
            .claim_and_run(harness.delivery.clone(), harness.stored.clone())
            .await;

        let row = harness.delivery_row().await;
        assert_eq!(
            row.state,
            DeliveryState::Delivered,
            "a completed run must complete its delivery; last_error was {:?}",
            row.last_error
        );
        let run_id = RunId::from_uuid(
            Uuid::parse_str(row.run_id.as_deref().expect("reserve stamps a run id")).unwrap(),
        );
        let session_id = row.session_id.expect("reserve stamps a session id");

        let run = {
            let conn = harness.store.pool.get().await.unwrap();
            conn.interact(move |connection| recover_run(connection, run_id).unwrap().run)
                .await
                .unwrap()
        };
        assert_eq!(run.session_id, session_id);
        assert_eq!(
            run.binding_id,
            Some(harness.stored.binding.id),
            "the run must be attributable back to the binding that scheduled it"
        );
        assert_eq!(
            run.trigger_event_id,
            Some(harness.delivery.trigger_event_id),
            "the run must be attributable back to the occurrence that fired it"
        );
        assert_eq!(
            run.session_depth,
            Some(0),
            "a root run with no recorded depth is inert — admit_call_from_run refuses it"
        );
        assert_eq!(
            run.caps,
            Some(ResourceCaps::default()),
            "a run with no recorded caps is inert — LedgerError::CapsNotRecorded refuses it"
        );
        assert_eq!(run.state, RunState::Completed);

        assert_eq!(
            harness.active(),
            0,
            "a completed delivery must release the admission slot accept_occurrence charged, \
             or this binding never fires again"
        );
        assert!(
            harness.sessions.actor(session_id).is_some(),
            "the delivery must have created a real, registered headless session"
        );
        assert!(
            harness.session_event_count(session_id).await > 1,
            "the run's task events must reach the session's log, not just its SessionCreated"
        );
    }

    #[tokio::test]
    async fn a_failing_workflow_fails_its_delivery_and_still_releases_the_slot() {
        let harness = harness(failing_workflow()).await;

        harness
            .executor
            .claim_and_run(harness.delivery.clone(), harness.stored.clone())
            .await;

        let row = harness.delivery_row().await;
        assert_eq!(row.state, DeliveryState::Failed);
        assert!(
            row.last_error.as_deref().is_some_and(|e| !e.is_empty()),
            "a failed delivery must say why, got {:?}",
            row.last_error
        );
        assert_eq!(row.attempts, 1, "fail_delivery counts the attempt");
        assert_eq!(
            harness.active(),
            0,
            "a FAILED run must release its slot too — a held slot wedges the binding shut \
             exactly like the never-released case"
        );
    }

    /// A parked run is not terminal. Completing or failing its delivery would
    /// be a lie, and releasing its slot would let the same binding start a
    /// second run on top of one that is still live.
    #[tokio::test]
    async fn a_parked_run_leaves_its_delivery_running_and_holds_its_slot() {
        let harness = harness(parking_workflow()).await;

        harness
            .executor
            .claim_and_run(harness.delivery.clone(), harness.stored.clone())
            .await;

        let row = harness.delivery_row().await;
        assert_eq!(
            row.state,
            DeliveryState::Running,
            "a parked run's delivery must stay `running`; last_error was {:?}",
            row.last_error
        );
        assert!(row.last_error.is_none());
        assert_eq!(
            harness.active(),
            1,
            "a parked run is still live, so its admission slot must stay held"
        );
    }

    /// Losing the `ready -> leased` race is an ordinary no-op: this claimer
    /// never owned the delivery, so it must neither touch the row nor release
    /// a slot whose real owner will release it.
    #[tokio::test]
    async fn a_delivery_someone_else_already_leased_is_skipped_without_release() {
        let harness = harness(completing_workflow()).await;

        let id = harness.delivery.delivery_id.clone();
        let conn = harness.store.pool.get().await.unwrap();
        let leased = conn
            .interact(move |connection| {
                roundhouse_sched::store::lease_delivery(
                    connection,
                    &id,
                    Timestamp::from_unix_nanos(i64::MAX),
                    Timestamp::from_unix_nanos(0),
                )
                .unwrap()
            })
            .await
            .unwrap();
        assert!(leased);

        harness
            .executor
            .claim_and_run(harness.delivery.clone(), harness.stored.clone())
            .await;

        let row = harness.delivery_row().await;
        assert_eq!(row.state, DeliveryState::Leased);
        assert!(row.run_id.is_none(), "a lost claim must reserve nothing");
        assert_eq!(
            harness.active(),
            1,
            "a claimer that never owned the delivery must not release its slot"
        );
    }

    /// A delivery whose binding is not in the driver's boot snapshot has no
    /// honest `StoredBinding` to run against; leaving it `ready` is what lets
    /// a daemon that *does* know the binding pick it up later.
    #[tokio::test]
    async fn a_delivery_for_an_unknown_binding_is_left_ready() {
        let harness = harness(completing_workflow()).await;

        dispatch_ready_deliveries(&harness.executor, &HashMap::new()).await;

        assert_eq!(harness.delivery_row().await.state, DeliveryState::Ready);
        assert_eq!(harness.active(), 1);
    }

    /// The failure this driver must survive rather than propagate: the
    /// binding's job is not registered in the workspace it names.
    #[tokio::test]
    async fn an_unresolvable_job_fails_the_delivery_rather_than_the_driver() {
        let mut harness = harness(completing_workflow()).await;
        harness.stored.binding.job_id = JobId::new();

        harness
            .executor
            .claim_and_run(harness.delivery.clone(), harness.stored.clone())
            .await;

        let row = harness.delivery_row().await;
        assert_eq!(
            row.state,
            DeliveryState::Failed,
            "a delivery that can never run must fail rather than sit leased forever"
        );
        assert_eq!(harness.active(), 0);
        assert!(
            harness.workspace_root.is_dir(),
            "the workspace must be untouched by a failed resolution"
        );
    }
}
