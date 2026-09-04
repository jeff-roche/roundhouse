//! The **run-level ledger** (Phase 5, B12b — ruling P77's split of Task 20):
//! §8.4's caps and §8.12's budget transfer, read and written as durable
//! columns rather than held in process memory.
//!
//! # Why every number here is a column
//!
//! Three separate places in this crate had already recorded the same
//! conclusion before the columns existed, each about a different quantity and
//! each for the same reason:
//!
//! - [`crate::caps::ResourceCaps::run_active_timeout`] *"excludes parked
//!   time"*, and measuring that *"requires a durable place to record park
//!   intervals — a column, not an in-process tracker, which a daemon restart
//!   would lose precisely across the multi-day park it exists to measure."*
//! - [`crate::compose::ChildBudget`]'s refund residual: the token is
//!   deliberately non-`Deserialize`, *"so a daemon restart loses the
//!   in-process grant record too and Task 20 must re-derive the refund from
//!   durable rows rather than from a rehydrated token."*
//! - [`crate::parking::reaper_cutoff`] has taken a `parked_at` argument since
//!   Task 17 with **no durable source for it anywhere in the schema** (ruling
//!   P72).
//!
//! Migration 0008 supplies all three, and this module is their only reader
//! and — with [`crate::durability`]'s `transition` — their only writer.
//!
//! # This module never reads a clock
//!
//! `now` is a parameter, exactly as it is in [`crate::durability`] and
//! [`crate::parking`]. That is what makes an elapsed-time ledger testable
//! without sleeping, and it is why [`active_elapsed`] is a pure function over
//! a [`RunLedger`] rather than something that consults the system time.
//!
//! # What this module is NOT
//!
//! **It is not the run loop.** Nothing here decides *when* to admit a task,
//! park a run, start a child, or reap a workspace; each function is the
//! durable half of a decision B12c (the run loop) or the daemon makes:
//!
//! - [`parked_runs_past_hold_cap`] is the reaper's **query**, in the shape of
//!   `roundhouse_store::blobs::gc_eligible_blobs` — and, like it, its periodic
//!   caller does not exist. Ruling P77 §C moved that runner out of Task 20
//!   entirely: it is daemon-side, timer-driven, and wants the identical
//!   machinery `blobs.rs`'s daily GC wants, so one owner should take both.
//!   **B12b supplies the column and the query; not the runner.**
//! - [`admit_spend`] is the chokepoint §8.4's *"caps enforced at task
//!   admission"* describes, but the thing that calls it once per task is the
//!   run loop's.
//! - [`draw_child_run`] and [`refund_child_run`] are §8.12's transfer, both
//!   halves of it, over rows. B12b's job was to make the pair *symmetric* —
//!   see [`draw_child_run`] for what the missing half cost. **B12c wired the
//!   draw**, and not where either slice expected: not at a `call:` arm, but at
//!   [`crate::durability`]'s `insert_run_row`, so that ruling P114 §A's
//!   invariant — *no `workflow_run` row carrying a `parent_run_id` is
//!   committed without a draw in the same transaction* — holds for every
//!   creator of a child row rather than for the one this slice happened to
//!   build. The **refund** still has no production caller: returning a child's
//!   grant on completion is the run loop's, and today only the `call:` arm
//!   creates a child run whose completion it could observe.
//! - [`crate::exec::map_step::MapBudget::from_run_ledger`] sources a `map`'s
//!   budget from [`remaining_caps`], but the `map` dispatch arm still builds
//!   [`crate::exec::map_step::MapBudget::unenforced_placeholder`], because
//!   `Executor` holds no [`Connection`] and giving it one is run-loop
//!   plumbing. See that constructor's doc for the exact swap B12c makes.
//!
//! # Named gap: a run-level `caps:` block is not authorable
//!
//! §8.4's `ResourceCaps` is a **run-level** ceiling, and
//! [`crate::parse::types::WorkflowDef`] has no `caps:` field — only
//! [`crate::parse::steps::CapsDef`], the per-step override. So the grant a run
//! is created with can come from a caller (the daemon's configuration, or
//! [`crate::compose::draw_child_budget`] for a child run) but **not from the
//! workflow author**, and a workflow that writes a top-level `caps:` gets a
//! hard parse error, since `WorkflowDef` is `#[serde(deny_unknown_fields)]`.
//! Recorded as a wire-shape gap of the same class as `on_crash:` and
//! `outputs:` (see [`crate::durability`]'s and [`crate::compose`]'s module
//! docs), owned by **B12c** for the same reason those are: it is the first
//! task with a run loop, and therefore the first that can observe what a
//! declared run-level cap would have to mean.

use crate::caps::{is_usable_cost_usd, ResourceCaps};
use crate::compose::{admit_child_call, child_call_depth, CallDepthError, CallFanOutError};
use crate::durability::{DurabilityError, RunState};
use crate::exec::RunId;
use crate::parking::reaper_cutoff_instant;
use roundhouse_core::Timestamp;
use rusqlite::{params, Connection, OptionalExtension};
use std::time::Duration;
use thiserror::Error;

/// Why a ledger operation refused.
///
/// Several variants exist to keep facts apart that a coarser taxonomy would
/// merge — the same discipline [`DurabilityError`] applies to "no such run"
/// versus "that run is in the wrong state". In particular
/// [`Self::CapsNotRecorded`] is **not** [`Self::CapsExceeded`]: a run whose
/// grant was never recorded has an unknown budget, and answering an unknown
/// budget with `ResourceCaps::default()` would hand a full allowance to
/// exactly the rows the schema knows least about.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum LedgerError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// A read-back failure from the shared `workflow_run` decoding path —
    /// an unrecognised state discriminant, a malformed id, a stored
    /// `session_depth` outside `u32`.
    #[error(transparent)]
    Durability(#[from] DurabilityError),
    #[error("no workflow_run row for run {run_id}")]
    RunNotFound { run_id: RunId },
    /// `workflow_run.caps_json` is `NULL`: this run's grant was never
    /// recorded (a row written before migration 0008, or by a caller that
    /// supplied no [`crate::durability::WorkflowRun::caps`]). **Fail-closed
    /// on purpose** — see this enum's own doc.
    #[error("run {run_id} has no recorded resource caps")]
    CapsNotRecorded { run_id: RunId },
    /// `workflow_run.session_depth` is `NULL`, so how deep this run's Session
    /// sits is unknown and no `call:` beneath it can be bounded. Refusing is
    /// the only fail-closed answer: reading `NULL` as `0` would hand a run of
    /// unknown depth a full four levels (ruling P76 §1's escape, reached
    /// through the schema instead of through the wrong counter).
    #[error("run {run_id} has no recorded session depth")]
    SessionDepthNotRecorded { run_id: RunId },
    /// [`crate::compose::child_call_depth`] refused: §7.7's depth limit.
    #[error(transparent)]
    CallDepth(#[from] CallDepthError),
    /// [`crate::compose::admit_child_call`] refused: §7.7's fan-out limit.
    #[error(transparent)]
    CallFanOut(#[from] CallFanOutError),
    /// The run's grant does not cover what was asked for. `field` names the
    /// [`ResourceCaps`] field that ran out — the *first* one checked that did,
    /// so a request over budget in several dimensions reports one of them
    /// rather than all; admission is a yes/no and the caller does not get to
    /// spend the fields that would have fit.
    #[error("run {run_id} cannot admit this spend: {field} would exceed its grant")]
    CapsExceeded { run_id: RunId, field: &'static str },
    /// The run is not in a state that admits new work. §8.13 states the
    /// `Cancelling` half verbatim (*"refuse new task admission"*); the rest is
    /// this module's reading — see [`admit_spend`].
    #[error("run {run_id} is {state:?} and is not admitting new work")]
    NotAdmitting { run_id: RunId, state: RunState },
    /// A dollar figure that is not a usable non-negative amount reached a
    /// writer. `max_cost_usd` is an `f64` (see [`ResourceCaps`]'s recorded
    /// deviation from §8.4's `Decimal`) sourced from workflow YAML, where
    /// `.nan`, `.inf` and `-1e18` are all authorable scalars. Refused rather
    /// than clamped, because the column cannot catch it either: migration
    /// 0008's `CHECK (spent_cost_usd >= 0)` rejects a negative and (via
    /// `NOT NULL`, since SQLite stores `NaN` as `NULL`) a `NaN`, but **`+inf`
    /// satisfies `>= 0` and is stored**.
    #[error("run {run_id} was handed {amount} as a dollar amount, which is not usable")]
    UnusableCostAmount { run_id: RunId, amount: f64 },
    /// [`refund_child_run`] was asked to refund a run with no
    /// `parent_run_id`. A refund is a transfer to a parent, and a root run
    /// has none — this is the cross-column rule migration 0008 cannot express
    /// as a `CHECK` (ruling P104: that would need the table rebuild).
    #[error("run {run_id} has no parent run to refund to")]
    NotAChildRun { run_id: RunId },
    /// [`refund_child_run`] was asked to refund a run that has not finished.
    /// §8.12 says the draw is *"refunded on completion"*; returning a live
    /// child's grant would let it keep spending against budget its parent has
    /// already reclaimed.
    #[error("run {run_id} is {state:?} and has not completed, so its grant cannot be refunded")]
    ChildNotFinished { run_id: RunId, state: RunState },
    /// [`refund_child_run`] was asked to refund a run whose `refunded_at` is
    /// already stamped. This is the durable equivalent of
    /// [`crate::compose::ChildBudget`] being consumed by value: a second
    /// refund would credit the parent budget its root never granted, which is
    /// exactly §8.12's invariant inverted.
    #[error("run {run_id} was already refunded at {at:?}")]
    AlreadyRefunded { run_id: RunId, at: Timestamp },
    /// [`refund_child_run`] was asked to refund a child whose
    /// `workflow_run.drawn_at` is `NULL`: **no draw against the parent was
    /// ever recorded**, so there is nothing to give back and crediting the
    /// parent would decrement spend it really made.
    ///
    /// This is ruling P109 §A's defect as a refusal. Before the column
    /// existed, `caps_json` and `parent_run_id` were the whole evidence a
    /// refund needed — and both are values a row can carry without any draw
    /// having happened, which is precisely what `control::retry_from_step`'s
    /// fork produces by copying them.
    #[error("run {run_id} has no recorded draw against its parent, so there is nothing to refund")]
    DrawNotRecorded { run_id: RunId },
    /// [`draw_child_run`] was asked to charge a parent for a child that is
    /// already stamped `drawn_at`. `refunded_at`'s mirror image: a second draw
    /// would charge the parent twice for one grant, so §8.12's invariant fails
    /// in the *other* direction — a subtree unable to spend what its root gave
    /// it.
    #[error("run {run_id} was already drawn at {at:?}")]
    AlreadyDrawn { run_id: RunId, at: Timestamp },
    /// [`draw_child_run`] was asked to charge a parent for a run whose
    /// `refunded_at` is already stamped — a settled run, which
    /// `durability::fork_run` also produces at creation. Drawing for one would
    /// charge the parent a grant [`refund_child_run`] can then never return.
    #[error("run {run_id} was settled at {at:?} and cannot be drawn for")]
    AlreadySettled { run_id: RunId, at: Timestamp },
    /// A `u64` counter does not fit SQLite's signed 64-bit `INTEGER`.
    /// Surfaced rather than silently wrapped, the same rule
    /// [`DurabilityError::SeqOutOfRange`] states for a task `seq`.
    #[error("column {column} cannot hold {value}, which does not fit a SQLite INTEGER")]
    ValueOutOfRange { column: &'static str, value: u64 },
}

/// A **measured consumption**, as opposed to [`ResourceCaps`]'s ceiling.
///
/// # Why this is not a `ResourceCaps`
///
/// [`crate::compose::refund_child_budget`] takes its `spent` argument as a
/// `&ResourceCaps` and its own doc calls that out as a wart —
/// *"`spent` is a measurement typed as a ceiling"* — accepted at the time
/// because the seven countables line up field for field and it was the only
/// call site. It is no longer the only one, and the mismatch has teeth here:
/// a `ResourceCaps` carries three `Duration`s that a spend has no meaning
/// for, so passing one means silently ignoring three fields at every call.
/// This type carries the seven countables and nothing else.
///
/// # Who measures it
///
/// The same answer [`crate::compose::refund_child_budget`] gives: the parent
/// side, from outside the run being measured — Phase 2's cost accounting —
/// never a figure originating inside the run and never one derived from a
/// model's output. §8.12's invariant reduces entirely to this number being
/// truthful; every guard in this module is about the *shape* of the number,
/// and none of them can tell an honest small spend from a self-reported one.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Spend {
    pub tokens: u64,
    pub cost_usd: f64,
    pub tasks: u32,
    pub tool_calls: u32,
    pub subagents: u32,
    pub bytes_written: u64,
    pub escalations: u32,
}

impl Spend {
    /// A run that has consumed nothing. The value migration 0008's
    /// accumulators default to, spelled once.
    pub const ZERO: Spend = Spend {
        tokens: 0,
        cost_usd: 0.0,
        tasks: 0,
        tool_calls: 0,
        subagents: 0,
        bytes_written: 0,
        escalations: 0,
    };

    /// What a parent is charged when it grants `caps` to a child run.
    ///
    /// §8.12: *"the child's `max_cost_usd`/`max_tokens` are drawn from the
    /// parent's remaining budget, refunded on completion, enforced."* A draw
    /// is a spend against the parent's ledger of the child's **whole grant**,
    /// and [`refund_child_run`] later returns the part the child did not use.
    /// Charging the grant up front rather than the child's running total is
    /// what makes the invariant hold while the child is still running: a
    /// parent with $1 left cannot start two children each promised $1.
    ///
    /// [`draw_child_run`] is the caller, and until it existed there was none
    /// anywhere in the workspace — which is exactly why a refund could pay out
    /// against a draw that never happened (ruling P109 §A).
    pub fn for_grant(caps: &ResourceCaps) -> Spend {
        Spend {
            tokens: caps.max_tokens,
            cost_usd: caps.max_cost_usd,
            tasks: caps.max_tasks,
            tool_calls: caps.max_tool_calls,
            subagents: caps.max_subagents,
            bytes_written: caps.max_bytes_written,
            escalations: caps.max_escalations,
        }
    }
}

/// One run's ledger columns, plus the few `workflow_run` columns the ledger's
/// own arithmetic reads.
///
/// # Why this is a separate struct from [`crate::durability::WorkflowRun`]
///
/// `WorkflowRun` is the value a **caller constructs** to insert a run. Six of
/// the fields below — [`Self::parked_at`], [`Self::hold_until`],
/// [`Self::parked_nanos`], [`Self::spent`], [`Self::drawn_at`] and
/// [`Self::refunded_at`], which are twelve columns between them — are written
/// **only** by this crate's own writers and default to zero or `NULL` in the
/// schema. Putting those on the constructed type would invite a caller to
/// insert a run that claims five hours of parked time, or a spend it never
/// made, and would make every construction site in the tree responsible for
/// twelve columns it has no opinion about.
///
/// The other seven (`run_id`, `state`, `parent_run_id`, `started_at`,
/// `ended_at`, `session_depth`, `caps`) *are* on `WorkflowRun`, and are read
/// here because the ledger's own arithmetic needs them. That overlap is
/// deliberate duplication of read-only values, not a second identity for the
/// row.
#[derive(Debug, Clone, PartialEq)]
pub struct RunLedger {
    pub run_id: RunId,
    pub state: RunState,
    pub parent_run_id: Option<RunId>,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
    /// When the run's **current** park began, or `None` if it is not parked.
    /// Preserved across a re-park (see [`crate::durability`]'s `transition`),
    /// so it is the start of the park, never the start of the latest re-drive
    /// of it.
    pub parked_at: Option<Timestamp>,
    /// The workspace hold's absolute, already-clamped instant — the durable
    /// half of [`crate::parking::WorkspaceDisposition::HoldUntil`].
    pub hold_until: Option<Timestamp>,
    /// Park time from **completed** parks only. The park in progress, if
    /// there is one, is [`Self::parked_at`]; [`active_elapsed`] adds the two.
    pub parked_nanos: u64,
    /// See [`crate::durability::WorkflowRun::session_depth`] — the Session's
    /// depth, not the run's.
    pub session_depth: Option<u32>,
    /// The grant. See [`crate::durability::WorkflowRun::caps`].
    pub caps: Option<ResourceCaps>,
    /// What the run has consumed so far, against [`Self::caps`]. Written only
    /// by [`admit_spend`] and [`refund_child_run`].
    pub spent: Spend,
    /// Stamped when this run's grant was **drawn from its parent** — the
    /// durable record that [`Spend::for_grant`] was charged, without which a
    /// row that merely carries a parent id and a grant is indistinguishable
    /// from one that was really paid for. `None` on a root run, and on a
    /// child whose draw has not happened yet.
    pub drawn_at: Option<Timestamp>,
    /// Stamped when this run's unspent grant was returned to its parent — or,
    /// for a fork, at creation, because a fork's copied grant was never drawn
    /// and so has nothing to return (see `durability::fork_run`).
    pub refunded_at: Option<Timestamp>,
}

/// The ledger columns, in the order [`ledger_from_row`] reads them. One
/// definition rather than one per query, for the reason
/// `durability::WORKFLOW_RUN_SELECT` gives: tuple positions are what bind a
/// `SELECT` list to its decoder, and two columns of the same SQLite type
/// swapped between them is a mismatch no engine can catch.
const RUN_LEDGER_SELECT: &str = "SELECT id, state, parent_run_id, started_at, ended_at,
            parked_at, hold_until, parked_nanos, session_depth, caps_json,
            spent_tokens, spent_cost_usd, spent_tasks, spent_tool_calls,
            spent_subagents, spent_bytes_written, spent_escalations, drawn_at, refunded_at
     FROM workflow_run";

/// Loads one run's ledger.
pub fn run_ledger(conn: &Connection, run_id: RunId) -> Result<RunLedger, LedgerError> {
    read_ledger(conn, run_id)
}

fn read_ledger(conn: &Connection, run_id: RunId) -> Result<RunLedger, LedgerError> {
    let mut stmt = conn.prepare(&format!("{RUN_LEDGER_SELECT} WHERE id = ?1"))?;
    let row = stmt
        .query_row(params![run_id.to_string()], |row| {
            Ok(RawLedgerColumns {
                id: row.get(0)?,
                state: row.get(1)?,
                parent_run_id: row.get(2)?,
                started_at: row.get(3)?,
                ended_at: row.get(4)?,
                parked_at: row.get(5)?,
                hold_until: row.get(6)?,
                parked_nanos: row.get(7)?,
                session_depth: row.get(8)?,
                caps_json: row.get(9)?,
                spent_tokens: row.get(10)?,
                spent_cost_usd: row.get(11)?,
                spent_tasks: row.get(12)?,
                spent_tool_calls: row.get(13)?,
                spent_subagents: row.get(14)?,
                spent_bytes_written: row.get(15)?,
                spent_escalations: row.get(16)?,
                drawn_at: row.get(17)?,
                refunded_at: row.get(18)?,
            })
        })
        .optional()?;
    let raw = row.ok_or(LedgerError::RunNotFound { run_id })?;
    ledger_from_row(raw)
}

/// The raw columns, extracted inside the `rusqlite` closure (which can only
/// produce a `rusqlite::Error`) so the typed conversions can produce this
/// module's own errors.
struct RawLedgerColumns {
    id: String,
    state: String,
    parent_run_id: Option<String>,
    started_at: i64,
    ended_at: Option<i64>,
    parked_at: Option<i64>,
    hold_until: Option<i64>,
    parked_nanos: i64,
    session_depth: Option<i64>,
    caps_json: Option<String>,
    spent_tokens: i64,
    spent_cost_usd: f64,
    spent_tasks: i64,
    spent_tool_calls: i64,
    spent_subagents: i64,
    spent_bytes_written: i64,
    spent_escalations: i64,
    drawn_at: Option<i64>,
    refunded_at: Option<i64>,
}

fn ledger_from_row(raw: RawLedgerColumns) -> Result<RunLedger, LedgerError> {
    let run_id = RunId::from_uuid(raw.id.parse().map_err(|_| DurabilityError::MalformedId {
        column: "workflow_run.id",
    })?);
    let parent_run_id = raw
        .parent_run_id
        .map(|text| {
            text.parse()
                .map(RunId::from_uuid)
                .map_err(|_| DurabilityError::MalformedId {
                    column: "workflow_run.parent_run_id",
                })
        })
        .transpose()?;
    let caps = raw
        .caps_json
        .map(|text| {
            serde_json::from_str::<ResourceCaps>(&text)
                .map_err(|_| DurabilityError::MalformedStoredCaps { run_id })
        })
        .transpose()?;
    let session_depth = raw
        .session_depth
        .map(|stored| {
            u32::try_from(stored).map_err(|_| DurabilityError::SessionDepthOutOfRange { stored })
        })
        .transpose()?;

    Ok(RunLedger {
        run_id,
        state: RunState::from_sql_str(&raw.state)?,
        parent_run_id,
        started_at: Timestamp::from_unix_nanos(raw.started_at),
        ended_at: raw.ended_at.map(Timestamp::from_unix_nanos),
        parked_at: raw.parked_at.map(Timestamp::from_unix_nanos),
        hold_until: raw.hold_until.map(Timestamp::from_unix_nanos),
        parked_nanos: nonneg(raw.parked_nanos),
        session_depth,
        caps,
        spent: Spend {
            tokens: nonneg(raw.spent_tokens),
            cost_usd: raw.spent_cost_usd,
            tasks: nonneg_u32(raw.spent_tasks),
            tool_calls: nonneg_u32(raw.spent_tool_calls),
            subagents: nonneg_u32(raw.spent_subagents),
            bytes_written: nonneg(raw.spent_bytes_written),
            escalations: nonneg_u32(raw.spent_escalations),
        },
        drawn_at: raw.drawn_at.map(Timestamp::from_unix_nanos),
        refunded_at: raw.refunded_at.map(Timestamp::from_unix_nanos),
    })
}

/// Migration 0008's `CHECK (… >= 0)` is the insert-time leg; this is the
/// read-back leg. Unlike `session_depth` it **saturates rather than
/// failing**, and the difference is deliberate: a negative accumulator can
/// only mean a hand-edited or pre-`CHECK` row, and reading it as zero
/// under-states a *spend*, which the caps check then treats as more budget
/// remaining — so the choice is between refusing to run the run at all and
/// over-crediting a corrupt row. `session_depth` refuses because its
/// corrupt-row failure is a *bound* being bypassed; these saturate because
/// theirs is an accounting figure, and the alternative is a run that can
/// never be admitted again.
fn nonneg(stored: i64) -> u64 {
    u64::try_from(stored).unwrap_or(0)
}

/// [`nonneg`] for a counter whose Rust type is `u32`. A value past
/// `u32::MAX` saturates *up*, not down: for a spend, the larger number is
/// the one that admits less.
fn nonneg_u32(stored: i64) -> u32 {
    match u32::try_from(stored) {
        Ok(value) => value,
        Err(_) if stored > 0 => u32::MAX,
        Err(_) => 0,
    }
}

/// Wall-clock elapsed time: §8.4's `run_wall_timeout`, which *"includes
/// parked time"*.
///
/// Measured to [`RunLedger::ended_at`] when the run has ended, so a completed
/// run's elapsed time is fixed rather than growing with every later `now`.
pub fn wall_elapsed(ledger: &RunLedger, now: Timestamp) -> Duration {
    let end = ledger.ended_at.unwrap_or(now).as_unix_nanos();
    Duration::from_nanos(nonneg(
        end.saturating_sub(ledger.started_at.as_unix_nanos()),
    ))
}

/// §8.4's `run_active_timeout`: wall-clock elapsed time **excluding**
/// `AwaitingHuman`.
///
/// `wall - (completed parks + the park in progress)`, floored at zero. The
/// park in progress is measured from [`RunLedger::parked_at`] to the same
/// endpoint [`wall_elapsed`] uses, so a run that ends while parked does not
/// keep accruing parked time either.
///
/// Floored rather than trusted: `parked_nanos` and `parked_at` are written by
/// [`crate::durability`]'s `transition` and cannot exceed the wall in a
/// consistent row, but a hand-edited row could, and an unsigned subtraction
/// that wrapped would report an enormous *active* time — the direction that
/// refuses work forever.
pub fn active_elapsed(ledger: &RunLedger, now: Timestamp) -> Duration {
    let end = ledger.ended_at.unwrap_or(now).as_unix_nanos();
    let in_progress = ledger
        .parked_at
        .map_or(0, |start| nonneg(end.saturating_sub(start.as_unix_nanos())));
    // `saturating_add` here can never actually saturate, and the margin is
    // exactly one: both operands come through [`nonneg`], so each is at most
    // `i64::MAX`, and `2 * (2^63 - 1) = 2^64 - 2`, one below `u64::MAX`.
    // Measured rather than assumed, because "saturating" reads as though the
    // ceiling were reachable. It is kept as the saturating form anyway: it
    // costs nothing, and the property that makes it unreachable is a property
    // of `nonneg`, one call away, not of this line.
    let parked = ledger.parked_nanos.saturating_add(in_progress);
    Duration::from_nanos(
        nonneg(end.saturating_sub(ledger.started_at.as_unix_nanos())).saturating_sub(parked),
    )
}

/// The run's grant **minus what it has already consumed** — the real
/// `total_remaining` [`crate::exec::map_step::MapBudget`] was built to divide
/// and, until this task, could only be handed
/// [`ResourceCaps::default`] for.
///
/// Every countable is `grant - spent`, floored at zero. The three
/// [`Duration`]s are the reason this takes a `now`:
///
/// - `run_wall_timeout` and `run_active_timeout` are decremented by
///   [`wall_elapsed`] and [`active_elapsed`], which is what
///   [`crate::compose::draw_child_budget`]'s *"keeping the `Duration` fields
///   meaning 'remaining' is the caller's job"* residual was waiting for. A
///   child clamped against a parent's *original* window could outlive it;
///   clamped against what is left, it cannot.
/// - `step_timeout` passes through unchanged. It is a per-step ceiling, not a
///   run-level pool, so there is nothing for a run's elapsed time to subtract
///   from it.
pub fn remaining_caps(
    conn: &Connection,
    run_id: RunId,
    now: Timestamp,
) -> Result<ResourceCaps, LedgerError> {
    let ledger = read_ledger(conn, run_id)?;
    remaining_from_ledger(&ledger, now)
}

fn remaining_from_ledger(ledger: &RunLedger, now: Timestamp) -> Result<ResourceCaps, LedgerError> {
    let caps = ledger.caps.as_ref().ok_or(LedgerError::CapsNotRecorded {
        run_id: ledger.run_id,
    })?;
    let spent = &ledger.spent;
    Ok(ResourceCaps {
        run_wall_timeout: caps
            .run_wall_timeout
            .saturating_sub(wall_elapsed(ledger, now)),
        run_active_timeout: caps
            .run_active_timeout
            .saturating_sub(active_elapsed(ledger, now)),
        step_timeout: caps.step_timeout,
        max_tokens: caps.max_tokens.saturating_sub(spent.tokens),
        // The same `.max(0.0)` normalisation `compose`'s draw and refund both
        // apply on this field, for the same reason: `f64` subtraction of a
        // stored `+inf` spend yields `-inf`, and an un-normalised negative
        // remaining would make every later `min` hand the whole pool back.
        max_cost_usd: (caps.max_cost_usd - spent.cost_usd).max(0.0),
        max_tasks: caps.max_tasks.saturating_sub(spent.tasks),
        max_tool_calls: caps.max_tool_calls.saturating_sub(spent.tool_calls),
        max_subagents: caps.max_subagents.saturating_sub(spent.subagents),
        max_bytes_written: caps.max_bytes_written.saturating_sub(spent.bytes_written),
        max_escalations: caps.max_escalations.saturating_sub(spent.escalations),
    })
}

/// §8.4's *"caps enforced at task admission"* — the one chokepoint every task
/// passes through, as a single transaction that **checks and records
/// together**.
///
/// Returns the run's remaining budget after the spend is recorded, so a
/// caller that wants to know what is left does not have to read it back in a
/// second statement that a concurrent writer could have moved.
///
/// # Why the check and the write are one transaction
///
/// A check in one statement and a `+=` in another is a race with itself: two
/// admissions can both read a budget that covers them and both spend it.
/// `roundhouse_store::begin_immediate` holds SQLite's single write lock
/// across the pair, so the budget the check saw is the budget the `UPDATE`
/// writes over — the same argument [`crate::durability`]'s `transition` makes
/// for reading a run's state before writing it.
///
/// # Which states admit work
///
/// See [`ensure_admitting`], which is the shared predicate this and
/// [`admit_call_from_run`] both apply.
///
/// # The dollar guard the column cannot be
///
/// A non-finite or negative `cost_usd` — in the request, in the **ceiling**,
/// or in the total the two produce — is [`LedgerError::UnusableCostAmount`],
/// not a clamp. Measured: migration 0008's `CHECK (spent_cost_usd >= 0)`
/// rejects a negative, and `NOT NULL` rejects a `NaN` (SQLite stores `NaN` as
/// `NULL`), but **`+inf` passes both and is stored**. A stored `+inf` spend
/// makes every later `remaining_caps` return an empty pool, which is the safe
/// direction — but it is unrecoverable, and refusing the write is better than
/// poisoning the row.
///
/// **The ceiling was the leg this function was missing** (ruling P109 §D):
/// against a `NaN` `max_cost_usd`, `cost_total > caps.max_cost_usd` is
/// `false`, so **every** spend would be admitted — the one direction in this
/// module where a bad `f64` means *yes*.
///
/// Scoped to what is actually reachable, which is narrower than P109 §D says
/// and is measured by
/// `tests/ledger.rs::serde_json_refuses_a_non_finite_dollar_figure_in_both_directions`:
/// `serde_json` treats a non-finite `f64` as unrepresentable **both ways** —
/// it writes `inf`/`NaN` as `null` *and* refuses to parse an out-of-range
/// literal (`1e999` is `number out of range`, not `+inf`, which is the one
/// thing P109 §D asserts about it). So a non-finite ceiling cannot reach this
/// comparison through `caps_json`, and the fail-open case is not live today.
///
/// A **negative** ceiling is a different matter: `-1.0` is finite, valid JSON
/// and round-trips cleanly. Its old behaviour was fail-closed but misnamed —
/// every spend refused as `CapsExceeded { field: "max_cost_usd" }`, which
/// reports a run over budget when the truth is a stored ceiling that is not a
/// dollar amount. That case is why this guard earns its place even with the
/// serialiser's accidental help; the other reason is that the help is
/// accidental, undocumented in `serde_json`'s contract, and one hand-built
/// writer away from being gone.
pub fn admit_spend(
    conn: &mut Connection,
    run_id: RunId,
    requested: &Spend,
    now: Timestamp,
) -> Result<ResourceCaps, LedgerError> {
    admit(conn, run_id, requested, now, Admission::Ordinary)
}

/// [`admit_spend`] for a step of the workflow's `finally:` block — the **one**
/// exemption from the `Cancelling` refusal, ruled in B12c's brief against
/// §8.13.
///
/// §8.13 requires *both* *"refuse new task admission"* **and** *"run
/// `finally:`"* of one cancel, so an exemption is unavoidable and the only
/// question is where it lives. It lives in [`ensure_admitting`], once, which is
/// why this is a second entry point rather than a second predicate: a cancel
/// that skips cleanup is worse than one that does a little work, and two
/// chokepoints disagreeing about run state is the defect ruling P109 §C
/// already had to fix here.
///
/// **A `call:` inside `finally:` is deliberately not exempt.** There is no
/// `admit_call_from_run` twin of this function: a `call:` creates a child run
/// *and* a child Session — an unbounded subtree — and cancel must converge.
/// Cleanup that spawns a workflow is not cleanup.
pub fn admit_spend_during_finally(
    conn: &mut Connection,
    run_id: RunId,
    requested: &Spend,
    now: Timestamp,
) -> Result<ResourceCaps, LedgerError> {
    admit(conn, run_id, requested, now, Admission::FinallyBlock)
}

fn admit(
    conn: &mut Connection,
    run_id: RunId,
    requested: &Spend,
    now: Timestamp,
    admission: Admission,
) -> Result<ResourceCaps, LedgerError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let remaining = admit_spend_within(&txn, run_id, requested, now, admission)?;
    txn.commit()?;
    Ok(remaining)
}

/// Which of §8.13's two conflicting clauses a spend is being admitted under —
/// see [`admit_spend_during_finally`] and [`ensure_admitting`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// A step of `steps:` or `catch:`, or a `call:` anywhere: refused by every
    /// state but `Running`.
    Ordinary,
    /// A step of `finally:`, which §8.13 requires to run during a cancel.
    FinallyBlock,
}

/// [`admit_spend`] without a transaction of its own, so [`draw_child_run`] can
/// charge a parent and stamp the child inside **one** transaction. Takes
/// `&Connection` for the reason `durability`'s `insert_run_row` does:
/// `rusqlite::Transaction` derefs to it.
fn admit_spend_within(
    txn: &Connection,
    run_id: RunId,
    requested: &Spend,
    now: Timestamp,
    admission: Admission,
) -> Result<ResourceCaps, LedgerError> {
    let ledger = read_ledger(txn, run_id)?;
    ensure_admitting(&ledger, admission)?;

    let caps = ledger
        .caps
        .as_ref()
        .ok_or(LedgerError::CapsNotRecorded { run_id })?;

    if !is_usable_cost_usd(requested.cost_usd) {
        return Err(LedgerError::UnusableCostAmount {
            run_id,
            amount: requested.cost_usd,
        });
    }
    if !is_usable_cost_usd(caps.max_cost_usd) {
        return Err(LedgerError::UnusableCostAmount {
            run_id,
            amount: caps.max_cost_usd,
        });
    }

    // The two elapsed-time ceilings are checked here rather than only being
    // reported by `remaining_caps`, because §8.4 lists them among the caps and
    // admission is where a cap is enforced. `>=`, not `>`: at exactly the
    // limit the window has been used up, matching `parking::reaper_cutoff`'s
    // boundary convention rather than introducing a second one a nanosecond
    // apart.
    if wall_elapsed(&ledger, now) >= caps.run_wall_timeout {
        return Err(LedgerError::CapsExceeded {
            run_id,
            field: "run_wall_timeout",
        });
    }
    if active_elapsed(&ledger, now) >= caps.run_active_timeout {
        return Err(LedgerError::CapsExceeded {
            run_id,
            field: "run_active_timeout",
        });
    }

    let cost_total = ledger.spent.cost_usd + requested.cost_usd;
    // `is_usable_cost_usd`, not a bare `is_finite()` (ruling P114 §C): both
    // operands were checked with the shared predicate three lines up, so this
    // sum cannot be negative today — a negative total would need a negative
    // stored `spent_cost_usd`, which migration 0008's column `CHECK` blocks.
    // It uses the shared predicate anyway because the crate's own claim is
    // that there is *one* definition of a usable dollar figure, and a fourth
    // site spelling it differently is how that claim stops being true.
    if !is_usable_cost_usd(cost_total) {
        return Err(LedgerError::UnusableCostAmount {
            run_id,
            amount: cost_total,
        });
    }
    if cost_total > caps.max_cost_usd {
        return Err(LedgerError::CapsExceeded {
            run_id,
            field: "max_cost_usd",
        });
    }

    let tokens = checked_total(
        ledger.spent.tokens,
        requested.tokens,
        caps.max_tokens,
        "max_tokens",
        run_id,
    )?;
    let bytes_written = checked_total(
        ledger.spent.bytes_written,
        requested.bytes_written,
        caps.max_bytes_written,
        "max_bytes_written",
        run_id,
    )?;
    let tasks = checked_total_u32(
        ledger.spent.tasks,
        requested.tasks,
        caps.max_tasks,
        "max_tasks",
        run_id,
    )?;
    let tool_calls = checked_total_u32(
        ledger.spent.tool_calls,
        requested.tool_calls,
        caps.max_tool_calls,
        "max_tool_calls",
        run_id,
    )?;
    let subagents = checked_total_u32(
        ledger.spent.subagents,
        requested.subagents,
        caps.max_subagents,
        "max_subagents",
        run_id,
    )?;
    let escalations = checked_total_u32(
        ledger.spent.escalations,
        requested.escalations,
        caps.max_escalations,
        "max_escalations",
        run_id,
    )?;

    write_spend(
        txn,
        run_id,
        &Spend {
            tokens,
            cost_usd: cost_total,
            tasks,
            tool_calls,
            subagents,
            bytes_written,
            escalations,
        },
    )?;

    // Recomputed from the values just written rather than re-read: the write
    // lock is still held, so a second `SELECT` would return exactly these.
    let after = RunLedger {
        spent: Spend {
            tokens,
            cost_usd: cost_total,
            tasks,
            tool_calls,
            subagents,
            bytes_written,
            escalations,
        },
        ..ledger
    };
    remaining_from_ledger(&after, now)
}

/// The one predicate for *"is this run admitting new work?"*, shared by
/// [`admit_spend`] and [`admit_call_from_run`] so the two chokepoints cannot
/// drift.
///
/// # Which half is quoted and which is inferred
///
/// **Named:** §8.13's cancel is *"cooperative — mark `Cancelling`, **refuse
/// new task admission**, SIGTERM->SIGKILL running shells, run `finally:`"*.
/// That sentence is the whole reason either function looks at run state.
///
/// **Inferred:** that `Paused`, `AwaitingHuman` and the three terminal states
/// also admit nothing. No document says so. Each is the reading that refuses:
/// a paused run is executing no step, a parked run is waiting on a human, and
/// a run that has ended has ended.
///
/// # Why a `call:` is admission too (ruling P109 §C)
///
/// [`admit_call_from_run`] used to consult only `session_depth`, so a `call:`
/// was admissible from a `Cancelling` run — and a `call:` **is** new task
/// admission by §8.12's own description: it creates a child `workflow_run`, a
/// child Session, and an `agent`-kind task in the parent's log. The visible
/// consequence was a cancel that does not converge: an operator marks a
/// misbehaving run `Cancelling` and it keeps spawning children, each starting
/// `Running` and admitting freely.
///
/// # The one exemption, written here because there is one predicate (B12c)
///
/// **Does a `finally:` block's own work run during `Cancelling`?** §8.13
/// requires *both* *"refuse new task admission"* **and** *"run `finally:`"* of
/// the same cancel, so an exemption is unavoidable; B12b concentrated the
/// tension here so that whoever resolved it would write **one** exemption
/// rather than two that must be remembered together. This is it:
/// [`Admission::FinallyBlock`] is admitted from `Cancelling` and from nothing
/// else it would otherwise be refused from.
///
/// - **`Cancelling` only.** A `finally:` block does not resurrect a `Paused`,
///   `AwaitingHuman` or terminal run: those are not the state §8.13's sentence
///   is about, and a run that has ended has ended. The exemption is exactly as
///   wide as the clause that forces it.
/// - **`call:` is never exempt.** [`admit_call_from_run`] passes
///   [`Admission::Ordinary`] unconditionally. A `call:` creates a child run
///   *and* a child Session — an unbounded subtree — and cancel must converge;
///   cleanup that spawns a workflow is not cleanup.
fn ensure_admitting(ledger: &RunLedger, admission: Admission) -> Result<(), LedgerError> {
    let admits = match ledger.state {
        RunState::Running => true,
        RunState::Cancelling => admission == Admission::FinallyBlock,
        RunState::Paused
        | RunState::AwaitingHuman
        | RunState::Completed
        | RunState::Failed
        | RunState::Cancelled => false,
    };
    if !admits {
        return Err(LedgerError::NotAdmitting {
            run_id: ledger.run_id,
            state: ledger.state,
        });
    }
    Ok(())
}

/// `spent + requested`, refused if it would pass `ceiling`. Saturating on the
/// way to the comparison so that a hostile pair cannot wrap into a small
/// total that fits: a saturated `u64::MAX` is refused by any ceiling below
/// it, and a ceiling of `u64::MAX` itself is caught by [`u64_to_sql`] when
/// the total is written.
fn checked_total(
    spent: u64,
    requested: u64,
    ceiling: u64,
    field: &'static str,
    run_id: RunId,
) -> Result<u64, LedgerError> {
    let total = spent.saturating_add(requested);
    if total > ceiling {
        return Err(LedgerError::CapsExceeded { run_id, field });
    }
    Ok(total)
}

/// [`checked_total`] for the four `u32` countables.
fn checked_total_u32(
    spent: u32,
    requested: u32,
    ceiling: u32,
    field: &'static str,
    run_id: RunId,
) -> Result<u32, LedgerError> {
    let total = spent.saturating_add(requested);
    if total > ceiling {
        return Err(LedgerError::CapsExceeded { run_id, field });
    }
    Ok(total)
}

/// Writes the seven accumulators to their absolute totals.
///
/// Absolute rather than `spent_x = spent_x + ?`: the totals were computed
/// from a read taken inside this same transaction, and computing them in Rust
/// is what lets the ceiling comparison and the write use one set of numbers.
/// A SQL-side `+=` would leave the check reasoning about a value the write
/// then recomputed.
fn write_spend(conn: &Connection, run_id: RunId, spend: &Spend) -> Result<(), LedgerError> {
    conn.execute(
        "UPDATE workflow_run
            SET spent_tokens = ?1, spent_cost_usd = ?2, spent_tasks = ?3,
                spent_tool_calls = ?4, spent_subagents = ?5, spent_bytes_written = ?6,
                spent_escalations = ?7
          WHERE id = ?8",
        params![
            u64_to_sql(spend.tokens, "spent_tokens")?,
            spend.cost_usd,
            spend.tasks,
            spend.tool_calls,
            spend.subagents,
            u64_to_sql(spend.bytes_written, "spent_bytes_written")?,
            spend.escalations,
            run_id.to_string(),
        ],
    )?;
    Ok(())
}

/// SQLite has no unsigned integers, so a `u64` counter round-trips through
/// `i64` and a value past `i64::MAX` is refused rather than wrapped — the
/// same rule `durability`'s `seq_to_sql` states, and for the same reason: a
/// wrapped counter would read back as a negative and then saturate to zero,
/// turning an enormous spend into no spend at all.
fn u64_to_sql(value: u64, column: &'static str) -> Result<i64, LedgerError> {
    i64::try_from(value).map_err(|_| LedgerError::ValueOutOfRange { column, value })
}

/// §7.7's two bounds on a `call:`, checked over the **session** tree, as one
/// admission decision against the parent's durable row. Returns the session
/// depth the child run must be created with.
///
/// # Where each number comes from — and why only one of them is a column
///
/// `parent_depth` is read here, from `workflow_run.session_depth`: it is a
/// property of the parent run that does not change, so it is durable, and
/// migration 0008 added the column precisely so this function does not have
/// to walk `parent_run_id` (ruling P76 §1 — those are two independent
/// counters over one session tree, and counting the wrong one grants a
/// sub-agent at session depth 3 four more levels).
///
/// `parent_direct_children` is a **parameter**, and deliberately not a
/// `SELECT COUNT(*) FROM workflow_run WHERE parent_run_id = ?`. That count
/// would be the same mistake one noun over: §7.7's fan-out is *"≤8 direct
/// children **per session**"*, and a parent Session's direct children include
/// its sub-agent spawns, which have no `workflow_run` row at all. A parent
/// session with 8 sub-agents and no child runs would count 0 and admit 8
/// more. The number that is correct is `roundhouse_engine::agent_spawn`'s
/// `parent_direct_children`, which lives in the session tree — and
/// `roundhouse-flow`'s §5.2 row (`core, engine, store`) does not reach
/// `roundhouse-bus`'s roster, so the caller that can see it supplies it. This
/// function's job is to make the depth half durable and to put both checks in
/// one place; it does not pretend to source a number this crate cannot read.
///
/// # Run state is checked first, and §7.7 is not why
///
/// A `call:` is **new task admission** — §8.12 describes it as creating a
/// child `workflow_run`, a child Session and an `agent`-kind task — so §8.13's
/// *"refuse new task admission"* binds here exactly as it binds
/// [`admit_spend`]. The predicate is [`ensure_admitting`], shared with that
/// function rather than restated, because two admission chokepoints in one
/// module disagreeing about whether run state is load-bearing is how a cancel
/// stops converging (ruling P109 §C).
pub fn admit_call_from_run(
    conn: &Connection,
    parent_run_id: RunId,
    parent_direct_children: u32,
) -> Result<u32, LedgerError> {
    let ledger = read_ledger(conn, parent_run_id)?;
    // `Ordinary`, never `FinallyBlock`: a `call:` inside a `finally:` block is
    // not exempt from the cancel refusal — see [`ensure_admitting`].
    ensure_admitting(&ledger, Admission::Ordinary)?;
    let parent_depth = ledger
        .session_depth
        .ok_or(LedgerError::SessionDepthNotRecorded {
            run_id: parent_run_id,
        })?;
    let child_depth = child_call_depth(parent_depth)?;
    admit_child_call(parent_direct_children)?;
    Ok(child_depth)
}

/// §8.12's **draw**: charges `child_run_id`'s parent the child's whole grant
/// and stamps the child `drawn_at`, in one transaction.
///
/// # Why this exists at all — the asymmetry ruling P109 §A found
///
/// The refund half shipped a durable idempotency stamp (`refunded_at`); the
/// draw half shipped **nothing**, and [`Spend::for_grant`] had no caller
/// anywhere in the workspace. So a refund paid out on `caps_json` plus
/// `parent_run_id` alone — two values a row can carry with no draw behind them
/// — and `control::retry_from_step` copies both. Measured before this
/// existed: **one draw of 100 produced two refunds**, and a parent holding 500
/// tokens of unrelated spend recorded 400 afterwards.
///
/// `drawn_at` is what makes the pair symmetric: [`refund_child_run`] now
/// refuses a child whose draw was never recorded, which closes the whole class
/// rather than the one path a fork takes.
///
/// # What it charges, and against whom
///
/// [`Spend::for_grant`] of the child's **recorded** `caps_json` — never a
/// caller-supplied figure — against the parent named by the child's own
/// `parent_run_id`, through the same [`admit_spend`] chokepoint any other
/// spend passes. So a parent with $1 left cannot start two children each
/// promised $1, and a parent that is `Cancelling` cannot be drawn from at all.
///
/// # Where it is called from (B12c)
///
/// **Not from a run loop arm, and deliberately so.** Ruling P114 §A restated
/// P113's fork-shaped obligation as an invariant over the *class*:
///
/// > No `workflow_run` row carrying a `parent_run_id` is committed without a
/// > draw in the same transaction.
///
/// So the call site is [`crate::durability`]'s `insert_run_row` — the one
/// statement that writes a `workflow_run` row at all — through
/// [`draw_child_run_within`], which shares that statement's transaction. Every
/// creator of a parented row therefore draws by construction: the `call:` arm,
/// `control::retry_from_step`'s fork, and any future caller of
/// [`crate::durability::insert_workflow_run`] alike. A fork-only fix would
/// have closed the instance and left the class, which is the mistake P109 §B
/// corrected on the refund side.
///
/// This function remains `pub` as the standalone, after-the-fact draw for a
/// child row that already exists — which, given the invariant above, means a
/// row written before it existed.
pub fn draw_child_run(
    conn: &mut Connection,
    child_run_id: RunId,
    now: Timestamp,
) -> Result<Spend, LedgerError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let draw = draw_child_run_within(&txn, child_run_id, now)?;
    txn.commit()?;
    Ok(draw)
}

/// [`draw_child_run`] without a transaction of its own, so that a child run's
/// `INSERT` and its draw against the parent land in **one** transaction.
///
/// # Why the split had to happen before the call site could exist (ruling P114 §B)
///
/// [`draw_child_run`] opens its own `BEGIN IMMEDIATE`, and so does every
/// creator of a run row. Called in sequence rather than composed, a **refused**
/// draw leaves a committed child row that is `Running` and spends anyway —
/// which defeats the "refused with a distinguishable error" half of ruling
/// P113 and leaves a retry reporting success against an uncharged budget. The
/// shape is the one B12b already applied to
/// [`admit_spend`]/[`admit_spend_within`]; `&Connection` works for both
/// because `rusqlite::Transaction` derefs to it.
pub(crate) fn draw_child_run_within(
    txn: &Connection,
    child_run_id: RunId,
    now: Timestamp,
) -> Result<Spend, LedgerError> {
    let child = read_ledger(txn, child_run_id)?;

    let parent_run_id = child.parent_run_id.ok_or(LedgerError::NotAChildRun {
        run_id: child_run_id,
    })?;
    if let Some(at) = child.drawn_at {
        return Err(LedgerError::AlreadyDrawn {
            run_id: child_run_id,
            at,
        });
    }
    // A run already stamped `refunded_at` is settled: drawing for it would
    // charge the parent a grant `refund_child_run` could then never give back.
    //
    // `durability::fork_run` used to stamp one at creation, which made this
    // refusal fire on every fork and is why the stamp had to come **out**
    // before a fork could draw (ruling P114 §B). Removing it is safe because
    // `drawn_at` replaced what it was defending: with the stamp gone, a fork
    // whose draw was forgotten or refused still has `drawn_at IS NULL`, and
    // `refund_child_run` still refuses it with `DrawNotRecorded`.
    if let Some(at) = child.refunded_at {
        return Err(LedgerError::AlreadySettled {
            run_id: child_run_id,
            at,
        });
    }
    let grant = child.caps.as_ref().ok_or(LedgerError::CapsNotRecorded {
        run_id: child_run_id,
    })?;

    let draw = Spend::for_grant(grant);
    admit_spend_within(txn, parent_run_id, &draw, now, Admission::Ordinary)?;
    txn.execute(
        "UPDATE workflow_run SET drawn_at = ?1 WHERE id = ?2",
        params![now.as_unix_nanos(), child_run_id.to_string()],
    )?;
    Ok(draw)
}

/// §8.12's *"refunded on completion"*, re-derived from durable rows: returns
/// the unspent part of `child_run_id`'s grant to its parent's ledger, and
/// stamps the child so it cannot be refunded twice.
///
/// # What this closes that [`crate::compose::ChildBudget`] could not
///
/// That token has three properties enforced by the type system — consumed by
/// value, constructible only by a draw, neither `Serialize` nor
/// `Deserialize` — and its own doc names two residuals it cannot close, both
/// of which this function closes because it works on rows instead:
///
/// - *"the token names an amount, not a parent"*: `refund_child_budget` takes
///   any `&mut ResourceCaps`, so a refund can be credited to the wrong
///   subtree. Here the parent is **read from the child's own
///   `parent_run_id`** and is not a parameter at all, so there is no wrong
///   parent to pass.
/// - *"a daemon restart loses the in-process grant record"*: the grant is
///   `workflow_run.caps_json` and the spend is the seven accumulators, so the
///   refund is computable from the database alone, at any time, by any
///   process.
///
/// The double-refund property the token got from being non-`Clone` is kept by
/// `refunded_at`: a second call is [`LedgerError::AlreadyRefunded`], not a
/// second credit. That matters more here than there, because a durable
/// refund is exactly the operation a crash-and-retry loop would repeat.
///
/// # Preconditions, each a distinct refusal
///
/// The child must have a parent ([`LedgerError::NotAChildRun`]), must have
/// reached a terminal state ([`LedgerError::ChildNotFinished`] — §8.12 says
/// *on completion*, and returning a live child's grant would let it spend
/// budget its parent has reclaimed), must carry a recorded **draw**
/// ([`LedgerError::DrawNotRecorded`]), must have a recorded grant
/// ([`LedgerError::CapsNotRecorded`]), and must not already be stamped.
///
/// # The draw check comes before the `refunded_at` check, deliberately
///
/// The two guards cover different cases and neither is redundant: `drawn_at`
/// catches every child that was never charged for, `refunded_at` catches the
/// second refund of one that was.
///
/// Until B12c, a fork satisfied **both** refusals: it had no `drawn_at` *and*
/// `durability::fork_run` stamped its `refunded_at` at creation. The stamp is
/// gone (a fork now draws like any other child, ruling P113), so `drawn_at` is
/// the guard that carries that case alone — which is why the order matters and
/// why *"no draw was recorded"* is the better diagnosis of the two: *"already
/// refunded at its own creation instant"* read as though a refund had
/// happened.
pub fn refund_child_run(
    conn: &mut Connection,
    child_run_id: RunId,
    now: Timestamp,
) -> Result<Spend, LedgerError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    let child = read_ledger(&txn, child_run_id)?;

    let parent_run_id = child.parent_run_id.ok_or(LedgerError::NotAChildRun {
        run_id: child_run_id,
    })?;
    if !child.state.is_terminal() {
        return Err(LedgerError::ChildNotFinished {
            run_id: child_run_id,
            state: child.state,
        });
    }
    if child.drawn_at.is_none() {
        return Err(LedgerError::DrawNotRecorded {
            run_id: child_run_id,
        });
    }
    if let Some(at) = child.refunded_at {
        return Err(LedgerError::AlreadyRefunded {
            run_id: child_run_id,
            at,
        });
    }
    let grant = child.caps.as_ref().ok_or(LedgerError::CapsNotRecorded {
        run_id: child_run_id,
    })?;

    // `grant - spent`, floored per field — never `spent` itself and never a
    // caller-supplied figure, so no call site can return more than the draw
    // took out. Exactly `compose::refund_child_budget`'s arithmetic, over
    // columns instead of over a token.
    let unspent = Spend {
        tokens: grant.max_tokens.saturating_sub(child.spent.tokens),
        cost_usd: refundable_dollars(grant.max_cost_usd, child.spent.cost_usd),
        tasks: grant.max_tasks.saturating_sub(child.spent.tasks),
        tool_calls: grant.max_tool_calls.saturating_sub(child.spent.tool_calls),
        subagents: grant.max_subagents.saturating_sub(child.spent.subagents),
        bytes_written: grant
            .max_bytes_written
            .saturating_sub(child.spent.bytes_written),
        escalations: grant
            .max_escalations
            .saturating_sub(child.spent.escalations),
    };

    let parent = read_ledger(&txn, parent_run_id)?;
    // The parent was charged the child's whole grant at the draw
    // (`draw_child_run` -> `Spend::for_grant`), so returning the unspent part
    // is a *decrement* of the parent's spend, not a credit to its caps.
    //
    // Floored at zero, and here is what the floor does and does not do. It
    // stops an accumulator going negative and wrapping into an enormous
    // apparent spend. It does **not** make a refund safe against a child that
    // was never charged for: measured (ruling P110), a parent holding 500
    // tokens of unrelated spend plus a 100-token draw recorded **400** after
    // two refunds of that one draw — real spend erased, with every counter
    // still non-negative throughout. An earlier draft of this comment claimed
    // the floor "cannot mint budget the root never granted"; that was false,
    // and the guard that actually holds the invariant is the
    // `DrawNotRecorded` refusal above, not this `.max`/`saturating_sub`.
    let parent_spend = Spend {
        tokens: parent.spent.tokens.saturating_sub(unspent.tokens),
        cost_usd: (parent.spent.cost_usd - unspent.cost_usd).max(0.0),
        tasks: parent.spent.tasks.saturating_sub(unspent.tasks),
        tool_calls: parent.spent.tool_calls.saturating_sub(unspent.tool_calls),
        subagents: parent.spent.subagents.saturating_sub(unspent.subagents),
        bytes_written: parent
            .spent
            .bytes_written
            .saturating_sub(unspent.bytes_written),
        escalations: parent.spent.escalations.saturating_sub(unspent.escalations),
    };
    write_spend(&txn, parent_run_id, &parent_spend)?;
    txn.execute(
        "UPDATE workflow_run SET refunded_at = ?1 WHERE id = ?2",
        params![now.as_unix_nanos(), child_run_id.to_string()],
    )?;
    txn.commit()?;
    Ok(unspent)
}

/// The unspent part of a dollar grant. An unusable stored spend refunds
/// nothing — the direction that cannot inflate the parent's pool — matching
/// `compose::refund_f64` exactly, including its treatment of a `NaN` spend.
fn refundable_dollars(grant: f64, spent: f64) -> f64 {
    if !is_usable_cost_usd(spent) {
        return 0.0;
    }
    (grant - spent).max(0.0)
}

/// §8.11's reaper query: every parked run whose park began at least
/// [`crate::parking::SYSTEM_WIDE_HOLD_CAP`] ago, *"regardless of what any
/// individual gate specifies"*.
///
/// In the shape of `roundhouse_store::blobs::gc_eligible_blobs` — a pure
/// query with **no periodic caller** (see this module's "What this module is
/// NOT"). Ordered oldest park first, so a caller acting on a prefix of the
/// list acts on the runs that have been held longest.
///
/// # Why the bound is computed in Rust and bound as a parameter
///
/// The comparison is `parked_at <= reaper_cutoff_instant(now)`, and
/// [`crate::parking::reaper_cutoff`] is *the same comparison against the same
/// function*. Restating "seven days" in SQL would be the two-legs-of-one-rule
/// hazard ruling P72 describes, with the legs a nanosecond apart and no test
/// that could tell. Binding the instant as a parameter also lets
/// `workflow_run_parked_idx` serve the query as an index seek
/// (`SEARCH workflow_run USING INDEX workflow_run_parked_idx (parked_at<?)`,
/// per `EXPLAIN QUERY PLAN`) rather than a scan of every run ever recorded.
///
/// # This returns runs whose *hold* has expired, not runs whose wait has
///
/// `parked_at` and `hold_until` are §8.11's two legs
/// ([`crate::parking::resolve_hold_ttl`]): `hold_until` records the intended
/// expiry — already clamped at park time — and this query is the independent
/// backstop that catches a hold whose deadline was never cancelled, or one
/// registered before the cap existed. A run listed here may have an
/// `awaiting_until` still in the future, and deliberately so: §8.11 does not
/// clamp the *wait* to seven days, only the workspace hold.
pub fn parked_runs_past_hold_cap(
    conn: &Connection,
    now: Timestamp,
) -> Result<Vec<RunId>, LedgerError> {
    // `None` means no instant a cap's width before `now` is representable, so
    // no park can have lasted that long — the same answer
    // [`crate::parking::reaper_cutoff`] gives for every `parked_at` at such a
    // `now`, and the reason that function returns an `Option` rather than
    // saturating.
    let Some(cutoff) = reaper_cutoff_instant(now) else {
        return Ok(Vec::new());
    };
    let mut stmt = conn.prepare(
        "SELECT id FROM workflow_run
          WHERE parked_at IS NOT NULL AND parked_at <= ?1
          ORDER BY parked_at ASC, id ASC",
    )?;
    let ids: Vec<String> = stmt
        .query_map(params![cutoff], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    ids.into_iter()
        .map(|text| {
            text.parse().map(RunId::from_uuid).map_err(|_| {
                LedgerError::Durability(DurabilityError::MalformedId {
                    column: "workflow_run.id",
                })
            })
        })
        .collect()
}
