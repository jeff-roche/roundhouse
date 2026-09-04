//! Workflow durability (Subsystem B, Task 16; §8.10) — the `workflow_run` /
//! `workflow_step_run` state machine behind
//! *"**Checkpoint-and-re-drive beats replay whenever control flow is data
//! rather than code**"*.
//!
//! Interpreter state for a declarative graph is small and explicit —
//! completed step ids with outputs, plus attempt counters — so it is
//! checkpointed directly rather than reconstructed by re-execution. Tier 1 of
//! §8.10: *"`workflow_run` + `workflow_step_run` rows; every transition one
//! SQLite transaction through the single writer. Recovery = load and
//! resume."*
//!
//! # Where the tables live (ruling P4)
//!
//! Both tables are `MIGRATION_0007_WORKFLOW_RUN` in
//! `roundhouse-store/src/migrations.rs`, not a per-crate `migrations/*.sql`
//! file — such a file would never reach the daemon's actual database. This
//! module only reads and writes them.
//!
//! # This module never reads a clock
//!
//! Every instant is a [`roundhouse_core::Timestamp`] (unix nanoseconds)
//! supplied by the caller. That keeps the durability layer deterministically
//! testable and preserves the clock-free property the human-in-the-loop layer
//! established one task earlier.
//!
//! # What this task does NOT own
//!
//! The scope line here is deliberate; several obligations that look adjacent
//! belong to named later tasks, and the schema above is shaped so that none of
//! them needs to migrate it:
//!
//! - **Actual parking** — the implicit `checkpoint` task, `hold_workspace`
//!   TTL, the 7-day reaper, and writing [`WorkflowRun::awaiting_until`] —
//!   **Task 17 (B9)**, since landed as [`crate::parking`]. The run loop that
//!   *decides* to park, and the deadline registration/cancellation that
//!   `awaiting_until` feeds, are still **B12c** and daemon work
//!   respectively.
//! - **The run loop itself**: `catch:`/`finally:`/stop-on-failure, calling
//!   task admission, and `map` process spawn / `max_parallel`. Writing
//!   [`StepRunState::Skipped`] and [`WorkflowStepRun::error`] belongs to that
//!   loop too: Task 16 shipped the columns and the types, and produces
//!   neither value. Task 20 has since been split (ruling P77): **Task 20a
//!   landed the state machine ([`transition_is_legal`], [`transition_run`])
//!   and §8.13's cancel/pause/resume/retry-from-step in [`crate::control`];
//!   B12b landed migration 0008 and the run-level ledger
//!   ([`crate::ledger`]), including this module's own park-column writes**;
//!   the run loop itself is **B12c**. `map` worktree spawn is not B12 at all
//!   — §5.2 gives this crate no git and no `tokio`.
//! - **Clearing `output` for steps no fork can still target** — **still
//!   unowned after ruling P77's split; not B12a**. This is the one residual with a security edge, so it is named
//!   rather than assumed: [`checkpoint_step`] deliberately makes `output`
//!   last-write-wins, so checkpointing a step with `output: None` already
//!   writes `output = NULL, output_is_secret_derived = 0` and (with
//!   `PRAGMA secure_delete = ON`, set in `roundhouse-store`'s pool) zeroes
//!   the freed bytes — but only once that clearing write is itself
//!   checkpointed, and only as far as the main database file: an ordinary
//!   `PASSIVE` autocheckpoint backfills the main file but does not truncate
//!   or zero `-wal`, so the pre-clear page image can still be sitting there
//!   in raw bytes (measured; see `roundhouse-store::pool`'s pragma comment
//!   for the full matrix, fix round 2 M-1). **The eraser whoever takes this
//!   therefore owes one more step than the `UPDATE` alone**: after clearing
//!   `output`, it must also issue `PRAGMA wal_checkpoint(TRUNCATE)` (not
//!   rely on the default `PASSIVE` autocheckpoint) to actually reach `-wal`,
//!   or the erasure is real only in the main database file and the prior
//!   bytes remain recoverable from the WAL sidecar. The **mechanism for the
//!   `UPDATE` half exists and is tested; what is missing is a caller** — a
//!   retention policy deciding which completed runs can no longer be
//!   forked, plus the `TRUNCATE` checkpoint named above. Until then,
//!   unredacted step output stays at rest for the life of the row.
//! - **§8.10 tier 3** (agent-step conversation reload) and
//!   `round workflow replay --dry` — unscheduled; recorded as phase
//!   residuals, not silently assumed.
//!
//! # Closed gap: `on_crash:` is a declarable step attribute (B12c)
//!
//! §8.10 tier 2 writes `on_crash: rerun | fail | ask` as a **declared
//! per-step attribute**. Until B12c [`crate::parse::steps::StepDef`] had no
//! such field, and its wire struct is `#[serde(deny_unknown_fields)]`, so a
//! workflow that wrote `on_crash:` got a hard parse error; [`on_crash_policy`]
//! implemented only the **default** half of the contract (§8.10 does specify
//! default `ask`).
//!
//! B12c adds [`crate::parse::steps::StepDef::on_crash`] as an
//! `Option<CrashPolicy>` — the same enum, not a second copy of the vocabulary
//! — and [`crash_policy`] is the reader that prefers a declaration over the
//! derivation. [`CrashPolicy::Fail`], which no derivation can produce, is
//! reachable for the first time.
//!
//! **What still has no owner is the recovery path that acts on it.** A killed
//! daemon writes nothing, so re-driving an interrupted run — reading each
//! step's policy, re-running the `Rerun`s, queueing the `Ask`s as a gate,
//! failing the `Fail`s, and synthesising the report the run loop never got to
//! write (ruling P112 §5) — is daemon-side work over
//! `roundhouse_store::recover_interrupted_tasks`, and ruling P77 §C leaves that
//! owner unassigned. Named here, not built here.

use crate::caps::ResourceCaps;
use crate::exec::{RunId, StepOutcome};
use crate::parse::steps::{StepBody, StepDef};
use roundhouse_core::{BindingId, JobId, SessionId, Timestamp};
use rusqlite::{params, Connection, OptionalExtension};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Why a durability operation failed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum DurabilityError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// A run has no `workflow_run` row: [`recover_run`] was asked to load it,
    /// or [`checkpoint_step`] was asked to write a step of it.
    ///
    /// For [`recover_run`] this is deliberately distinguished from "a run with
    /// no steps checkpointed yet", which is a legitimate state and returns an
    /// empty [`RecoveredRun::steps`].
    #[error("no workflow_run row for run {run_id}")]
    RunNotFound { run_id: RunId },
    /// A stored discriminant is not one this crate recognises. The `CHECK`
    /// constraints in migration 0007 are the insert-time enforcement leg;
    /// this is the read-back leg, so a hand-edited or corrupted row cannot
    /// produce a value that does not exist either way (the same dual-leg
    /// shape `tasks.state` documents in migration 0001).
    #[error("column {column} holds {value:?}, which is not a recognised discriminant")]
    UnrecognizedDiscriminant { column: &'static str, value: String },
    /// A stored id column does not parse as a UUID. The offending text is
    /// deliberately not echoed: it is not needed to locate the row (the query
    /// that produced it names one), and this crate's convention elsewhere is
    /// to name the field rather than reproduce a stored value.
    #[error("column {column} does not hold a valid UUID")]
    MalformedId { column: &'static str },
    /// A stored `output` column is not valid JSON. The text is not echoed for
    /// the same reason as [`Self::MalformedId`] — and here it may additionally
    /// be secret-derived material (see [`StepOutput`]).
    #[error("column output does not hold valid JSON")]
    MalformedStoredOutput,
    /// A stored `caps_json` column does not deserialize as a
    /// [`ResourceCaps`]. The read-back leg of migration 0008's `caps_json`,
    /// which carries no `CHECK` of its own: a `json_valid()` constraint would
    /// bind the schema to SQLite's JSON1 extension being present in every
    /// future build, which is the same class of hazard as ruling P104's
    /// `ADD CONSTRAINT` — works today, fails on a build that differs. The
    /// text is not echoed, for [`Self::MalformedStoredOutput`]'s reason: a
    /// caps block is not secret-derived, but it is stored content and the
    /// query that produced it already names the row.
    #[error("column workflow_run.caps_json does not hold a valid ResourceCaps")]
    MalformedStoredCaps { run_id: RunId },
    /// A stored `session_depth` is outside `u32`. Migration 0008's
    /// `CHECK (session_depth IS NULL OR (session_depth BETWEEN 0 AND
    /// 4294967295))` is the insert-time leg; this is the read-back leg, and
    /// it catches a hand-edited or pre-`CHECK` row. Refused rather than
    /// clamped: a depth silently clamped to `u32::MAX` would be refused by
    /// [`crate::compose::child_call_depth`] anyway, but a depth clamped the
    /// other way would hand a deep run a fresh budget.
    #[error("column workflow_run.session_depth holds {stored}, which is not a u32")]
    SessionDepthOutOfRange { stored: i64 },
    /// A task `seq` (a `u64` in `roundhouse-core`) does not fit SQLite's
    /// signed 64-bit `INTEGER`. Surfaced rather than silently wrapped, since
    /// the value's only purpose is to join back to the log.
    #[error("task seq {seq} does not fit a SQLite INTEGER")]
    SeqOutOfRange { seq: u64 },
    /// The run exists, but §8.13's run state machine does not permit this
    /// move — see [`transition_is_legal`] for the matrix and where each edge
    /// comes from. **Deliberately distinct from [`Self::RunNotFound`]**: "no
    /// such run" and "that run is in the wrong state" are different facts,
    /// and before Task 20a `park` reported the second as the first (its
    /// `UPDATE` could only see a zero row count and had no way to tell them
    /// apart).
    #[error("run {run_id} cannot move from {from:?} to {to:?}")]
    IllegalTransition {
        run_id: RunId,
        from: RunState,
        to: RunState,
    },
    /// The run row exists but is not attached to the session the caller
    /// required. Only [`transition_run_to_awaiting_human`] passes such a
    /// requirement, and only because [`crate::parking::park`] reads
    /// `session_id`, checkpoints *that* session, and must not then write a
    /// row whose session has changed underneath it. Nothing in this
    /// workspace updates `workflow_run.session_id` after insert, so this is
    /// a checked precondition rather than an expected failure.
    #[error("run {run_id} is not attached to the session the caller required")]
    RunSessionMismatch { run_id: RunId },
    /// A stored `item_index` is neither [`TOP_LEVEL_ITEM_INDEX`] nor a `u32`.
    /// The same read-back rule as [`Self::UnrecognizedDiscriminant`], applied
    /// to a numeric column: mapping an out-of-domain value onto `None` would
    /// make it indistinguishable from the sentinel, so two rows with
    /// different states could be recovered under one identity. The value is
    /// echoed because it is a bounded integer, not stored content.
    #[error("column workflow_step_run.item_index holds {stored}, which is neither the top-level sentinel nor a u32")]
    ItemIndexOutOfRange { stored: i64 },
    /// [`insert_run_row`]'s guard (fix round 1, Task 20a): a run inserted with
    /// a terminal [`RunState`] but no `ended_at`, or a non-terminal state with
    /// one already set. [`transition_run`]'s own doc names "a run that looks
    /// live forever" as the failure its writer prevents for an *existing*
    /// row; without this guard, [`insert_workflow_run`] — a different, wider
    /// writer — could produce exactly that row (or its mirror image, a
    /// `Completed` run with `ended_at: None`) on the very first write.
    #[error("run {run_id} has state {state:?} (terminal: {is_terminal}), but ended_at.is_some() is {ended_at_is_some}")]
    TerminalStateEndedAtMismatch {
        run_id: RunId,
        state: RunState,
        is_terminal: bool,
        ended_at_is_some: bool,
    },
    /// [`insert_run_row`] was handed a [`ResourceCaps`] whose `max_cost_usd`
    /// is not [`crate::caps::is_usable_cost_usd`] — the **diagnosis** leg of
    /// ruling P109 §D, refusing the insert that would otherwise store a
    /// `caps_json` nobody can use.
    ///
    /// Diagnosis rather than enforcement: `ledger::admit_spend` refuses such a
    /// ceiling too, and that is the leg that stops a `NaN` ceiling admitting
    /// every spend. This one exists because the alternative is a row that
    /// fails at some later, unrelated read — `serde_json` writes a non-finite
    /// `f64` as `null`, so the caps block round-trips into
    /// [`Self::MalformedStoredCaps`] whenever the row is next loaded, which
    /// names neither the field nor the writer that stored it.
    #[error("run {run_id} was inserted with {amount} as max_cost_usd, which is not usable")]
    UnusableCostAmount { run_id: RunId, amount: f64 },
    /// A run carrying a [`WorkflowRun::parent_run_id`] was refused because its
    /// draw against that parent was refused — so the child row was **not**
    /// created and the whole insert rolled back.
    ///
    /// This is ruling P114 §A's invariant as an error: *no `workflow_run` row
    /// carrying a `parent_run_id` is committed without a draw in the same
    /// transaction.* [`insert_run_row`] draws through
    /// [`crate::ledger::draw_child_run_within`] inside its caller's
    /// transaction, and this variant is what the caller sees when the parent
    /// cannot cover the child's grant, is not `Running`, or has no recorded
    /// caps of its own.
    ///
    /// **Distinguishable on purpose** (ruling P113): *"this retry needs $40 and
    /// the root has $12 — raise the ceiling or accept the failure"* is
    /// actionable, where a silent grant or a silent truncation is a control
    /// that reports success while doing nothing. The refusal's own reason
    /// travels as the `source`, so a caller can tell `CapsExceeded` from
    /// `NotAdmitting` from `CapsNotRecorded` without re-querying.
    ///
    /// `Box`ed because [`crate::ledger::LedgerError`] carries a
    /// `Durability(DurabilityError)` variant of its own, and the two types
    /// would otherwise be infinitely sized.
    #[error("run {run_id} could not draw its grant from its parent run")]
    ChildDrawRefused {
        run_id: RunId,
        #[source]
        source: Box<crate::ledger::LedgerError>,
    },
}

/// §8.10 tier 2's crash-recovery classification of a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepDisposition {
    /// Reads nothing the world can notice. Safe to re-run blindly.
    Pure,
    /// Has effects, but re-running produces the same end state.
    Idempotent,
    /// "shell, write, push, POST" — re-running may duplicate an effect.
    Effectful,
}

/// §8.10 tier 2's mapping from step kind to crash-recovery disposition, as a
/// real function rather than a variant hand-picked wherever a test needed one.
///
/// An explicit `idempotency_key` always wins: the workflow author has
/// asserted the step is safe to re-run under that key, whatever the tool.
/// Absent that:
///
/// - `read`/`find` write nothing — `Pure`.
/// - `http` is `Pure` only when its `method:` is the literal `GET` or `HEAD`
///   (§8.9's own reference workflow uses `GET` for `list_prs`); anything else
///   is `Effectful`. **Anything this function cannot read as one of those two
///   literals falls to `Effectful`**, which is the fail-safe side: a
///   still-uninterpolated `${{ inputs.method }}`, a lowercase `get`, a
///   non-object `with:`, or a missing `method:` all land there. HTTP methods
///   are uppercase tokens, so matching them case-sensitively costs only
///   over-conservatism on an unconventional spelling, whereas case-folding
///   would widen `Pure`.
/// - `shell`/`write`/`edit`/`git` and any other tool are `Effectful`: this
///   crate cannot inspect an arbitrary command for safety.
/// - `gate` is `Idempotent` — re-presenting an unanswered human prompt after a
///   crash is safe, and `hitl::AwaitingHuman` is itself stateless.
/// - `agent`/`call`/`map`/`emit`/`report` are `Effectful`: an agent turn and a
///   sub-workflow can do anything, a `map`'s items may be a mix, an `emit` is
///   a notification send that must not silently repeat, and re-persisting a
///   `report` task would duplicate the run's own record.
pub fn derive_disposition(step: &StepDef) -> StepDisposition {
    if step.idempotency_key.is_some() {
        return StepDisposition::Idempotent;
    }
    match &step.body {
        StepBody::Tool { tool, with } => match tool.as_str() {
            "read" | "find" => StepDisposition::Pure,
            "http" => match with.get("method").and_then(|v| v.as_str()) {
                Some("GET") | Some("HEAD") => StepDisposition::Pure,
                _ => StepDisposition::Effectful,
            },
            _ => StepDisposition::Effectful,
        },
        StepBody::Gate { .. } => StepDisposition::Idempotent,
        StepBody::Agent { .. }
        | StepBody::Call { .. }
        | StepBody::Map { .. }
        | StepBody::Emit { .. }
        | StepBody::Report { .. } => StepDisposition::Effectful,
    }
}

impl StepDisposition {
    fn as_sql_str(self) -> &'static str {
        match self {
            StepDisposition::Pure => "pure",
            StepDisposition::Idempotent => "idempotent",
            StepDisposition::Effectful => "effectful",
        }
    }

    /// The read-back leg of migration 0007's `CHECK` constraint. Deliberately
    /// **not** a lossy `_ => Effectful` catch-all: a value that reaches here
    /// unrecognised means the row does not say what this crate thinks it
    /// says, and quietly substituting a plausible variant is how a corrupted
    /// row becomes a wrong recovery decision.
    fn from_sql_str(s: &str) -> Result<Self, DurabilityError> {
        match s {
            "pure" => Ok(StepDisposition::Pure),
            "idempotent" => Ok(StepDisposition::Idempotent),
            "effectful" => Ok(StepDisposition::Effectful),
            other => Err(DurabilityError::UnrecognizedDiscriminant {
                column: "workflow_step_run.disposition",
                value: other.to_string(),
            }),
        }
    }
}

/// The persisted state of one step attempt.
///
/// As with [`RunState`], the set is deliberately wider than this task's own
/// writes need — see [`Self::Skipped`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepRunState {
    Pending,
    Running,
    Completed,
    /// §8.10 tier 2: an `Effectful` step found `Running` after a crash. It is
    /// *not known* to have completed, and saying so is the point — see
    /// [`recover_run`].
    Indeterminate,
    Failed,
    /// A step whose `when:` guard evaluated false. **Written by B12c**,
    /// which owns the run loop; `exec::StepStatus::Skipped` is
    /// already produced there.
    ///
    /// It is in the enum, and in migration 0007's `CHECK`, now rather than
    /// later for the reason [`RunState`]'s doc gives: a skipped step is
    /// *finished*, so on re-drive the run loop must not re-evaluate its
    /// `when:` (the condition may read differently by then, changing control
    /// flow) and downstream steps interpolate `${{ steps.<id>.status }}`. A
    /// `CHECK` that omitted it would force that task to rebuild the table —
    /// SQLite has no `ALTER TABLE … DROP/MODIFY CONSTRAINT`. Shape now,
    /// behaviour later.
    Skipped,
}

impl StepRunState {
    fn as_sql_str(self) -> &'static str {
        match self {
            StepRunState::Pending => "pending",
            StepRunState::Running => "running",
            StepRunState::Completed => "completed",
            StepRunState::Indeterminate => "indeterminate",
            StepRunState::Failed => "failed",
            StepRunState::Skipped => "skipped",
        }
    }

    /// See [`StepDisposition::from_sql_str`] for why this is fallible rather
    /// than defaulting.
    fn from_sql_str(s: &str) -> Result<Self, DurabilityError> {
        match s {
            "pending" => Ok(StepRunState::Pending),
            "running" => Ok(StepRunState::Running),
            "completed" => Ok(StepRunState::Completed),
            "indeterminate" => Ok(StepRunState::Indeterminate),
            "failed" => Ok(StepRunState::Failed),
            "skipped" => Ok(StepRunState::Skipped),
            other => Err(DurabilityError::UnrecognizedDiscriminant {
                column: "workflow_step_run.state",
                value: other.to_string(),
            }),
        }
    }
}

/// The state of a whole run.
///
/// The set was deliberately wider than Task 16's own writes needed: §8.13's
/// controls (cancel — *"mark `Cancelling`"* — pause, resume) and §8.11's
/// parking were **Task 17/Task 20** work, and a `CHECK` constraint that
/// omitted their states would have forced one of them to migrate the table.
/// Shape then, behaviour now: [`transition_is_legal`] is the state machine
/// over these variants, and [`transition_run`] the only writer of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    /// §8.13's `pause`. Written by [`crate::control::pause`].
    Paused,
    /// §8.13's cooperative `cancel`: new task admission is refused while
    /// running work drains. Written by [`crate::control::cancel`].
    Cancelling,
    /// §8.11's park. Written by [`crate::parking::park`], together with
    /// [`WorkflowRun::awaiting_until`].
    AwaitingHuman,
    Completed,
    Failed,
    Cancelled,
}

impl RunState {
    /// A state a run can never leave: it has no outgoing transition in
    /// [`transition_is_legal`], and reaching it stamps
    /// [`WorkflowRun::ended_at`].
    ///
    /// `Cancelling` is **not** terminal — §8.13 is explicit that cancel is
    /// cooperative (*"mark `Cancelling`"*), so the run is still draining and
    /// has not ended.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            RunState::Completed | RunState::Failed | RunState::Cancelled
        )
    }

    /// Private again as of Task 20a. It was `pub(crate)` because
    /// [`crate::parking`] owned §8.11's park write and had to name the same
    /// discriminant text this module reads back; that write now routes
    /// through [`transition_run_to_awaiting_human`], so this module is once
    /// more the only place a run-state discriminant is spelled.
    fn as_sql_str(self) -> &'static str {
        match self {
            RunState::Running => "running",
            RunState::Paused => "paused",
            RunState::Cancelling => "cancelling",
            RunState::AwaitingHuman => "awaiting_human",
            RunState::Completed => "completed",
            RunState::Failed => "failed",
            RunState::Cancelled => "cancelled",
        }
    }

    /// See [`StepDisposition::from_sql_str`] for why this is fallible rather
    /// than defaulting.
    ///
    /// `pub(crate)` for the read-back direction only (B12b):
    /// [`crate::ledger`] selects its own projection of `workflow_run` and has
    /// to decode the same column. The **write** direction stays private —
    /// `as_sql_str` is still this module's alone, so there is exactly one
    /// place in the crate where a run-state discriminant is *spelled*, which
    /// is the property that comment was defending.
    pub(crate) fn from_sql_str(s: &str) -> Result<Self, DurabilityError> {
        match s {
            "running" => Ok(RunState::Running),
            "paused" => Ok(RunState::Paused),
            "cancelling" => Ok(RunState::Cancelling),
            "awaiting_human" => Ok(RunState::AwaitingHuman),
            "completed" => Ok(RunState::Completed),
            "failed" => Ok(RunState::Failed),
            "cancelled" => Ok(RunState::Cancelled),
            other => Err(DurabilityError::UnrecognizedDiscriminant {
                column: "workflow_run.state",
                value: other.to_string(),
            }),
        }
    }
}

/// §8.13's run state machine, as an explicit matrix: may a run move from
/// `from` to `to`?
///
/// Fourteen of the forty-nine ordered pairs are permitted. This predicate is
/// pure so that the matrix can be reviewed and tested as a table rather than
/// inferred from the writer's control flow; [`transition_run`] is the only
/// thing that consults it against a real row.
///
/// # Where each edge comes from — named by the frozen docs, or inferred
///
/// The distinction matters more than the edges: this crate has already
/// shipped comments that read as quotation while actually being inference.
/// **Quoted text below is verbatim from `docs/architecture/`; everything
/// marked INFERRED is this task's reading, not the document's words.**
///
/// **Named.**
///
/// - `Running -> Cancelling`. §8.13: *"**cancel** (cooperative — mark
///   `Cancelling`, refuse new task admission, SIGTERM->SIGKILL running
///   shells, run `finally:`)"*. The same sentence is why there is **no**
///   `Running -> Cancelled` edge: the document says cancel *marks
///   `Cancelling`*, and the terminal state lands only after the drain.
/// - `AwaitingHuman -> AwaitingHuman`. **pre-specified by `parking.rs`'s own
///   doc** (*"it must be `state IN ('running', 'awaiting_human')`, not
///   `= 'running'`"*) because re-driving a park is idempotent and a test pins
///   it. Both ends of this edge are the same named state, so — unlike the two
///   edges fix round 1 moved out of this section below — there is no
///   ordered-pair inference here at all.
///
/// **Inferred.** (Fix round 1, Task 20a: the following two edges used to sit
/// under **Named** above with no quotation actually behind the *ordered
/// pair* — only one end of each was named, which is the discipline this
/// module's own opening paragraph exists to hold everything else to.)
///
/// - `Running -> AwaitingHuman`. §8.11 names `AwaitingHuman` and names three
///   sources of human waits (a `gate:`, an `Escalate::Park`, a mid-step
///   elicitation), but never names the *source run state* a park moves from.
///   INFERRED: every one of those three sources fires from a step a run is
///   actively executing, which is `Running`.
/// - `AwaitingHuman -> {Running, Failed}` as a **pair**. §8.11 names four
///   wait outcomes verbatim — *"`on_timeout: deny | fail | default(value) |
///   approve`"* — so the *outcomes* are named, but mapping `fail` onto the
///   *run* state `Failed`, and the other three onto `Running`, is this
///   matrix's own reading, not the document's. Which of the four maps to
///   which target is the run loop's (B12c's) call, not this matrix's; the
///   matrix only needs both targets to exist.
/// - `Running <-> Paused`. §8.13 names the controls *"**pause**; **resume**"*
///   and [`RunState::Paused`]'s own doc calls itself *"§8.13's `pause`"*, but
///   no document says pause writes `Paused` or that resume writes `Running`.
///   INFERRED from the control names and the enum's vocabulary.
/// - `Cancelling -> Cancelled`. INFERRED: `cancel` is the only producer of
///   either state and §8.13 describes the drain finishing, but no document
///   spells the final write.
/// - `Running -> {Completed, Failed}`. INFERRED. §8's run outcomes exist
///   throughout (a report has an outcome, §8.10 re-drives to completion) but
///   §8.13 discusses controls, not ordinary completion.
/// - `Paused -> {Cancelling, Failed}` and `AwaitingHuman -> Cancelling`.
///   INFERRED, and the second goes **beyond** the minimum matrix this task's
///   brief listed: §8.13 states its controls unconditionally, and a run
///   waiting on a human who never answers is exactly the run an operator
///   most needs to cancel — §8.11's whole reaper exists because humans do
///   not answer. Refusing it would leave such a run cancellable only by
///   waiting out its deadline.
/// - `Completed`/`Failed`/`Cancelled` are **absorbing** — no outgoing edge
///   at all. INFERRED from §8.13's *"history is append-only, so we never
///   rewrite it"*, which is said about retry-from-step rather than about run
///   states; resurrecting a run that has ended would rewrite its recorded
///   outcome, and retry-from-step's fork is the sanctioned way to continue
///   from one.
///
/// **Deliberately absent, and named so the gap is a decision.**
/// `AwaitingHuman -> Paused` (a parked run is already not executing; pausing
/// it would overwrite the park state and lose `awaiting_until`'s meaning),
/// `Paused -> AwaitingHuman` (a paused run runs no step, so it can reach no
/// gate), `Cancelling -> Completed` (a cancelled run did not complete), and
/// every self-edge except `AwaitingHuman`'s (a control that finds the run
/// already in its target state is telling the caller something, and
/// [`crate::control`] surfaces that rather than reporting a no-op as a fresh
/// action).
pub fn transition_is_legal(from: RunState, to: RunState) -> bool {
    matches!(
        (from, to),
        (RunState::Running, RunState::Paused)
            | (RunState::Running, RunState::Cancelling)
            | (RunState::Running, RunState::AwaitingHuman)
            | (RunState::Running, RunState::Completed)
            | (RunState::Running, RunState::Failed)
            | (RunState::Paused, RunState::Running)
            | (RunState::Paused, RunState::Cancelling)
            | (RunState::Paused, RunState::Failed)
            | (RunState::AwaitingHuman, RunState::AwaitingHuman)
            | (RunState::AwaitingHuman, RunState::Running)
            | (RunState::AwaitingHuman, RunState::Cancelling)
            | (RunState::AwaitingHuman, RunState::Failed)
            | (RunState::Cancelling, RunState::Cancelled)
            | (RunState::Cancelling, RunState::Failed)
    )
}

/// §8.10 tier 2's `on_crash` outcomes — one closed three-word vocabulary,
/// used both as the **derived** default ([`on_crash_policy`]) and as the
/// **declared** per-step attribute ([`crate::parse::steps::StepDef::on_crash`],
/// which deserializes into this type rather than minting a second copy of the
/// same set).
///
/// The wire spellings are §8.10's own words: `rerun`, `fail`, `ask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashPolicy {
    Rerun,
    /// Only a step that *declared* `on_crash: fail` produces this —
    /// [`on_crash_policy`] never returns it, because §8.10 gives no
    /// disposition that defaults to failing. **Reachable since B12c**, which
    /// added the declared attribute; before that the variant existed only so a
    /// two-member enum would not misreport the contract as smaller than it is.
    Fail,
    Ask,
}

/// §8.10 tier 2: `Pure`/`Idempotent` steps are safely re-run; an `Effectful`
/// step defaults to `ask` (landing in the gate queue) rather than guessing.
///
/// This is the **default** half of §8.10's `on_crash: rerun | fail | ask`, and
/// only that half. Call [`crash_policy`] instead unless you specifically want
/// the derivation with any authored override ignored: consulting this function
/// alone on a step that declared `on_crash: rerun` silently discards the
/// declaration.
pub fn on_crash_policy(disposition: StepDisposition) -> CrashPolicy {
    match disposition {
        StepDisposition::Pure | StepDisposition::Idempotent => CrashPolicy::Rerun,
        StepDisposition::Effectful => CrashPolicy::Ask,
    }
}

/// §8.10 tier 2's crash policy for one step: **the author's declaration if
/// there is one, otherwise the derived default.**
///
/// The declaration wins outright, exactly as an explicit `idempotency_key`
/// already wins inside [`derive_disposition`] — §8.10 writes `on_crash:` as a
/// declared attribute, and an override a run loop then second-guessed would
/// not be one. That includes overriding *downwards*: `on_crash: ask` on a
/// `tool: read` step is an author saying this particular read is not as safe
/// to repeat as its kind suggests, and it is honoured.
///
/// This is the function a recovery path should call. [`on_crash_policy`] and
/// [`derive_disposition`] remain `pub` because both are meaningful on their
/// own — the *disposition* is recorded per step row in
/// [`WorkflowStepRun::disposition`] and drives §8.10's `Indeterminate`
/// reclassification, which is a different question from what to do about it.
pub fn crash_policy(step: &StepDef) -> CrashPolicy {
    step.on_crash
        .unwrap_or_else(|| on_crash_policy(derive_disposition(step)))
}

/// A completed step's output together with the executor's own
/// `output_is_secret_derived` verdict.
///
/// # Why the two travel as one value
///
/// `exec::StepOutcome::output_is_secret_derived`'s own doc comment is
/// explicit that this layer must **read** that flag rather than recompute it:
/// *"a re-derivation that disagrees with this one is a leak."* Pairing the
/// value with the flag in a type whose only public constructor is
/// [`StepOutput::from_outcome`] is what makes that structural — for
/// *accidental* mis-pairing, which is the failure this defends against: no
/// caller can hand this type a value and a taint verdict chosen
/// independently. It is **not** a laundering barrier: `exec::StepOutcome` is
/// `pub` with `pub` fields and no `#[non_exhaustive]`, so a determined caller
/// can build one whose flag disagrees with its value (this crate's own tests
/// build outcomes that way) and pass it in. Making that impossible would mean
/// changing `exec`'s public shape, which this task deliberately does not
/// touch.
///
/// # This holds UNREDACTED material, by design
///
/// §8.13's retry-from-step *"forks a new run inheriting completed step
/// outputs"*, and a dependent step reading `${{ steps.<id>.output }}` must
/// see the step's real value — so a redacted stand-in stored here would make
/// resume and fork silently produce different results from the original run.
/// The consequence, stated plainly rather than left implicit: **the
/// `workflow_step_run.output` column can contain secret-derived material at
/// rest**, and every consumer that renders, logs, or ships it onward (the web
/// Runs inbox, [`crate::control::retry_from_step`]'s fork) owes a taint check
/// first.
///
/// That obligation is carried by the accessors rather than by this comment:
/// [`Self::value_for_display`] performs the check and yields `None` when the
/// value is tainted, and [`Self::value_unredacted_for_resume`] is named so
/// that reaching past the check is a visible act rather than the path of
/// least resistance. [`Self`]'s hand-written [`fmt::Debug`] closes the third
/// route, its own `{:?}`.
#[derive(Clone, PartialEq)]
pub struct StepOutput {
    value: serde_json::Value,
    is_secret_derived: bool,
}

impl StepOutput {
    /// The only public constructor: the taint flag comes from the executor's
    /// own [`StepOutcome`], never from a caller's judgement.
    pub fn from_outcome(outcome: &StepOutcome) -> Self {
        StepOutput {
            value: outcome.output.clone(),
            is_secret_derived: outcome.output_is_secret_derived,
        }
    }

    /// The step's real, **unredacted** output, for the two callers that need
    /// the real value and nothing else will do: persisting it here, and
    /// §8.13's fork/resume re-seeding a step context from it.
    ///
    /// Named the way it is on purpose. The neighbouring module already
    /// settled this convention — `exec` pairs `redacted_for_logging()` with
    /// `into_unredacted_for_dispatch()` so the hazardous call cannot be typed
    /// innocently — and a display path that reaches for this one is visibly
    /// reaching for the wrong thing. Anything that renders, logs, or ships an
    /// output onward wants [`Self::value_for_display`] instead.
    pub fn value_unredacted_for_resume(&self) -> &serde_json::Value {
        &self.value
    }

    /// The output when it is safe to show, and `None` when it is not.
    ///
    /// This is the accessor a web handler, an inbox renderer, or a log line
    /// should call: the taint check is *inside* it, so forgetting the check is
    /// not something a caller can do by typing the obvious thing. `None` here
    /// means exactly one thing — there **is** an output and it is
    /// secret-derived, so it is withheld. ("There is no output at all" is
    /// [`WorkflowStepRun::output`] being `None`, one level up.) A renderer
    /// that wants to say *why* it is showing nothing asks
    /// [`Self::is_secret_derived`].
    pub fn value_for_display(&self) -> Option<&serde_json::Value> {
        if self.is_secret_derived {
            None
        } else {
            Some(&self.value)
        }
    }

    /// Whether the output was computed by reading secret-marked material.
    pub fn is_secret_derived(&self) -> bool {
        self.is_secret_derived
    }

    /// The read-back path, private to this module so that
    /// [`Self::from_outcome`] stays the only way an external caller can
    /// produce one.
    fn from_stored(value: serde_json::Value, is_secret_derived: bool) -> Self {
        StepOutput {
            value,
            is_secret_derived,
        }
    }
}

impl fmt::Debug for StepOutput {
    /// Hand-written, not derived — this type is `pub`, `Clone`, and
    /// deliberately holds unredacted secret-derived material, so a derived
    /// `Debug` would put it in any consumer's `tracing::debug!` output. Prints
    /// the value's *shape* only, exactly as `exec::StepOutcome`'s own
    /// hand-written `Debug` does and for the same reason: a sorted key list
    /// for an object, a length for an array, the JSON type name for a scalar —
    /// never a leaf's content. A bare `emit: "${{ secrets.X }}"` resolves to a
    /// `String` leaf with no key to list, which is why scalars print only
    /// their type.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StepOutput")
            .field("value", &ValueShape(&self.value))
            .field("is_secret_derived", &self.is_secret_derived)
            .finish()
    }
}

/// Renders a [`serde_json::Value`]'s shape without printing a leaf's content
/// — see [`StepOutput`]'s `Debug` impl.
///
/// A near-duplicate of `exec`'s private helper of the same name. Kept
/// separate rather than promoting that one, because this task's scope
/// deliberately excludes editing `exec/`; the two are independent
/// eight-line renderers with no shared invariant to drift on beyond "never
/// print a leaf", which each one's own test pins.
struct ValueShape<'a>(&'a serde_json::Value);

impl fmt::Debug for ValueShape<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
                keys.sort_unstable();
                write!(f, "Object {{ keys: {keys:?} }}")
            }
            serde_json::Value::Array(items) => write!(f, "Array {{ len: {} }}", items.len()),
            serde_json::Value::Null => write!(f, "Null"),
            serde_json::Value::Bool(_) => write!(f, "Bool(..)"),
            serde_json::Value::Number(_) => write!(f, "Number(..)"),
            serde_json::Value::String(_) => write!(f, "String(..)"),
        }
    }
}

/// Stored in `workflow_step_run.item_index` for a step that is not a `map`
/// item (i.e. [`WorkflowStepRun::item_index`] is `None`).
///
/// A sentinel rather than `NULL` because `workflow_step_run` is a `STRICT`
/// table, and `STRICT` makes every `PRIMARY KEY` column implicitly `NOT
/// NULL` — so `NULL` is not storable in this column at all, and a "nullable"
/// `item_index` would fail the very first top-level checkpoint with
/// *"NOT NULL constraint failed"*.
///
/// The failure would be **loud**, not silent. (In an ordinary, non-`STRICT`
/// rowid table it would instead be silent duplicate rows, since SQLite does
/// permit `NULL`s in such a `PRIMARY KEY` and compares every `NULL` as
/// distinct. Both halves verified directly against SQLite 3.53.4.) The
/// sentinel is required either way; only the shape of the averted failure
/// differs.
///
/// `-1` is outside `u32`, so it can never collide with a real item index —
/// and migration 0007 bounds the column at `u32::MAX` above so that nothing
/// *else* can land outside `u32` either and become indistinguishable from
/// this sentinel on read-back (see [`item_index_from_sql`]).
pub const TOP_LEVEL_ITEM_INDEX: i64 = -1;

/// One attempt at one step (of one `map` item, where applicable).
///
/// The identity fields are exactly `exec::provenance::Provenance`'s —
/// `(run_id, step_id, attempt, item_index)` — and are exactly migration
/// 0007's primary key. Keeping the three in step is what stops a `map` step's
/// per-item rows from colliding.
#[derive(Clone, PartialEq)]
pub struct WorkflowStepRun {
    pub run_id: RunId,
    pub step_id: String,
    pub attempt: u32,
    /// `None` for a top-level step; `Some(i)` for `map` item `i`. Persisted
    /// as [`TOP_LEVEL_ITEM_INDEX`] when `None`.
    pub item_index: Option<u32>,
    pub disposition: StepDisposition,
    pub state: StepRunState,
    /// §8.10: `first_task_seq`/`last_task_seq` join back to the log. `None`
    /// while the step has emitted no task yet — the honest state for a
    /// `Pending` step, and one a non-nullable column could only fake.
    pub first_task_seq: Option<u64>,
    pub last_task_seq: Option<u64>,
    /// The step's output once it has one — see [`StepOutput`].
    pub output: Option<StepOutput>,
    /// The message from `exec::StepStatus::Failed { message }` or the reason
    /// from `Skipped { reason }`, persisted because it cannot be recomputed
    /// once the process that produced it is gone — the same argument that
    /// puts [`Self::output`] in the row. **B12c**'s `catch:` and the web
    /// Runs inbox are the consumers; **B12c is also the writer**, since
    /// this task owns no run loop and so never produces a `Failed`/`Skipped`
    /// status of its own. `None` for any step that neither failed nor was
    /// skipped.
    ///
    /// Not redacted, and no taint flag: the executor computes none for a
    /// status message — no failure path formats a resolved `secrets.*` value
    /// into one, so a taint flag would have nothing to compute from (see
    /// `exec::StepStatus`'s doc comment). But before fix round 2 (M-2) this
    /// column was a second, uncapped sink for the same text `exec`'s
    /// `MAX_STEPS_CONTEXT_ERROR_LEN` was written to bound at its one funnel
    /// (`steps_context_entry`): [`WorkflowStepRun`] derived `Debug`, so one
    /// `tracing::debug!(?step)` printed `error` at full length, undoing for
    /// the persisted copy exactly what `StepStatus`'s hand-written `Debug`
    /// was written to prevent for the in-memory value it came from.
    ///
    /// Both legs are bounded now, independently of `exec`'s bound (this
    /// task's scope excludes editing `exec/`, same reasoning as
    /// [`ValueShape`]'s doc comment): [`checkpoint_step`] truncates this
    /// field to [`MAX_STORED_STEP_ERROR_LEN`] before writing the column, and
    /// this struct's own hand-written `Debug` impl (below) truncates the
    /// same way when printing. A value built by a future caller and
    /// inspected *before* its first [`checkpoint_step`] call — e.g. a
    /// `WorkflowStepRun` constructed in memory but not yet persisted — is
    /// covered by the `Debug` truncation but still carries whatever length
    /// its constructor gave it as a plain `String`; only the persisted row
    /// and `{:?}` output are bounded, not this field itself.
    pub error: Option<String>,
}

impl fmt::Debug for WorkflowStepRun {
    /// Hand-written (fix round 2, M-2), not derived, so that `error` is
    /// bounded by [`MAX_STORED_STEP_ERROR_LEN`] wherever a `WorkflowStepRun`
    /// is printed — see the field's own doc comment above for what this
    /// closes. Every other field already has a bounded `Debug` of its own
    /// ([`StepOutput`]'s is hand-written for the same reason) or is a plain
    /// scalar, so only `error` needs special handling here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkflowStepRun")
            .field("run_id", &self.run_id)
            .field("step_id", &self.step_id)
            .field("attempt", &self.attempt)
            .field("item_index", &self.item_index)
            .field("disposition", &self.disposition)
            .field("state", &self.state)
            .field("first_task_seq", &self.first_task_seq)
            .field("last_task_seq", &self.last_task_seq)
            .field("output", &self.output)
            .field(
                "error",
                &self.error.as_deref().map(truncate_stored_step_error),
            )
            .finish()
    }
}

/// Independent bound on [`WorkflowStepRun::error`] (fix round 2, M-2) — a
/// second, previously-uncapped sink for the same `StepStatus::Failed
/// { message }` / `Skipped { reason }` text `exec::MAX_STEPS_CONTEXT_ERROR_LEN`
/// bounds at its own funnel, `exec::steps_context_entry`. Deliberately its
/// own constant rather than reusing that one: this task's scope excludes
/// editing `exec/` (that constant and its truncation helper are private to
/// that module), and a near-duplicate here means a future change to one
/// bound does not silently move the other — the same reasoning
/// [`ValueShape`]'s doc comment gives for not promoting that helper either.
/// Same value, chosen for the same reason: comfortably larger than this
/// crate's own diagnostic text, comfortably smaller than the
/// multi-hundred-KB amplification such a bound exists to rule out.
const MAX_STORED_STEP_ERROR_LEN: usize = 512;

/// Truncates `text` to at most [`MAX_STORED_STEP_ERROR_LEN`] bytes (at a
/// valid UTF-8 boundary), appending the original byte length when
/// truncation actually happens. Used both to bound what [`checkpoint_step`]
/// writes into `workflow_step_run.error` and what
/// [`WorkflowStepRun`]'s hand-written `Debug` prints for a value that has
/// not gone through `checkpoint_step` yet — the same helper closes both
/// legs of the M-2 gap.
fn truncate_stored_step_error(text: &str) -> std::borrow::Cow<'_, str> {
    if text.len() <= MAX_STORED_STEP_ERROR_LEN {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut end = MAX_STORED_STEP_ERROR_LEN;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    std::borrow::Cow::Owned(format!("{}... ({} bytes total)", &text[..end], text.len()))
}

/// One workflow run.
///
/// `(job_id, job_version, content_hash)` is the pinned job content: old
/// `JobVersion`s are never removed, so a run always resolves back to exactly
/// what it ran.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowRun {
    pub id: RunId,
    pub job_id: JobId,
    pub job_version: u32,
    pub content_hash: String,
    /// §8.6: each run creates a new Session.
    pub session_id: SessionId,
    /// §8.6: *"a `workflow_run.binding_id` / `trigger_event_id` column on
    /// every run row — this is how 'the previous run of this binding' is
    /// queried"*. `None` for a manually-invoked `round workflow run`, which
    /// has neither a binding nor a trigger firing behind it.
    pub binding_id: Option<BindingId>,
    /// The `trigger_event.id` rowid of the firing that started this run.
    /// `i64`, not a string, because `trigger_event.id` is
    /// `INTEGER PRIMARY KEY AUTOINCREMENT` (store migration 0006).
    pub trigger_event_id: Option<i64>,
    pub state: RunState,
    /// §8.12: set on the child run a `call:` sub-workflow creates. Written by
    /// **B12c**, which owns composition's run loop.
    pub parent_run_id: Option<RunId>,
    /// §8.13: set on the run that retry-from-step forks, linking back to the
    /// run whose completed step outputs it inherits. Written by
    /// [`crate::control::retry_from_step`] through [`fork_run`] (Task 20a).
    pub forked_from_run_id: Option<RunId>,
    /// The **absolute** instant a park expires. **Written by Task 17 (B9)**,
    /// which owns the relative-to-absolute conversion; this task creates the
    /// column and nothing more.
    ///
    /// `hitl::AwaitingHuman` carries a *relative* `timeout_after` and is
    /// deliberately `Serialize` but not `Deserialize`, so that a park record
    /// cannot be stored as that struct and re-derived with a fresh full
    /// window on every resume. The absolute instant lives here instead;
    /// nothing in this crate serializes an `AwaitingHuman`.
    pub awaiting_until: Option<Timestamp>,
    pub started_at: Timestamp,
    pub ended_at: Option<Timestamp>,
    /// How deep this run's **Session** sits in the session tree: the same
    /// number `roundhouse_engine::agent_spawn` takes as its `parent_depth`,
    /// widened to `u32`. Migration 0008's column, read by
    /// [`crate::ledger::admit_call_from_run`].
    ///
    /// **Not a run depth.** It is deliberately not derived by walking
    /// [`Self::parent_run_id`], because those are two independent counters
    /// over one session tree: §8.12's `call:` creates a child *Session*, so a
    /// sub-agent already at session depth 3 that starts a workflow run would
    /// begin its `call:` chain at run-depth 0 and be granted four more —
    /// session depth 7 against §7.7's limit of 4, with `check_depth` and
    /// `child_call_depth` both returning `Ok` at every step (ruling P76 §1).
    ///
    /// `None` means *not recorded* — a row written before migration 0008, or
    /// by a caller that could not determine the depth. It is **not** read as
    /// zero: [`crate::ledger::admit_call_from_run`] refuses such a run rather
    /// than treating it as a root, which is why the column is nullable
    /// instead of `NOT NULL DEFAULT 0`.
    pub session_depth: Option<u32>,
    /// §8.4's run-level ceiling as **granted** when this run was created —
    /// for a child run, exactly what [`crate::compose::draw_child_budget`]
    /// withdrew from its parent. Migration 0008's `caps_json` column.
    ///
    /// Durable rather than in-process because §8.12's refund is
    /// `grant - spent` and both operands must survive a daemon restart:
    /// [`crate::compose::ChildBudget`] is deliberately non-`Deserialize`, so
    /// the in-process token cannot be rehydrated, and its own doc names
    /// re-deriving the refund from durable rows as this task's obligation.
    ///
    /// `None` means *not recorded*, and every ledger reader refuses rather
    /// than substituting [`ResourceCaps::default`] — a default budget handed
    /// to a run nobody granted one is the fail-open direction, and baking a
    /// serialized default into an immutable migration string would have it
    /// drift from `ResourceCaps::default` the moment either changed.
    pub caps: Option<ResourceCaps>,
}

/// What §8.10's *"Recovery = load and resume"* loads: the run row plus every
/// checkpointed step attempt, with §8.10 tier 2's `Indeterminate`
/// reclassification already applied.
#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredRun {
    pub run: WorkflowRun,
    pub steps: Vec<WorkflowStepRun>,
}

/// Inserts a new `workflow_run` row.
///
/// §8.10 tier 1: one SQLite transaction per transition, through
/// `roundhouse_store::begin_immediate` (never a hand-rolled
/// `BEGIN IMMEDIATE`/`COMMIT` pair, which has no rollback on the `?` between
/// them and would strand the write lock).
///
/// **A run carrying a [`WorkflowRun::parent_run_id`] draws its grant from that
/// parent in this same transaction**, and the insert is refused with
/// [`DurabilityError::ChildDrawRefused`] if the draw is — see
/// [`insert_run_row`]'s invariant comment and ruling P114 §A. That applies to
/// every caller of this function, not only to the `call:` arm: this is `pub`,
/// and a caller-supplied `parent_run_id` plus `caps` minted a grant at every
/// site before the invariant existed.
pub fn insert_workflow_run(
    conn: &mut Connection,
    run: &WorkflowRun,
) -> Result<(), DurabilityError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    insert_run_row(&txn, run)?;
    txn.commit()?;
    Ok(())
}

/// The `INSERT` itself, without a transaction of its own, so that
/// [`fork_run`] can write a run row and its inherited step rows inside **one**
/// transaction. Takes `&Connection` because `rusqlite::Transaction` derefs to
/// it, so the same helper serves both call sites.
///
/// **Guards the same invariant [`transition`] enforces for an existing row,
/// at the one other place `workflow_run.state` can be written** (fix round 1,
/// Task 20a): [`insert_workflow_run`] is `pub`, so a caller — nothing in this
/// workspace today, but nothing stops a future one — could insert
/// `state: Completed, ended_at: None`, which is exactly the "run that looks
/// live forever" [`transition_run`]'s doc names as the defect this module
/// exists to prevent, just reached through the other writer instead. A
/// `CHECK` constraint would enforce this at the schema level too, and **B12b
/// deliberately did not add one** although it was the migration slice: a
/// `state <> 'completed' OR ended_at IS NOT NULL` is a *table*-level
/// constraint, and SQLite has no `ALTER TABLE … ADD CONSTRAINT` — the
/// statement is accepted and enforced by today's parser, but it is outside
/// the grammar and survives only as an artefact of how `ADD COLUMN` appends
/// text, so a future parser would reject fresh installs while existing ones
/// kept working (ruling P104). The real schema leg needs the 12-step
/// create-copy-drop-rename rebuild, which is a materially different migration
/// from the `ADD COLUMN`s around it and is **its own task**. Until then this
/// guard and [`transition`]'s are the whole enforcement, which is why they
/// are two guards and not one.
fn insert_run_row(conn: &Connection, run: &WorkflowRun) -> Result<(), DurabilityError> {
    let is_terminal = run.state.is_terminal();
    let ended_at_is_some = run.ended_at.is_some();
    if is_terminal != ended_at_is_some {
        return Err(DurabilityError::TerminalStateEndedAtMismatch {
            run_id: run.id,
            state: run.state,
            is_terminal,
            ended_at_is_some,
        });
    }
    // Migration 0008's ledger accumulators (`parked_nanos`, the seven
    // `spent_*`) are deliberately absent from this statement: their column
    // `DEFAULT 0` is the exact value for a run that has recorded nothing, and
    // leaving them out of the caller-supplied `WorkflowRun` is what stops a
    // caller inserting a run that claims five hours of parked time or a spend
    // it never made. `parked_at`/`hold_until`/`drawn_at`/`refunded_at` are
    // absent for the same reason: they are written only by this crate's own
    // transitions and by `ledger`'s draw and refund.
    // `session_depth` and `caps_json` *are* here, because both are facts only
    // the run's creator knows.
    // Ruling P109 §D's diagnosis leg. Checked *before* serialising, because
    // `serde_json` does not refuse a non-finite `f64` on the way out — it
    // writes `null` — so the failure this replaces was not a serialisation
    // error at all but a `MalformedStoredCaps` at whatever unrelated read next
    // touched the row. (On the way *in* it does refuse: an out-of-range
    // literal is a parse error, measured in `tests/ledger.rs`. That asymmetry
    // is why the enforcement leg in `ledger::admit_spend` is scoped to a
    // negative ceiling rather than a non-finite one.)
    // The predicate is `caps::is_usable_cost_usd`, shared with `parse::steps`
    // and `ledger::admit_spend`, so the crate keeps one definition of "a
    // usable dollar figure".
    let caps_json = run
        .caps
        .as_ref()
        .map(|caps| {
            if !crate::caps::is_usable_cost_usd(caps.max_cost_usd) {
                return Err(DurabilityError::UnusableCostAmount {
                    run_id: run.id,
                    amount: caps.max_cost_usd,
                });
            }
            // Infallible for the reason stated, and now genuinely so: the one
            // value `serde_json` would have mishandled has been refused above.
            Ok(serde_json::to_string(caps).expect(
                "ResourceCaps is a plain struct of finite scalars and Durations, \
                 whose only non-finite-capable field was refused above",
            ))
        })
        .transpose()?;
    conn.execute(
        "INSERT INTO workflow_run
            (id, job_id, job_version, content_hash, session_id, binding_id, trigger_event_id,
             state, parent_run_id, forked_from_run_id, awaiting_until, started_at, ended_at,
             session_depth, caps_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            run.id.to_string(),
            run.job_id.to_string(),
            run.job_version,
            run.content_hash,
            run.session_id.to_string(),
            run.binding_id.map(|b| b.to_string()),
            run.trigger_event_id,
            run.state.as_sql_str(),
            run.parent_run_id.map(|r| r.to_string()),
            run.forked_from_run_id.map(|r| r.to_string()),
            run.awaiting_until.map(|t| t.as_unix_nanos()),
            run.started_at.as_unix_nanos(),
            run.ended_at.map(|t| t.as_unix_nanos()),
            run.session_depth,
            caps_json,
        ],
    )?;
    // Ruling P114 §A's invariant, enforced at the one statement that writes a
    // `workflow_run` row: **no row carrying a `parent_run_id` is committed
    // without a draw in the same transaction.** `conn` is the caller's
    // transaction (`insert_workflow_run`'s or `fork_run`'s), so a refused draw
    // rolls the child row back with it rather than leaving a `Running` child
    // spending against a grant nobody was charged for.
    //
    // Stating it as the invariant rather than as "the fork draws" is what
    // makes it cover `call:` before that path has a production caller — the
    // whole point of P114's correction to P113. Both creators reach it here
    // and neither can opt out.
    //
    // **`run.started_at` is the draw's instant**, not a second parameter: a
    // child's grant is drawn when the child is created, and that value is
    // already in the row. A separate `now` could disagree with it — the same
    // argument `fork_run`'s (now removed) `refunded_at` stamp made for using
    // `fork.started_at`.
    if run.parent_run_id.is_some() {
        crate::ledger::draw_child_run_within(conn, run.id, run.started_at).map_err(|source| {
            DurabilityError::ChildDrawRefused {
                run_id: run.id,
                source: Box::new(source),
            }
        })?;
    }
    Ok(())
}

/// Which **deadline** write a transition carries — §8.11's two, which are
/// two different quantities (see [`crate::parking::park`]'s "The wait's
/// deadline and the workspace hold are two different quantities"): the wait's
/// own `awaiting_until` and the workspace's `hold_until`.
///
/// Private: only [`transition_run_to_awaiting_human`] sets either, and only
/// because a park's deadlines and the run state are one fact that must land
/// in one transaction. `Leave` is not `Set { .. : None }` — the first leaves
/// whatever the row holds **unless the transition is itself leaving
/// `AwaitingHuman`**, in which case [`transition`] clears both (see that
/// function's doc); the second unconditionally writes over them.
///
/// Fix round 1 (Task 20a): before this, `Leave` really did always leave
/// `awaiting_until` untouched, so `AwaitingHuman -> Running`, `-> Cancelling`
/// and `-> Failed` all kept whatever deadline the park had written — the exact
/// inverse of the discipline this same function applies to `ended_at`. A
/// deadline consumer (B12c or the daemon reaper) that selects
/// `awaiting_until <= now` without *also* filtering `state = 'awaiting_human'`
/// would then fire `on_timeout` against a run a human had already answered or
/// an operator had already cancelled. B12b adds `hold_until` under the same
/// rule, and for a sharper version of the same reason: a stale hold instant
/// on a resumed run is a directive to keep a worktree for a run that is using
/// it again.
enum DeadlineWrite {
    Leave,
    Set {
        awaiting_until: Option<Timestamp>,
        hold_until: Option<Timestamp>,
    },
}

/// The park columns as this transaction found them, before the transition's
/// own rules are applied to them. Read in the same `SELECT` as `state`, so
/// the values the rules below compute from are the values the `UPDATE`
/// writes over.
struct StoredParkColumns {
    parked_at: Option<i64>,
    parked_nanos: i64,
    awaiting_until: Option<i64>,
    hold_until: Option<i64>,
}

/// Moves a run to `to`, enforcing [`transition_is_legal`] and stamping
/// [`WorkflowRun::ended_at`] when `to` is terminal. Returns the state the
/// write displaced.
///
/// **This is the only writer of an *existing* row's `workflow_run.state`**
/// (radius: `grep -rn "UPDATE workflow_run" --include=*.rs crates/` finds the
/// two statements in this module's private `transition`, which only this
/// function, [`transition_run_from`] and [`transition_run_to_awaiting_human`]
/// reach, plus this comment; before Task 20a it also found `parking::park`'s
/// own inline `UPDATE`, which now routes through here). Nothing in the tree
/// could move a run to a terminal state at all before it existed, so
/// `ended_at` was never written.
///
/// That radius is narrower than "the only writer of `workflow_run.state`,
/// full stop" — fix round 1 (Task 20a): [`insert_run_row`] also writes the
/// column, by `INSERT`, not `UPDATE`, so the grep above does not find it.
/// [`insert_workflow_run`] (and [`fork_run`]) establish a row's *initial*
/// state; this function and its two callers above are the only writers of a
/// state an existing row already holds. [`insert_run_row`]'s own guard is
/// what keeps that initial write from producing the "run that looks live
/// forever" this comment used to claim only this function prevented — see
/// its doc.
///
/// # Why the read and the write share one transaction
///
/// A single `UPDATE ... WHERE state IN (...)` can report only a row count,
/// which cannot distinguish "no such run" from "wrong state" — the
/// conflation the brief for this task names as a lie, and exactly what
/// `park` used to report. So the current state is read first and the two
/// facts are separated as [`DurabilityError::RunNotFound`] and
/// [`DurabilityError::IllegalTransition`]. Both statements run inside one
/// `roundhouse_store::begin_immediate` transaction, which holds SQLite's
/// single write lock across them, so the state the check saw is the state the
/// `UPDATE` writes over. §8.10 tier 1's *"every transition one SQLite
/// transaction"*, taken literally.
///
/// The `UPDATE`'s own row count is therefore not re-checked: the row was
/// found inside this transaction, no other connection can hold the write lock
/// concurrently, and nothing in this workspace ever deletes a `workflow_run`
/// row (radius: `grep -rn "DELETE FROM workflow_run" --include=*.rs crates/`
/// finds only this comment).
///
/// `now` is written **only** when `to` is terminal; every other target
/// writes `ended_at = NULL`, which is what "the run has not ended" means and
/// which no terminal stamp can be lost to, since terminal states are
/// absorbing.
pub fn transition_run(
    conn: &mut Connection,
    run_id: RunId,
    to: RunState,
    now: Timestamp,
) -> Result<RunState, DurabilityError> {
    transition(conn, run_id, to, now, DeadlineWrite::Leave, None, None)
}

/// [`transition_run`] plus the caller's **own** precondition on the source
/// state, checked in the same transaction.
///
/// The matrix is the system-wide rule; a caller may be narrower. The one
/// caller that is, today, is [`crate::control::resume`]: the matrix admits
/// `AwaitingHuman -> Running` because that is how a gate's answer releases a
/// park, but pressing *resume* on a parked run must not release it. Without
/// this, resume would have to read the state in a separate statement and act
/// on a value that could already be stale.
///
/// A source state outside `permitted_from` is reported as
/// [`DurabilityError::IllegalTransition`], the same as one the matrix
/// rejects — from the row's point of view they are the same refusal, and the
/// error carries the state actually found either way.
pub(crate) fn transition_run_from(
    conn: &mut Connection,
    run_id: RunId,
    permitted_from: &[RunState],
    to: RunState,
    now: Timestamp,
) -> Result<RunState, DurabilityError> {
    transition(
        conn,
        run_id,
        to,
        now,
        DeadlineWrite::Leave,
        None,
        Some(permitted_from),
    )
}

/// §8.11's park, as a transition: `-> AwaitingHuman` together with both
/// absolute deadlines, in one transaction.
///
/// `pub(crate)` because [`crate::parking::park`] is the entry point that owns
/// the relative-to-absolute conversion, the implicit checkpoint, and the
/// workspace directive; this is only the write at the end of it.
///
/// `expect_session_id` is the precondition `park` needs and
/// [`transition_run`] has no use for: `park` reads `session_id`, checkpoints
/// **that** session outside any transaction, and must not then write a row
/// whose session has changed underneath it. Previously this was a bound
/// `AND session_id = ?` in `park`'s own `UPDATE`, whose only signal was a
/// zero row count.
///
/// `hold_until` (B12b) is the durable half of
/// [`crate::parking::WorkspaceDisposition::HoldUntil`], which until migration
/// 0008 was an in-process return value that survived no restart. It travels
/// with `awaiting_until` because a park writes both or neither, and they are
/// deliberately **two different quantities**: only the hold is clamped to
/// [`crate::parking::SYSTEM_WIDE_HOLD_CAP`].
pub(crate) fn transition_run_to_awaiting_human(
    conn: &mut Connection,
    run_id: RunId,
    expect_session_id: SessionId,
    awaiting_until: Option<Timestamp>,
    hold_until: Option<Timestamp>,
    now: Timestamp,
) -> Result<RunState, DurabilityError> {
    transition(
        conn,
        run_id,
        RunState::AwaitingHuman,
        now,
        DeadlineWrite::Set {
            awaiting_until,
            hold_until,
        },
        Some(expect_session_id),
        None,
    )
}

fn transition(
    conn: &mut Connection,
    run_id: RunId,
    to: RunState,
    now: Timestamp,
    deadlines: DeadlineWrite,
    expect_session_id: Option<SessionId>,
    permitted_from: Option<&[RunState]>,
) -> Result<RunState, DurabilityError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    // B12b: the park columns are read in this same statement, inside this
    // same `BEGIN IMMEDIATE`, so the values the rules below compute from are
    // the values the `UPDATE` writes over. That is also why the three
    // statement variants this function used to pick between collapsed into
    // one: with `parked_at`, `parked_nanos` and `hold_until` joining
    // `awaiting_until`, "which columns does this arm mention" stopped being a
    // readable way to express the rules, and a `SET awaiting_until = ?` of the
    // value just read is identical to omitting the column while the write lock
    // is held.
    let row: Option<(String, String, StoredParkColumns)> = txn
        .query_row(
            "SELECT state, session_id, parked_at, parked_nanos, awaiting_until, hold_until
             FROM workflow_run WHERE id = ?1",
            params![run_id.to_string()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    StoredParkColumns {
                        parked_at: row.get(2)?,
                        parked_nanos: row.get(3)?,
                        awaiting_until: row.get(4)?,
                        hold_until: row.get(5)?,
                    },
                ))
            },
        )
        .optional()?;
    let (stored_state, stored_session, stored) =
        row.ok_or(DurabilityError::RunNotFound { run_id })?;
    let from = RunState::from_sql_str(&stored_state)?;

    if let Some(expected) = expect_session_id {
        let stored = SessionId::from_uuid(parse_uuid(&stored_session, "workflow_run.session_id")?);
        if stored != expected {
            return Err(DurabilityError::RunSessionMismatch { run_id });
        }
    }
    let caller_permits = permitted_from.is_none_or(|states| states.contains(&from));
    if !caller_permits || !transition_is_legal(from, to) {
        return Err(DurabilityError::IllegalTransition { run_id, from, to });
    }

    // Written on every transition, not only the terminal ones: the instant
    // for a terminal target and `NULL` otherwise, which makes "`ended_at` is
    // NULL exactly while the run has not ended" a property this writer
    // enforces rather than one it assumes. Nothing is lost by the `NULL`
    // half — terminal states are absorbing, so no transition can follow the
    // one that stamped an instant.
    let ended_at = to.is_terminal().then(|| now.as_unix_nanos());

    let entering_park = to == RunState::AwaitingHuman;
    // Fix round 1 (Task 20a): the same discipline as `ended_at`, applied to
    // `awaiting_until`, and (B12b) to `hold_until` and `parked_at` with it. A
    // `Leave` write is not a no-op write of those columns when `from` is
    // `AwaitingHuman` and `to` is not — that is a run *leaving* the park, and
    // a stale deadline left behind is indistinguishable from a still-parked
    // one to anything that reads the column alone. The
    // `AwaitingHuman -> AwaitingHuman` self-edge is deliberately excluded
    // (`to == AwaitingHuman` short-circuits this): that is a re-park, and it
    // always carries its own `DeadlineWrite::Set`, never `Leave`, so this
    // branch cannot fire for it — but the guard is written on `from`/`to`
    // rather than on which `DeadlineWrite` arm was passed, so it stays
    // correct even if a future caller reaches `Leave` on that self-edge.
    let leaving_park = from == RunState::AwaitingHuman && !entering_park;

    // `parked_at` is the park's *start*, not its deadline, and the re-park
    // self-edge must not move it: §8.11's 7-day cap is enforced "regardless of
    // what any individual gate specifies", so a run that re-drives its own
    // park every hour would otherwise reset the reaper's clock forever and
    // hold a worktree indefinitely with every predicate returning `Ok`. This
    // is the durable sibling of the idempotency `parking.rs` already pins for
    // `awaiting_until`: a re-park moves the *wait's* deadline by exactly the
    // delta the caller's `now` supplies, and moves the park's start not at
    // all.
    let parked_at = if leaving_park {
        None
    } else if entering_park {
        stored.parked_at.or_else(|| Some(now.as_unix_nanos()))
    } else {
        stored.parked_at
    };

    // §8.4's `run_active_timeout` "excludes `AwaitingHuman`", so the closed
    // stretch is banked here, at the one edge where a park ends. A row whose
    // `parked_at` is `NULL` while parked — a run that was already
    // `awaiting_human` when migration 0008 landed — banks nothing, which
    // *under*-counts parked time and therefore *over*-counts active time: the
    // direction that makes a timeout fire sooner, not later.
    let parked_nanos = if leaving_park {
        let stretch = stored
            .parked_at
            .map_or(0, |start| now.as_unix_nanos().saturating_sub(start).max(0));
        stored.parked_nanos.saturating_add(stretch)
    } else {
        stored.parked_nanos
    };

    let (awaiting_until, hold_until) = match deadlines {
        DeadlineWrite::Set {
            awaiting_until,
            hold_until,
        } => (
            awaiting_until.map(|t| t.as_unix_nanos()),
            hold_until.map(|t| t.as_unix_nanos()),
        ),
        DeadlineWrite::Leave if leaving_park => (None, None),
        DeadlineWrite::Leave => (stored.awaiting_until, stored.hold_until),
    };

    txn.execute(
        "UPDATE workflow_run
            SET state = ?1, ended_at = ?2, awaiting_until = ?3, hold_until = ?4,
                parked_at = ?5, parked_nanos = ?6
          WHERE id = ?7",
        params![
            to.as_sql_str(),
            ended_at,
            awaiting_until,
            hold_until,
            parked_at,
            parked_nanos,
            run_id.to_string(),
        ],
    )?;
    txn.commit()?;
    Ok(from)
}

/// §8.13's retry-from-step fork, as one transaction: the new `workflow_run`
/// row plus every step row it inherits.
///
/// *"forks a new run inheriting completed step outputs with a
/// `forked_from_run_id` link — history is append-only, so we never rewrite
/// it"*. Nothing here touches the run being forked; the only writes are
/// inserts of new rows.
///
/// **All of it in one transaction on purpose.** Doing it as
/// [`insert_workflow_run`] followed by N [`checkpoint_step`] calls would
/// leave a half-populated fork behind on any failure between them — a run row
/// in `Running` state missing some of the completed steps it was supposed to
/// inherit, which on re-drive would re-execute effectful work the original
/// had already done.
///
/// Every row in `inherited` is written under `fork.id`; a row's own
/// [`WorkflowStepRun::run_id`] is **not read**, so a caller cannot
/// accidentally file an inherited step under the run it came from.
///
/// `pub(crate)`: [`crate::control::retry_from_step`] is the entry point that
/// decides *which* steps are inheritable, and a fork assembled any other way
/// would bypass that policy.
///
/// **Precondition, not checked here:** `fork.forked_from_run_id` names a run
/// that exists. [`checkpoint_step`]'s existence check has no counterpart in
/// this function because `retry_from_step` establishes the property by
/// construction — it [`recover_run`]s the origin (which errors when the row
/// is absent) before assembling anything — and nothing in this workspace
/// deletes a `workflow_run` row, so the property cannot lapse between the two
/// calls. Re-querying it here would be an unreachable branch.
///
/// # A fork of a child run **draws**, and the `refunded_at` stamp it used to carry is gone
///
/// A fork copies `parent_run_id` **and** `caps` from the run it forks, and its
/// own `spent_*` accumulators start at zero — which made it satisfy every
/// precondition of [`crate::ledger::refund_child_run`]: a parent, a terminal
/// state (in due course), an unstamped `refunded_at`, a recorded grant.
/// Measured before B12b's fix: **one draw of 100 produced two refunds** — one
/// for the original and one for the fork — and a parent holding 500 tokens of
/// unrelated spend recorded 400 afterwards. Not phantom credit but **real
/// spend erased**, and floors at zero do not stop it; they only stop the
/// counter going negative (rulings P109 §A, P110).
///
/// B12b's contained fix was to stamp the fork `refunded_at` at creation, on the
/// grounds that its grant was never drawn here so there is nothing to return.
/// **That stamp is removed**, because the premise stopped being true: ruling
/// P113 rules that a retry *draws from the parent like any other child*, and
/// P114 §B records that the two are not additive —
/// [`crate::ledger::draw_child_run_within`] refuses a stamped run with
/// `AlreadySettled`, so the stamp had to come out before a fork could draw.
///
/// **Removing a guard that currently reads as the fix looks alarming and is
/// not**, and the reason is `drawn_at`: with the stamp gone, a fork whose draw
/// is forgotten or refused still has `drawn_at IS NULL`, and
/// [`crate::ledger::refund_child_run`] still refuses it with
/// `DrawNotRecorded`. The Critical cannot reopen through that route. And the
/// draw is not something this function has to remember to do — it happens
/// inside [`insert_run_row`], in this transaction, for every parented row (see
/// that function's invariant comment), so a refused draw rolls the whole fork
/// back and [`crate::control::retry_from_step`] reports
/// [`DurabilityError::ChildDrawRefused`] rather than a fork that spends
/// against an uncharged budget.
///
/// A fork of a **root** run (no `parent_run_id`, which is every fork in the
/// tree today) draws nothing and is unaffected.
pub(crate) fn fork_run(
    conn: &mut Connection,
    fork: &WorkflowRun,
    inherited: &[WorkflowStepRun],
) -> Result<(), DurabilityError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    insert_run_row(&txn, fork)?;
    for step in inherited {
        write_step_row(&txn, fork.id, step)?;
    }
    txn.commit()?;
    Ok(())
}

/// Writes one step transition (§8.10 tier 1: *"every transition one SQLite
/// transaction"*), inserting the row or updating the existing one for the
/// same `(run_id, step_id, attempt, item_index)`.
///
/// The upsert refreshes every non-key column except `first_task_seq`, which
/// is `COALESCE`d: *first* means first, so once a step's log range has a
/// start, a later checkpoint never moves it.
///
/// **`output` is deliberately last-write-wins, not `COALESCE`d**, so a
/// checkpoint carrying no output *clears* a previously persisted one. Two
/// reasons, both load-bearing:
///
/// 1. `output` and `output_is_secret_derived` are one fact in two columns —
///    that pairing is the whole point of [`StepOutput`]. `COALESCE`ing the
///    value while taking the flag from the incoming row would let a tainted
///    output survive next to a `0` flag, which is the leak this design
///    exists to prevent; keeping them both last-write-wins keeps them
///    honest.
/// 2. This is the only mechanism by which a stored output can ever be
///    erased, and migration 0007 names erasing outputs no fork can still
///    target as a residual that ruling P77's split left unowned. `COALESCE`ing here
///    would delete that mechanism before its caller was written.
///
/// The erasure is pinned by a test rather than left to be rediscovered.
///
/// The taint flag written here is [`StepOutput`]'s, i.e. the executor's own —
/// this function has no way to compute one and deliberately offers none.
///
/// Fails with [`DurabilityError::RunNotFound`] if the step's run has no
/// `workflow_run` row, checked inside the same transaction as the write. This
/// is the application-level leg of the reference migration 0007 documents but
/// cannot enforce: no connection in this workspace sets
/// `PRAGMA foreign_keys = ON`, so a declared `FOREIGN KEY` would be inert.
/// Without the check, a step row for a run that was never inserted would be
/// written happily and then be invisible to [`recover_run`], which errors on
/// the missing run — a row that exists but can never be recovered.
pub fn checkpoint_step(
    conn: &mut Connection,
    step: &WorkflowStepRun,
) -> Result<(), DurabilityError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    if !run_exists(&txn, step.run_id)? {
        return Err(DurabilityError::RunNotFound {
            run_id: step.run_id,
        });
    }
    write_step_row(&txn, step.run_id, step)?;
    txn.commit()?;
    Ok(())
}

fn run_exists(conn: &Connection, run_id: RunId) -> Result<bool, DurabilityError> {
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM workflow_run WHERE id = ?1)",
        params![run_id.to_string()],
        |row| row.get(0),
    )?)
}

/// The upsert itself, without a transaction of its own and with `run_id`
/// supplied separately — see [`insert_run_row`] for why the helpers are split
/// out, and [`fork_run`] for why the run id is a parameter rather than
/// `step.run_id`.
fn write_step_row(
    conn: &Connection,
    run_id: RunId,
    step: &WorkflowStepRun,
) -> Result<(), DurabilityError> {
    // The unredacted accessor, deliberately: this column stores the real
    // value (see `StepOutput`), and a redacted stand-in here would make a
    // resumed or forked run compute different results from the original.
    //
    // The serialization is infallible in practice — a `serde_json::Value` has
    // no non-string map keys and no custom `Serialize` that can fail — so it
    // is `expect`ed rather than given an error variant that could never be
    // constructed.
    let output_json = step.output.as_ref().map(|output| {
        serde_json::to_string(output.value_unredacted_for_resume())
            .expect("a serde_json::Value always serializes")
    });
    let output_is_secret_derived = step
        .output
        .as_ref()
        .is_some_and(StepOutput::is_secret_derived);
    // Fix round 2 (M-2): bound what actually reaches the column, at this
    // funnel — the sole INSERT/UPDATE call site for `workflow_step_run.error`
    // — the same way `exec::steps_context_entry` bounds `steps.<id>.error`
    // at its own sole funnel. Truncating rather than rejecting: the lens's
    // rejected alternative, a length `CHECK` on the column, would turn an
    // oversized diagnostic string into a failed checkpoint, losing the run's
    // durability record over a message rather than the message itself.
    let error_to_store = step.error.as_deref().map(truncate_stored_step_error);

    conn.execute(
        "INSERT INTO workflow_step_run
            (run_id, step_id, attempt, item_index, disposition, state,
             first_task_seq, last_task_seq, output, output_is_secret_derived, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(run_id, step_id, attempt, item_index) DO UPDATE SET
             disposition = excluded.disposition,
             state = excluded.state,
             first_task_seq = COALESCE(workflow_step_run.first_task_seq, excluded.first_task_seq),
             last_task_seq = excluded.last_task_seq,
             output = excluded.output,
             output_is_secret_derived = excluded.output_is_secret_derived,
             error = excluded.error",
        params![
            run_id.to_string(),
            step.step_id,
            step.attempt,
            item_index_to_sql(step.item_index),
            step.disposition.as_sql_str(),
            step.state.as_sql_str(),
            seq_to_sql(step.first_task_seq)?,
            seq_to_sql(step.last_task_seq)?,
            output_json,
            output_is_secret_derived,
            error_to_store.as_deref(),
        ],
    )?;
    Ok(())
}

/// §8.10's *"Recovery = load and resume"*.
///
/// A step found `Running` is **not** assumed to have completed: an
/// `Effectful` one is reclassified [`StepRunState::Indeterminate`] here, at
/// load time, so every caller downstream sees the honest state rather than
/// re-deriving it (and rather than each caller deriving it differently).
/// `Pure`/`Idempotent` steps keep their `Running` state — §8.10 tier 2 sends
/// those straight back through [`on_crash_policy`] to `Rerun`.
///
/// The reclassification is applied to what is **returned**, not written back
/// to the row. Persisting the mark is a transition, and transitions belong to
/// the run loop — **B12c**; doing it inside a read would also make a
/// plain inspection of a run mutate it.
///
/// Two statements (the run row, then its steps), not one snapshot: they are
/// not atomic against a concurrent writer. The run row is read first, so the
/// only way they can disagree is a run that transitions between them, which
/// reads as the older run state alongside fresher steps — the conservative
/// direction, since a resumer then sees more completed work than the run state
/// implies, never less. Crash recovery, this function's actual caller, runs
/// before the run is re-driven at all, so nothing is writing to it then.
pub fn recover_run(conn: &Connection, run_id: RunId) -> Result<RecoveredRun, DurabilityError> {
    let run = workflow_run_row(conn, run_id)?.ok_or(DurabilityError::RunNotFound { run_id })?;

    let mut stmt = conn.prepare(
        "SELECT step_id, attempt, item_index, disposition, state,
                first_task_seq, last_task_seq, output, output_is_secret_derived, error
         FROM workflow_step_run WHERE run_id = ?1
         ORDER BY step_id, attempt, item_index",
    )?;
    let rows = stmt.query_map(params![run_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, Option<i64>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, bool>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;

    let mut steps = Vec::new();
    for row in rows {
        let (
            step_id,
            attempt,
            item_index,
            disposition,
            state,
            first_task_seq,
            last_task_seq,
            output,
            output_is_secret_derived,
            error,
        ) = row?;
        let disposition = StepDisposition::from_sql_str(&disposition)?;
        let mut state = StepRunState::from_sql_str(&state)?;
        if state == StepRunState::Running && disposition == StepDisposition::Effectful {
            state = StepRunState::Indeterminate;
        }
        let output = match output {
            Some(text) => Some(StepOutput::from_stored(
                serde_json::from_str(&text).map_err(|_| DurabilityError::MalformedStoredOutput)?,
                output_is_secret_derived,
            )),
            None => None,
        };
        steps.push(WorkflowStepRun {
            run_id,
            step_id,
            attempt,
            item_index: item_index_from_sql(item_index)?,
            disposition,
            state,
            first_task_seq: first_task_seq.map(seq_from_sql),
            last_task_seq: last_task_seq.map(seq_from_sql),
            output,
            error,
        });
    }
    Ok(RecoveredRun { run, steps })
}

/// §8.6's *"the previous run of this binding"* — the query behind
/// `carry_over: { last_report: true }` and Task 10's fingerprint diffing.
///
/// **`previous` means strictly earlier, not merely "some other run".** The
/// asking run's own `(started_at, id)` is looked up first and used as an
/// upper bound, so a binding's *first* run correctly has no previous run even
/// once later runs exist — a query that only excluded the asking run's id
/// would hand that first run a run from its own future. Excluding by id
/// rather than by `OFFSET 1` also keeps this correct when two runs share a
/// `started_at`.
///
/// **If the asking run has no row yet**, the bound cannot be computed and the
/// most recent run of the binding is returned instead. That is the deliberate
/// answer, not a fallback: `carry_over` seeds a run from the previous run's
/// report, and the daemon needs that seed *while* it is building the new run,
/// before the row exists.
///
/// Ordering ties break on `id`. That is arbitrary but deterministic — two
/// calls agree with each other — and it is not a temporal ordering; do not
/// read it as one.
///
/// Two statements, not one transaction: this is a read, and the pair is not
/// atomic against a concurrent writer. The only way the two disagree is if
/// the asking run's row appears between them, which turns the answer from the
/// wider form into the narrower one — never into a run the caller may not see.
pub fn previous_run_for_binding(
    conn: &Connection,
    binding_id: BindingId,
    exclude_run_id: RunId,
) -> Result<Option<WorkflowRun>, DurabilityError> {
    let asking: Option<(i64, String)> = conn
        .query_row(
            "SELECT started_at, id FROM workflow_run WHERE id = ?1",
            params![exclude_run_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;

    let columns = format!("{WORKFLOW_RUN_SELECT} WHERE binding_id = ?1 AND id != ?2");
    const ORDER: &str = " ORDER BY started_at DESC, id DESC LIMIT 1";

    let row = match asking {
        Some((started_at, id)) => {
            // Row-value comparison: strictly earlier by `started_at`, with
            // `id` as the same deterministic tiebreak the ORDER BY uses.
            let sql = format!("{columns} AND (started_at, id) < (?3, ?4){ORDER}");
            conn.prepare(&sql)?
                .query_row(
                    params![
                        binding_id.to_string(),
                        exclude_run_id.to_string(),
                        started_at,
                        id
                    ],
                    workflow_run_columns,
                )
                .optional()?
        }
        None => {
            let sql = format!("{columns}{ORDER}");
            conn.prepare(&sql)?
                .query_row(
                    params![binding_id.to_string(), exclude_run_id.to_string()],
                    workflow_run_columns,
                )
                .optional()?
        }
    };
    match row {
        Some(columns) => Ok(Some(workflow_run_from_columns(columns)?)),
        None => Ok(None),
    }
}

fn workflow_run_row(
    conn: &Connection,
    run_id: RunId,
) -> Result<Option<WorkflowRun>, DurabilityError> {
    let mut stmt = conn.prepare(&format!("{WORKFLOW_RUN_SELECT} WHERE id = ?1"))?;
    let row = stmt
        .query_row(params![run_id.to_string()], workflow_run_columns)
        .optional()?;
    match row {
        Some(columns) => Ok(Some(workflow_run_from_columns(columns)?)),
        None => Ok(None),
    }
}

/// The most recently started runs, newest first, at most `limit` of them.
///
/// The Runs inbox's outer query ([`crate::runs::load_run_summaries`], Task 34).
/// `pub(crate)`: an unbounded "every run ever" listing is not something to hand
/// out, and the only caller that wants this shape applies its own cap.
///
/// **The cap is the point, not a nicety.** `workflow_run` grows once per run
/// forever, and the caller renders the result into an HTTP response body, so an
/// uncapped `SELECT` is an unbounded response whose cost scales with how long
/// the daemon has been running. Ordering ties break on `id`, deterministically
/// but arbitrarily — the same convention (and the same non-temporal caveat) as
/// [`previous_run_for_binding`].
///
/// A `limit` past `i64::MAX` saturates rather than failing: SQLite takes the
/// bound as a signed 64-bit integer, and no caller can mean anything by a
/// larger number than "all of them".
pub(crate) fn recent_workflow_runs(
    conn: &Connection,
    limit: usize,
) -> Result<Vec<WorkflowRun>, DurabilityError> {
    let mut stmt = conn.prepare(&format!(
        "{WORKFLOW_RUN_SELECT} ORDER BY started_at DESC, id DESC LIMIT ?1"
    ))?;
    let rows = stmt
        .query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            workflow_run_columns,
        )?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter().map(workflow_run_from_columns).collect()
}

/// The `workflow_run` columns every reader in this module selects, in the exact
/// order [`workflow_run_columns`] reads them back out of the row.
///
/// One definition rather than one per query: the tuple positions are what bind
/// the `SELECT` list to [`WorkflowRunColumns`], and a hand-copied list per
/// reader is a chance for one of them to drift into reading `binding_id` out of
/// the `session_id` slot — a mismatch SQLite cannot catch, because both columns
/// are `TEXT`.
const WORKFLOW_RUN_SELECT: &str =
    "SELECT id, job_id, job_version, content_hash, session_id, binding_id, trigger_event_id,
            state, parent_run_id, forked_from_run_id, awaiting_until, started_at, ended_at,
            session_depth, caps_json
     FROM workflow_run";

/// The raw `workflow_run` columns, in query order. Extracted as a tuple
/// inside the `rusqlite` closure (which can only produce `rusqlite::Error`)
/// so the typed conversions below can produce this module's own errors.
type WorkflowRunColumns = (
    String,
    String,
    u32,
    String,
    String,
    Option<String>,
    Option<i64>,
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    i64,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

fn workflow_run_columns(row: &rusqlite::Row) -> rusqlite::Result<WorkflowRunColumns> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
    ))
}

fn workflow_run_from_columns(c: WorkflowRunColumns) -> Result<WorkflowRun, DurabilityError> {
    let (
        id,
        job_id,
        job_version,
        content_hash,
        session_id,
        binding_id,
        trigger_event_id,
        state,
        parent_run_id,
        forked_from_run_id,
        awaiting_until,
        started_at,
        ended_at,
        session_depth,
        caps_json,
    ) = c;
    let run_id = RunId::from_uuid(parse_uuid(&id, "workflow_run.id")?);
    Ok(WorkflowRun {
        id: run_id,
        job_id: JobId::from_uuid(parse_uuid(&job_id, "workflow_run.job_id")?),
        job_version,
        content_hash,
        session_id: SessionId::from_uuid(parse_uuid(&session_id, "workflow_run.session_id")?),
        binding_id: binding_id
            .map(|b| parse_uuid(&b, "workflow_run.binding_id").map(BindingId::from_uuid))
            .transpose()?,
        trigger_event_id,
        state: RunState::from_sql_str(&state)?,
        parent_run_id: parent_run_id
            .map(|r| parse_uuid(&r, "workflow_run.parent_run_id").map(RunId::from_uuid))
            .transpose()?,
        forked_from_run_id: forked_from_run_id
            .map(|r| parse_uuid(&r, "workflow_run.forked_from_run_id").map(RunId::from_uuid))
            .transpose()?,
        awaiting_until: awaiting_until.map(Timestamp::from_unix_nanos),
        started_at: Timestamp::from_unix_nanos(started_at),
        ended_at: ended_at.map(Timestamp::from_unix_nanos),
        session_depth: session_depth.map(session_depth_from_sql).transpose()?,
        caps: caps_json
            .map(|text| {
                serde_json::from_str(&text)
                    .map_err(|_| DurabilityError::MalformedStoredCaps { run_id })
            })
            .transpose()?,
    })
}

/// The read-back leg of migration 0008's `session_depth` `CHECK`, fallible
/// for the reason [`item_index_from_sql`] is: a value outside `u32` means the
/// row does not say what this crate thinks it says, and clamping it would
/// turn a corrupt row into a depth decision rather than an error.
fn session_depth_from_sql(stored: i64) -> Result<u32, DurabilityError> {
    u32::try_from(stored).map_err(|_| DurabilityError::SessionDepthOutOfRange { stored })
}

fn parse_uuid(text: &str, column: &'static str) -> Result<Uuid, DurabilityError> {
    text.parse()
        .map_err(|_| DurabilityError::MalformedId { column })
}

fn item_index_to_sql(item_index: Option<u32>) -> i64 {
    match item_index {
        Some(i) => i64::from(i),
        None => TOP_LEVEL_ITEM_INDEX,
    }
}

/// The inverse of [`item_index_to_sql`], and fallible for the reason
/// [`StepDisposition::from_sql_str`] is: the sentinel and an out-of-domain
/// value are two different facts, and `u32::try_from(..).ok()` would collapse
/// them into the same `None`. That is not merely lossy — it is lossy in the
/// *aliasing* direction, so [`recover_run`] could return two
/// [`WorkflowStepRun`]s with identical identity fields and different states,
/// which is exactly the collision migration 0007's primary key exists to
/// prevent. Migration 0007's
/// `CHECK (item_index BETWEEN -1 AND 4294967295)` is the insert-time leg of
/// the same rule; this is the read-back leg, and it is what catches a
/// hand-edited or pre-`CHECK` row.
fn item_index_from_sql(stored: i64) -> Result<Option<u32>, DurabilityError> {
    if stored == TOP_LEVEL_ITEM_INDEX {
        return Ok(None);
    }
    u32::try_from(stored)
        .map(Some)
        .map_err(|_| DurabilityError::ItemIndexOutOfRange { stored })
}

fn seq_to_sql(seq: Option<u64>) -> Result<Option<i64>, DurabilityError> {
    seq.map(|s| i64::try_from(s).map_err(|_| DurabilityError::SeqOutOfRange { seq: s }))
        .transpose()
}

/// SQLite has no unsigned integers, so a `seq` round-trips through `i64`.
/// [`seq_to_sql`] refuses to write a value that does not fit, so a negative
/// value can only come from outside this crate; it saturates at 0 rather than
/// wrapping to an enormous `u64` that would silently widen the
/// `seq BETWEEN ? AND ?` join §8.10 describes.
fn seq_from_sql(stored: i64) -> u64 {
    u64::try_from(stored).unwrap_or(0)
}

/// Test-only helper: an in-memory SQLite connection with the **real** store
/// migrations applied (ruling P4 — never a per-crate migration file, since
/// that would never reach the daemon's actual database).
///
/// Ruling L7: gated behind `cfg(test)` / the `test-util` feature, so daemon
/// code can never reach for this as if it were the normal way to get a
/// connection — doing so would silently write a run's whole durable state to
/// a private in-memory database that vanishes with the process, which is the
/// exact opposite of what this module exists for. Integration tests under
/// `tests/` activate `test-util` through this crate's own dev-dependency on
/// itself; `cfg(test)` alone covers only in-lib unit tests.
#[cfg(any(test, feature = "test-util"))]
pub fn open_test_db() -> Connection {
    let mut conn = roundhouse_store::open_memory_connection();
    roundhouse_store::migrations()
        .to_latest(&mut conn)
        .expect("apply store migrations, including workflow_run/workflow_step_run");
    conn
}
