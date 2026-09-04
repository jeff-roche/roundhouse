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
//!   **Task 17 (B9)**.
//! - **The run loop itself**: `catch:`/stop-on-failure, task admission, `map`
//!   process spawn / `max_parallel`, the run-level budget ledger, and
//!   cancel/pause/resume/retry-from-step — **Task 20 (B12)**. Writing
//!   [`StepRunState::Skipped`] and [`WorkflowStepRun::error`] belongs to that
//!   loop too: this task has the columns and the types, and produces neither
//!   value.
//! - **Clearing `output` for steps no fork can still target** — **Task 20
//!   (B12)**. This is the one residual with a security edge, so it is named
//!   rather than assumed: [`checkpoint_step`] deliberately makes `output`
//!   last-write-wins, so checkpointing a step with `output: None` already
//!   writes `output = NULL, output_is_secret_derived = 0` and (with
//!   `PRAGMA secure_delete = ON`, set in `roundhouse-store`'s pool) zeroes
//!   the freed bytes. The **mechanism exists and is tested; what is missing
//!   is a caller** — a retention policy deciding which completed runs can no
//!   longer be forked. Until then, unredacted step output stays at rest for
//!   the life of the row.
//! - **§8.10 tier 3** (agent-step conversation reload) and
//!   `round workflow replay --dry` — unscheduled; recorded as phase
//!   residuals, not silently assumed.
//!
//! # Named gap: `on_crash:` is not a declarable step attribute
//!
//! §8.10 tier 2 writes `on_crash: rerun | fail | ask` as a **declared
//! per-step attribute**. [`crate::parse::steps::StepDef`] has no such field,
//! and its wire struct is `#[serde(deny_unknown_fields)]`, so a workflow that
//! writes `on_crash:` today gets a hard parse error. [`on_crash_policy`]
//! below implements the **default** half of that contract (§8.10 does specify
//! default `ask`); the author-declared override is **not implemented**, and
//! is recorded as a residual owned by **Task 20 (B12)**, which owns
//! retry-from-step and is the first task with a run loop that would act on
//! it. Adding the field means touching `parse/steps.rs`'s wire shape, which
//! this task deliberately does not do.

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
    /// A task `seq` (a `u64` in `roundhouse-core`) does not fit SQLite's
    /// signed 64-bit `INTEGER`. Surfaced rather than silently wrapped, since
    /// the value's only purpose is to join back to the log.
    #[error("task seq {seq} does not fit a SQLite INTEGER")]
    SeqOutOfRange { seq: u64 },
    /// A stored `item_index` is neither [`TOP_LEVEL_ITEM_INDEX`] nor a `u32`.
    /// The same read-back rule as [`Self::UnrecognizedDiscriminant`], applied
    /// to a numeric column: mapping an out-of-domain value onto `None` would
    /// make it indistinguishable from the sentinel, so two rows with
    /// different states could be recovered under one identity. The value is
    /// echoed because it is a bounded integer, not stored content.
    #[error("column workflow_step_run.item_index holds {stored}, which is neither the top-level sentinel nor a u32")]
    ItemIndexOutOfRange { stored: i64 },
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
    /// A step whose `when:` guard evaluated false. **Written by Task 20
    /// (B12)**, which owns the run loop; `exec::StepStatus::Skipped` is
    /// already produced there.
    ///
    /// It is in the enum, and in migration 0007's `CHECK`, now rather than
    /// later for the reason [`RunState`]'s doc gives: a skipped step is
    /// *finished*, so on re-drive the run loop must not re-evaluate its
    /// `when:` (the condition may read differently by then, changing control
    /// flow) and downstream steps interpolate `${{ steps.<id>.status }}`. A
    /// `CHECK` that omitted it would force Task 20 to rebuild the table —
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
/// The set is deliberately wider than this task's own writes need: §8.13's
/// controls (cancel — *"mark `Cancelling`"* — pause, resume) and §8.11's
/// parking are **Task 17/Task 20** work, and a `CHECK` constraint that
/// omitted their states would force one of them to migrate the table. Shape
/// now, behaviour later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running,
    /// §8.13's `pause`. Written by Task 20 (B12).
    Paused,
    /// §8.13's cooperative `cancel`: new task admission is refused while
    /// running work drains. Written by Task 20 (B12).
    Cancelling,
    /// §8.11's park. Written by Task 17 (B9), together with
    /// [`WorkflowRun::awaiting_until`].
    AwaitingHuman,
    Completed,
    Failed,
    Cancelled,
}

impl RunState {
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
    fn from_sql_str(s: &str) -> Result<Self, DurabilityError> {
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

/// §8.10 tier 2's `on_crash` outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashPolicy {
    Rerun,
    /// Only a step that *declared* `on_crash: fail` produces this, and no
    /// step can declare anything today — see this module's "Named gap"
    /// section. [`on_crash_policy`] therefore never returns it; the variant
    /// exists because §8.10 tier 2's vocabulary has three members, and a
    /// two-member enum would misreport the contract as smaller than it is.
    Fail,
    Ask,
}

/// §8.10 tier 2: `Pure`/`Idempotent` steps are safely re-run; an `Effectful`
/// step defaults to `ask` (landing in the gate queue) rather than guessing.
///
/// This is the **default** half of §8.10's `on_crash: rerun | fail | ask`.
/// The author-declared per-step override does not exist — see this module's
/// "Named gap" section, which records it as a residual rather than pretending
/// derivation is declaration. [`CrashPolicy::Fail`] is consequently
/// unreachable from this function today; it is part of the contract's
/// vocabulary and the declared override is what would produce it.
pub fn on_crash_policy(disposition: StepDisposition) -> CrashPolicy {
    match disposition {
        StepDisposition::Pure | StepDisposition::Idempotent => CrashPolicy::Rerun,
        StepDisposition::Effectful => CrashPolicy::Ask,
    }
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
/// Runs inbox, Task 20's fork) owes a taint check first.
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
#[derive(Debug, Clone, PartialEq)]
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
    /// puts [`Self::output`] in the row. Task 20 (B12)'s `catch:` and the web
    /// Runs inbox are the consumers; **Task 20 is also the writer**, since
    /// this task owns no run loop and so never produces a `Failed`/`Skipped`
    /// status of its own. `None` for any step that neither failed nor was
    /// skipped.
    ///
    /// Not redacted, and no taint flag: the executor computes none for a
    /// status message. `exec::StepStatus`'s hand-written `Debug` bounds what
    /// a `{:?}` of such a message *prints*, which is not the same as bounding
    /// what is stored here — this column holds the message in full. Treat it
    /// with the same care as [`Self::output`].
    pub error: Option<String>,
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
    /// **Task 20 (B12)**, which owns composition's run loop.
    pub parent_run_id: Option<RunId>,
    /// §8.13: set on the run that retry-from-step forks, linking back to the
    /// run whose completed step outputs it inherits. Written by **Task 20
    /// (B12)**.
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
pub fn insert_workflow_run(
    conn: &mut Connection,
    run: &WorkflowRun,
) -> Result<(), DurabilityError> {
    let txn = roundhouse_store::begin_immediate(conn)?;
    txn.execute(
        "INSERT INTO workflow_run
            (id, job_id, job_version, content_hash, session_id, binding_id, trigger_event_id,
             state, parent_run_id, forked_from_run_id, awaiting_until, started_at, ended_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
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
        ],
    )?;
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
///    target as a residual owned by **Task 20 (B12)**. `COALESCE`ing here
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

    let txn = roundhouse_store::begin_immediate(conn)?;
    let run_exists: bool = txn.query_row(
        "SELECT EXISTS (SELECT 1 FROM workflow_run WHERE id = ?1)",
        params![step.run_id.to_string()],
        |row| row.get(0),
    )?;
    if !run_exists {
        return Err(DurabilityError::RunNotFound {
            run_id: step.run_id,
        });
    }
    txn.execute(
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
            step.run_id.to_string(),
            step.step_id,
            step.attempt,
            item_index_to_sql(step.item_index),
            step.disposition.as_sql_str(),
            step.state.as_sql_str(),
            seq_to_sql(step.first_task_seq)?,
            seq_to_sql(step.last_task_seq)?,
            output_json,
            output_is_secret_derived,
            step.error,
        ],
    )?;
    txn.commit()?;
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
/// the run loop — **Task 20 (B12)**; doing it inside a read would also make a
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

    const COLUMNS: &str =
        "SELECT id, job_id, job_version, content_hash, session_id, binding_id, trigger_event_id,
                state, parent_run_id, forked_from_run_id, awaiting_until, started_at, ended_at
         FROM workflow_run
         WHERE binding_id = ?1 AND id != ?2";
    const ORDER: &str = " ORDER BY started_at DESC, id DESC LIMIT 1";

    let row = match asking {
        Some((started_at, id)) => {
            // Row-value comparison: strictly earlier by `started_at`, with
            // `id` as the same deterministic tiebreak the ORDER BY uses.
            let sql = format!("{COLUMNS} AND (started_at, id) < (?3, ?4){ORDER}");
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
            let sql = format!("{COLUMNS}{ORDER}");
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
    let mut stmt = conn.prepare(
        "SELECT id, job_id, job_version, content_hash, session_id, binding_id, trigger_event_id,
                state, parent_run_id, forked_from_run_id, awaiting_until, started_at, ended_at
         FROM workflow_run WHERE id = ?1",
    )?;
    let row = stmt
        .query_row(params![run_id.to_string()], workflow_run_columns)
        .optional()?;
    match row {
        Some(columns) => Ok(Some(workflow_run_from_columns(columns)?)),
        None => Ok(None),
    }
}

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
    ) = c;
    Ok(WorkflowRun {
        id: RunId::from_uuid(parse_uuid(&id, "workflow_run.id")?),
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
    })
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
