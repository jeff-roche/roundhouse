//! **The run loop** (Subsystem B, B12c — ruling P77's third slice of Task
//! 20): the thing that drives a parsed [`WorkflowDef`] from a `Running`
//! `workflow_run` row to a terminal one, checkpointing every step, admitting
//! every step against §8.4's caps, parking on a `gate:`, creating a child run
//! on a `call:`, running `catch:` and `finally:`, and — ruling P112 — leaving
//! **exactly one** `TaskKind::Report` task behind whichever way the run ends.
//!
//! B12a landed the durable state writer, B12b the schema and the ledger. Every
//! function this module calls was built by one of them and left without a
//! caller on purpose; this is where they acquire one.
//!
//! # Where the sequencing lives, and why it is not [`Executor::run_to_completion`]
//!
//! [`Executor::run_to_completion`] is the **in-memory** sequencer: it runs a
//! step graph against an [`ExprContext`](crate::expr::ExprContext) and a
//! [`TaskSink`] with no `workflow_run` row anywhere. It stays, because it is
//! what this crate's own tests and `examples/measure_dual_render.rs` exercise
//! and because a pure sequencer is a useful thing to be able to run. What it
//! cannot do is anything durable, which is everything below.
//!
//! [`run_workflow`] does not wrap it — it re-implements the same three lines of
//! per-step sequencing (bind `steps`, evaluate `when:`, dispatch) around a
//! great deal more, and shares the two decisions that must not diverge through
//! the same helpers `run_to_completion` uses:
//! [`evaluate_when_gate`] and [`steps_context_entry`]. That is the same
//! reasoning `evaluate_when_gate` itself records for why `map`'s inner loop
//! shares it rather than owning a second copy.
//!
//! # What this module does NOT own, and why each is structural
//!
//! - **Driving a child run.** The `call:` arm creates the child
//!   `workflow_run` (drawing its grant, §8.12) and emits the parent's
//!   `agent`-kind task standing for the call. The daemon's delivery driver
//!   recursively executes the child and resumes the parent with its report.
//!   Two independent reasons keep that I/O out of this crate: resolving
//!   `call: <name>` to a definition needs a jobs table that does not exist in
//!   the schema (`control::retry_from_step`'s own doc records the radius), and
//!   [`TaskSink::emit`] carries no `SessionId`, so this crate cannot write
//!   into a second session's log at all — a child run has its own Session
//!   (§8.6), and emitting its tasks through the parent's sink would file them
//!   under the parent. The daemon drives the child by calling [`run_workflow`]
//!   on it, exactly as it drives the parent.
//!
//!   **§8.12's refund needs no such driver, and is wired here.** A run that
//!   *is* a child refunds its own unspent grant to its parent at its own
//!   terminal transition — which is what *"refunded on completion"* says, from
//!   inside the run whose completion it is. So the durable transfer is closed
//!   end to end (`insert_workflow_run` draws, [`run_workflow`] refunds)
//!   without anything recursing.
//! - **A `map` inner step's real process spawn, and `max_parallel`.** §5.2
//!   gives this crate no `tokio`, so `tool`/`agent` step bodies still only
//!   emit a `TaskCreated` and defer the real dispatch, inside a `map` exactly
//!   as at the top level (see [`Executor::dispatch_step`]'s own doc comment
//!   on those arms). `max_parallel` is accepted and threaded through unread
//!   — see [`crate::exec::map_step::run_map`]'s own doc comment. (Task 34 closed the
//!   *other* half this bullet used to name here: `map`'s worktree fan-out is
//!   real now, via the `flow -> sandbox` edge §5.2's `roundhouse-flow` row
//!   gained in Task 14 — see `Executor::dispatch_map_step`'s own
//!   doc comment, "Task 34".) Ruling P77 §C calls the remaining gap a
//!   frozen-contract escalation rather than a scoping choice, and it is
//!   still why a `gate:` or `call:` nested inside a `map` is refused — see
//!   [`Executor::dispatch_step`]'s own arm for both reasons.
//! - **The crash half of report mandatoriness.** A killed daemon writes
//!   nothing, so the report for a run that died mid-step is the **recovery
//!   path's** to synthesise on restart (ruling P112 §5), over
//!   `roundhouse_store::recover_interrupted_tasks` and each step's
//!   [`crash_policy`](crate::durability::crash_policy). Named here; the
//!   daemon-side periodic owner is unassigned (P77 §C).
//! - **Retry.** [`crate::retry`] is built and every step row this module
//!   writes carries `attempt: 1`. Wiring backoff around a failed step is a
//!   loop of its own inside this one, and it is not in B12c's brief; the
//!   column is honest about what happened rather than claiming an attempt
//!   count nothing produced.
//! - **`rerun`.** §8.13's fifth control, recorded unowned by
//!   [`crate::control`]'s module doc: a *new* run of the same pinned
//!   `(job_id, job_version, content_hash)`. Starting one is a caller's
//!   `insert_workflow_run` plus a [`run_workflow`] call, so it is now
//!   expressible; nothing here names it.

use std::collections::HashMap;

use roundhouse_core::{
    EventPayload, JobId, Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput, Timestamp,
    Usage,
};
use rusqlite::Connection;
use serde_json::Value;
use thiserror::Error;

use super::map_step::MapBudget;
use super::{
    evaluate_when_gate, redact_with_needles, steps_context_entry, truncate_diagnostic, Executor,
    GateDecision, ReportEmission, RunId, StepOutcome, StepStatus, TaskSink,
};
use crate::caps::ResourceCaps;
use crate::compose::draw_child_budget;
use crate::durability::{
    checkpoint_step, crash_policy, derive_disposition, recover_run, transition_run, ChildCallJoin,
    CrashPolicy, DurabilityError, RunState, StepDisposition, StepOutput, StepRunState,
    WorkflowChildCall, WorkflowRun, WorkflowStepRun,
};
use crate::hitl::{AwaitingHuman, CrashResolution, HitlError};
use crate::ledger::{
    admit_spend, admit_spend_during_finally, refund_child_run, remaining_caps, run_ledger,
    LedgerError, Spend,
};
use crate::parking::{
    park, CheckpointError, Checkpointer, ParkError, ParkResult, DEFAULT_HOLD_TTL,
};
use crate::parse::steps::{parse_step, topological_order, StepBody, StepDef};
use crate::parse::{ParseError, WorkflowDef};
use crate::report::{build_carry_over_seed, validate_report};

/// What a `call:` step's target resolves to: the child run's pinned job
/// identity, plus the Session the host has **already created** for it.
///
/// The Session is the host's because §8.6 gives every run one and this crate
/// cannot create one; having it come back from the same call that resolves the
/// workflow is what keeps the ordering honest, since the `workflow_run` row
/// references a `session_id` that must already exist.
#[derive(Debug, Clone, PartialEq)]
pub struct CalledWorkflow {
    pub job_id: JobId,
    pub job_version: u32,
    /// The pinned content hash of the called job version — §8.10's
    /// *"a run always resolves back to exactly what it ran"*.
    pub content_hash: String,
    pub session_id: SessionId,
}

/// Why a production workflow host could not resolve or inspect durable state.
#[derive(Debug, Error)]
pub enum WorkflowHostError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    JobStore(#[from] crate::job_store::JobStoreError),
    #[error(transparent)]
    Durability(#[from] crate::durability::DurabilityError),
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error("workflow child count for session {session_id} exceeds u32::MAX")]
    ChildCountOverflow { session_id: SessionId },
    #[error("workflow session tree is not configured")]
    SessionTreeUnavailable,
    #[error("workflow child reservation for session {session_id} was refused")]
    ChildReservationRefused { session_id: SessionId },
    #[error(transparent)]
    Store(#[from] roundhouse_store::StoreError),
    #[error("child admission failed: {primary}; session rollback failed: {rollback}")]
    ChildAdmissionRollback { primary: String, rollback: String },
}

/// The engine-owned session-tree operations required when a workflow creates a
/// child session. The flow crate cannot mint lifecycle events or see agent
/// children itself, so production callers must provide this authority.
pub trait SessionTree: Send {
    /// Atomically holds one direct-child slot and returns the pre-reservation
    /// committed child count used for depth/fan-out admission.
    fn reserve_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
    ) -> Result<u32, WorkflowHostError>;

    /// Releases a slot when durable child admission does not commit.
    fn release_child(&mut self, parent: SessionId, child: SessionId);

    /// Appends the child SessionCreated lifecycle event into `txn`. `parent`
    /// is the actual calling session (durable spawn-tree linkage,
    /// `SessionSpec::parent`) — implementors must record it on the child's
    /// spec themselves, never substitute a stored template spec's own
    /// `parent` field.
    fn persist_child_session(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        parent: SessionId,
        child: &WorkflowRun,
    ) -> Result<(), WorkflowHostError>;

    /// Persists the redacted parent task that represents a `call:` in the same
    /// transaction as its child run and call association.
    fn persist_parent_call_task(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        parent: SessionId,
        created_at: Timestamp,
        task_id: TaskId,
        input: TaskInput,
    ) -> Result<(), WorkflowHostError>;

    /// Makes a committed child admission visible to runtime traversal.
    fn register_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
        job_id: JobId,
    ) -> Result<(), WorkflowHostError>;

    /// Releases the runtime slot a **committed** child holds, because that
    /// child's run has reached a terminal state.
    ///
    /// The counterpart of [`Self::register_child`], not of
    /// [`Self::release_child`]: `release_child` compensates a reservation that
    /// never committed, this ends an edge that did. Without it a parent's
    /// §7.7 fan-out ceiling is a lifetime quota rather than a concurrency one
    /// — eight `call:` children per parent per daemon process, ever.
    ///
    /// Infallible on purpose, exactly as `release_child` is: dropping the
    /// bookkeeping edge is best-effort, so a run that has already
    /// transitioned and already refunded its grant is never reported as
    /// failing *by this call*. That is a claim about this hook only, not
    /// about the whole of [`finish_run`]'s terminal branch — the
    /// `recover_run` lookup that finds the parent's session a few lines
    /// before this call can still fail and propagate, exactly as the
    /// `refund_child_run` beside it already can.
    ///
    /// The daemon's scheduled-delivery driver recursively drives a `call:`
    /// child to this terminal branch. Keeping the release beside the durable
    /// refund means that driver inherits both halves of child completion rather
    /// than having to remember either independently.
    ///
    /// Implementors must be idempotent. **Not** because this call site
    /// duplicates — [`run_workflow`] refuses to drive a run that is already
    /// terminal, so a crash after the transition cannot produce a second
    /// call from here — but because the fact it reports is about a *session*,
    /// and the daemon learns that a session ended by more routes than this
    /// one (boot-time reconciliation of the tree, and whatever eventually
    /// reaps a finished child). Removal that is only correct once is removal
    /// that breaks the first time two of those agree.
    fn child_terminated(&mut self, parent: SessionId, child: SessionId);

    fn direct_children(&mut self, parent: SessionId) -> Result<u32, WorkflowHostError>;
}

/// The two things the run loop needs that this crate cannot do for itself.
///
/// Both are named rather than faked, in the shape [`Checkpointer`] already
/// established for §8.11's implicit checkpoint — which is the supertrait, so
/// one host value serves the park too.
pub trait WorkflowHost: Checkpointer {
    /// Resolve a `call:` step's workflow name to a job version and register the
    /// child's Session on the way.
    ///
    /// `None` means the name does not resolve, and the step fails: §8.12's
    /// `workflow:<name>` registration lives in a jobs table this crate cannot
    /// read (radius: `roundhouse-store`'s `CREATE TABLE` statements are
    /// `events`, `tasks`, `blobs`, `trigger_event`, `workflow_run`,
    /// `workflow_step_run` — a `Job`/`JobVersion` is an in-memory type in
    /// [`crate::job`]).
    fn resolve_call(
        &mut self,
        conn: &Connection,
        workflow: &str,
        parent: SessionId,
    ) -> Result<Option<CalledWorkflow>, WorkflowHostError>;

    /// Atomically reserves one direct-child slot and returns the committed
    /// direct-child count observed before the reservation.
    fn reserve_child_session(
        &mut self,
        parent: SessionId,
        child: &CalledWorkflow,
    ) -> Result<u32, WorkflowHostError>;

    /// Releases an uncommitted child slot.
    fn release_child_session(&mut self, parent: SessionId, child: &CalledWorkflow);

    /// Persists the child session lifecycle event, workflow row, and parent
    /// `Running` checkpoint in one transaction, then registers the runtime
    /// spawn-tree edge after commit.
    fn create_child_run(
        &mut self,
        conn: &mut Connection,
        parent: SessionId,
        child: &WorkflowRun,
        called: &CalledWorkflow,
        parent_step: &WorkflowStepRun,
        parent_call: &WorkflowChildCall,
        parent_task_input: TaskInput,
    ) -> Result<(), WorkflowHostError>;

    /// Drops the runtime edge [`Self::create_child_run`] registered, because
    /// the child run it stands for has ended. Called by [`finish_run`] from
    /// the child's **own** terminal transition, beside the durable refund —
    /// see [`SessionTree::child_terminated`], which this exists to reach.
    fn child_session_terminated(&mut self, parent: SessionId, child: SessionId);
}

/// Why a run could not be driven. **Not** a step failing — a step failure is
/// ordinary control flow and produces a `Failed` run with a report, which is
/// the whole point of ruling P112.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum RunLoopError {
    /// The workflow's own step graph is malformed: a cycle, an unknown
    /// `needs:`, a duplicate id, a step with no body. Workflow YAML is
    /// untrusted input, so this is a run-level error and never a panic — the
    /// same call [`Executor::run_to_completion`] makes.
    #[error(transparent)]
    Parse(#[from] ParseError),
    #[error(transparent)]
    Durability(#[from] DurabilityError),
    #[error(transparent)]
    Ledger(#[from] LedgerError),
    #[error(transparent)]
    Park(#[from] ParkError),
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    /// [`run_workflow`] was asked to drive a run that is not `Running`, and
    /// was given no answer ([`Resume::Gate`] or [`Resume::CrashRecovery`])
    /// that would release it.
    ///
    /// Distinguished from a step failure because it is a caller mistake, not a
    /// workflow outcome: pausing or cancelling a run and then asking the loop
    /// to drive it anyway must not be answered by inventing a terminal state
    /// for it.
    #[error("run {run_id} is {state:?}, so the run loop will not drive it")]
    RunNotDrivable { run_id: RunId, state: RunState },
    /// A gate answer names a step this run's graph does not contain, or one
    /// whose body is not a `gate:`.
    #[error("gate answer names step {step_id:?}, which is not a gate step of this workflow")]
    UnknownGateStep { step_id: String },
    /// A [`CrashRecoveryAnswer`] names a step this run's `steps:` phase does
    /// not contain, or one that could never have produced a crash-recovery
    /// park in the first place (its resolved
    /// [`CrashPolicy`](crate::durability::CrashPolicy) is not `Ask`).
    ///
    /// Refused rather than ignored, and for a sharper reason than
    /// [`Self::UnknownGateStep`]'s: an answer nothing consumes would still
    /// have released the park on the way in, leaving the run driving on with
    /// the question it parked for unanswered — and the next load would park
    /// it again, so the run would ping-pong rather than fail visibly.
    #[error(
        "crash-recovery answer names step {step_id:?}, which is not a step of this workflow's \
         `steps:` phase whose on_crash policy is `ask`"
    )]
    UnknownCrashRecoveryStep { step_id: String },
    /// §8.8's `report:` block is *the* mandatory per-run block, and ruling
    /// P112 makes it **exactly one**. Two authored `report:` steps would
    /// persist two `TaskKind::Report` tasks and leave the Runs inbox choosing
    /// between them; refused **before any step runs**, so a workflow that
    /// cannot satisfy the invariant never starts rather than discovering it at
    /// the end with side effects already committed.
    #[error("workflow declares {count} `report:` steps; §8.6 and ruling P112 allow exactly one")]
    MultipleReportSteps { count: usize },
    /// The report this module synthesised does not pass
    /// [`validate_report`] — an internal invariant, not a workflow error. It
    /// is checked rather than assumed for the reason the authored path checks:
    /// the `events` table physically rejects `UPDATE`/`DELETE`, so a malformed
    /// report that reaches the sink is there permanently.
    #[error("the synthesised report is not a valid report: {0}")]
    SynthesisedReportInvalid(String),
    /// Ruling P117 §C's `run_state` annotation turned an **authored** report
    /// that already validated at its own step into one that does not.
    ///
    /// Distinct from [`Self::SynthesisedReportInvalid`] because it blames a
    /// different author: that variant means this module assembled a bad
    /// document, this one means this module's own one-key annotation broke a
    /// document the workflow wrote and [`validate_report`] had already
    /// accepted. Checked rather than assumed for the same reason the two
    /// producers check: the `events` table physically rejects
    /// `UPDATE`/`DELETE`.
    #[error("annotating the report with the run's terminal state made it invalid: {0}")]
    AnnotatedReportInvalid(String),
    /// A `gate:` step's own fields are not usable — an empty `title`, a
    /// malformed `timeout:`, a `form:` that is not an object.
    #[error(transparent)]
    Hitl(#[from] HitlError),
    /// The run could not be started because its [`super::RunContext`] carries
    /// a secret this crate cannot safely use as a redaction needle.
    ///
    /// A run-level configuration fault, not a workflow one, and the reason it
    /// is a distinct variant rather than folded into a general "could not
    /// start": [`super::ExecutorError::SecretTooShortToRedact`] is the refusal
    /// that keeps a credential out of an append-only log, and an operator
    /// reading a run that failed needs to be told *that*, by name, rather than
    /// something about a report.
    #[error(transparent)]
    Executor(#[from] super::ExecutorError),
    #[error(transparent)]
    Host(#[from] WorkflowHostError),
}

/// A human's answer to the gate a run is parked on, supplied to
/// [`run_workflow`] to release it.
///
/// `output` becomes `steps.<step_id>.output`, so a dependent's
/// `${{ steps.gate.output.approve }}` reads what the human actually said.
/// **Not** validated against the gate's own `form:` schema here: this crate
/// has no JSON Schema validator (radius: no `jsonschema`/`valico` dependency
/// in any `Cargo.toml`), and the renderer that produced the form is the layer
/// that can check the answer against it.
#[derive(Debug, Clone, PartialEq)]
pub struct GateAnswer {
    pub step_id: String,
    pub output: Value,
}

/// A human's answer to the §8.10 crash-recovery park a step's
/// [`CrashPolicy::Ask`] took — the resume half of
/// [`crate::hitl::HumanWaitSource::CrashRecovery`].
///
/// # Why this is not a [`GateAnswer`] (Phase 8 Task 25.4 Task 5's one open decision)
///
/// A [`GateAnswer`] is *data*: its `output` becomes
/// `steps.<step_id>.output`, so a dependent's
/// `${{ steps.gate.output.approve }}` reads what the human said, and
/// [`ensure_gate_step`] refuses an answer naming a non-`gate:` step
/// precisely because injecting a value under an id whose real step is about
/// to run would overwrite it.
///
/// A crash-recovery answer is neither of those things. It is *control flow*
/// — re-dispatch, skip, or fail — the step it names is by construction
/// **not** a `gate:` step (it is the `shell`/`write`/`edit` step that was
/// interrupted), and it must produce no `steps.<id>.output` at all, because
/// on [`CrashResolution::Rerun`] the step is about to run and write its own.
/// Reusing `GateAnswer` would therefore have meant relaxing
/// [`ensure_gate_step`]'s check — the one check that stops exactly that
/// overwrite — and then reading `output` as a control decision on some steps
/// and as data on others. So this is a separate variant with a typed
/// [`CrashResolution`] instead of an untyped `Value`, and
/// [`ensure_crash_recovery_step`] is its own, differently-shaped check.
#[derive(Debug, Clone, PartialEq)]
pub struct CrashRecoveryAnswer {
    pub step_id: String,
    pub resolution: CrashResolution,
}

/// What to hand [`run_workflow`] on a call that resumes a suspended run — a
/// run has at most one live suspension at a time, so which case applies is
/// the caller's to know, not this crate's to infer.
#[derive(Debug, Clone)]
pub enum Resume {
    /// Resolves an [`RunOutcome::Parked`] gate.
    Gate(GateAnswer),
    /// Resolves an [`RunOutcome::Parked`] **crash-recovery** wait — §8.10's
    /// `on_crash: ask`, which is the default for every `Effectful` step. See
    /// [`CrashRecoveryAnswer`] for why this is not a [`Resume::Gate`].
    CrashRecovery(CrashRecoveryAnswer),
    /// Resolves an [`RunOutcome::AwaitingWork`] suspension — one entry per
    /// [`PendingWork`] the caller was handed. Always length 1 today (nothing
    /// yet batches pending work); the `Vec` is here so a future caller that
    /// answers several pending items in one call does not need a second
    /// contract change — see [`PendingKind::ChildRun`] and Phase 8 Task
    /// 25.7 (map `max_parallel`) for why that future caller exists.
    ///
    /// **Only the outstanding items**: a caller never re-sends what earlier
    /// segments of the same drive already answered, and does not have to —
    /// [`run_workflow`] inherits those outcomes from the durable rows
    /// itself, which is what [`failed_step_rows`] exists for. Carrying this
    /// variant is also how the loop *knows* this entry is a continuation
    /// rather than a cold start, so constructing one for any other reason
    /// would be a lie about which drive the run is in.
    Work(Vec<WorkDone>),
}

/// One unit of work [`run_workflow`] cannot perform itself: real dispatch is
/// async and requires a live `Session` and the engine's policy admission,
/// both of which live outside this crate — see this module's own doc,
/// "What this module does NOT own".
///
/// By the time this is returned, the step's row is already
/// [`StepRunState::Running`] — so a crash between here and the matching
/// [`WorkDone`] is [`crate::durability::recover_run`]'s `Indeterminate`
/// reclassification, by construction, not a rule the caller must remember.
#[derive(Debug, Clone)]
pub struct PendingWork {
    pub run_id: RunId,
    /// The Session the eventual task must be filed under —
    /// [`TaskSink::emit`] structurally cannot carry this; see that trait's
    /// own doc for why.
    pub session_id: SessionId,
    pub step_id: String,
    /// Always `1` today — see `crate::retry`'s own "built, unwired" note.
    pub attempt: u32,
    /// Always `None` today: a `map` item's own pending work is Phase 8 Task
    /// 25.7's scope, not this one's.
    pub item_index: Option<u32>,
    pub disposition: StepDisposition,
    /// The run's real remaining per-step ceiling as of the moment this step
    /// started, from the same [`crate::ledger::remaining_caps`] read
    /// `map`'s own per-step budget refresh already takes (§8.9's "at the
    /// moment the map starts", applied here to a single step's dispatch).
    /// The caller must bound the real work with it — nothing inside this
    /// crate can.
    pub step_timeout: std::time::Duration,
    pub kind: PendingKind,
}

/// What kind of work is pending, and everything a caller needs to dispatch
/// it for real without re-deriving anything this crate already resolved.
///
/// Every field here is already interpolated and dual-rendered (ruling P33):
/// the `logged_*` value is what a caller mints its `TaskCreated` with, the
/// `dispatch_*` value is the real one — never for logging or persisting.
#[derive(Debug, Clone)]
pub enum PendingKind {
    Tool {
        tool: String,
        task_kind: TaskKind,
        logged_input: Value,
        dispatch_input: Value,
    },
    Agent {
        /// `{"prompt": .., "model": ..}` — the redacted rendering of both
        /// templated fields (ruling P33). `tools`/`output_schema` are not
        /// templated (a tool allowlist and a JSON Schema literal, never
        /// `${{ }}` text), so they are not duplicated here.
        logged_prompt: Value,
        dispatch_prompt: String,
        /// The step's declared `agent.model`, interpolated — `None` when the
        /// step didn't set one. Previously dropped entirely: `Executor::
        /// dispatch_step`'s `StepBody::Agent { prompt, .. }` arm destructured
        /// only `prompt`.
        model: Option<String>,
        /// The step's declared `agent.tools` allowlist, passed through
        /// verbatim — a plain list of tool names, not a template.
        tools: Vec<String>,
        /// The step's declared `agent.output_schema`, passed through
        /// verbatim — a JSON Schema literal, not a template.
        output_schema: Option<Value>,
        /// The run's real remaining `max_tokens` ceiling as of the moment
        /// this step dispatched, sourced from `executor.map_budget` exactly
        /// as [`PendingWork::step_timeout`] already is (ruling P108 §C) — a
        /// workflow `agent:` step has no authored token budget of its own to
        /// transfer, unlike the model-issued `agent` tool's `budget_tokens`
        /// argument.
        budget_tokens: u64,
    },
    /// A `call:` child run and Session already exist (created by
    /// [`Loop::dispatch_call`]); the caller drives the child and reports its
    /// outcome.
    ChildRun {
        child_run_id: RunId,
        child_session_id: SessionId,
        parent_task_id: TaskId,
        dispatch_input: Value,
        /// Whether `dispatch_input` was derived from a parent secret. The
        /// daemon passes this to the child's `RunContext` so the child can
        /// bind its complete `inputs` root conservatively as secret-derived.
        inputs_secret_derived: bool,
    },
}

/// What a caller did with one [`PendingWork`].
#[derive(Debug, Clone)]
pub struct WorkDone {
    pub step_id: String,
    pub status: WorkStatus,
    /// Becomes `steps.<id>.output` — the real value, never redacted here;
    /// the redaction that matters happens on the way into the log
    /// ([`Loop::record`]/`steps_context_entry`), not on the way in here.
    pub output: Value,
    /// Read, never recomputed — [`StepOutcome::output_is_secret_derived`]'s
    /// own doc: "a re-derivation that disagrees with this one is a leak."
    pub output_is_secret_derived: bool,
    /// The task the caller actually minted, and its log range — the first
    /// real values `WorkflowStepRun::first_task_seq`/`last_task_seq` have
    /// ever carried; see [`Loop::checkpoint`]'s own note on why they were
    /// `None` before this.
    pub task_id: Option<TaskId>,
    pub first_task_seq: Option<u64>,
    pub last_task_seq: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum WorkStatus {
    Completed,
    /// Ordinary control flow — `continue_on_error` applies exactly as it
    /// does to any other step failure.
    Failed {
        message: String,
    },
    /// §8.13 cancel, observed by the caller mid-dispatch. Recorded as a step
    /// failure (there is no separate `StepStatus::Cancelled`); the run's own
    /// `Cancelled` state, not this step's status, is what a reader keys off.
    Cancelled {
        reason: String,
    },
}

/// Converts what a caller did with a [`PendingWork`] into the same
/// [`StepOutcome`] shape every other dispatch arm produces, so [`Loop::record`]
/// has one input type regardless of whether a step ran synchronously or was
/// suspended and resumed.
fn step_outcome_from_work_done(work: WorkDone) -> StepOutcome {
    let status = match work.status {
        WorkStatus::Completed => StepStatus::Completed,
        WorkStatus::Failed { message } => StepStatus::Failed { message },
        WorkStatus::Cancelled { reason } => StepStatus::Failed { message: reason },
    };
    StepOutcome {
        step_id: work.step_id,
        output: work.output,
        status,
        output_is_secret_derived: work.output_is_secret_derived,
        // Overwritten by the caller immediately after, exactly as every
        // other arm's outcome is — see `Loop::run_phase`'s
        // `outcome.gate_condition_was_secret_derived = gate_secret_derived;`.
        gate_condition_was_secret_derived: false,
    }
}

/// Where the run's one `TaskKind::Report` task came from.
///
/// The document itself is deliberately **not** carried here: §8.6 requires it
/// to be persisted and loadable back (*"never assembled in memory and
/// discarded"*), so the log is its home, and returning a second copy would
/// invite a caller to read the copy instead — the copy that, for an authored
/// report, is the *unredacted* value the step returned rather than the
/// redacted one that was persisted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportOrigin {
    /// The workflow declared a `report:` step and it completed. §8.6's first
    /// producer.
    Authored { step_id: String },
    /// The run loop assembled one from the run's own tasks — §4.2's
    /// *"input: none (assembled from the run's tasks)"*, and the common case
    /// for a failed or cancelled run, which never reaches an authored
    /// `report:` step at all.
    Synthesised,
}

/// What [`run_workflow`] did.
#[derive(Debug, Clone)]
pub enum RunOutcome {
    /// The run reached a terminal state, and carries exactly one report.
    Terminal {
        state: RunState,
        report: ReportOrigin,
        /// Every step the loop ran, across all three phases, in the order it
        /// ran them. Steps skipped by re-drive (already checkpointed on an
        /// earlier pass) are not here; they are in the database.
        steps: Vec<StepOutcome>,
    },
    /// A human wait parked the run — either a `gate:` step or (since Phase 8
    /// Task 25.4) §8.10's `on_crash: ask` crash recovery. **Not terminal, so
    /// it carries no report** — see [`crate::report::Outcome`]'s own doc: a
    /// run in `AwaitingHuman` has no result to report yet. Call
    /// [`run_workflow`] again with the matching [`Resume`] variant —
    /// [`Resume::Gate`] or [`Resume::CrashRecovery`] — to resume it; the
    /// [`crate::hitl::HumanWaitSource`] in the `awaiting_human` task this
    /// park put in the log says which.
    ///
    /// **This holds even when the workflow's `report:` step has already
    /// completed** — the document it produced is held, not emitted, until the
    /// run reaches a terminal state (see `super::ReportEmission`). The park
    /// that never gets answered is therefore the one terminal path with no
    /// report and no owner: `crate::report`'s module doc records that
    /// obligation for whoever builds §8.11's reaper.
    Parked(Box<ParkResult>),
    /// A `tool:`/`agent:`/`call:` step needs real work this crate cannot
    /// perform. A pending call already has its funded child run and parent
    /// agent task; the caller returns its child result as [`WorkDone`].
    /// **Not terminal, so it carries no report** — the run is still
    /// `Running` (unlike `Parked`, which writes `AwaitingHuman`: the run
    /// genuinely is running, its caller is simply not inside
    /// [`run_workflow`] at this instant). Call [`run_workflow`] again with
    /// [`Resume::Work`] to resume it.
    AwaitingWork { pending: Vec<PendingWork> },
}

/// Which of the three step lists is running — the one thing §8.13's admission
/// exemption turns on, and the one thing that decides what a failure means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// `steps:`. A failure here stops the phase (unless `continue_on_error`)
    /// and fails the run.
    Main,
    /// `catch:`. Runs only when the main phase failed. §8.9's own example
    /// names its single step `on_failure`.
    Catch,
    /// `finally:`. Runs on every path, including a cancel — §8.13 requires
    /// both *"refuse new task admission"* and *"run `finally:`"*, and
    /// [`admit_spend_during_finally`] is the one exemption that makes those
    /// two sentences consistent.
    Finally,
}

/// Proof that this run has persisted its one `TaskKind::Report` task.
///
/// **This is what makes ruling P112's mandatoriness structural rather than a
/// comment.** [`finish_run`] takes one and there is no other way to reach the
/// terminal `transition_run`, and the only two constructors are the two §8.6
/// producers — an authored `report:` step that completed, and
/// [`Loop::synthesise_report`]. A future edit that adds a third terminal path
/// has to produce a report to compile, rather than remembering to.
///
/// The type is private and carries no data: it is a capability, not a value.
struct ReportPersisted(ReportOrigin);

/// §8.10's *"Recovery = load and resume"*, plus §8.13's controls, plus §8.11's
/// park, plus §8.12's transfer, driven over one parsed workflow.
///
/// # Preconditions
///
/// `run_id` names an existing `workflow_run` row. It must be `Running`;
/// `Cancelling`, which is drivable **because** §8.13's cancel is cooperative
/// and this loop is what drains it (ruling P115 §A — refusing would leave
/// `finally:` unrun and the mandatory report unwritten); or `AwaitingHuman`
/// together with a `resume` answer for the wait it is parked on — a
/// [`Resume::Gate`] for a `gate:` step, a [`Resume::CrashRecovery`] for
/// §8.10's `on_crash: ask`. Anything else
/// is [`RunLoopError::RunNotDrivable`]. Creating the row is
/// the caller's — [`crate::durability::insert_workflow_run`], which is also
/// where a child run's grant is drawn from its parent.
///
/// `run_ctx.run_id` must be `run_id`; [`Executor::new`] takes the run identity
/// from the context, so a mismatch would bind `${{ run.id }}` to a different
/// run than the one being checkpointed.
///
/// # Re-drive, not replay (§8.10 tier 1)
///
/// Every step that already has a **finished** `workflow_step_run` row —
/// `Completed` or `Skipped` — is not re-run. Its recorded output is folded
/// straight into `steps.<id>` so dependents read the same value they would
/// have. That is what makes a resumed park, or a second pass after any
/// interruption, not repeat effectful work; and `Skipped` is deliberately in
/// that set, because re-evaluating a `when:` on re-drive would let a condition
/// that reads differently now change control flow that already happened
/// ([`StepRunState::Skipped`]'s own doc says so).
///
/// # Stop-on-failure
///
/// A failed step ends the `steps:` phase unless it declared
/// `continue_on_error: true` — §8.9: *"`continue_on_error` distinguishes 'the
/// command failed' (data) from 'the step failed' (control flow)"*. Every step
/// the stop skipped is checkpointed [`StepRunState::Skipped`] with a reason,
/// so the row says why it did not run rather than being silently absent.
///
/// # Exactly one report, on every terminal path
///
/// Ruling P112, built to rather than commented: `Completed`, `Failed` and
/// `Cancelled` all leave one `TaskKind::Report` task, authored or synthesised.
/// A run that is *not* terminal (a park) carries none, deliberately.
pub fn run_workflow<H: WorkflowHost>(
    conn: &mut Connection,
    def: &WorkflowDef,
    run_id: RunId,
    sink: &mut dyn TaskSink,
    host: &mut H,
    run_ctx: super::RunContext,
    now: Timestamp,
    resume: Option<Resume>,
) -> Result<RunOutcome, RunLoopError> {
    // **Whether this entry is a later segment of a drive already in
    // progress**, which is exactly what [`Resume::Work`] means and the one
    // thing nothing durable records — see [`failed_step_rows`].
    let resuming_work = matches!(resume, Some(Resume::Work(_)));
    // Split the one `resume` parameter into the two internal channels it can
    // carry — a run has at most one live suspension at a time, so exactly
    // one of these is ever non-empty on any call.
    type ResumeChannels = (
        Option<GateAnswer>,
        Option<CrashRecoveryAnswer>,
        HashMap<String, WorkDone>,
    );
    let (gate_answer, crash_answer, work_results): ResumeChannels = match resume {
        Some(Resume::Gate(answer)) => (Some(answer), None, HashMap::new()),
        Some(Resume::CrashRecovery(answer)) => (None, Some(answer), HashMap::new()),
        Some(Resume::Work(work)) => (
            None,
            None,
            work.into_iter().map(|w| (w.step_id.clone(), w)).collect(),
        ),
        None => (None, None, HashMap::new()),
    };

    let main = parse_phase(&def.steps)?;
    let catch = parse_phase(&def.catch)?;
    let finally = parse_phase(&def.finally)?;

    // Checked before anything runs: a workflow that cannot satisfy §8.6's
    // "exactly one" must not get halfway through committing side effects
    // before saying so.
    //
    // It cannot see a `report:` nested inside a `map` — it flattens the three
    // phase lists only — which is why such a step is refused where the nesting
    // *is* visible, in `map_step`'s inner-step loop.
    let report_steps: Vec<&StepDef> = [&main, &catch, &finally]
        .iter()
        .flat_map(|phase| phase.iter())
        .filter(|step| matches!(step.body, StepBody::Report { .. }))
        .collect();
    if report_steps.len() > 1 {
        return Err(RunLoopError::MultipleReportSteps {
            count: report_steps.len(),
        });
    }
    let report_step = report_steps.first().map(|s| (*s).clone());

    let recovered = recover_run(conn, run_id)?;
    let session_id = recovered.run.session_id;
    let started_state = recovered.run.state;

    match (started_state, &gate_answer, &crash_answer) {
        (RunState::Running, _, _) => {}
        // **`Cancelling` is drivable, and it has to be.** §8.13's cancel is
        // cooperative: an operator marks the row and the loop is what drains
        // it — refusing to drive it would leave the run `Cancelling` forever,
        // with `finally:` never run and no report ever written. Every step of
        // `steps:`/`catch:` is refused by admission (that is where the cancel
        // is observed), so what actually runs is the cleanup §8.13 requires.
        (RunState::Cancelling, _, _) => {}
        (RunState::AwaitingHuman, Some(answer), _) => {
            release_park(conn, run_id, &main, answer, now)?;
        }
        // The two answers cannot both be present: `Resume` is one enum and
        // carries exactly one of them, which is §8.11's "a run has at most
        // one live suspension at a time" expressed in the type.
        (RunState::AwaitingHuman, None, Some(answer)) => {
            release_crash_recovery_park(conn, run_id, &main, answer, now)?;
        }
        (state, _, _) => return Err(RunLoopError::RunNotDrivable { run_id, state }),
    }
    // Checked even when the run was already `Running`, so an answer naming a
    // step that is not a gate is refused on every path rather than only on the
    // resume path — see `release_park`.
    if let Some(answer) = &gate_answer {
        ensure_gate_step(&main, answer)?;
    }
    if let Some(answer) = &crash_answer {
        ensure_crash_recovery_step(&main, answer)?;
    }

    // Task 19a: computed before `run_ctx` moves into `Executor::new` below,
    // since `RunContext::previous_report` is what feeds it. `None` when
    // `defaults.carry_over.last_report` is unset, or when it is set but the
    // caller found no previous report (a binding's first-ever run) — see
    // `build_carry_over_seed`'s own doc comment for why that is `None`, not
    // an error.
    let carry_over_seed =
        build_carry_over_seed(&def.defaults.carry_over, run_ctx.previous_report.as_ref());

    // `Executor::new`'s only refusal is a secret too short to redact, which is
    // a run-level configuration fault — see `RunLoopError::Executor`.
    let mut executor = Executor::new(def, sink, run_ctx)?;
    // Ruling P117 §C: under a real run the one report task is emitted by
    // `ensure_report`, after the terminal state is known, so that the document
    // can carry it. See `super::ReportEmission`.
    executor.report_emission = ReportEmission::Deferred(None);

    // Task 19a: bind the carry-over seed as a root a workflow expression can
    // read (`${{ carry_over.previous_report.headline }}`, etc.) — a seed
    // that is computed and dropped is not wired. `"carry_over"` is not a
    // name the architecture doc (§8.6) or `build_carry_over_seed`'s own doc
    // comment spells out as the binding name, so this task picked it as the
    // obvious match for the `defaults.carry_over` config key that produced
    // it; see this task's report.
    //
    // Bound through `set_secret`, the same conservative choice `secrets`
    // itself uses, and for the reason ruling P35 gives for it: this binding
    // site does not know the previous report's provenance. The previous
    // run's `headline`/`findings` are model-authored text that run may have
    // derived from its own `secrets`, and nothing here can tell clean
    // content apart from content quietly derived from a credential. Taint
    // only affects the *logged* rendering (`interpolate`/`interpolate_json`
    // replace the whole tainted value with `***`); the real value still
    // reaches the dispatched task, so a workflow can still act on the prior
    // report — it just cannot make it appear in cleartext in the log.
    if let Some(seed) = carry_over_seed {
        executor.ctx.set_secret("carry_over", seed);
    }

    let mut run = Loop {
        conn,
        host,
        run_id,
        session_id,
        now,
        steps_context: serde_json::Map::new(),
        secret_derived_steps: Vec::new(),
        outcomes: Vec::new(),
        report_step,
        report_completed_before: false,
        finished_before: finished_step_rows(&recovered.steps),
        indeterminate_before: indeterminate_step_rows(&recovered.steps),
        failed_before: if resuming_work {
            failed_step_rows(&recovered.steps)
        } else {
            HashMap::new()
        },
        gate_answer,
        crash_answer,
        work_results,
    };
    run.seed_context_from_checkpoints(&recovered.steps);

    let main_result = run.run_phase(&mut executor, Phase::Main, &main)?;
    if let PhaseEnd::Parked(parked) = main_result {
        return Ok(RunOutcome::Parked(Box::new(parked)));
    }
    if let PhaseEnd::AwaitingWork(pending) = main_result {
        return Ok(RunOutcome::AwaitingWork {
            pending: vec![*pending],
        });
    }
    let main_failed = matches!(main_result, PhaseEnd::Failed);
    let cancelled = matches!(main_result, PhaseEnd::Cancelled);

    if main_failed {
        // §8.9's `catch:` runs on failure and only on failure. Its own failures
        // do not re-enter it: the run is failing either way, and a `catch:`
        // that could trigger itself is a loop.
        match run.run_phase(&mut executor, Phase::Catch, &catch)? {
            PhaseEnd::Parked(parked) => return Ok(RunOutcome::Parked(Box::new(parked))),
            PhaseEnd::AwaitingWork(pending) => {
                return Ok(RunOutcome::AwaitingWork {
                    pending: vec![*pending],
                })
            }
            PhaseEnd::Completed | PhaseEnd::Failed | PhaseEnd::Cancelled => {}
        }
    }

    // §8.13: `finally:` runs on every path, cancel included. A park inside
    // `finally:` would suspend a run that is already ending, so a gate here is
    // refused by `dispatch_gate` rather than honoured. A `tool:`/`agent:`
    // step is not refused the same way — it is ordinary work, not a wait on
    // a human — so `finally:` can suspend on one exactly like `steps:` can.
    let finally_result = run.run_phase(&mut executor, Phase::Finally, &finally)?;
    if let PhaseEnd::AwaitingWork(pending) = finally_result {
        return Ok(RunOutcome::AwaitingWork {
            pending: vec![*pending],
        });
    }
    let finally_failed = matches!(finally_result, PhaseEnd::Failed);

    // **Ruling P117 §A, leg 1: the durable row is the second observer of a
    // cancel, and it has to be consulted.** `cancelled` above is set only by
    // `admit`, which runs only for steps *not* already checkpointed — so the
    // last admission of the run is the last instant a cancel can be seen that
    // way. Everything after it (that step's execution, the whole `finally:`
    // phase, `ensure_report`) was a window in which an operator's `cancel`
    // was invisible here: `state` computed `Completed`, `transition_is_legal`
    // has no `Cancelling -> Completed` edge, and because `finish_run` is the
    // **only** writer of `Cancelled`/`Failed` in the workspace, the run then
    // could never be moved again — `ended_at` stayed `NULL`, the "run that
    // looks live forever" `insert_run_row`'s guard is named for, and a
    // cancelled child's grant leaked to nobody because `refund_child_run`
    // correctly refuses a non-terminal child.
    //
    // One row read closes it, and it also closes ruling P116 §C's variant of
    // the same defect (a run cancelled with nothing left to admit, where
    // `admit` never runs at all). It is read here rather than at entry
    // because a cancel that lands *during* the run must be seen too.
    let observed = run_ledger(run.conn, run_id)?.state;
    let state = if cancelled || observed == RunState::Cancelling {
        RunState::Cancelled
    } else if main_failed || finally_failed {
        RunState::Failed
    } else {
        RunState::Completed
    };

    let report = run.ensure_report(&mut executor, state)?;
    let steps = std::mem::take(&mut run.outcomes);
    let landed = finish_run(
        run.conn,
        run.host,
        run_id,
        run.session_id,
        state,
        now,
        &report,
    )?;

    Ok(RunOutcome::Terminal {
        // The state that **actually landed on the row**, not the one computed
        // above: leg 2 of the fix can re-target a cancel that raced the read,
        // and a returned value that disagreed with the row would be exactly
        // the "in-memory answer nothing else can see" defect this subsystem
        // keeps producing.
        state: landed,
        report: report.0,
        steps,
    })
}

/// Parses one of the three step lists into a dependency-ordered `Vec`.
///
/// Each list is its own graph: a `catch:` step's `needs:` names another
/// `catch:` step, never a `steps:` one. §8.9 gives no cross-list `needs:`, and
/// admitting one would make `catch:` re-run work the failed phase already did.
fn parse_phase(raw: &[serde_yaml::Value]) -> Result<Vec<StepDef>, ParseError> {
    let defs: Vec<StepDef> = raw.iter().map(parse_step).collect::<Result<_, _>>()?;
    let order = topological_order(&defs)?;
    Ok(order.into_iter().map(|idx| defs[idx].clone()).collect())
}

/// Every step id whose row is already **finished** — `Completed` or `Skipped`
/// — mapped to the row, for §8.10's re-drive.
///
/// `Failed` and `Indeterminate` are deliberately absent: §8.10 tier 2 exists
/// precisely so those are re-decided rather than inherited, and
/// `control::retry_from_step` inherits only `Completed` for the same reason.
/// `Pending`/`Running` rows are a step the loop started and did not finish, so
/// they re-run.
///
/// **That is a statement about a *cold* entry**, which is the only kind this
/// set used to see. A `Failed` row belonging to the drive that is still in
/// progress is [`failed_step_rows`]'s, not this one's — keeping the two
/// separate is what lets a failure this drive already decided be terminal
/// without making a dead run's failure inheritable.
fn finished_step_rows(rows: &[WorkflowStepRun]) -> HashMap<String, WorkflowStepRun> {
    rows.iter()
        .filter(|row| {
            row.item_index.is_none()
                && matches!(row.state, StepRunState::Completed | StepRunState::Skipped)
        })
        .map(|row| (row.step_id.clone(), row.clone()))
        .collect()
}

/// Every step id whose row says `Failed`, for the one entry kind on which
/// such a row belongs to **this** drive rather than to a dead one: an entry
/// carrying [`Resume::Work`].
///
/// # Why a `Failed` row needs a second, narrower set at all
///
/// [`run_workflow`] is re-entered once per [`RunOutcome::AwaitingWork`]
/// suspension, which happens many times inside a single uncrashed run — not
/// only once after a crash. Every re-entry rebuilds [`finished_step_rows`]
/// and [`indeterminate_step_rows`] from the durable rows, and a `Failed` row
/// is in neither: not "finished" (§8.10 tier 2 re-decides one), and not
/// `Indeterminate` (so [`Loop::run_phase`]'s crash-policy branch never sees
/// it). Nothing therefore stopped a later segment re-deciding a step an
/// earlier segment of the same drive had already settled — re-admitting it
/// (double-charging §8.4's caps), re-dispatching it for real, and suspending
/// on it again, while the completed [`WorkDone`] the caller had just been
/// handed for the step the run *actually* suspended on went unconsumed
/// because [`Loop::run_phase`] returns at the first step that dispatches
/// `Pending`. The cycle repeats until [`Loop::admit`] exhausts the run's
/// grant, so the run ends `Failed` reporting "admission refused" rather than
/// what really happened.
///
/// # Why [`Resume::Work`] is the right discriminator, and the only one
///
/// The two cases a `Failed` row can be in are indistinguishable on the row:
/// a step failed by an earlier segment of a live drive, and a step failed by
/// a drive that then died. Nothing durable separates them, because a crash
/// writes nothing — which is the whole premise of §8.10.
///
/// What does separate them is how the caller got here. A [`Resume::Work`]
/// can only be built from [`PendingWork`] this crate handed out moments
/// earlier in the same drive, so an entry carrying one is by construction a
/// continuation, never a cold start; and a driver recovering a run after a
/// restart necessarily enters with `resume: None` (it has no outstanding
/// `PendingWork` to answer — see `DeliveryExecutor::drive_run_to_completion`
/// in `roundhouse-daemon`, whose loop starts every drive that way). So §8.10
/// tier 2's re-decision survives untouched on exactly the entries it was
/// written for, and only the segments of a live drive inherit.
fn failed_step_rows(rows: &[WorkflowStepRun]) -> HashMap<String, WorkflowStepRun> {
    rows.iter()
        .filter(|row| row.item_index.is_none() && row.state == StepRunState::Failed)
        .map(|row| (row.step_id.clone(), row.clone()))
        .collect()
}

/// Every step id [`crate::durability::recover_run`] reclassified
/// `Indeterminate` — an `Effectful` step found `Running` when this run was
/// loaded. Consulted by [`Loop::run_phase`] only when the resumed step
/// carries no caller-supplied [`WorkDone`] (a genuine resume — an ordinary
/// answer for a step this run just suspended on — is trusted outright and
/// never routed through the crash policy at all).
fn indeterminate_step_rows(rows: &[WorkflowStepRun]) -> HashMap<String, WorkflowStepRun> {
    rows.iter()
        .filter(|row| row.item_index.is_none() && row.state == StepRunState::Indeterminate)
        .map(|row| (row.step_id.clone(), row.clone()))
        .collect()
}

/// Moves a parked run back to `Running` on a human's answer, after checking
/// the answer names a real `gate:` step of this workflow.
///
/// The check is not a formality: `steps.<id>.output` is bound from the answer,
/// so an answer naming a step that is not a gate would inject a value under an
/// id whose real step is about to run and overwrite it.
fn release_park(
    conn: &mut Connection,
    run_id: RunId,
    main: &[StepDef],
    answer: &GateAnswer,
    now: Timestamp,
) -> Result<(), RunLoopError> {
    ensure_gate_step(main, answer)?;
    // `transition` clears `awaiting_until`/`hold_until` and banks the parked
    // stretch into `parked_nanos` on this edge, which is what makes §8.4's
    // `run_active_timeout` exclude the wait.
    transition_run(conn, run_id, RunState::Running, now)?;
    Ok(())
}

/// The check [`release_park`] exists for, split out so it runs on every entry
/// carrying an answer and not only on the parked one.
fn ensure_gate_step(main: &[StepDef], answer: &GateAnswer) -> Result<(), RunLoopError> {
    if main
        .iter()
        .any(|s| s.id == answer.step_id && matches!(s.body, StepBody::Gate { .. }))
    {
        return Ok(());
    }
    Err(RunLoopError::UnknownGateStep {
        step_id: answer.step_id.clone(),
    })
}

/// [`release_park`]'s counterpart for §8.10's crash-recovery wait: check the
/// answer names a step that could actually have parked, then move the run
/// back to `Running`.
///
/// Two functions rather than one with an either-or parameter because the two
/// checks are genuinely different questions — see [`CrashRecoveryAnswer`]'s
/// own doc — while the `transition_run` they share is one line.
fn release_crash_recovery_park(
    conn: &mut Connection,
    run_id: RunId,
    main: &[StepDef],
    answer: &CrashRecoveryAnswer,
    now: Timestamp,
) -> Result<(), RunLoopError> {
    ensure_crash_recovery_step(main, answer)?;
    // `transition` clears `awaiting_until`/`hold_until` and banks the parked
    // stretch into `parked_nanos` on this edge, which is what makes §8.4's
    // `run_active_timeout` exclude the wait.
    transition_run(conn, run_id, RunState::Running, now)?;
    Ok(())
}

/// The check [`release_crash_recovery_park`] exists for, split out so it runs
/// on every entry carrying an answer and not only on the parked one — the
/// same shape as [`ensure_gate_step`], asking the question that actually
/// applies here.
///
/// **`steps:` only, and that is the whole set.** A crash-recovery park is
/// taken by [`Loop::crash_recovery_park`], which refuses to park from
/// `catch:`/`finally:` for §8.13's cancel-must-converge reason, so a `catch:`
/// step can never be the subject of one.
///
/// **[`crash_policy`], not [`derive_disposition`]**: §8.10 lets an author
/// override in both directions, and it is the *resolved* policy that decides
/// whether a park was ever possible. A step declaring `on_crash: rerun` or
/// `on_crash: fail` never parks, so an answer naming one is answering a
/// question nobody asked.
fn ensure_crash_recovery_step(
    main: &[StepDef],
    answer: &CrashRecoveryAnswer,
) -> Result<(), RunLoopError> {
    if main
        .iter()
        .any(|s| s.id == answer.step_id && crash_policy(s) == CrashPolicy::Ask)
    {
        return Ok(());
    }
    Err(RunLoopError::UnknownCrashRecoveryStep {
        step_id: answer.step_id.clone(),
    })
}

/// The terminal write, gated on a [`ReportPersisted`].
///
/// **The parameter is the whole point** and it is why this is a function
/// rather than an inline `transition_run` call: ruling P112 says *"a run must
/// not be markable terminal without one"*, and a witness a caller cannot forge
/// makes that a compile-time property of this module rather than a rule to
/// remember. See [`ReportPersisted`].
///
/// §8.12's *"refunded on completion"* also lands here, for the same reason
/// `ended_at` does: it is a thing that is true exactly once, at the one edge
/// where a run ends. A run with no `parent_run_id` refunds nothing.
///
/// # Leg 2 of ruling P117 §A: a cancel that raced the terminal write
///
/// Returns the state that **actually landed**, which is not always the one
/// asked for. `run_workflow` reads the run's observed state just before
/// computing `state` (leg 1), but a `cancel` can still land in the gap between
/// that read and this write. The retry below closes it, and it is **race-free
/// rather than a narrower window**: `Cancelling` has exactly two outgoing
/// edges (`Cancelled` and `Failed`) and this function is the only writer of
/// either, so a `Cancelling` observed by `transition_run`'s own
/// `BEGIN IMMEDIATE` cannot become anything else before the retry runs.
///
/// Three alternatives were considered and rejected. Adding
/// `(Running, Cancelled)` to [`transition_is_legal`](crate::durability::transition_is_legal)
/// creates a path that skips `Cancelling`, which is the state
/// [`admit_spend_during_finally`] keys off — `finally:` would stop running.
/// Refusing to drive a `Cancelling` run at all leaves `finally:` unrun and the
/// mandatory report unwritten (ruling P115 §A). Mapping the error onto
/// `Failed` converges, but misreports an operator's cancel as a failure.
///
/// The `Paused` sibling is closed differently — by the
/// `Paused -> Completed` edge the matrix was missing, so there is nothing to
/// retry. See `transition_is_legal`'s own section on it.
///
/// **What the retry cannot fix, stated rather than implied:** the report was
/// already persisted, with the terminal state as of leg 1's read annotated
/// onto it. A cancel landing inside this gap therefore leaves a `Cancelled`
/// run whose one report says `completed`. The row is authoritative; the
/// annotation is one edge stale in exactly this race and no other. Closing
/// that too would need the report emit and the transition in one transaction,
/// and the sink is not a database handle (see [`TaskSink`]).
fn finish_run<H: WorkflowHost>(
    conn: &mut Connection,
    host: &mut H,
    run_id: RunId,
    session_id: SessionId,
    state: RunState,
    now: Timestamp,
    _report: &ReportPersisted,
) -> Result<RunState, RunLoopError> {
    let landed = match transition_run(conn, run_id, state, now) {
        Ok(_) => state,
        Err(DurabilityError::IllegalTransition {
            from: RunState::Cancelling,
            ..
        }) => {
            transition_run(conn, run_id, RunState::Cancelled, now)?;
            RunState::Cancelled
        }
        Err(other) => return Err(other.into()),
    };
    // Read *after* the transition, because `refund_child_run` refuses a child
    // that has not reached a terminal state — correctly, since returning a live
    // child's grant would let it spend budget its parent had reclaimed.
    let ledger = run_ledger(conn, run_id)?;
    if let Some(parent_run_id) = ledger.parent_run_id {
        refund_child_run(conn, run_id, now)?;
        // The runtime half of the same "the child has ended" fact, released
        // from the same branch as the durable half so the two cannot drift.
        // The parent's SESSION, not its run: the spawn tree §7.7's fan-out
        // ceiling is counted in is keyed by session, and a run's session is
        // the only thing the two child kinds (`call:` children and the
        // `agent` tool's sub-agents) have in common to be counted under.
        //
        // The parent row is guaranteed present: `refund_child_run` above
        // just credited it, and `insert_workflow_run` refuses to commit a
        // row carrying a `parent_run_id` without drawing from that parent.
        let parent_session = recover_run(conn, parent_run_id)?.run.session_id;
        host.child_session_terminated(parent_session, session_id);
    }
    Ok(landed)
}

/// How a phase ended.
enum PhaseEnd {
    /// Every step ran (or was skipped by its own `when:`), with no fatal
    /// failure.
    Completed,
    /// A step failed and did not declare `continue_on_error`.
    Failed,
    /// The run was marked `Cancelling` and admission refused, so the phase
    /// stopped draining. §8.13's cooperative cancel, observed at the
    /// chokepoint rather than by a second state read that could disagree
    /// with it.
    Cancelled,
    /// A human wait — a `gate:` step, or §8.10's `on_crash: ask` crash
    /// recovery — parked the run. The whole loop unwinds; nothing after this
    /// step runs, and no report is written, because the run has not ended.
    ///
    /// Only [`Phase::Main`] ever produces this: both park sites refuse to
    /// suspend a run from `catch:`/`finally:` (see [`Loop::dispatch_gate`]
    /// and [`Loop::crash_recovery_park`]), because §8.13's cancel must
    /// converge.
    Parked(ParkResult),
    /// A `tool:`/`agent:`/`call:` step needs real work. The whole loop unwinds
    /// exactly as for `Parked` — nothing after this step runs — but the run
    /// stays `Running`, not `AwaitingHuman`.
    AwaitingWork(Box<PendingWork>),
}

struct Loop<'c, H: WorkflowHost> {
    conn: &'c mut Connection,
    host: &'c mut H,
    run_id: RunId,
    session_id: SessionId,
    now: Timestamp,
    steps_context: serde_json::Map<String, Value>,
    secret_derived_steps: Vec<String>,
    outcomes: Vec<StepOutcome>,
    /// The workflow's one `report:` step, if it declares one — `run_workflow`'s
    /// §8.6 pre-check has already established there is at most one.
    ///
    /// The `StepDef` itself and not just an id, because a re-drive whose
    /// report step is already checkpointed has to **re-render** the document;
    /// see [`Loop::ensure_report`].
    report_step: Option<StepDef>,
    /// Whether that step's row already says `Completed` from an earlier pass.
    ///
    /// The other half of "did the author write a report", and the half
    /// `finished_before` hides — see
    /// [`Loop::seed_context_from_checkpoints`].
    report_completed_before: bool,
    finished_before: HashMap<String, WorkflowStepRun>,
    /// Every step id whose row is `Indeterminate` — an `Effectful` step found
    /// `Running` after a crash, per [`crate::durability::recover_run`].
    /// Consulted once per matching step, on the pass that first re-drives
    /// it, so §8.10 tier 2's `on_crash` policy is applied instead of the
    /// step being treated as never-started.
    indeterminate_before: HashMap<String, WorkflowStepRun>,
    /// Every step id whose row says `Failed` **and** whose failure this same
    /// drive decided, which is why it is empty on every entry that is not a
    /// [`Resume::Work`] continuation — see [`failed_step_rows`] for the whole
    /// argument. Drained as each is inherited.
    failed_before: HashMap<String, WorkflowStepRun>,
    gate_answer: Option<GateAnswer>,
    /// A human's answer to the §8.10 crash-recovery park this run took, if
    /// this entry carries one. Read (not drained) by [`Self::run_phase`]'s
    /// crash-policy branch for the one step it names; every other step falls
    /// through to `crash_policy` exactly as on a cold entry.
    ///
    /// It is consulted **only inside** that branch, so an answer for a step
    /// this load no longer finds `Indeterminate` (it completed before the
    /// crash, or its row was re-decided in between) is simply not applied,
    /// and the step is driven normally. That is the right outcome: the
    /// question the park asked no longer has a subject, and the run has
    /// already been released back to `Running`, so there is nothing left to
    /// answer. [`ensure_crash_recovery_step`] is what refuses the case that
    /// *is* a caller mistake — an answer naming a step that could never have
    /// parked at all.
    crash_answer: Option<CrashRecoveryAnswer>,
    /// What a caller reported for a step this run suspended on, keyed by
    /// step id and drained as each is consumed. Populated from
    /// [`Resume::Work`]; empty on every other entry, including a crash
    /// re-drive with no caller-supplied answer at all.
    work_results: HashMap<String, WorkDone>,
}

impl<H: WorkflowHost> Loop<'_, H> {
    /// Folds every already-finished step's recorded output into `steps.<id>`,
    /// so a re-driven run's dependents read what the first pass produced.
    ///
    /// Uses [`StepOutput::value_unredacted_for_resume`] — the accessor whose
    /// name says what it is for. A dependent reading
    /// `${{ steps.build.output.sha }}` after a resume must see the real value,
    /// not the display stand-in; the redaction that matters happens where the
    /// value reaches the sink, which is `dispatch_step`'s job on the way out,
    /// not this fold's on the way in. The step id is re-added to
    /// `secret_derived_steps` when the row says the output was secret-derived,
    /// so the taint survives the restart rather than being re-derived — the
    /// property [`StepOutcome::output_is_secret_derived`]'s doc calls a leak to
    /// recompute.
    ///
    /// # `authored_report` is restored here for the same reason, and it is not cosmetic
    ///
    /// [`Loop::authored_report`] used to be written **only** by
    /// [`Loop::record`], which the `finished_before` skip bypasses. So a run
    /// whose `report:` step completed on an earlier pass — an authored
    /// `report:` ordered before a `gate:` is enough, no crash required —
    /// resumed with `authored_report: None` and **synthesised a second
    /// report** into an append-only log.
    ///
    /// The cost is not "two reports", it is triage inversion: a synthesised
    /// report is generic by construction (`outcome: nothing`, `severity: low`,
    /// `needs_human: false`), so a run whose author reported
    /// `findings`/`high`/`needs_human: true` acquired a companion that sorts
    /// it to the **bottom** of §8.6's order — ruling P112's own failure mode,
    /// reached by *adding* a report rather than omitting one.
    ///
    /// It was invisible to the suite because every test built a fresh
    /// `TaskSink` per `run_workflow` call while the production sink is per
    /// **session**, so the second pass's assertion never saw the first pass's
    /// report at all.
    fn seed_context_from_checkpoints(&mut self, rows: &[WorkflowStepRun]) {
        for row in rows {
            if row.item_index.is_some() {
                continue;
            }
            if row.state == StepRunState::Completed
                && self
                    .report_step
                    .as_ref()
                    .is_some_and(|step| step.id == row.step_id)
            {
                self.report_completed_before = true;
            }
            let (status, output) = match row.state {
                StepRunState::Completed => (
                    "completed",
                    row.output
                        .as_ref()
                        .map_or(Value::Null, |o| o.value_unredacted_for_resume().clone()),
                ),
                StepRunState::Skipped => ("skipped", Value::Null),
                // A `Failed` row is seeded **only** when this segment is
                // going to inherit it rather than re-decide it — see
                // `failed_step_rows`, which is what populates
                // `failed_before`. Without this a dependent's
                // `${{ steps.<id>.status }}` would read `null` for a step
                // whose failure is the reason it is running at all, and a
                // `catch:`/`finally:` block would have no way to say what
                // went wrong. A row that is going to be re-decided is left
                // out, because the re-decision writes the entry itself a
                // moment later.
                StepRunState::Failed if self.failed_before.contains_key(&row.step_id) => {
                    ("failed", Value::Null)
                }
                _ => continue,
            };
            if row
                .output
                .as_ref()
                .is_some_and(StepOutput::is_secret_derived)
            {
                self.secret_derived_steps.push(row.step_id.clone());
            }
            self.steps_context.insert(
                row.step_id.clone(),
                serde_json::json!({
                    "output": output,
                    "status": status,
                    "error": row.error,
                }),
            );
        }
    }

    /// Rebinds `${{ steps }}` from the loop's own fold, carrying the taint
    /// paths with it.
    ///
    /// **The projection below is where every secret-derived step's output is
    /// marked, and its cardinality is load-bearing.** `set_with_secret_paths`
    /// marks exactly the paths this iterator yields; a truncation of it
    /// (`.take(1)`, `.skip(1)`) leaves some tainted step's output *unmarked*,
    /// and an unmarked derived leaf reaches the log in **cleartext** — the
    /// whole-value needle backstop structurally cannot catch a leaf of a JSON
    /// secret. `tests/run_loop.rs` therefore carries two secret-derived steps,
    /// with the leaf that matters relayed from the first in one test and the
    /// last in another.
    fn bind_steps_context(&self, executor: &mut Executor<'_>) {
        executor.ctx.set_with_secret_paths(
            "steps",
            Value::Object(self.steps_context.clone()),
            self.secret_derived_steps
                .iter()
                .map(|id| vec![id.clone(), "output".to_string()]),
        );
    }

    fn run_phase(
        &mut self,
        executor: &mut Executor<'_>,
        phase: Phase,
        steps: &[StepDef],
    ) -> Result<PhaseEnd, RunLoopError> {
        let mut end = PhaseEnd::Completed;
        let mut stopped_at: Option<usize> = None;

        for (index, step) in steps.iter().enumerate() {
            if self.finished_before.contains_key(&step.id) {
                continue;
            }

            // A step an **earlier segment of this same drive** already
            // settled `Failed`. Its outcome is decided, so this segment
            // re-applies the control flow that failure implies rather than
            // re-deciding the step: no second admission, no second dispatch,
            // and — the reason it matters — no second suspension, which would
            // discard the answer this call is carrying for the step the run
            // actually suspended on.
            //
            // A caller-supplied answer for this exact step still wins, for
            // the reason stated below where one is consumed; a step that just
            // suspended has a `Running` row rather than a `Failed` one, so
            // the two sets do not overlap in practice, and the guard is here
            // so that ordering is a property of the code and not of a
            // coincidence.
            //
            // The row itself is not re-written: it already says exactly this,
            // and `outcomes` deliberately omits steps a re-drive inherited —
            // see `RunOutcome::Terminal`'s own `steps` doc.
            if !self.work_results.contains_key(&step.id)
                && self.failed_before.remove(&step.id).is_some()
            {
                if !step.continue_on_error {
                    end = PhaseEnd::Failed;
                    stopped_at = Some(index + 1);
                    break;
                }
                continue;
            }

            self.bind_steps_context(executor);

            // A caller-supplied answer for this exact step always wins,
            // whether this is an ordinary resume (the run never crashed,
            // the caller simply was not inside `run_workflow` while the
            // work ran) or a resume after a restart the caller's own
            // durable state survived. Consuming it here — before admission,
            // before the crash-policy check below — is what stops a step
            // this run already knows the answer to being re-admitted or
            // re-decided.
            let resumed_work = self.work_results.remove(&step.id);

            if resumed_work.is_none() {
                // §8.10 tier 2: a step found `Indeterminate` (`Effectful`,
                // `Running` when this run was loaded — see
                // `crate::durability::recover_run`) with no caller-supplied
                // answer is a step this run does not know completed. This is
                // what stops it being silently treated as never-started and
                // re-admitted/re-dispatched regardless of its declared
                // `on_crash`.
                if let Some(row) = self.indeterminate_before.remove(&step.id) {
                    // A human's answer to **this step's own** crash-recovery
                    // park wins over re-deriving the policy: the park is the
                    // question and this is its answer. Consulted before
                    // `crash_policy` so an answered park cannot re-park,
                    // which would be a wait nobody could ever escape.
                    let answered = self
                        .crash_answer
                        .as_ref()
                        .filter(|a| a.step_id == step.id)
                        .map(|a| a.resolution);
                    match answered {
                        // §8.10's `rerun`, which is exactly an at-least-once
                        // crash re-run: the `Indeterminate` classification is
                        // already cleared by the `remove` above, so falling
                        // through re-admits and re-dispatches the step the
                        // same way a declared `on_crash: rerun` does.
                        Some(CrashResolution::Rerun) => {}
                        Some(CrashResolution::Skip) => {
                            // Durably skipped, with the reason naming the
                            // human: a reader of the row must be able to tell
                            // a person's decision from a `when:` that
                            // evaluated false.
                            let outcome = StepOutcome {
                                step_id: step.id.clone(),
                                output: Value::Null,
                                status: StepStatus::Skipped {
                                    reason: format!(
                                        "a human answered this step's crash-recovery park with \
                                         `skip`: it was interrupted mid-dispatch (found {:?}) \
                                         and will not be re-run",
                                        row.state
                                    ),
                                },
                                // Nothing ran, so there is no output and
                                // nothing derived from a secret in it.
                                output_is_secret_derived: false,
                                gate_condition_was_secret_derived: false,
                            };
                            self.record(step, outcome)?;
                            continue;
                        }
                        Some(CrashResolution::Fail) => {
                            let outcome = StepOutcome::failed(
                                &step.id,
                                format!(
                                    "a human answered this step's crash-recovery park with \
                                     `fail`: it was interrupted mid-dispatch (found {:?}) and \
                                     will not be re-run",
                                    row.state
                                ),
                            );
                            self.record(step, outcome)?;
                            // Stops the phase regardless of
                            // `continue_on_error`, exactly as the
                            // `CrashPolicy::Fail` arm below does:
                            // `continue_on_error` distinguishes "the command
                            // failed" from "the step failed" (§8.9), and this
                            // is neither — it is a human saying the run
                            // should not go on.
                            end = PhaseEnd::Failed;
                            stopped_at = Some(index + 1);
                            break;
                        }
                        None => match crash_policy(step) {
                            CrashPolicy::Rerun => {}
                            CrashPolicy::Ask => {
                                // §8.10's default for **every** `Effectful`
                                // step, and Phase 8 Task 25.4 Task 5's whole
                                // point: ask a human rather than failing the
                                // run closed, which would mean any daemon
                                // restart mid-`shell`/`write`/`edit`
                                // permanently failed the run.
                                match self.crash_recovery_park(executor, step, phase, row.state)? {
                                    CrashPark::Parked(parked) => {
                                        return Ok(PhaseEnd::Parked(parked))
                                    }
                                    CrashPark::Refused(outcome) => {
                                        self.record(step, outcome)?;
                                        end = PhaseEnd::Failed;
                                        stopped_at = Some(index + 1);
                                        break;
                                    }
                                }
                            }
                            CrashPolicy::Fail => {
                                // The author declared `on_crash: fail`, which
                                // is the one policy that asks for exactly
                                // this: never re-run, never ask, end the run.
                                let outcome = StepOutcome::failed(
                                    &step.id,
                                    format!(
                                        "step was interrupted mid-dispatch (found {:?}) and its \
                                         on_crash policy is {:?}: refusing to silently re-run an \
                                         effectful step whose completion is unknown",
                                        row.state,
                                        CrashPolicy::Fail
                                    ),
                                );
                                self.record(step, outcome)?;
                                end = PhaseEnd::Failed;
                                stopped_at = Some(index + 1);
                                break;
                            }
                        },
                    }
                }

                // §8.4's *"caps enforced at task admission"*, at the one
                // place every step passes. This is also where §8.13's cancel
                // is observed: `admit_spend` refuses a `Cancelling` run, so
                // the cooperative drain is read off the same chokepoint that
                // enforces the budget rather than from a second state read
                // that could disagree with it.
                //
                // Skipped for a step with a `resumed_work` answer above: it
                // was already charged on the pass that produced the
                // `PendingWork` this answers, and admitting it a second time
                // would double-charge the run's ledger.
                match self.admit(phase, step) {
                    Ok(()) => {}
                    Err(LedgerError::NotAdmitting {
                        state: RunState::Cancelling,
                        ..
                    }) => {
                        end = PhaseEnd::Cancelled;
                        stopped_at = Some(index);
                        break;
                    }
                    Err(LedgerError::NotAdmitting { state, .. }) => {
                        return Err(RunLoopError::RunNotDrivable {
                            run_id: self.run_id,
                            state,
                        })
                    }
                    Err(refused) => {
                        // A budget refusal is a *step* failure, not a run-loop
                        // error: the run has an outcome (it ran out of what it
                        // was given), and an outcome is exactly what the
                        // report exists to carry. `LedgerError`'s `Display`
                        // names the field that ran out.
                        let outcome =
                            StepOutcome::failed(&step.id, format!("admission refused: {refused}"));
                        self.record(step, outcome)?;
                        end = PhaseEnd::Failed;
                        stopped_at = Some(index + 1);
                        break;
                    }
                }

                // Ruling P108 §C, discharged: the `map` split is taken from
                // the run's real remaining ceiling, read at the moment the
                // step starts — §8.9's own words for when it is taken.
                //
                // **Sourced, not yet enforced, and this slice's mutation
                // sweep measured exactly that.** `map_step::run_map` computes
                // `split_budget(&budget.total_remaining, n)` and hands the
                // result to a closure that binds it `_item_caps`; nothing
                // reads it. So mutating this line away survives at zero test
                // failures, and the honest reading is that the *sourcing*
                // half of P108 §C is done and the *enforcement* half is
                // per-item admission — which belongs with `map`'s worktree
                // fan-out, deferred out of B12 entirely by ruling P77 §C.
                // Kept rather than deleted because the value is now real and
                // correct, and the consumer arrives with fan-out.
                executor.map_budget = Some(MapBudget::from_run_ledger(
                    self.conn,
                    self.run_id,
                    self.now,
                )?);
            }

            let gate_secret_derived = match evaluate_when_gate(step, &executor.ctx) {
                GateDecision::Decided(outcome) => {
                    self.record(step, outcome)?;
                    continue;
                }
                GateDecision::Proceed {
                    gate_condition_was_secret_derived,
                } => gate_condition_was_secret_derived,
            };

            let mut resumed_seqs: (Option<u64>, Option<u64>) = (None, None);
            let mut outcome = if let Some(work) = resumed_work {
                resumed_seqs = (work.first_task_seq, work.last_task_seq);
                step_outcome_from_work_done(work)
            } else {
                match &step.body {
                    StepBody::Gate {
                        title,
                        form,
                        timeout,
                        on_timeout,
                        hold_workspace,
                    } => match self.dispatch_gate(
                        executor,
                        step,
                        title,
                        form,
                        timeout,
                        on_timeout,
                        *hold_workspace,
                        phase,
                    )? {
                        GateStep::Answered(outcome) => outcome,
                        GateStep::Parked(parked) => return Ok(PhaseEnd::Parked(parked)),
                    },
                    StepBody::Call { workflow, with } => {
                        match self.dispatch_call(executor, step, workflow, with) {
                            CallStep::Completed(outcome) => outcome,
                            CallStep::AwaitingWork(kind) => {
                                return Ok(PhaseEnd::AwaitingWork(Box::new(
                                    self.pending_work(executor, step, kind),
                                )));
                            }
                        }
                    }
                    _ => match executor.dispatch_step(step) {
                        super::DispatchDecision::Done(outcome) => outcome,
                        super::DispatchDecision::Pending(kind) => {
                            return self.awaiting_work(executor, step, kind);
                        }
                    },
                }
            };
            outcome.gate_condition_was_secret_derived = gate_secret_derived;

            let failed = matches!(outcome.status, StepStatus::Failed { .. });
            self.record_with_seqs(step, outcome, resumed_seqs.0, resumed_seqs.1)?;
            if failed && !step.continue_on_error {
                end = PhaseEnd::Failed;
                stopped_at = Some(index + 1);
                break;
            }
        }

        // The `Skipped` writer P77 names, in its second of two roles: a step
        // that never ran because an earlier one stopped the phase gets a row
        // saying so, rather than being silently absent from the run's history.
        // (The first role is a `when:` that evaluated false, written by
        // `record` below.)
        if let Some(from) = stopped_at {
            let reason = match end {
                PhaseEnd::Cancelled => "the run was cancelled before this step ran",
                _ => "an earlier step failed",
            };
            for step in &steps[from..] {
                if self.finished_before.contains_key(&step.id) {
                    continue;
                }
                self.checkpoint(step, StepRunState::Skipped, None, Some(reason.to_string()))?;
            }
        }
        Ok(end)
    }

    fn awaiting_work(
        &mut self,
        executor: &Executor<'_>,
        step: &StepDef,
        kind: PendingKind,
    ) -> Result<PhaseEnd, RunLoopError> {
        self.checkpoint(step, StepRunState::Running, None, None)?;
        Ok(PhaseEnd::AwaitingWork(Box::new(
            self.pending_work(executor, step, kind),
        )))
    }

    fn pending_work(
        &self,
        executor: &Executor<'_>,
        step: &StepDef,
        kind: PendingKind,
    ) -> PendingWork {
        PendingWork {
            run_id: self.run_id,
            session_id: self.session_id,
            step_id: step.id.clone(),
            attempt: 1,
            item_index: None,
            disposition: derive_disposition(step),
            step_timeout: executor
                .map_budget
                .as_ref()
                .map(|b| b.total_remaining.step_timeout)
                .unwrap_or_default(),
            kind,
        }
    }

    /// §8.4's admission, with §8.13's one exemption applied by phase.
    ///
    /// # What a step is charged
    ///
    /// The countables this loop **knows**: one task, plus one tool call for a
    /// `tool:` step and one sub-agent for an `agent:` or `call:` step. Tokens,
    /// dollars and bytes are deliberately zero here, and that is not an
    /// omission: [`Spend`]'s own doc records that those are measured *"from
    /// outside the run being measured — Phase 2's cost accounting"*, and a
    /// figure this loop invented would be the self-reported number that doc
    /// says the whole invariant reduces to not trusting. Whoever measures them
    /// records them through the same [`admit_spend`] chokepoint.
    ///
    /// So what this makes real today is `max_tasks`, `max_tool_calls` and
    /// `max_subagents` — a run cannot execute more steps than its grant allows
    /// — plus both elapsed-time ceilings, which `admit_spend` checks on every
    /// call regardless of what is being spent.
    fn admit(&mut self, phase: Phase, step: &StepDef) -> Result<(), LedgerError> {
        let requested = Spend {
            tasks: 1,
            tool_calls: u32::from(matches!(step.body, StepBody::Tool { .. })),
            subagents: u32::from(matches!(
                step.body,
                StepBody::Agent { .. } | StepBody::Call { .. }
            )),
            ..Spend::ZERO
        };
        match phase {
            Phase::Finally => {
                admit_spend_during_finally(self.conn, self.run_id, &requested, self.now)
            }
            Phase::Main | Phase::Catch => admit_spend(self.conn, self.run_id, &requested, self.now),
        }
        .map(|_| ())
    }

    /// Folds one step's outcome into the expression context, the returned
    /// summary, and its `workflow_step_run` row.
    ///
    /// The three happen together because they are one fact: a `steps.<id>`
    /// entry a dependent can read, a row a re-drive can read, and an entry in
    /// what the caller gets back.
    fn record(&mut self, step: &StepDef, outcome: StepOutcome) -> Result<(), RunLoopError> {
        self.record_with_seqs(step, outcome, None, None)
    }

    /// [`Self::record`], but also threading through the real
    /// `first_task_seq`/`last_task_seq` a resumed [`WorkDone`] carries —
    /// see [`Self::checkpoint_with_seqs`] for why this is a second method
    /// rather than a parameter every caller has to pass `None` for.
    fn record_with_seqs(
        &mut self,
        step: &StepDef,
        outcome: StepOutcome,
        first_task_seq: Option<u64>,
        last_task_seq: Option<u64>,
    ) -> Result<(), RunLoopError> {
        if outcome.output_is_secret_derived {
            self.secret_derived_steps.push(step.id.clone());
        }
        self.steps_context
            .insert(step.id.clone(), steps_context_entry(&outcome));

        let (state, output, error) = match &outcome.status {
            StepStatus::Completed => (
                StepRunState::Completed,
                Some(StepOutput::from_outcome(&outcome)),
                None,
            ),
            // The `error` writer P77 names, whose consumer `durability.rs`
            // records as the Runs inbox: the message cannot be recomputed once
            // the process that produced it is gone, so it goes in the row.
            // `checkpoint_step` bounds it to `MAX_STORED_STEP_ERROR_LEN`.
            StepStatus::Failed { message } => (StepRunState::Failed, None, Some(message.clone())),
            StepStatus::Skipped { reason } => (StepRunState::Skipped, None, Some(reason.clone())),
        };
        self.checkpoint_with_seqs(step, state, output, error, first_task_seq, last_task_seq)?;
        self.outcomes.push(outcome);
        Ok(())
    }

    fn checkpoint(
        &mut self,
        step: &StepDef,
        state: StepRunState,
        output: Option<StepOutput>,
        error: Option<String>,
    ) -> Result<(), RunLoopError> {
        self.checkpoint_with_seqs(step, state, output, error, None, None)
    }

    /// [`Self::checkpoint`], but also writing the real
    /// `first_task_seq`/`last_task_seq` a resumed [`WorkDone`] carries.
    ///
    /// A second method, not a parameter [`Self::checkpoint`]'s own callers
    /// have to pass `None` for: every dispatch that runs *inside* this
    /// crate (`emit:`, `report:`, `gate:`, `call:`, and the `Running`
    /// checkpoint just before a step suspends) genuinely has no task-log
    /// range of its own — [`TaskSink::emit`] returns no `seq`, and the
    /// `Running` row is written before any task exists at all. Only a
    /// resumed [`WorkDone`] — the caller's real, already-appended
    /// `TaskCreated`/`TaskCompleted` pair — ever has one to write.
    fn checkpoint_with_seqs(
        &mut self,
        step: &StepDef,
        state: StepRunState,
        output: Option<StepOutput>,
        error: Option<String>,
        first_task_seq: Option<u64>,
        last_task_seq: Option<u64>,
    ) -> Result<(), RunLoopError> {
        checkpoint_step(
            self.conn,
            &self.step_run(step, state, output, error, first_task_seq, last_task_seq),
        )?;
        Ok(())
    }

    fn step_run(
        &self,
        step: &StepDef,
        state: StepRunState,
        output: Option<StepOutput>,
        error: Option<String>,
        first_task_seq: Option<u64>,
        last_task_seq: Option<u64>,
    ) -> WorkflowStepRun {
        WorkflowStepRun {
            run_id: self.run_id,
            step_id: step.id.clone(),
            attempt: 1,
            item_index: None,
            disposition: derive_disposition(step),
            state,
            first_task_seq,
            last_task_seq,
            output,
            error,
        }
    }
}

/// What a `gate:` step did.
enum GateStep {
    /// A human's answer was supplied at entry, so the gate resolves rather
    /// than parks.
    Answered(StepOutcome),
    Parked(ParkResult),
}

enum CallStep {
    Completed(StepOutcome),
    AwaitingWork(PendingKind),
}

/// What [`Loop::crash_recovery_park`] did.
enum CrashPark {
    Parked(ParkResult),
    /// This run must not acquire a new indefinite wait on a human, so the
    /// step fails closed instead — Task 25.3's original behaviour, kept for
    /// exactly the two cases where parking would be wrong. The outcome
    /// carries the reason.
    Refused(StepOutcome),
}

impl<H: WorkflowHost> Loop<'_, H> {
    /// §8.11's park, as a step: build the [`AwaitingHuman`] the gate
    /// describes, then hand it to [`park`], which takes the implicit
    /// checkpoint and writes `AwaitingHuman` plus both absolute deadlines in
    /// one transaction.
    ///
    /// # A gate inside `finally:` is refused rather than honoured
    ///
    /// §8.13 requires `finally:` to run *during a cancel*, and a park suspends
    /// the run indefinitely waiting on a human. A cancel that stops on a
    /// cleanup prompt is a cancel that does not converge — the same property
    /// that makes a `call:` inside `finally:` refused at
    /// [`crate::ledger::admit_call_from_run`]. This is the run loop's leg of
    /// that rule, and it applies to `catch:` too, for the weaker but
    /// sufficient reason that a failing run should end rather than wait.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_gate(
        &mut self,
        executor: &mut Executor<'_>,
        step: &StepDef,
        title: &str,
        form: &Value,
        timeout: &str,
        on_timeout: &crate::parse::types::OnTimeout,
        hold_workspace: bool,
        phase: Phase,
    ) -> Result<GateStep, RunLoopError> {
        if let Some(answer) = self
            .gate_answer
            .as_ref()
            .filter(|a| a.step_id == step.id)
            .cloned()
        {
            return Ok(GateStep::Answered(StepOutcome {
                step_id: step.id.clone(),
                output: answer.output,
                status: StepStatus::Completed,
                // A human's answer is not derived from this run's secrets: it
                // came in from the form, which is the same provenance
                // `inputs`/`vars` have (see `Executor::new`'s `set_public`
                // calls and the boundary ruling P35 makes load-bearing).
                output_is_secret_derived: false,
                gate_condition_was_secret_derived: false,
            }));
        }

        if phase != Phase::Main {
            return Ok(GateStep::Answered(StepOutcome::failed(
                &step.id,
                format!(
                    "a `gate:` step cannot park a run from a `{}` block: the run is already ending",
                    match phase {
                        Phase::Catch => "catch:",
                        Phase::Finally => "finally:",
                        // Unreachable: the guard above is `phase != Main`.
                        // Written out rather than left to a `_` arm so that a
                        // fourth phase is a compile error here, not a step
                        // failure that blames the wrong block.
                        Phase::Main => "steps:",
                    }
                ),
            )));
        }

        // The gate's own `title:`/`form:` are interpolated workflow source, so
        // a `${{ }}` in either resolves here — and the *redacted* rendering is
        // what reaches the form a human sees, for the reason every other
        // dispatch arm redacts: the form is rendered and persisted, and a
        // resolved secret in it would be unrecoverable.
        let resolved_title = match crate::expr::interpolate(
            crate::expr::TemplateSource::from_workflow_file(title),
            &executor.ctx,
        ) {
            Ok(t) => t,
            Err(e) => {
                return Ok(GateStep::Answered(StepOutcome::failed(
                    &step.id,
                    format!("interpolating `gate.title`: {e}"),
                )))
            }
        };
        let logged_title = redact_with_needles(
            &Value::String(resolved_title.redacted_for_logging().to_string()),
            &executor.redaction_needles,
        );
        let title_text = logged_title.as_str().unwrap_or_default().to_string();

        let awaiting =
            AwaitingHuman::from_gate(TaskId::new(), &title_text, form, timeout, on_timeout)?;
        let parked = park(
            self.conn,
            self.run_id,
            &awaiting,
            hold_workspace,
            self.now,
            self.host,
        )?;
        self.emit_awaiting_human(executor, &step.id, &awaiting, &parked);

        // The step's row records that it is waiting, not that it finished: a
        // `Running` row is what §8.10 tier 2 reclassifies as `Indeterminate`
        // for an `Effectful` step after a crash, and a gate is `Idempotent`
        // (`derive_disposition`), so re-presenting it is safe and correct.
        self.checkpoint(step, StepRunState::Running, None, None)?;
        Ok(GateStep::Parked(parked))
    }

    /// Puts a park's checkpoint handle and its [`AwaitingHuman`] form in the
    /// session's log — shared by [`Self::dispatch_gate`] and
    /// [`Self::crash_recovery_park`] rather than written twice.
    ///
    /// **Because otherwise nobody is ever asked.** [`park`] reads only the
    /// wait's deadline; the title and form it is handed go nowhere, so
    /// without this emit a parked run is a run waiting on a prompt that was
    /// never shown. (Found by B12c's mutation sweep: removing the gate
    /// title's redaction survived, because the redacted title reached no
    /// observer at all.) One function, so a second park source cannot
    /// silently ship without the prompt.
    ///
    /// `TaskKind::Flow`, for the reason the `emit:` arm records for its own
    /// choice: §4.2's frozen table has no `AwaitingHuman` kind, and `Flow` is
    /// this crate's general workflow-bookkeeping kind. Adding one is a
    /// frozen-contract amendment, not a run loop's call.
    ///
    /// `AwaitingHuman` is `Serialize` and deliberately not `Deserialize`, so
    /// that a park record cannot be stored as this struct and re-derived with
    /// a fresh window on every resume. Serialising it *into the log for
    /// rendering* is the sanctioned direction of that rule, not an exception
    /// to it: what a resume reads back is the absolute
    /// `workflow_run.awaiting_until`, never this payload.
    fn emit_awaiting_human(
        &self,
        executor: &mut Executor<'_>,
        step_id: &str,
        awaiting: &AwaitingHuman,
        parked: &ParkResult,
    ) {
        executor.sink.emit(
            TaskId::new(),
            None,
            TaskKind::Checkpoint,
            EventPayload::TaskCreated {
                kind: TaskKind::Checkpoint,
                parent: None,
                origin: Origin::System,
                input: TaskInput::Json(serde_json::json!({
                    "run_id": self.run_id,
                    "checkpoint": parked.checkpoint_ref.0,
                })),
            },
        );
        let form_task = TaskId::new();
        let awaiting_payload = serde_json::to_value(awaiting).unwrap_or(Value::Null);
        executor.sink.emit(
            form_task,
            None,
            TaskKind::Flow,
            EventPayload::TaskCreated {
                kind: TaskKind::Flow,
                parent: None,
                origin: Origin::System,
                input: TaskInput::Json(serde_json::json!({
                    "awaiting_human": awaiting_payload,
                    "step_id": step_id,
                    "checkpoint": parked.checkpoint_ref.0,
                })),
            },
        );
    }

    /// §8.10 tier 2's `on_crash: ask`, as a park: the step was interrupted
    /// mid-dispatch and nothing knows whether its effect landed, so ask a
    /// human `rerun | skip | fail` on §8.11's one mechanism rather than
    /// guessing — or failing the run closed, which is what this branch did
    /// before Phase 8 Task 25.4 and which meant **any** daemon restart
    /// mid-`shell`/`write`/`edit` permanently failed the run.
    ///
    /// # The two cases that refuse to park, and why they are not slack
    ///
    /// - **Outside `steps:`.** A park suspends the run indefinitely, and
    ///   §8.13 requires `finally:` to run *during a cancel* — the same rule
    ///   [`Self::dispatch_gate`] applies to a `gate:` in `catch:`/`finally:`.
    /// - **A run already `Cancelling`.** The cooperative cancel must
    ///   converge, and this branch runs *before* [`Self::admit`], which is
    ///   where the loop normally observes a cancel — so the state is read
    ///   from the row here rather than inferred. Without the read, [`park`]
    ///   would refuse the illegal `Cancelling -> AwaitingHuman` transition
    ///   and the refusal would surface as a whole-run
    ///   [`RunLoopError::Park`], stranding a run that should simply finish
    ///   draining.
    ///
    /// Both fall back to the fail-closed outcome, which never re-runs the
    /// step without a human decision — the safety property that has to hold
    /// on every path here.
    ///
    /// # `on_timeout` and the wait's window have no author
    ///
    /// Unlike a `gate:` step, which always has one. `on_timeout` is
    /// therefore the conservative [`OnTimeout::Fail`](crate::parse::types::OnTimeout::Fail)
    /// — an unanswered crash question must not resolve itself into
    /// re-running an effectful step or into an approval — and the window is
    /// §8.11's *"with no explicit gate timeout, fall back to 72h"*
    /// ([`DEFAULT_HOLD_TTL`]). `hold_workspace` is §8.11's default, `false`:
    /// no author asked for a hold, and the implicit checkpoint is what a
    /// resume restores from.
    fn crash_recovery_park(
        &mut self,
        executor: &mut Executor<'_>,
        step: &StepDef,
        phase: Phase,
        found: StepRunState,
    ) -> Result<CrashPark, RunLoopError> {
        let refuse = |why: &str| {
            CrashPark::Refused(StepOutcome::failed(
                &step.id,
                format!(
                    "step was interrupted mid-dispatch (found {found:?}) and its on_crash \
                     policy is Ask, but {why}: refusing to silently re-run an effectful step \
                     whose completion is unknown"
                ),
            ))
        };
        if phase != Phase::Main {
            return Ok(refuse(match phase {
                Phase::Catch => "a `catch:` block cannot park a run that is already failing",
                Phase::Finally => "a `finally:` block cannot park a run that is already ending",
                // Unreachable: the guard above is `phase != Main`. Written
                // out rather than left to a `_` arm so that a fourth phase is
                // a compile error here, not a step failure that blames the
                // wrong block.
                Phase::Main => "steps:",
            }));
        }
        let run_state = run_ledger(self.conn, self.run_id)?.state;
        if run_state != RunState::Running {
            return Ok(refuse(&format!(
                "the run is not `Running` (currently `{run_state:?}`), and must converge rather than wait on a human"
            )));
        }

        let awaiting = AwaitingHuman::from_crash_recovery(
            TaskId::new(),
            &format!(
                "step `{}` was interrupted mid-dispatch and its completion is unknown — re-run \
                 it, skip it, or fail the run?",
                step.id
            ),
            DEFAULT_HOLD_TTL,
            &crate::parse::types::OnTimeout::Fail,
        )?;
        let parked = park(
            self.conn,
            self.run_id,
            &awaiting,
            false,
            self.now,
            self.host,
        )?;
        self.emit_awaiting_human(executor, &step.id, &awaiting, &parked);
        // The step's row is deliberately **not** rewritten. It already says
        // `Running`, which is exactly what makes the next load reclassify it
        // `Indeterminate` again (`durability::recover_run`) — which is how
        // the human's answer finds the step it belongs to. Writing anything
        // else here would lose the classification the park exists to resolve.
        Ok(CrashPark::Parked(parked))
    }

    /// §8.12's `call:`, as far as one run's loop can take it: admit against
    /// §7.7's two bounds, decide the child's grant, create the child
    /// `workflow_run` (which draws that grant from this run, in the insert's
    /// own transaction), and emit the parent's `agent`-kind task standing for
    /// the call.
    ///
    /// The call remains `Running` until its child driver returns [`WorkDone`].
    /// That result becomes the call step's output; the child id is carried only
    /// in [`PendingKind::ChildRun`] while dispatch is outstanding.
    ///
    /// # The in-memory token and the durable draw are not two draws
    ///
    /// [`draw_child_budget`] is used for its **arithmetic** — `min(requested,
    /// remaining)` per field, with the three `Duration`s clamped rather than
    /// withdrawn, which is the rule §8.12 states and which nothing else in the
    /// crate implements. Its [`crate::compose::ChildBudget`] token is not the
    /// accounting: the accounting is the row, drawn by
    /// `insert_workflow_run` and returned by [`refund_child_run`] when the
    /// child ends, exactly as `ChildBudget`'s own doc names the durable
    /// re-derivation as its successor.
    ///
    /// # Measured: a `call:` is never refused for **funding**, because it clamps first
    ///
    /// Ruling P113's *"this retry needs $40 and the root has $12"* refusal is
    /// real, and it is **not reachable from here**. [`draw_child_budget`] takes
    /// `min(requested, remaining)` in every field, so the grant this arm asks
    /// the row to draw is by construction exactly what the parent still has —
    /// a call against an exhausted parent gets a grant of zero and fails on its
    /// own first step, rather than being refused at creation. That is the right
    /// behaviour (a sub-workflow that gets what is left is more useful than one
    /// that is refused), and the refusal still earns its place: the path that
    /// reaches it is `control::retry_from_step`, which **copies** the original's
    /// caps rather than clamping them, and is measured doing so in
    /// `tests/control.rs`.
    ///
    /// What *is* reachable from here is [`crate::ledger::admit_call_from_run`]
    /// refusing on §7.7's depth or fan-out, or on the run's state — and those
    /// are checked before anything is created.
    fn dispatch_call(
        &mut self,
        executor: &mut Executor<'_>,
        step: &StepDef,
        workflow: &str,
        with: &Value,
    ) -> CallStep {
        let called = match self
            .host
            .resolve_call(&*self.conn, workflow, self.session_id)
        {
            Ok(Some(called)) => called,
            Ok(None) => {
                return CallStep::Completed(StepOutcome::failed(
                    &step.id,
                    format!("`call:` names workflow {workflow:?}, which does not resolve to a job"),
                ))
            }
            Err(e) => {
                return CallStep::Completed(StepOutcome::failed(
                    &step.id,
                    format!("`call:` refused: {e}"),
                ))
            }
        };
        let direct_children = match self.host.reserve_child_session(self.session_id, &called) {
            Ok(count) => count,
            Err(e) => {
                return CallStep::Completed(StepOutcome::failed(
                    &step.id,
                    format!("`call:` refused: {e}"),
                ))
            }
        };
        let child_depth =
            match crate::ledger::admit_call_from_run(self.conn, self.run_id, direct_children) {
                Ok(depth) => depth,
                Err(e) => {
                    self.host.release_child_session(self.session_id, &called);
                    return CallStep::Completed(StepOutcome::failed(
                        &step.id,
                        format!("`call:` refused: {e}"),
                    ));
                }
            };

        let mut remaining = match remaining_caps(self.conn, self.run_id, self.now) {
            Ok(caps) => caps,
            Err(e) => {
                self.host.release_child_session(self.session_id, &called);
                return CallStep::Completed(StepOutcome::failed(
                    &step.id,
                    format!("`call:` refused: {e}"),
                ));
            }
        };
        let requested = requested_child_caps(step, &remaining);
        let grant = draw_child_budget(&mut remaining, &requested);

        let child_run_id = RunId::new();
        let child = WorkflowRun {
            id: child_run_id,
            job_id: called.job_id,
            job_version: called.job_version,
            content_hash: called.content_hash.clone(),
            session_id: called.session_id,
            // §8.6's binding/trigger columns answer "the previous run of this
            // binding". A child run is not a firing of a binding; it is a step
            // of one. Copying the parent's would make a `call:` child a
            // candidate answer to that question.
            binding_id: None,
            trigger_event_id: None,
            state: RunState::Running,
            parent_run_id: Some(self.run_id),
            forked_from_run_id: None,
            awaiting_until: None,
            checkpoint_ref: None,
            checkpoint_blob_ref: None,
            started_at: self.now,
            ended_at: None,
            // **The depth `admit_call_from_run` returned**, never a number
            // computed here. `insert_workflow_run` accepts any depth a caller
            // supplies, including `Some(0)`, so a loop that checked with the
            // predicate and then inserted its own number would re-open ruling
            // P76 §1 with the predicate still returning `Ok`.
            session_depth: Some(child_depth),
            caps: Some(grant.caps().clone()),
        };
        // §8.12: *"The parent's log gets one `agent`-kind task standing for the
        // call — identical to sub-agent spawning, which is the point."* The
        // `with:` block is interpolated and redacted on the way in, the same
        // as every other dispatch arm.
        let resolved_with = match crate::expr::interpolate_json(
            crate::expr::JsonTemplateSource::from_workflow_file(with),
            &executor.ctx,
        ) {
            Ok(resolved) => resolved,
            Err(e) => {
                self.host.release_child_session(self.session_id, &called);
                return CallStep::Completed(StepOutcome::failed(
                    &step.id,
                    format!("interpolating `call.with`: {e}"),
                ));
            }
        };
        let logged_with = redact_with_needles(
            resolved_with.redacted_for_logging(),
            &executor.redaction_needles,
        );
        let inputs_secret_derived = resolved_with.is_secret_derived();
        let dispatch_input = resolved_with.into_unredacted_for_dispatch();
        let parent_step = self.step_run(step, StepRunState::Running, None, None, None, None);
        let task_id = TaskId::new();
        let parent_call = WorkflowChildCall {
            child_run_id,
            parent_run_id: self.run_id,
            parent_step_id: step.id.clone(),
            parent_attempt: 1,
            parent_item_index: None,
            parent_task_id: task_id,
            join: ChildCallJoin::Pending,
        };
        let parent_task_input = TaskInput::Json(serde_json::json!({
            "workflow": workflow,
            "child_run_id": child_run_id.to_string(),
            "with": logged_with,
        }));
        if let Err(e) = self.host.create_child_run(
            self.conn,
            self.session_id,
            &child,
            &called,
            &parent_step,
            &parent_call,
            parent_task_input.clone(),
        ) {
            return CallStep::Completed(StepOutcome::failed(
                &step.id,
                format!("`call:` could not be funded: {e}"),
            ));
        }
        executor.sink.emit_already_persisted(
            task_id,
            None,
            TaskKind::Agent,
            EventPayload::TaskCreated {
                kind: TaskKind::Agent,
                parent: None,
                origin: Origin::System,
                input: parent_task_input,
            },
        );

        CallStep::AwaitingWork(PendingKind::ChildRun {
            child_run_id,
            child_session_id: called.session_id,
            parent_task_id: task_id,
            dispatch_input,
            inputs_secret_derived,
        })
    }
}

/// The child caps a `call:` asks for: the step's own `caps:` overlaid on a
/// **bounded share** of the parent's remaining ceiling.
///
/// # Why a share, and not the remainder (ruling P116 §A)
///
/// This used to default every field to `parent_remaining`. Combined with
/// rulings P113/P114 — *every* child run draws its grant at insert, and
/// [`Spend::for_grant`] charges the parent the child's **whole** grant up
/// front — that made an uncapped `call:` take everything the parent had left.
/// Every step after it was then refused `CapsExceeded`, **`finally:`
/// included**: §8.13's *"`finally:` runs"* defeated by the budget route that
/// [`admit_spend_during_finally`]'s admission exemption does not cover,
/// because this is the caps check, not the admission gate. The run always
/// ended `Failed`.
///
/// It was measured, not reasoned: with `max_tasks: 100` and one step spent,
/// the child drew all 99 remaining tasks and the parent's next `admit` refused.
/// Two things hid it — a test asserting the old behaviour as correct, and the
/// fact that **no fixture placed any step after a `call:`**.
///
/// The rule is per *field*, so a declared `caps:` block is honoured for what
/// it names and everything it does not name is bounded rather than total.
/// [`crate::parse::steps::CapsDef`] carries only `max_cost_usd` and
/// `max_tool_calls` — the two §8.9's reference workflow writes — so the other
/// five countables are the ones this default actually governs, which is the
/// sharper half: a `caps:` block does not save an author from it.
///
/// Asking is still not receiving: [`draw_child_budget`] takes
/// `min(requested, remaining)` per field, so a declared figure larger than the
/// parent's remainder is clamped to it.
fn requested_child_caps(step: &StepDef, parent_remaining: &ResourceCaps) -> ResourceCaps {
    let mut requested = bounded_child_share(parent_remaining);
    if let Some(caps) = &step.caps {
        if let Some(usd) = caps.max_cost_usd {
            requested.max_cost_usd = usd;
        }
        if let Some(tool_calls) = caps.max_tool_calls {
            requested.max_tool_calls = tool_calls;
        }
    }
    requested
}

/// Half of each of the parent's remaining countables — the *"bounded share,
/// never the remainder"* ruling P116 §A settles on, with the three
/// `Duration` ceilings passed through unchanged.
///
/// # Why not [`split_budget`](super::map_step::split_budget)`(remaining, 2)` verbatim
///
/// Ruling P116 §A names that call as "the shape", and it is — but reusing it
/// here would **not fix the defect**, which is why this is a second function
/// rather than a call to that one. `split_budget` divides `max_cost_usd`,
/// `max_tokens`, `max_tool_calls` and `max_bytes_written` and deliberately
/// passes `max_tasks`, `max_subagents` and `max_escalations` through whole —
/// correctly for its own caller, where the run-level cap is the meaningful
/// per-item ceiling and nothing is *withdrawn* from the parent.
///
/// A child-run draw is the opposite: [`Spend::for_grant`] charges the parent
/// **every** field of the grant, `max_tasks` included, and `max_tasks` is the
/// field that actually starves the run — the loop charges one task per step.
/// Measured against a parent with `max_tasks: 100` and 99 remaining:
/// `split_budget(&remaining, 2).max_tasks` is 99, the parent is charged 99,
/// and the step after the `call:` is refused exactly as before. So the
/// division has to cover the fields `for_grant` charges, which is all seven.
///
/// The three `Duration`s are not divided for the reason
/// [`draw_child_budget`] gives for clamping rather than withdrawing them: wall
/// clock is not a quantity a parent hands over.
fn bounded_child_share(remaining: &ResourceCaps) -> ResourceCaps {
    ResourceCaps {
        max_tokens: remaining.max_tokens / 2,
        max_cost_usd: remaining.max_cost_usd / 2.0,
        max_tasks: remaining.max_tasks / 2,
        max_tool_calls: remaining.max_tool_calls / 2,
        max_subagents: remaining.max_subagents / 2,
        max_bytes_written: remaining.max_bytes_written / 2,
        max_escalations: remaining.max_escalations / 2,
        run_wall_timeout: remaining.run_wall_timeout,
        run_active_timeout: remaining.run_active_timeout,
        step_timeout: remaining.step_timeout,
    }
}

impl<H: WorkflowHost> Loop<'_, H> {
    /// Ruling P112's two producers, in order: an authored `report:` step that
    /// completed, otherwise one assembled from the run's tasks.
    ///
    /// Returning a [`ReportPersisted`] is what lets [`finish_run`] be called
    /// at all, so there is no path from here to a terminal state that skips
    /// this function.
    ///
    /// An authored report's document is **emitted here**, not at its own step
    /// — [`super::ReportEmission`] says why, and it is what lets the
    /// `run_state` annotation carry the run's real terminal state rather than
    /// a guess made before `finally:` ran.
    fn ensure_report(
        &mut self,
        executor: &mut Executor<'_>,
        state: RunState,
    ) -> Result<ReportPersisted, RunLoopError> {
        let Some(step) = self.report_step.clone() else {
            return self.synthesise_report(executor, state);
        };

        // **The document is the gate, not the step's status.** With the emit
        // deferred, "the author wrote a report" and "there is a report
        // document to emit" are the same fact, and reading it off the slot
        // rather than off a second flag is what keeps them from disagreeing —
        // a `report:` step that failed, or that its `when:` skipped, leaves
        // the slot empty and falls through to synthesis with no special case
        // anywhere.
        let document = match take_deferred_report(executor) {
            Some(document) => Some(document),
            // Nothing ran it on this pass. If its row says it completed on an
            // earlier one, re-render: `report:` is an interpolation of
            // workflow source against a context this loop has already rebuilt
            // from the checkpoint rows, and the redaction that makes it safe
            // to persist needs live provenance the stored (unredacted) step
            // output cannot supply.
            //
            // Deliberately dispatched **here** rather than by un-skipping the
            // step in `run_phase`: that would re-admit it against the budget
            // and re-evaluate its `when:`, letting a condition that reads
            // differently now change a control-flow decision that already
            // happened ([`StepRunState::Skipped`]'s own argument).
            None if self.report_completed_before => {
                self.bind_steps_context(executor);
                executor.dispatch_step(&step);
                take_deferred_report(executor)
            }
            None => None,
        };

        match document {
            Some(document) => {
                persist_report(executor, document, state)
                    .map_err(RunLoopError::AnnotatedReportInvalid)?;
                Ok(ReportPersisted(ReportOrigin::Authored { step_id: step.id }))
            }
            // The `report:` step failed, was skipped by its own `when:`, never
            // ran, or re-rendered into something that no longer validates.
            // §8.6 still owes this run a report, so the second producer runs.
            None => self.synthesise_report(executor, state),
        }
    }

    /// §4.2's *"input: none (assembled from the run's tasks)"*.
    ///
    /// # Why every terminal state gets one, including the unhappy ones
    ///
    /// Ruling P112, and the argument rather than the authority: **the inbox
    /// exists to triage, and a run that failed or was cancelled needs triage
    /// more than one that succeeded.** §8.6 sorts on
    /// `(needs_human, severity, outcome != nothing)`, so a report is exactly
    /// the mechanism by which such a run surfaces. Without one the Runs inbox
    /// would silently omit precisely the runs an operator most needs to see —
    /// omission, not error, which is the harder failure to notice.
    ///
    /// That is also why a `Cancelled` run reports [`Outcome::Failed`] rather
    /// than [`Outcome::Nothing`](crate::report::Outcome::Nothing): `nothing`
    /// is the value the sort pushes to the bottom, and a run an operator
    /// stopped by hand is not a run that found nothing.
    ///
    /// # What it is assembled from
    ///
    /// The run's own step outcomes and its ledger row — `cost` is
    /// `spent_cost_usd`/`spent_tokens`, the numbers Phase 2's accounting
    /// recorded through [`admit_spend`], never a figure invented here. Each
    /// failed step becomes one finding whose `id` and `location` are the step
    /// id (workflow source text) and whose `title` is the step's own bounded
    /// diagnostic.
    ///
    /// # Redacted, then validated, then emitted — in that order
    ///
    /// The same order and for the same reasons as the authored path: the
    /// document that reaches the sink is the redacted one, validation runs on
    /// exactly the bytes that will be persisted, and nothing is emitted if
    /// validation fails. A step's failure message is *this crate's* diagnostic
    /// text plus, for an evaluation failure, a bounded prefix of the offending
    /// workflow-source field — which can be a credential an author pasted
    /// literally into the YAML, and which no provenance can see. That is
    /// exactly what [`redact_with_needles`] exists to catch.
    ///
    /// **And here, unlike on the authored path, "redaction can only ever steer
    /// valid -> invalid" is not a safe direction** (ruling P117 §D). There the
    /// invalid document fails one step and the run goes on to end. Here there
    /// is no step to fail: a `secrets` value that redaction substitutes into a
    /// field validation constrains — a secret whose literal value is
    /// `findings`, say, redacting `outcome` to `***` — returns
    /// [`RunLoopError::SynthesisedReportInvalid`], and since `finish_run`
    /// cannot be reached without a [`ReportPersisted`], the run reaches **no**
    /// terminal state on this drive or any later one. Absurdly narrow, and the
    /// same shape as the Critical this fix round closed, so it is written down
    /// rather than left to be rediscovered.
    fn synthesise_report(
        &mut self,
        executor: &mut Executor<'_>,
        state: RunState,
    ) -> Result<ReportPersisted, RunLoopError> {
        let ledger = run_ledger(self.conn, self.run_id)?;
        let failures: Vec<&StepOutcome> = self
            .outcomes
            .iter()
            .filter(|o| matches!(o.status, StepStatus::Failed { .. }))
            .collect();

        let (outcome, severity, needs_human) = match state {
            RunState::Failed => ("failed", "high", true),
            RunState::Cancelled => ("failed", "med", true),
            _ if !failures.is_empty() => ("findings", "med", false),
            _ => ("nothing", "low", false),
        };
        let headline = match state {
            RunState::Cancelled => "run cancelled".to_string(),
            RunState::Failed => match failures.first() {
                Some(first) => format!("run failed at step `{}`", first.step_id),
                None => "run failed".to_string(),
            },
            _ if failures.is_empty() => format!("run completed: {} steps", self.outcomes.len()),
            _ => format!(
                "run completed with {} non-fatal step failures",
                failures.len()
            ),
        };
        let findings: Vec<Value> = failures
            .iter()
            .map(|o| {
                let message = match &o.status {
                    StepStatus::Failed { message } => message.as_str(),
                    _ => unreachable!("filtered to Failed above"),
                };
                serde_json::json!({
                    "id": o.step_id,
                    // The **third** sink for a step's failure message, and
                    // until B12c's fix round the only unbounded one: the other
                    // two are `durability`'s `MAX_STORED_STEP_ERROR_LEN` and
                    // `exec`'s `MAX_STEPS_CONTEXT_ERROR_LEN`, both 512. A
                    // `call:` naming a workflow whose name is arbitrarily long
                    // produces an arbitrarily long step failure, and this
                    // finding title is written into a table that physically
                    // rejects `UPDATE`/`DELETE`.
                    "title": truncate_diagnostic(message, MAX_FINDING_TITLE_LEN).as_ref(),
                    "severity": "high",
                    "location": o.step_id,
                })
            })
            .collect();

        let document = serde_json::json!({
            "outcome": outcome,
            "severity": severity,
            "headline": headline,
            "needs_human": needs_human,
            "cost": { "usd": ledger.spent.cost_usd, "tokens": ledger.spent.tokens },
            "findings": findings,
            "artifacts": [],
            "next_actions": [],
            // §8.6's extension half, carrying the one fact a reader cannot
            // recover from the core: this report was assembled by the run loop
            // rather than written by the job's author, so its `headline` and
            // `findings` are generic by construction.
            "synthesised_by": "run_loop",
        });
        let logged = redact_with_needles(&document, &executor.redaction_needles);
        persist_report(executor, logged, state).map_err(RunLoopError::SynthesisedReportInvalid)?;
        Ok(ReportPersisted(ReportOrigin::Synthesised))
    }
}

/// §8.6's extension key carrying the run's **real** terminal state (ruling
/// P117 §C).
///
/// The one fact about a run that its report cannot otherwise be trusted for:
/// an authored `report:` that completed before a later step failed says
/// `outcome: changed, needs_human: false` about a run that is `Failed`, and
/// §8.6's `(needs_human, severity, outcome != nothing)` sort then buries
/// exactly the run ruling P112 exists to surface. The core half is the
/// author's judgement and stays theirs; this is the loop's fact, on the half
/// §8.6 leaves open for facts.
///
/// The alternative considered and rejected was refusing an authored `report:`
/// outside `finally:` — that forbids the ordinary authoring pattern to work
/// around an accounting bug.
const RUN_STATE_KEY: &str = "run_state";

/// A step's failure message, on its way into a synthesised report's finding
/// `title`. Matches `durability`'s `MAX_STORED_STEP_ERROR_LEN` and `exec`'s
/// `MAX_STEPS_CONTEXT_ERROR_LEN`, the other two sinks for the same text, and
/// carries the same status they document: a round number, not a figure
/// derived from any analysis.
const MAX_FINDING_TITLE_LEN: usize = 512;

/// Takes the document an authored `report:` step handed back instead of
/// emitting — see [`super::ReportEmission`]. `None` when no `report:` step ran
/// on this pass.
fn take_deferred_report(executor: &mut Executor<'_>) -> Option<Value> {
    match &mut executor.report_emission {
        ReportEmission::Deferred(slot) => slot.take(),
        // Unreachable from this module: `run_workflow` sets `Deferred` before
        // any step dispatches. Written out rather than left to a `_` so that a
        // third emission mode is a compile error here.
        ReportEmission::Immediate => None,
    }
}

/// Annotates the run's terminal state onto a report's extension half,
/// re-validates, and emits the one `TaskKind::Report` task the run leaves
/// behind. Both of §8.6's producers end here, so there is one place where a
/// report reaches the log.
///
/// **Annotate, then validate, then emit** — the order the authored path
/// already documents for redaction, and for the same reason: the bytes that
/// are validated are byte-for-byte the bytes that are persisted, in a table
/// that physically rejects `UPDATE`/`DELETE`. A `run_state` the author had
/// also written is overwritten, deliberately: the loop's is the fact.
///
/// Returns the validation error's text rather than a [`RunLoopError`] so the
/// two callers can each blame the right author — see
/// [`RunLoopError::AnnotatedReportInvalid`].
fn persist_report(
    executor: &mut Executor<'_>,
    document: Value,
    state: RunState,
) -> Result<(), String> {
    let mut annotated = document;
    if let Value::Object(fields) = &mut annotated {
        fields.insert(
            RUN_STATE_KEY.to_string(),
            Value::String(state.wire_name().to_string()),
        );
    }
    validate_report(&annotated).map_err(|e| e.to_string())?;

    let task_id = TaskId::new();
    executor.sink.emit(
        task_id,
        None,
        TaskKind::Report,
        EventPayload::TaskCreated {
            kind: TaskKind::Report,
            parent: None,
            origin: Origin::System,
            input: TaskInput::Json(annotated.clone()),
        },
    );
    executor.sink.emit(
        task_id,
        None,
        TaskKind::Report,
        EventPayload::TaskCompleted {
            output: TaskOutput::Json(annotated),
            usage: Usage::default(),
        },
    );
    Ok(())
}

/// Ruling P117 §A leg 2, at the only level it is reachable.
///
/// The retry defends a window between [`run_workflow`]'s state read and
/// [`finish_run`]'s write, which a single-threaded integration test over an
/// **in-memory** database cannot construct — there is no second connection to
/// the same database and no hook that hands a caller the loop's own
/// `&mut Connection` mid-run. `finish_run` is module-private, so this is where
/// the retry can be handed the state that fails and asked what it does.
///
/// The `Paused` sibling is here for the same reason and closes differently:
/// no retry, one matrix edge (`Paused -> Completed`) that was missing.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::durability::{insert_workflow_run, open_test_db, recover_run};
    use roundhouse_core::JobId;

    /// A host that does nothing, for the two tests below that drive
    /// [`finish_run`] directly.
    ///
    /// Both seed a **root** run, so neither reaches the one host call
    /// `finish_run` makes. `terminated` records it anyway rather than
    /// ignoring it: a root run that reported a child termination would be
    /// handing `SpawnTree::remove_child` a parent it invented, and this is
    /// the level at which that is visible.
    #[derive(Default)]
    struct NoopHost {
        terminated: Vec<(SessionId, SessionId)>,
    }

    impl Checkpointer for NoopHost {
        fn checkpoint(
            &mut self,
            _session_id: SessionId,
            _run_id: RunId,
            _label: &str,
        ) -> Result<crate::parking::CheckpointRef, CheckpointError> {
            unreachable!("these tests run no steps, so nothing is checkpointed")
        }
    }

    impl WorkflowHost for NoopHost {
        fn resolve_call(
            &mut self,
            _conn: &Connection,
            _workflow: &str,
            _parent: SessionId,
        ) -> Result<Option<CalledWorkflow>, WorkflowHostError> {
            unreachable!("these tests run no `call:` step")
        }

        fn reserve_child_session(
            &mut self,
            _parent: SessionId,
            _child: &CalledWorkflow,
        ) -> Result<u32, WorkflowHostError> {
            unreachable!("these tests run no `call:` step")
        }

        fn release_child_session(&mut self, _parent: SessionId, _child: &CalledWorkflow) {
            unreachable!("these tests run no `call:` step")
        }

        fn create_child_run(
            &mut self,
            _conn: &mut Connection,
            _parent: SessionId,
            _child: &WorkflowRun,
            _called: &CalledWorkflow,
            _parent_step: &WorkflowStepRun,
            _parent_call: &WorkflowChildCall,
            _parent_task_input: TaskInput,
        ) -> Result<(), WorkflowHostError> {
            unreachable!("these tests run no `call:` step")
        }

        fn child_session_terminated(&mut self, parent: SessionId, child: SessionId) {
            self.terminated.push((parent, child));
        }
    }

    fn seeded_run(conn: &mut Connection) -> (RunId, SessionId) {
        let run_id = RunId::new();
        let session_id = SessionId::new();
        insert_workflow_run(
            conn,
            &WorkflowRun {
                id: run_id,
                job_id: JobId::new(),
                job_version: 1,
                content_hash: "sha256:pinned".into(),
                session_id,
                binding_id: None,
                trigger_event_id: None,
                state: RunState::Running,
                parent_run_id: None,
                forked_from_run_id: None,
                awaiting_until: None,
                checkpoint_ref: None,
                checkpoint_blob_ref: None,
                started_at: Timestamp::from_unix_nanos(0),
                ended_at: None,
                session_depth: Some(0),
                caps: Some(ResourceCaps::default()),
            },
        )
        .expect("seed the run row");
        (run_id, session_id)
    }

    #[test]
    fn a_cancel_that_raced_the_terminal_write_lands_cancelled_not_stranded() {
        let mut conn = open_test_db();
        let (run_id, session_id) = seeded_run(&mut conn);
        // The operator's cancel, arriving after `run_workflow` read the state
        // and before it wrote the terminal one.
        transition_run(
            &mut conn,
            run_id,
            RunState::Cancelling,
            Timestamp::from_unix_nanos(1),
        )
        .expect("Running -> Cancelling");

        let mut host = NoopHost::default();
        let landed = finish_run(
            &mut conn,
            &mut host,
            run_id,
            session_id,
            RunState::Completed,
            Timestamp::from_unix_nanos(2),
            &ReportPersisted(ReportOrigin::Synthesised),
        )
        .expect("the run reaches a terminal state rather than being stranded");
        assert!(
            host.terminated.is_empty(),
            "a root run releases no parent's fan-out slot"
        );

        assert_eq!(
            landed,
            RunState::Cancelled,
            "an operator's cancel outranks the loop's `Completed`, and is not \
             misreported as `Failed`"
        );
        let row = recover_run(&conn, run_id).unwrap().run;
        assert_eq!(row.state, RunState::Cancelled);
        assert!(
            row.ended_at.is_some(),
            "and `ended_at` is stamped — the run does not look live forever"
        );
    }

    #[test]
    fn a_pause_that_raced_the_terminal_write_still_completes_the_run() {
        let mut conn = open_test_db();
        let (run_id, session_id) = seeded_run(&mut conn);
        crate::control::pause(&mut conn, run_id, Timestamp::from_unix_nanos(1))
            .expect("Running -> Paused");

        let mut host = NoopHost::default();
        let landed = finish_run(
            &mut conn,
            &mut host,
            run_id,
            session_id,
            RunState::Completed,
            Timestamp::from_unix_nanos(2),
            &ReportPersisted(ReportOrigin::Synthesised),
        )
        .expect("a run paused after its last step still ends");

        assert_eq!(
            landed,
            RunState::Completed,
            "a paused run whose steps all ran did complete — unlike a \
             cancelled one, which did not"
        );
        let row = recover_run(&conn, run_id).unwrap().run;
        assert_eq!(row.state, RunState::Completed);
        assert!(row.ended_at.is_some());
    }
}
