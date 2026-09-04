//! §8.11's *"Parking must be stateless"* — the half of it this crate can
//! actually build (Task 17, B9).
//!
//! Two things already existed and this module connects them; it invents no
//! third representation of a park:
//!
//! - **In:** [`crate::hitl::AwaitingHuman`] (Task 15), whose
//!   [`timeout_after`](crate::hitl::AwaitingHuman::timeout_after) is a
//!   **relative** [`Duration`] and which is deliberately `Serialize` but not
//!   `Deserialize`.
//! - **Out:** [`crate::durability::WorkflowRun::awaiting_until`] (Task 16), a
//!   nullable **absolute** unix-nanosecond column, together with
//!   [`RunState::AwaitingHuman`].
//!
//! [`park`] is the relative -> absolute conversion between them, and it is
//! keyed by [`RunId`]: §8.11 parks a *workflow run*, not a session (a
//! `SessionId` is a field of the run row, not its key).
//!
//! # Why the deadline is stored absolute, and why nothing here serializes a park
//!
//! A park record stored as a relative window is re-anchored every time it is
//! read back, so a re-driven run gets a fresh full window on each resume —
//! `deny`/`fail` would never fire and the 7-day reaper would become the only
//! bound. That is the exact failure `AwaitingHuman`'s missing `Deserialize`
//! was written to prevent, and it is why [`ParkResult`] carries
//! [`Timestamp`]s rather than a `Duration` TTL: **the durable truth is the
//! row**, and even the in-process return value states an instant rather than
//! a window, so no caller can persist a re-anchorable value by accident.
//!
//! # This module never reads a clock
//!
//! `now` is a parameter of [`park`], [`absolute_deadline`] and
//! [`reaper_cutoff`], exactly as it is of `durability`'s writers and of
//! `roundhouse_store::blobs::gc_eligible_blobs`. `roundhouse_core::Timestamp`
//! has no `now()` and no arithmetic at all, so this module hand-rolls
//! `now + duration` in [`absolute_deadline`], `i64`-overflow-checked
//! ([`Duration::as_nanos`] is a `u128`).
//!
//! # The deadline does NOT go on the scheduler's timer heap from here
//!
//! §8.11 says *"Deadlines use the same timer heap as triggers; there is
//! exactly one scheduler"*. It does not say **this crate** talks to that
//! heap, and this crate cannot: §5.2's row for `roundhouse-flow` is `core,
//! engine, store`. Four properties of `roundhouse-sched` as it stands today
//! also make the heap unable to hold a park deadline, recorded here so the
//! obligation stays visible rather than being lost between tasks:
//!
//! 1. `Scheduler::add_binding` is the only insertion point and admits only a
//!    `Binding` (which needs a `job_id` and a `TriggerSpec`).
//! 2. `TriggerSpec` has no one-shot / fire-at-an-instant variant; `Interval`
//!    is recurring.
//! 3. **There is no removal or cancel API at all.** This one is decisive: a
//!    park deadline must be cancellable, because the human usually answers
//!    before the timeout.
//! 4. `SchedulerEvent::Fire` carries only a `BindingId`, so a firing cannot
//!    say "run R timed out".
//!
//! **This crate computes and persists `awaiting_until`; the daemon — the
//! crate §5.2 permits to depend on both — registers and cancels the
//! deadline.**
//!
//! # What §8.11 asks for that is NOT built here, and who owns it
//!
//! §8.11: *"`AwaitingHuman` releases the worker slot, the provider
//! connection, and (unless `hold_workspace: true` with a TTL) the
//! worktree."* None of those three releases is performed here, and none is
//! simulated — a `workspace_released: true` flag from a crate that cannot
//! touch a worktree would be a claim, not a release:
//!
//! - **Releasing the worktree** — no worktree creation *or* teardown code
//!   exists anywhere in `crates/`; `exec::map_step`'s module doc already
//!   records that this crate has no git or process-spawning dependency and
//!   so cannot invoke `git worktree`. [`ParkResult::workspace`] is therefore
//!   a *directive to the caller* ([`WorkspaceDisposition`]), not a report of
//!   something done.
//! - **Releasing the worker slot** — there is no admission or slot concept
//!   in this crate (`roundhouse-sched`'s `admission` is trigger *overlap*, a
//!   different thing). Unowned.
//! - **Releasing the provider connection** — lives in `roundhouse-engine`'s
//!   `SessionActor`. Unowned here.
//! - **The implicit `checkpoint` task (§4.2)** — `TaskKind::Checkpoint` is a
//!   bare enum variant with zero producers tree-wide, and its real job
//!   (capturing untracked and staged-but-uncommitted files) is filesystem
//!   and git work this crate cannot reach. [`Checkpointer`] is the trait the
//!   owner of that work implements; this crate ships the trait, calls it in
//!   §8.11's order, and a test fake.
//! - **Active-vs-parked time accounting** (§8.4's `run_active_timeout`
//!   "excludes `AwaitingHuman`") — **built by B12b** (ruling P77 split Task
//!   20 in three), which added migration 0008's `parked_at`/`parked_nanos`
//!   and [`crate::ledger::active_elapsed`] over them. It needed a durable
//!   column to live in; an in-memory tracker would be lost on the first
//!   daemon restart, which is precisely the case it exists to measure. This
//!   module's [`park`] is what starts a park interval, through
//!   `durability`'s `transition`; nothing here reads the accumulator.
//! - **The reaper's periodic runner** — **still daemon-side and unowned**
//!   (ruling P77 §C moved it out of Task 20 entirely, since it shares its
//!   missing machinery with `blobs.rs`'s daily GC and one owner should take
//!   both). Its *input* is no longer missing: ruling P72's finding was that,
//!   unlike `blobs.rs`'s runner-only gap, `reaper_cutoff(parked_at, now)` had
//!   no durable source for `parked_at` anywhere in the schema — B12b added
//!   the column and [`crate::ledger::parked_runs_past_hold_cap`], the query
//!   in `gc_eligible_blobs`'s shape. What is left really is only the timer.
//! - **A `Duration::ZERO` screen for `timeout_after`.** No document-driven
//!   path produces one today — [`AwaitingHuman::from_gate`] rejects it and
//!   `TryFrom<&UnattendedDef>` rejects it before `from_escalate` ever sees
//!   it — and [`crate::hitl::HumanWaitSource::Elicitation`] has no
//!   constructor at all, so
//!   the only way to reach [`park`] with `timeout_after: Some(Duration::ZERO)`
//!   today is to hand-build an [`AwaitingHuman`], as
//!   `tests/parking.rs`'s elicitation fixtures do. [`absolute_deadline`]
//!   would turn that into `awaiting_until == now`: not wrong, but a park
//!   that expires the instant it is taken. The screen belongs either in
//!   whichever crate builds the real elicitation constructor, or in
//!   `absolute_deadline`/`park` directly once one exists — recorded here
//!   because neither exists yet.
//!
//! # The reaper's periodic runner does not exist — but since B12b its input does
//!
//! [`reaper_cutoff`] is a pure predicate in the shape of
//! `roundhouse_store::blobs::gc_eligible_blobs`, and the periodic runner
//! that would call it on a schedule is unowned daemon work: there is no
//! periodic-task machinery in `roundhouse-daemon` at all today (verified by
//! grep: one `tokio::spawn`, the socket accept loop, and no call to
//! `Scheduler::tick` anywhere). **That much of the comparison to
//! `blobs.rs`'s daily GC always held** — both want the identical missing
//! timer.
//!
//! **The rest of the comparison did not, and an earlier version of this note
//! stated it as an unqualified "same as `blobs.rs`", which was wrong (ruling
//! P72).** `gc_eligible_blobs` queries **real columns**; for it, the timer
//! really was the only missing piece. `reaper_cutoff(parked_at, now)` had
//! **no durable source for `parked_at` anywhere in the schema**:
//! `workflow_run` carried `started_at` (run start, not park time) and
//! `awaiting_until`; `workflow_step_run` has no timestamp column at all; and
//! [`WorkspaceDisposition::HoldUntil`] was an in-process return value that
//! survived no restart. `awaiting_until` cannot stand in for it — it is the
//! *wait's* own deadline, deliberately **not** clamped to
//! [`SYSTEM_WIDE_HOLD_CAP`] (see [`park`]'s "two different quantities"
//! section), and it is `NULL` in exactly the windowless-elicitation case
//! that can still hold a workspace.
//!
//! **B12b closed that half and only that half.** Migration 0008 adds
//! `workflow_run.parked_at` (written here, through `durability`'s
//! `transition`, and preserved across a re-park so the clock cannot be
//! reset), `hold_until` — the durable form of
//! [`WorkspaceDisposition::HoldUntil`] — and
//! [`crate::ledger::parked_runs_past_hold_cap`], the query
//! `gc_eligible_blobs`'s shape implies. So the two crates' remaining gaps are
//! now genuinely identical, which is what the original analogy claimed
//! prematurely: **a timer, and nothing else.**

use crate::durability::{transition_run_to_awaiting_human, DurabilityError};
use crate::exec::RunId;
use crate::hitl::AwaitingHuman;
use roundhouse_core::{SessionId, Timestamp};
use rusqlite::{params, Connection, OptionalExtension};
use std::time::Duration;
use thiserror::Error;

/// §8.11: *"With no explicit gate timeout, fall back to 72h."*
///
/// **Reachable only from an elicitation, not from a gate.** A `gate:` step's
/// `timeout:` is mandatory in the wire shape (`parse::steps::GateBodyDef`
/// has no `#[serde(default)]` on it), and `Escalate::Park` always carries a
/// deadline, so `AwaitingHuman::timeout_after` is `None` only for
/// `HumanWaitSource::Elicitation` — a mid-step elicitation with no declared
/// window. That is the one path this constant serves.
pub const DEFAULT_HOLD_TTL: Duration = Duration::from_secs(72 * 3600);

/// §8.11: *"a system-wide 7-day cap is enforced by a reaper regardless of
/// what any individual gate specifies"*.
///
/// This bounds the **workspace hold**, not the wait. See
/// [`resolve_hold_ttl`] and [`park`] for why those are two different
/// quantities.
pub const SYSTEM_WIDE_HOLD_CAP: Duration = Duration::from_secs(7 * 86400);

/// [`SYSTEM_WIDE_HOLD_CAP`] in the unit [`reaper_cutoff`] compares in.
///
/// **Derived, not restated**, so the two cannot drift apart into a clamp and
/// a reaper that disagree — the failure mode the "two legs of the same rule"
/// note on [`resolve_hold_ttl`] describes.
///
/// Goes through [`Duration::as_nanos`] rather than
/// `as_secs() as i64 * 1_000_000_000`: `as_nanos` is `const`, exact for the
/// current whole-week value, and stays exact if this constant is ever
/// edited to a non-whole-second duration — `as_secs()` would silently
/// truncate that precision away before the multiply ever ran. The remaining
/// `u128 -> i64` narrowing is exact for the current value (604,800 seconds
/// in nanoseconds is far under `i64::MAX`), but it is **not** a
/// self-defending guard the way the multiply it replaces would have been:
/// an `as` cast that no longer fits truncates silently rather than failing
/// the build, unlike the arithmetic overflow the const evaluator rejects at
/// compile time. A future edit large enough to overflow this cast would not
/// be caught here.
const SYSTEM_WIDE_HOLD_CAP_NANOS: i64 = SYSTEM_WIDE_HOLD_CAP.as_nanos() as i64;

/// A handle to the restore point §8.11's implicit `checkpoint` task
/// produces. Opaque text, because the shape belongs to whoever implements
/// [`Checkpointer`] and this crate never interprets it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRef(pub String);

/// Why a checkpoint could not be taken.
///
/// Deliberately a message rather than a taxonomy: every implementation of
/// [`Checkpointer`] lives outside this crate (git and filesystem work, see
/// the module doc), so this crate has no vocabulary of its own for the ways
/// it can fail — only the obligation to refuse to park when it does.
///
/// **Doc contract for implementors — not enforced by this crate.**
/// `message` never reaches a database column; it only flows into
/// [`ParkError`]'s `Display`, which is log-only, so this crate adds no
/// truncation machinery of its own here (contrast `durability.rs`'s
/// `truncate_stored_step_error`, which bounds the same class of text at its
/// funnel *because* that text does reach a column). But a [`Checkpointer`]
/// implementation is out-of-crate git/filesystem code that can see
/// arbitrarily large or sensitive text — a diff, a path under a secret
/// directory, a git error that echoes file contents — so an implementation
/// MUST keep `message` short (comfortably under a few hundred bytes, the
/// same order of magnitude other diagnostic text in this crate is bounded
/// to) and MUST NOT include secret material. Nothing here checks either
/// property; both are the contract this field's producer takes on.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("the implicit checkpoint task failed: {message}")]
pub struct CheckpointError {
    pub message: String,
}

/// §8.11's *"Before releasing, it runs an implicit `checkpoint` task
/// (§4.2)"* — *"a plain git ref alone wouldn't capture untracked or
/// staged-but-uncommitted files, but the checkpoint mechanism already
/// designed for restore points does, so releasing never loses anything a
/// resume would need."*
///
/// A trait rather than an implementation because that work is filesystem and
/// git work `roundhouse-flow` structurally cannot do: `TaskKind::Checkpoint`
/// exists in `roundhouse-core` as a bare enum variant with **zero producers
/// anywhere in the tree**, and this crate depends on `core`, `engine` and
/// `store` only. The owner of the checkpoint mechanism implements this; the
/// tests here use a fake.
///
/// **Fallible on purpose.** If the checkpoint cannot be taken, the release
/// §8.11 gates on it must not happen — so [`park`] calls this first and
/// refuses to write anything when it fails. An infallible signature would
/// force an implementor to swallow the failure or panic, and would turn
/// §8.11's ordering into a comment instead of a control-flow fact.
pub trait Checkpointer {
    /// `label` names why the checkpoint was taken; [`park`] passes
    /// `"awaiting_human_park"`.
    fn checkpoint(
        &mut self,
        session_id: SessionId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError>;
}

/// What the caller must do with the run's worktree — **a directive, not a
/// report**. Nothing in this crate can create or tear down a worktree (see
/// the module doc), so this says what should happen and names an absolute
/// instant for the holding case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDisposition {
    /// `hold_workspace` was not set: §8.11's default, release the worktree
    /// now that the checkpoint has been taken.
    Release,
    /// `hold_workspace: true`: keep the worktree until this **absolute**
    /// instant, already clamped to [`SYSTEM_WIDE_HOLD_CAP`].
    ///
    /// An absolute [`Timestamp`] rather than a TTL `Duration` for the reason
    /// in the module doc: a relative hold with no anchor is re-anchored on
    /// every read.
    ///
    /// Since B12b this value is also **persisted**, to
    /// `workflow_run.hold_until` in the same transaction as the park itself
    /// — so a daemon that restarts mid-hold can still find out which
    /// worktrees it owes a teardown to, which this in-process directive alone
    /// could never tell it. The directive is still a directive: nothing in
    /// this crate can touch a worktree.
    HoldUntil(Timestamp),
}

/// What [`park`] did, for the caller that must act on it. The **durable**
/// record is the `workflow_run` row; this is the in-process echo of it plus
/// the two things that are not columns (the checkpoint handle and the
/// worktree directive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParkResult {
    /// The restore point taken before anything was released.
    pub checkpoint_ref: CheckpointRef,
    /// The session that was checkpointed — read from the run row, not
    /// supplied by the caller (see [`park`]). Returned so the caller can act
    /// on it (§8.11's provider-connection release is per-session) without
    /// querying for it again.
    pub session_id: SessionId,
    /// Exactly the value written to `workflow_run.awaiting_until`. `None`
    /// means the wait has no deadline at all (an elicitation with no
    /// declared window), in which case `on_timeout` never fires and the
    /// reaper is the only bound.
    pub awaiting_until: Option<Timestamp>,
    /// What the caller must do with the worktree.
    pub workspace: WorkspaceDisposition,
}

/// Why a park failed.
///
/// **Every variant means nothing *durable* was written; the variants
/// reachable after the checkpoint has already been taken may leave behind
/// an unused restore point.** Those are [`Sqlite`](Self::Sqlite) and
/// [`Durability`](Self::Durability) — everything the write itself can
/// report, including the transition-legality refusal. `DeadlineOverflow`,
/// `MalformedId`, `Checkpoint`, and [`RunNotFound`](Self::RunNotFound) all
/// fail before any checkpoint is taken, so for those four nothing at all is
/// left behind, durable or not.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ParkError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The run has no `workflow_run` row, as [`park`]'s own pre-checkpoint
    /// read found (see [`run_session_id`]). The application-level leg of the
    /// reference `durability::checkpoint_step` also checks for the row's
    /// existence, for the same reason: no connection in this workspace sets
    /// `PRAGMA foreign_keys = ON`, so a declared `FOREIGN KEY` would be
    /// inert.
    ///
    /// **This variant no longer doubles as "wrong state"** (Task 20a). The
    /// write's zero-row `UPDATE` used to raise it for a run whose `WHERE`
    /// clause did not match, which for a run in a state that cannot be
    /// parked was a lie: the row was right there. That case is now
    /// `Durability(DurabilityError::IllegalTransition { .. })`.
    ///
    /// **This variant's twin, if the row vanishes between the two reads
    /// instead of never existing** (fix round 1, Task 20a): this is
    /// [`park`]'s own *pre-checkpoint* read finding no row; if the row is
    /// present here but gone by the time the write's own read runs inside
    /// [`durability::transition_run_to_awaiting_human`](crate::durability),
    /// the same fact surfaces as
    /// `Self::Durability(DurabilityError::RunNotFound)` instead — still
    /// expressed as two different variants for one underlying condition, not
    /// flattened into one taxonomy.
    #[error("no workflow_run row for run {run_id}")]
    RunNotFound { run_id: RunId },
    /// The durable write refused. Most importantly
    /// [`DurabilityError::IllegalTransition`] — the source-state check
    /// `park` did not used to make, which is what stops a park from
    /// resurrecting a terminal run or un-cancelling a cancel in flight (see
    /// [`park`]'s "Transition legality" section) — and
    /// [`DurabilityError::RunSessionMismatch`], the session precondition
    /// that used to be a bound `AND session_id = ?` with no signal of its
    /// own.
    #[error(transparent)]
    Durability(#[from] DurabilityError),
    /// A stored id column does not parse as a UUID — the read-back leg of
    /// the same rule `durability::DurabilityError::MalformedId` states, and
    /// the offending text is withheld for the same reason: it is not needed
    /// to locate the row, since the query that produced it names one.
    #[error("column {column} does not hold a valid UUID")]
    MalformedId { column: &'static str },
    /// §8.11's implicit checkpoint failed, so nothing was released and
    /// nothing was parked.
    #[error(transparent)]
    Checkpoint(#[from] CheckpointError),
    /// `now + after` is not representable as a unix-nanosecond `i64`.
    /// Surfaced rather than saturated: saturating would silently produce a
    /// deadline the author did not ask for, and wrapping would produce one
    /// in the past — a park born already expired.
    #[error("a park at {now_unix_nanos} lasting {after:?} is not a representable unix-nanosecond instant")]
    DeadlineOverflow {
        now_unix_nanos: i64,
        after: Duration,
    },
}

/// `now + after`, as an absolute unix-nanosecond [`Timestamp`].
///
/// Hand-rolled because `roundhouse_core::Timestamp` has no arithmetic and no
/// `Add<Duration>`, and there is no equivalent helper anywhere in `crates/`.
/// Both narrowing steps are checked: [`Duration::as_nanos`] returns a `u128`
/// that a large `Duration` overflows on the way into `i64`, and the addition
/// itself can overflow even when the delta fits.
pub fn absolute_deadline(now: Timestamp, after: Duration) -> Result<Timestamp, ParkError> {
    let overflow = || ParkError::DeadlineOverflow {
        now_unix_nanos: now.as_unix_nanos(),
        after,
    };
    let delta = i64::try_from(after.as_nanos()).map_err(|_| overflow())?;
    now.as_unix_nanos()
        .checked_add(delta)
        .map(Timestamp::from_unix_nanos)
        .ok_or_else(overflow)
}

/// §8.11's TTL rule for `hold_workspace`, in one place:
/// *"**`hold_workspace`'s TTL defaults to the enclosing gate's own
/// `timeout`** ... With no explicit gate timeout, fall back to 72h. Either
/// way, **a system-wide 7-day cap is enforced ... regardless of what any
/// individual gate specifies**."*
///
/// `gate_timeout` is the human wait's own relative window
/// (`AwaitingHuman::timeout_after`), so a gate that already said `timeout:
/// 24h` needs no second, disconnected knob.
///
/// The clamp here and [`reaper_cutoff`] are the two legs of the same rule —
/// compute-time and enforcement-time. The clamp alone would not bound a hold
/// registered before the cap existed or one whose deadline was never
/// cancelled; the reaper alone would let a 30-day hold look legitimate to
/// everything that reads the row.
pub fn resolve_hold_ttl(gate_timeout: Option<Duration>) -> Duration {
    gate_timeout
        .unwrap_or(DEFAULT_HOLD_TTL)
        .min(SYSTEM_WIDE_HOLD_CAP)
}

/// Parks a workflow run on §8.11's one mechanism: takes the implicit
/// checkpoint, then writes [`RunState::AwaitingHuman`] and the **absolute**
/// `awaiting_until` in a single `BEGIN IMMEDIATE` transaction.
///
/// # Order of operations, and what each failure leaves behind
///
/// 1. Resolve the wait's absolute deadline (`now + timeout_after`) and, if
///    `hold_workspace`, the workspace's own absolute hold instant. An
///    unrepresentable value fails here, before any side effect.
/// 2. Read the run's `session_id` from its row, which is also where a run
///    with no row is rejected — so no checkpoint is ever taken for a run
///    that cannot be parked.
/// 3. Take the checkpoint (§8.11: *"Before releasing, it runs an implicit
///    `checkpoint` task"*). A failure here fails the park: the run stays in
///    whatever state it was in and no deadline is written.
/// 4. Write the row. One transaction, through
///    `roundhouse_store::begin_immediate` — never a hand-rolled `BEGIN
///    IMMEDIATE`/`COMMIT` pair, which has no rollback on the `?` between
///    them and would strand the write lock.
///
/// The caller then acts on [`ParkResult::workspace`]; this function performs
/// none of §8.11's three releases (see the module doc for which crate owns
/// each).
///
/// # The session is read, not passed in
///
/// §8.11's implicit checkpoint is of *the parking run's own* session, and
/// `workflow_run.session_id` is where that fact already lives (§8.6: each
/// run creates a new Session). Taking it as a parameter would let a caller
/// silently checkpoint some other session while parking this run — a
/// restore point for the wrong worktree, which resume would then use — so it
/// is read here instead and echoed back in [`ParkResult::session_id`].
///
/// The read and the write are two statements, not one transaction, and the
/// read is deliberately taken *before* the checkpoint (a checkpoint may be
/// slow filesystem work, and holding SQLite's single write lock across it
/// would block every other writer). The gap is safe in the only direction
/// that matters: nothing in this workspace ever deletes a `workflow_run`
/// row, and `session_id` is never updated after insert, so a row read here
/// is still present and still carries the same session when the write runs.
/// The write requires that same `session_id` as an explicit precondition
/// rather than relying on the assumption alone — that is what turns
/// "`session_id` never changes after insert" into a checked property rather
/// than an unenforced one. Since Task 20a the check lives in
/// [`durability::transition_run_to_awaiting_human`](crate::durability)'s
/// `expect_session_id` and reports
/// [`DurabilityError::RunSessionMismatch`] rather than being a bound
/// `AND session_id = ?` whose only signal was a zero row count; either way
/// it happens inside the same `BEGIN IMMEDIATE` the write already opens, at
/// the cost of no extra lock time.
///
/// # Transition legality (added by Task 20a)
///
/// The write goes through
/// [`durability::transition_run_to_awaiting_human`](crate::durability), so
/// the run's *current* state is checked against
/// [`crate::durability::transition_is_legal`] inside the write's own
/// transaction. `-> AwaitingHuman` is legal from `Running` and from
/// `AwaitingHuman` and from nothing else, which is exactly the
/// `state IN ('running', 'awaiting_human')` predicate this doc comment
/// pre-specified — the `awaiting_human` half is not slack, it is the
/// idempotency
/// `a_re_driven_park_never_gets_a_fresh_window_it_moves_only_by_the_now_the_caller_supplied`
/// in `tests/parking.rs` pins, which a bare `= 'running'` would break.
///
/// Until Task 20a this function moved a `completed`, `failed`, `cancelled`,
/// or `cancelling` run to `AwaitingHuman` as readily as a `running` one —
/// resurrecting a terminal run, or silently un-cancelling a cancel in
/// flight, which the security lens reviewing Task 17 named as
/// **cancel-evasion**. A refusal is now
/// [`ParkError::Durability`]`(`[`DurabilityError::IllegalTransition`]`)`,
/// which is deliberately *not* [`ParkError::RunNotFound`]: the old zero-row
/// `UPDATE` could only report a row count, so it reported "wrong state" as
/// "no such run".
///
/// **The checkpoint still runs first**, so a park refused by this check has
/// already taken a restore point (§8.11's ordering gates the *release* on the
/// checkpoint, and the release is the caller's). Nothing durable is written;
/// the residue is one unused restore point, pinned by
/// `a_refused_park_leaves_its_checkpoint_behind_but_writes_nothing_durable`.
///
/// # The wait's deadline and the workspace hold are two different quantities
///
/// `awaiting_until` is **not** clamped to [`SYSTEM_WIDE_HOLD_CAP`]; the hold
/// is. §8.11's 7-day cap is stated about `hold_workspace` and justified by
/// disk accumulation (*"so forgotten `hold_workspace: true` runs can't
/// accumulate disk indefinitely"*), and a gate that declares `timeout: 30d`
/// with no workspace held costs nothing and has made a legitimate statement
/// about how long a human may take. Clamping the wait as well would silently
/// fire that gate's `on_timeout` three weeks early.
///
/// # Re-parking is idempotent for a given `now`
///
/// The write is a plain `UPDATE` of the two columns, so re-driving a park
/// with the same `now` and the same wait rewrites the same instant. Only a
/// caller that supplies a *later* `now` moves the deadline, and it moves by
/// exactly the delta that caller supplied — the row can never re-anchor
/// itself, which is the whole reason the column is absolute.
pub fn park(
    conn: &mut Connection,
    run_id: RunId,
    awaiting: &AwaitingHuman,
    hold_workspace: bool,
    now: Timestamp,
    checkpointer: &mut dyn Checkpointer,
) -> Result<ParkResult, ParkError> {
    let awaiting_until = awaiting
        .timeout_after
        .map(|after| absolute_deadline(now, after))
        .transpose()?;
    let workspace = if hold_workspace {
        WorkspaceDisposition::HoldUntil(absolute_deadline(
            now,
            resolve_hold_ttl(awaiting.timeout_after),
        )?)
    } else {
        WorkspaceDisposition::Release
    };

    let session_id = run_session_id(conn, run_id)?;
    let checkpoint_ref = checkpointer.checkpoint(session_id, "awaiting_human_park")?;

    // B12b: the hold instant is written to `workflow_run.hold_until` in the
    // same transaction as the state and the wait's deadline, so
    // [`WorkspaceDisposition::HoldUntil`] is now an echo of a durable column
    // rather than the only place the instant exists. `Release` writes `NULL`:
    // "no hold" is a fact about the row, not an absence of information.
    let hold_until = match workspace {
        WorkspaceDisposition::HoldUntil(instant) => Some(instant),
        WorkspaceDisposition::Release => None,
    };
    transition_run_to_awaiting_human(conn, run_id, session_id, awaiting_until, hold_until, now)?;

    Ok(ParkResult {
        checkpoint_ref,
        session_id,
        awaiting_until,
        workspace,
    })
}

/// §8.6's *"each run creates a new Session"*, read back — the session
/// [`park`] checkpoints. See [`park`]'s "The session is read, not passed in".
fn run_session_id(conn: &Connection, run_id: RunId) -> Result<SessionId, ParkError> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT session_id FROM workflow_run WHERE id = ?1",
            params![run_id.to_string()],
            |row| row.get(0),
        )
        .optional()?;
    let stored = stored.ok_or(ParkError::RunNotFound { run_id })?;
    stored
        .parse()
        .map(SessionId::from_uuid)
        .map_err(|_| ParkError::MalformedId {
            column: "workflow_run.session_id",
        })
}

/// §8.11's reaper predicate: has a park been held for at least
/// [`SYSTEM_WIDE_HOLD_CAP`], *"regardless of what any individual gate
/// specifies"*?
///
/// Pure and clock-free, in the shape of
/// `roundhouse_store::blobs::gc_eligible_blobs(conn, now, grace_period_secs)`
/// — and, like it, **its periodic caller does not exist yet** (module doc:
/// unowned daemon work, shared with that same GC).
///
/// `>=`, not `>`: at exactly seven days the cap has been reached, and this
/// matches `gc_eligible_blobs`'s own `(now - last_referenced_at) >= grace`
/// boundary rather than introducing a second convention one nanosecond
/// apart.
///
/// A `parked_at` in the future (a caller supplying instants out of order)
/// returns `false` and cannot wrap: the subtraction saturates, so the
/// elapsed time is never a huge positive value read out of a negative one.
///
/// Since B12b this predicate is expressed as a comparison against
/// [`reaper_cutoff_instant`] rather than as its own subtraction, so that
/// [`crate::ledger::parked_runs_past_hold_cap`] — which must do the
/// comparison in SQL, over an index, rather than by loading every parked run
/// and filtering in Rust — is comparing against the *same* instant this
/// returns `true` for. Two hand-written forms of "at least seven days ago"
/// are exactly the pair of legs ruling P72 warns about; one function feeding
/// both is what stops them drifting a nanosecond apart.
pub fn reaper_cutoff(parked_at: Timestamp, now: Timestamp) -> bool {
    reaper_cutoff_instant(now).is_some_and(|cutoff| parked_at.as_unix_nanos() <= cutoff)
}

/// The most recent park start [`reaper_cutoff`] still calls expired:
/// `now - `[`SYSTEM_WIDE_HOLD_CAP`], or `None` when no such instant is
/// representable.
///
/// `pub(crate)` because it is a query bound, not a predicate: the only caller
/// outside this module is [`crate::ledger::parked_runs_past_hold_cap`], which
/// binds it as the `parked_at <= ?` parameter of an index seek.
///
/// # Why `Option`, and not a saturating `i64`
///
/// This has to be **exactly** equivalent to the `now - parked_at >= CAP` it
/// replaced, or the rewrite has quietly changed a rule instead of factoring
/// it. A saturating version is not: at `now == i64::MIN` it yields `i64::MIN`,
/// which `parked_at == i64::MIN` satisfies, so a park of zero length would be
/// reported expired — the fail-*open* direction, and the opposite of what the
/// old subtraction (`0 >= CAP`, false) said. A `checked_sub` returning `None`
/// reproduces the old answer for every input pair, including both extremes:
/// `now = i64::MAX, parked_at = i64::MIN` is expired under both, and every
/// `now` within a cap's width of `i64::MIN` expires nothing under both.
///
/// The divergence was found by a test written for the rewrite, not reasoned
/// about — an earlier version of this function saturated, and its doc
/// asserted equivalence "for every value the schema can hold", which was true
/// (migration 0008's `CHECK` keeps `parked_at` non-negative) and beside the
/// point, since [`reaper_cutoff`] is `pub` and takes any two instants.
/// `tests/parking.rs`'s `a_now_earlier_than_the_cap_itself_reaps_nothing_and_does_not_wrap`
/// is the pin.
pub(crate) fn reaper_cutoff_instant(now: Timestamp) -> Option<i64> {
    now.as_unix_nanos().checked_sub(SYSTEM_WIDE_HOLD_CAP_NANOS)
}
