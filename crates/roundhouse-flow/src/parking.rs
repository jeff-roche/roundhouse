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
//!   "excludes `AwaitingHuman`") — **Task 20 (B12)**, which owns the
//!   run-level ledger. It needs a durable column to live in; an in-memory
//!   tracker would be lost on the first daemon restart, which is precisely
//!   the case it exists to measure.
//!
//! # The reaper's periodic runner does not exist
//!
//! [`reaper_cutoff`] is a pure predicate in the shape of
//! `roundhouse_store::blobs::gc_eligible_blobs`. **The periodic runner that
//! would call it on a schedule is unowned daemon work**: there is no
//! periodic-task machinery in `roundhouse-daemon` at all today (verified by
//! grep: one `tokio::spawn`, the socket accept loop, and no call to
//! `Scheduler::tick` anywhere). Whoever builds that runner serves two
//! callers, not one — `blobs.rs`'s daily GC wants the identical missing
//! machinery.

use crate::durability::RunState;
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
/// note on [`resolve_hold_ttl`] describes. `as_secs()` loses nothing here
/// because [`SYSTEM_WIDE_HOLD_CAP`] is a whole number of seconds
/// (`Duration::from_secs`), and a value large enough to make this multiply
/// overflow would be a compile error rather than a wrap.
const SYSTEM_WIDE_HOLD_CAP_NANOS: i64 = SYSTEM_WIDE_HOLD_CAP.as_secs() as i64 * 1_000_000_000;

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

/// Why a park failed. Every variant means **nothing was written**.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ParkError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    /// The run has no `workflow_run` row. The application-level leg of the
    /// reference `durability::checkpoint_step` also checks, for the same
    /// reason: no connection in this workspace sets `PRAGMA foreign_keys =
    /// ON`, so a declared `FOREIGN KEY` would be inert.
    #[error("no workflow_run row for run {run_id}")]
    RunNotFound { run_id: RunId },
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
/// is still present and still carries the same session when the `UPDATE`
/// runs. The `UPDATE`'s own zero-row check is kept anyway rather than being
/// assumed away — it is the leg that would catch that assumption becoming
/// false.
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

    let txn = roundhouse_store::begin_immediate(conn)?;
    let updated = txn.execute(
        "UPDATE workflow_run SET state = ?1, awaiting_until = ?2 WHERE id = ?3",
        params![
            RunState::AwaitingHuman.as_sql_str(),
            awaiting_until.map(|t| t.as_unix_nanos()),
            run_id.to_string(),
        ],
    )?;
    if updated == 0 {
        return Err(ParkError::RunNotFound { run_id });
    }
    txn.commit()?;

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
pub fn reaper_cutoff(parked_at: Timestamp, now: Timestamp) -> bool {
    now.as_unix_nanos()
        .saturating_sub(parked_at.as_unix_nanos())
        >= SYSTEM_WIDE_HOLD_CAP_NANOS
}
