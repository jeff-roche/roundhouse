//! §8.13's run controls — **cancel**, **pause**, **resume**,
//! **retry-from-step** (Task 20a, B12a).
//!
//! Every function here writes the `workflow_run` row through
//! [`crate::durability`]'s transition writer. That is the whole point of the
//! module: a control that flipped a `&mut RunState` would change nothing a
//! restart, a second client, or the web Runs inbox could see, and §8.13's
//! controls exist precisely to be issued from somewhere other than the run
//! loop.
//!
//! # The controls are narrower than the state machine
//!
//! [`durability::transition_is_legal`] admits every move the run *loop* also
//! needs — `AwaitingHuman -> Running` when a human answers a gate,
//! `Running -> Completed` when the last step finishes. The three controls
//! here admit strictly less:
//!
//! | control | permitted source states | target |
//! |---|---|---|
//! | [`cancel`] | `Running`, `Paused`, `AwaitingHuman` | `Cancelling` |
//! | [`pause`] | `Running` | `Paused` |
//! | [`resume`] | `Paused` | `Running` |
//!
//! [`resume`] deliberately does **not** move a parked run back to `Running`
//! even though the matrix permits that edge: §8.11's park is released by the
//! human answering (or by `on_timeout` firing), not by an operator pressing
//! resume, and letting resume do it would discard the wait's answer.
//!
//! # What this module does NOT own
//!
//! - **`rerun`.** §8.13 lists it as a fifth control and the plan section's
//!   own title promises it, but the plan's body never produced it and this
//!   task does not either. It is a *new* run of the same pinned
//!   `(job_id, job_version, content_hash)` with no inherited steps and no
//!   `forked_from_run_id`, which needs the run loop to start it — recorded
//!   here as an unowned residual rather than half-built.
//! - **The cooperative half of cancel.** §8.13's cancel is *"refuse new task
//!   admission, SIGTERM->SIGKILL running shells, run `finally:`"*; this
//!   module writes the `Cancelling` mark that those three read, and nothing
//!   else. Admission and `finally:` are [`crate::exec::run_loop`]'s (B12c) —
//!   it observes the mark at [`crate::ledger::admit_spend`]'s refusal and
//!   drains — and the signals are `roundhouse-tools`, which already implements
//!   them for a task.
//! - **Reaching `Cancelled`.** The drain ends the run, so the
//!   `Cancelling -> Cancelled` write is [`crate::exec::run_loop`]'s, through
//!   [`durability::transition_run`] — and it happens only after that loop has
//!   run `finally:` and left the run's one report task behind (ruling
//!   P112).
//! - **Clearing inherited outputs a fork can no longer target.** Migration
//!   0007 and `durability`'s module doc name that eraser as Task 20's; it
//!   needs a retention policy deciding which runs are past forking, which is
//!   a policy decision this slice does not make. [`retry_from_step`] widens
//!   the set of rows holding unredacted output (a fork copies them), so the
//!   obligation is louder now, not smaller.

use crate::durability::{
    self, fork_run, recover_run, DurabilityError, RunState, StepRunState, WorkflowRun,
    WorkflowStepRun,
};
use crate::exec::RunId;
use roundhouse_core::{SessionId, Timestamp};
use thiserror::Error;

/// Why a control could not be applied.
///
/// The three "wrong state" variants each carry the state the row was
/// **actually** in, read inside the same transaction that refused the write.
/// An operator (or the web Runs inbox) is then told what to do next rather
/// than only that the call failed.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ControlError {
    #[error(transparent)]
    Durability(#[from] DurabilityError),
    /// [`pause`] found a run that is not `Running`.
    #[error("run {run_id} cannot be paused: it is {state:?}, not Running")]
    NotRunning { run_id: RunId, state: RunState },
    /// [`resume`] found a run that is not `Paused` — including a parked run,
    /// which resume deliberately does not release (see the module doc).
    #[error("run {run_id} cannot be resumed: it is {state:?}, not Paused")]
    NotPaused { run_id: RunId, state: RunState },
    /// [`cancel`] found a run that has already ended, or one whose cancel is
    /// already in flight. Reported rather than treated as a no-op: an
    /// operator pressing cancel twice is told the run is already draining,
    /// which is different from a fresh cancel having landed.
    #[error("run {run_id} cannot be cancelled: it is {state:?}")]
    NotCancellable { run_id: RunId, state: RunState },
    /// [`retry_from_step`] was asked to fork a run that has not ended.
    #[error("run {run_id} is {state:?}, so it cannot be forked yet")]
    RunStillActive { run_id: RunId, state: RunState },
    /// [`retry_from_step`]'s `from_step_id` is not one of the step ids the
    /// caller supplied for the run's pinned job version.
    ///
    /// Echoes the offending id because it is the caller's own input and
    /// naming it is the whole diagnostic. Its length is whatever the caller
    /// passed — this text reaches no database column, only `Display`, so
    /// unlike `workflow_step_run.error` it carries no truncation of its own
    /// (the same log-only reasoning `parking::CheckpointError` records).
    #[error("step {step_id:?} is not a step of this run's job version")]
    UnknownStep { step_id: String },
    /// [`retry_from_step`] found a `Completed` step in the original run whose
    /// `step_id` the caller's `step_order` never names at all (fix round 1,
    /// Task 20a).
    ///
    /// This is a different fact from [`Self::UnknownStep`], which is about
    /// `from_step_id` itself. This is about a step [`recover_run`] returned as
    /// `Completed` that `step_order` is simply silent on. Silently treating
    /// that as "not before the cut, so it re-runs" would be wrong in the
    /// dangerous direction for an `Effectful` step: it duplicates a side
    /// effect the original run already had — the exact consequence
    /// [`fork_run`]'s own doc says wrapping the whole fork in one transaction
    /// exists to prevent, reached here by a `step_order` that does not
    /// actually describe the run's history rather than by a partial write.
    /// This is a caller-contract violation (the doc on `step_order` states the
    /// contract it violates), not a legitimate fork of a run whose history
    /// genuinely has fewer steps than the caller believes.
    #[error("step {step_id:?} completed in run {run_id}, but step_order does not name it")]
    StepOrderMissingCompletedStep { run_id: RunId, step_id: String },
}

/// §8.13's cooperative **cancel**: *"mark `Cancelling`, refuse new task
/// admission, SIGTERM->SIGKILL running shells, run `finally:`"*.
///
/// This writes the mark, durably. The other three clauses are the run loop's
/// and the tools layer's — see the module doc — and all three read this row,
/// which is why the mark has to be a row rather than a flag in whichever
/// process happened to receive the control.
///
/// A parked run is cancellable: a run waiting on a human who never answers is
/// exactly the one an operator needs to stop, and §8.11's reaper exists
/// because that case is real.
///
/// `now` is forwarded to [`durability::transition_run`], which writes it to
/// `ended_at` only for a terminal target. `Cancelling` is not terminal, so
/// this call writes no instant; the parameter is here because this crate
/// reads no clock and the run loop's own `Cancelling -> Cancelled` write does
/// need one.
pub fn cancel(
    conn: &mut rusqlite::Connection,
    run_id: RunId,
    now: Timestamp,
) -> Result<(), ControlError> {
    match durability::transition_run(conn, run_id, RunState::Cancelling, now) {
        Ok(_) => Ok(()),
        Err(DurabilityError::IllegalTransition { from, .. }) => Err(ControlError::NotCancellable {
            run_id,
            state: from,
        }),
        Err(other) => Err(other.into()),
    }
}

/// §8.13's **pause**, from `Running` only.
///
/// See [`cancel`] for why `now` is a parameter of a non-terminal transition.
pub fn pause(
    conn: &mut rusqlite::Connection,
    run_id: RunId,
    now: Timestamp,
) -> Result<(), ControlError> {
    match durability::transition_run(conn, run_id, RunState::Paused, now) {
        Ok(_) => Ok(()),
        Err(DurabilityError::IllegalTransition { from, .. }) => Err(ControlError::NotRunning {
            run_id,
            state: from,
        }),
        Err(other) => Err(other.into()),
    }
}

/// §8.13's **resume**, from `Paused` only — never from `AwaitingHuman`, see
/// the module doc.
///
/// The only control whose precondition is narrower than the matrix, so the
/// only one that goes through [`durability::transition_run_from`]: the
/// narrowing is checked inside the write's own transaction rather than by a
/// separate read whose answer could already be stale. [`cancel`] and
/// [`pause`] permit exactly what the matrix does for their targets, and
/// restating that here would be a second copy of the matrix to drift from.
///
/// See [`cancel`] for why `now` is a parameter of a non-terminal transition.
pub fn resume(
    conn: &mut rusqlite::Connection,
    run_id: RunId,
    now: Timestamp,
) -> Result<(), ControlError> {
    match durability::transition_run_from(conn, run_id, &[RunState::Paused], RunState::Running, now)
    {
        Ok(_) => Ok(()),
        Err(DurabilityError::IllegalTransition { from, .. }) => Err(ControlError::NotPaused {
            run_id,
            state: from,
        }),
        Err(other) => Err(other.into()),
    }
}

/// What [`retry_from_step`] created.
///
/// The durable record is the two sets of rows; this is the in-process echo,
/// in the shape the plan specified.
#[derive(Debug, Clone, PartialEq)]
pub struct ForkedRun {
    pub new_run_id: RunId,
    pub forked_from_run_id: RunId,
    /// The rows written under the fork — not the originals. Their
    /// `run_id` is [`Self::new_run_id`] and their task-seq ranges are
    /// `None`; see [`retry_from_step`].
    pub inherited_step_outputs: Vec<WorkflowStepRun>,
}

/// §8.13's **retry-from-step**: *"forks a new run inheriting completed step
/// outputs with a `forked_from_run_id` link — history is append-only, so we
/// never rewrite it"*.
///
/// The original run is read and never written. What is written is a new
/// `workflow_run` row carrying `forked_from_run_id`, plus a copy of every
/// completed step row strictly before `from_step_id` — one transaction, see
/// [`fork_run`].
///
/// # Why `step_order` is a parameter
///
/// Which steps are *before* the retry point is a property of the job's
/// declared step list (`parse::types::WorkflowDef::steps` is a `Vec` and
/// there is no `needs:` graph, so declaration order is execution order), and
/// **this crate cannot recover that list from the database**: there is no
/// jobs table anywhere in the schema (radius: the `CREATE TABLE` statements
/// in `roundhouse-store/src/migrations.rs` are `events`, `tasks`, `blobs`,
/// `trigger_event`, `workflow_run`, `workflow_step_run` — a `Job`/`JobVersion`
/// lives in [`crate::job`] as an in-memory type), so `(job_id, job_version,
/// content_hash)` cannot be resolved back to its content here. The caller —
/// which had to parse the workflow to run it in the first place — supplies
/// the ids in declaration order. Ordering the recovered rows instead would
/// not work: [`recover_run`] returns them sorted by `step_id`, which is
/// alphabetical, not temporal.
///
/// A `from_step_id` that is not in `step_order` is
/// [`ControlError::UnknownStep`], not a silent whole-run inheritance. A
/// recovered `Completed` row whose `step_id` is not in `step_order` is
/// refused ([`ControlError::StepOrderMissingCompletedStep`]) rather than
/// silently dropped — see that variant's doc for why silently dropping it
/// would be worse than refusing.
///
/// # `step_order`'s precondition (fix round 1, Task 20a — named, not checked)
///
/// `step_order` must be the step list of **the run's own pinned
/// `content_hash`** (`original.run.content_hash`, inherited unchanged into
/// the fork), not of the job's *current* definition. A retry can happen long
/// after the original run started, and by then `(job_id, job_version)` may
/// have been re-authored with a different step list; this function has no way
/// to detect a `step_order` drawn from the wrong version, because — as the
/// section above says — it cannot resolve `content_hash` back to a step list
/// at all. [`ControlError::StepOrderMissingCompletedStep`] catches the one
/// symptom that is detectable (a `Completed` step the caller's list does not
/// mention at all); a caller that instead passes a same-length list in the
/// *current* version's order, silently misaligned with the pinned one, is not
/// caught by anything here.
///
/// # What is inherited, and what is deliberately not
///
/// - **Only `Completed` steps**, per §8.13's own words ("completed step
///   outputs"). A step that failed, is pending, or was found
///   `Indeterminate` after a crash re-runs.
/// - `StepRunState::Skipped` rows are **not** inherited, and B12c — which
///   writes the first ones — settles that this is the right rule rather than
///   an open question. The apparent tension is between two different things: a
///   skipped step is *finished*, so **within one run** the loop must not
///   re-evaluate its `when:` on re-drive (migration 0007 and
///   [`StepRunState::Skipped`]'s doc say so, because a condition that reads
///   differently later would change control flow that already happened), and
///   [`crate::exec::run_loop`] honours that by treating `Skipped` as finished.
///   **A fork is not the same run.** It is a new run over the same pinned
///   content, with its own inputs and its own `steps` context, and §8.13 gives
///   it *"completed step outputs"* — not completed step *decisions*. Carrying
///   a skip forward would pin a control-flow choice the original made under
///   conditions the fork does not share, which is the opposite of what a retry
///   is for.
/// - **`attempt` is preserved, not renumbered.** An inherited step is not
///   re-run, so its attempt count is a fact about how the original reached
///   that output; rewriting it to 1 would claim the fork achieved in one
///   attempt what actually took several. A `map` step's per-item rows come
///   across the same way, each keeping its own `item_index`, because
///   `(step_id, attempt, item_index)` is what makes them distinct rows at
///   all.
/// - **`first_task_seq`/`last_task_seq` are cleared.** §8.10's ranges join
///   back to a *session's* task log, the inherited tasks live in the original
///   run's session, and §8.6 gives the fork a new session — so copying the
///   ranges would point the fork's join at seqs its own session never
///   emitted. The evidence is still reachable, through
///   `forked_from_run_id`.
/// - `binding_id` and `trigger_event_id` **are** inherited: the fork is a
///   continuation of the same firing, and `forked_from_run_id` is what
///   distinguishes it from a fresh one. The visible consequence, stated
///   rather than left to be discovered: a fork becomes a candidate answer for
///   [`durability::previous_run_for_binding`], so `carry_over` sees the fork
///   rather than the run it forked once the fork is the more recent row.
/// - `parent_run_id` is inherited, so a forked `call:` child still names the
///   run that called it — and since B12c's `call:` arm writes that column, the
///   case is live rather than reasoned-but-unexercised. It is also what makes
///   a retry **draw** from that parent (ruling P113): `fork_run` routes through
///   `insert_run_row`, which draws for any parented row in the same
///   transaction, so a retry the parent cannot fund is refused with
///   [`DurabilityError::ChildDrawRefused`] rather than forked.
///
/// # Why the original must have ended
///
/// [`ControlError::RunStillActive`] refuses to fork a run that is not
/// terminal. INFERRED, not stated by §8.13: forking a live run takes a
/// snapshot of a moving target and starts a second run that will re-execute
/// effectful steps the first is still executing. An operator cancels (or
/// waits for) the run first. If a later task finds a real need to fork a
/// paused run, this is the check to revisit — it is a policy in one `if`,
/// not a structural assumption.
pub fn retry_from_step(
    conn: &mut rusqlite::Connection,
    original_run_id: RunId,
    from_step_id: &str,
    step_order: &[&str],
    new_session_id: SessionId,
    now: Timestamp,
) -> Result<ForkedRun, ControlError> {
    let cut = step_order
        .iter()
        .position(|id| *id == from_step_id)
        .ok_or_else(|| ControlError::UnknownStep {
            step_id: from_step_id.to_string(),
        })?;
    let before_the_cut = &step_order[..cut];

    let original = recover_run(conn, original_run_id)?;
    if !original.run.state.is_terminal() {
        return Err(ControlError::RunStillActive {
            run_id: original_run_id,
            state: original.run.state,
        });
    }

    // Fix round 1 (Task 20a): a `Completed` step `step_order` never names at
    // all is a caller-contract violation, not a legitimate "nothing to
    // inherit" — see `ControlError::StepOrderMissingCompletedStep`'s doc.
    // Checked before any row is written, over the same `original.steps` the
    // inheritance filter below reads, so this cannot itself race against a
    // partially-applied fork.
    if let Some(missing) = original.steps.iter().find(|step| {
        step.state == StepRunState::Completed && !step_order.contains(&step.step_id.as_str())
    }) {
        return Err(ControlError::StepOrderMissingCompletedStep {
            run_id: original_run_id,
            step_id: missing.step_id.clone(),
        });
    }

    let new_run_id = RunId::new();
    let inherited: Vec<WorkflowStepRun> = original
        .steps
        .iter()
        .filter(|step| {
            step.state == StepRunState::Completed && before_the_cut.contains(&step.step_id.as_str())
        })
        .map(|step| WorkflowStepRun {
            run_id: new_run_id,
            first_task_seq: None,
            last_task_seq: None,
            ..step.clone()
        })
        .collect();

    let fork = WorkflowRun {
        id: new_run_id,
        job_id: original.run.job_id,
        job_version: original.run.job_version,
        content_hash: original.run.content_hash.clone(),
        session_id: new_session_id,
        binding_id: original.run.binding_id,
        trigger_event_id: original.run.trigger_event_id,
        state: RunState::Running,
        parent_run_id: original.run.parent_run_id,
        forked_from_run_id: Some(original_run_id),
        awaiting_until: None,
        checkpoint_ref: None,
        checkpoint_blob_ref: None,
        started_at: now,
        ended_at: None,
        // Inherited, not recomputed: §8.13's fork re-runs the *same* workflow
        // from a step, so its Session sits exactly where the original's did
        // in the session tree. Copying the number keeps
        // `ledger::admit_call_from_run` bounding the fork's `call:` chain the
        // way it bounded the original's; recomputing it as `0` would hand a
        // deep run a fresh four levels every time an operator retried it,
        // which is ruling P76 §1's escape reached through retry.
        session_depth: original.run.session_depth,
        // Also inherited — and the fork's own `spent_*` accumulators start at
        // zero, so **a fork asks for a fresh ceiling, not a continuation of
        // the original's remaining budget**. That is the usable reading:
        // charging a fork the original's spend would make a retry-from-step of
        // an expensive run fail immediately, which is the one thing retry
        // exists to avoid.
        //
        // **Asks for, and is charged for.** Ruling P113 settles what B12b
        // could only name: a fork of a *child* run draws that fresh grant from
        // its parent through the same chokepoint every other child passes, and
        // the retry is refused with a distinguishable error
        // (`DurabilityError::ChildDrawRefused`) when the parent cannot cover
        // it. Nothing here has to remember to do that — `durability::fork_run`
        // routes through `insert_run_row`, which draws for **any** row
        // carrying a `parent_run_id`, in the fork's own transaction (ruling
        // P114 §A's invariant). So:
        //
        // - §8.12's *"a workflow subtree can never spend more than its root
        //   was given"* holds across a fork. It did not before: n retries
        //   overshot it by n grants, because no draw was ever recorded.
        // - **A fork can be refunded again**, and correctly, because a draw
        //   now stands behind it. Before B12b it could be refunded with *no*
        //   draw behind it — measured at one draw producing two refunds, and
        //   erasing 500 tokens of the parent's real, unrelated spend down to
        //   400 (rulings P109 §A, P110). B12b's contained fix stamped the fork
        //   `refunded_at` at creation; B12c removes that stamp, because a run
        //   that draws is a run that has something to give back, and
        //   `refund_child_run`'s `DrawNotRecorded` refusal is what keeps the
        //   original defect closed if a draw is ever missed.
        //
        // A fork of a **root** run — every fork in the tree today, since
        // nothing yet writes `parent_run_id` — draws nothing and is
        // unaffected.
        caps: original.run.caps.clone(),
    };
    fork_run(conn, &fork, &inherited)?;

    Ok(ForkedRun {
        new_run_id,
        forked_from_run_id: original_run_id,
        inherited_step_outputs: inherited,
    })
}
