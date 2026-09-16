//! Phase 8 Task 25.3/25.4 — dispatches one `tool:` step of a workflow run
//! for real, through the same admission/execution machinery
//! [`crate::agent_loop`]'s chat dispatch uses (`SessionActor::admit_task`,
//! [`crate::tool_dispatch::execute_builtin`]), and folds the result into the
//! shape `roundhouse-flow`'s suspend/resume seam hands back to a run —
//! see `roundhouse_flow::exec::run_loop::WorkDone`'s own doc for the
//! contract this fills.
//!
//! **Scope: `TaskKind::Read | Write | Edit | Find | Shell`.** Every other
//! built-in is refused with a named, recorded failure. `Shell` is the one
//! kind that crosses the process isolation boundary: it pre-spawns its
//! child before `TaskStarted` and attests to the real isolate, mirroring
//! `agent_loop::dispatch_builtin`'s identical wiring (Phase 8 Task 25.4
//! Task 2). `Read`/`Write`/`Edit`/`Find` stay in-process and keep the
//! placeholder `IsolationAttestation { tier: Tier::None, .. }` (see the
//! comment at its literal below).
//!
//! # Why this is not `dispatch_builtin` with different arguments
//!
//! `dispatch_builtin` mints its task as a **child of a chat turn**
//! (`Origin::Model`, `parent: TaskId`) and takes one `input` value used for
//! admission, logging, and execution alike. A workflow `tool:` step has no
//! parent task (`Origin::System`, matching the fixed stub
//! `roundhouse-flow` produced for `Tool`/`Agent` steps before this seam
//! existed), and ruling P33 requires two different renderings of `with:` —
//! the redacted one for the log, the real one for admission and execution —
//! which `dispatch_builtin`'s single `input` parameter cannot carry.

use crate::agent_loop::now_ts;
use crate::session_actor::{SessionActor, TaskCreateRequest, TaskIsolator};
use roundhouse_core::{
    IsolationAttestation, Origin, TaskError, TaskId, TaskInput, TaskKind, TaskOutput, Tier, Usage,
};
use roundhouse_policy::TaskParams;

/// The terminal shape of one dispatched workflow `tool:` call.
///
/// Three-way rather than `Result<Value, String>` since Phase 8 Task 25.4
/// Task 4: §8.13's cooperative cancel is a distinct outcome from an
/// ordinary tool failure at the workflow-dispatch layer too —
/// `roundhouse_flow::exec::run_loop::WorkStatus::Cancelled` exists
/// specifically so a caller can tell "the run was cancelled mid-dispatch"
/// apart from "the tool call failed," and this is what
/// `DeliveryExecutor::work_done_from_dispatch`
/// (`roundhouse-daemon::scheduler_driver`) folds one of these into.
#[derive(Debug, Clone)]
pub enum DispatchOutcome {
    /// The call completed and produced this value.
    Completed(serde_json::Value),
    /// An ordinary failure: a denial, an admission refusal, a tool error, a
    /// `step_timeout` elapsing. Becomes `WorkStatus::Failed { message }`.
    Failed(String),
    /// §8.13's cooperative cancel was observed for this call. `Shell` is
    /// the only kind with a producer of its own today —
    /// `ToolDispatchError::ShellSessionCancelled`, surfaced by
    /// `execute_builtin`'s existing session-cancel race
    /// (`run_isolated_shell_dispatch`) — because the four filesystem kinds
    /// have no internal cancellation mechanism to observe from inside this
    /// function; see `DeliveryExecutor::execute_pending`'s own doc comment
    /// for how (and why) those four are instead reclassified after the
    /// fact, once their non-interruptible call has already returned.
    /// Becomes `WorkStatus::Cancelled { reason }`.
    Cancelled(String),
}

/// What dispatching one workflow `tool:` step for real produced.
pub struct WorkflowToolDispatch {
    pub task_id: TaskId,
    pub first_task_seq: u64,
    pub last_task_seq: Option<u64>,
    pub result: DispatchOutcome,
}

/// Dispatches one `tool:` step for real: mints and records its full
/// `TaskCreated`/`TaskStarted`/`TaskCompleted`|`TaskFailed` lifecycle
/// (S-LOG-1) under `actor`'s own session, admits it through the real
/// `SessionActor::admit_task` gate, and — for the five allowlisted kinds
/// (Read, Write, Edit, Find, Shell) — executes it through [`crate::tool_dispatch::execute_builtin`].
///
/// `logged_input` is what reaches the event log (ruling P33's redacted
/// half, already computed by `roundhouse-flow`); `dispatch_input` is what
/// admission and execution actually see — never persisted.
///
/// `step_timeout` is the run's real, already-clamped per-step ceiling
/// (`roundhouse_flow::exec::run_loop::PendingWork::step_timeout`, sourced by
/// `DeliveryExecutor::execute_pending` from the `PendingWork` it was
/// handed) — threaded straight into
/// [`crate::tool_dispatch::execute_builtin`]'s own `timeout` parameter
/// (Phase 8 Task 25.4 Task 3). For a `Shell` step this is what makes an
/// elapsed timeout a real process-group kill rather than an abandoned
/// orphan; the four filesystem kinds ignore it (they have no internal bound
/// of their own — `execute_pending`'s outer `tokio::time::timeout` is their
/// safety net, not this parameter).
///
/// `identity_sink`, when given, is sent `(task_id, first_task_seq)` the
/// instant `TaskCreated` is durably appended below — before admission,
/// execution, or any further `.await`. It exists purely so a caller that
/// races this whole future against an outer timeout (`execute_pending`'s
/// filesystem-kind branch) can still learn the real task identity if that
/// race is lost and this future gets dropped before ever returning: the
/// send and the `TaskCreated` append it follows both happen inside the same
/// poll, with no intervening `.await`, so by the time any outer combinator
/// could observe its own deadline and drop this future, the send has either
/// already landed in the channel (durably, `oneshot` buffers one value past
/// the sender's own drop) or `TaskCreated` was never appended at all — there
/// is no window in between. See issue #69 for the failure this closes.
pub async fn dispatch_tool_for_workflow(
    actor: &SessionActor,
    task_kind: TaskKind,
    logged_input: serde_json::Value,
    dispatch_input: serde_json::Value,
    step_timeout: std::time::Duration,
    identity_sink: Option<tokio::sync::oneshot::Sender<(TaskId, u64)>>,
) -> Result<WorkflowToolDispatch, String> {
    let writer = actor.writer();
    let runner = actor.runner();
    let task_id = TaskId::new();

    let created = runner.record_task_created(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        task_kind.clone(),
        None,
        Origin::System,
        TaskInput::Json(logged_input),
        1,
    );
    let first_task_seq = writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record a dispatched workflow tool call: {e}"))?;
    if let Some(sink) = identity_sink {
        // The receiver may already be gone (a caller that doesn't need this,
        // e.g. `execute_pending`'s `Shell` branch, never constructs one) —
        // that is not this function's problem to report.
        let _ = sink.send((task_id, first_task_seq));
    }

    // Explicit allowlist over the five kinds this function actually dispatches.
    // Everything else is refused with `unsupported_workflow_tool`.
    let is_supported = matches!(
        task_kind,
        TaskKind::Read | TaskKind::Write | TaskKind::Edit | TaskKind::Find | TaskKind::Shell
    );
    if !is_supported {
        let last_task_seq = record_workflow_task_failed(
            actor,
            task_id,
            "unsupported_workflow_tool",
            "tool execution failed".into(),
        )
        .await?;
        return Ok(WorkflowToolDispatch {
            task_id,
            first_task_seq,
            last_task_seq: Some(last_task_seq),
            result: DispatchOutcome::Failed(format!(
                "workflow dispatch of `{task_kind:?}` is not wired yet (Phase 8 Task 25.4)"
            )),
        });
    }

    let (params, extras) = match crate::tool_dispatch::task_params_for_in_workspace(
        task_kind.clone(),
        &dispatch_input,
        actor.workspace_root(),
    ) {
        Ok(resolved) => resolved,
        Err(err) => {
            let (category, message) = err.unadmitted_refusal();
            tracing::warn!(error = %err, "refusing a workflow tool call before admission");
            let last_task_seq =
                record_workflow_task_failed(actor, task_id, category, message.clone()).await?;
            return Ok(WorkflowToolDispatch {
                task_id,
                first_task_seq,
                last_task_seq: Some(last_task_seq),
                result: DispatchOutcome::Failed(message),
            });
        }
    };

    let req = TaskCreateRequest {
        kind: task_kind.clone(),
        origin: Origin::System,
        is_finally_step: false,
        params: params.clone(),
    };
    if let Err(admit_err) = actor.admit_task(&req).await {
        let message = crate::agent_loop::record_denial(
            writer,
            runner,
            actor.session_id(),
            task_id,
            admit_err,
        )
        .await;
        return Ok(WorkflowToolDispatch {
            task_id,
            first_task_seq,
            // `record_denial` is best-effort about its own appends (see its
            // own doc comment) and does not hand back the seq it assigned.
            last_task_seq: None,
            result: DispatchOutcome::Failed(message),
        });
    }

    // Start a shell child before `TaskStarted` so its attestation reflects
    // the live process that will execute the admitted task — mirrors
    // `agent_loop::dispatch_builtin`'s identical, load-bearing ordering:
    // the attestation appended below must describe the process that
    // actually executes this task, so the spawn happens first. The child is
    // handed to `execute_builtin` below; it is not spawned a second time.
    let pre_spawned = if let TaskParams::Shell(cmd) = &params {
        let cwd = match extras.shell_cwd.as_deref() {
            Some(cwd) => cwd,
            None => {
                let last_task_seq = record_workflow_task_failed(
                    actor,
                    task_id,
                    "isolation_error",
                    "tool execution failed".into(),
                )
                .await?;
                return Ok(WorkflowToolDispatch {
                    task_id,
                    first_task_seq,
                    last_task_seq: Some(last_task_seq),
                    result: DispatchOutcome::Failed("tool execution failed".into()),
                });
            }
        };
        match actor
            .spawn_isolated(crate::tool_dispatch::isolated_shell_command(cmd, cwd))
            .await
        {
            Ok(child) => Some(child),
            Err(err) => {
                tracing::warn!(error = %err, "admitted workflow shell isolation spawn failed");
                let last_task_seq = record_workflow_task_failed(
                    actor,
                    task_id,
                    "isolation_error",
                    "tool execution failed".into(),
                )
                .await?;
                return Ok(WorkflowToolDispatch {
                    task_id,
                    first_task_seq,
                    last_task_seq: Some(last_task_seq),
                    result: DispatchOutcome::Failed("tool execution failed".into()),
                });
            }
        }
    } else {
        None
    };

    let started = runner.record_task_started(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        // Only shell tasks cross the process isolation boundary. Filesystem
        // helpers remain in-process and must not inherit the session's shell
        // attestation in their per-task event — matches
        // `agent_loop::dispatch_builtin`'s identical conditional. A future
        // editor: do not "generalize" real attestation onto the
        // Read/Write/Edit/Find arms above — they never pre-spawn a child.
        if pre_spawned.is_some() {
            let attestation = actor.isolation_attestation();
            IsolationAttestation {
                tier: attestation.tier,
                digest: attestation.digest,
                net_enforced: attestation.net_enforced,
            }
        } else {
            IsolationAttestation {
                tier: Tier::None,
                digest: String::new(),
                net_enforced: false,
            }
        },
        None,
        1,
    );
    if let Err(err) = writer.append(started).await {
        // A shell child that was pre-spawned above must not outlive a
        // failed `TaskStarted` append — mirrors
        // `agent_loop::dispatch_builtin`'s identical cleanup branch.
        if let Some(child) = pre_spawned.as_ref() {
            if let Err(cleanup_err) = child.cancel().await {
                tracing::error!(
                    error = %cleanup_err,
                    "failed to clean up an isolated workflow shell child after TaskStarted append failure"
                );
            }
        }
        let last_task_seq = record_workflow_task_failed(
            actor,
            task_id,
            "event_error",
            "tool execution failed".into(),
        )
        .await?;
        return Ok(WorkflowToolDispatch {
            task_id,
            first_task_seq,
            last_task_seq: Some(last_task_seq),
            result: DispatchOutcome::Failed(format!(
                "failed to record the dispatched tool call starting: {err}"
            )),
        });
    }

    match crate::tool_dispatch::execute_builtin(
        &params,
        &extras,
        &dispatch_input,
        Some(actor.subscribe()),
        pre_spawned,
        actor,
        step_timeout,
    )
    .await
    {
        Ok(parts) => {
            let text = parts
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let output = serde_json::json!({ "content": text });
            let completed = runner.record_task_completed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                TaskOutput::Json(output.clone()),
                Usage::default(),
                1,
            );
            let last_task_seq = writer.append(completed).await.map_err(|e| {
                format!("failed to record the dispatched tool call completing: {e}")
            })?;
            Ok(WorkflowToolDispatch {
                task_id,
                first_task_seq,
                last_task_seq: Some(last_task_seq),
                result: DispatchOutcome::Completed(output),
            })
        }
        Err(tool_err) => {
            // Phase 8 Task 25.4 Task 4: `ShellSessionCancelled` is §8.13's
            // cooperative cancel, observed by `execute_builtin`'s own
            // session-cancel race (`run_isolated_shell_dispatch`) — a
            // distinct outcome from an ordinary tool failure, and the one
            // case this function folds into `DispatchOutcome::Cancelled`
            // rather than `::Failed`. Every other `ToolDispatchError`
            // (including a `ShellCancelled` *timeout*, which is an ordinary
            // failure, not a cancel — see that variant's own doc comment)
            // stays `::Failed`, exactly as before this task.
            let cancelled_reason = match &tool_err {
                crate::tool_dispatch::ToolDispatchError::ShellSessionCancelled(reason) => {
                    Some(reason.clone())
                }
                _ => None,
            };
            let category = match &tool_err {
                crate::tool_dispatch::ToolDispatchError::Isolation(_) => "isolation_error",
                crate::tool_dispatch::ToolDispatchError::ShellSessionCancelled(_) => {
                    "shell_session_cancelled"
                }
                _ => "tool_error",
            };
            tracing::warn!(error = %tool_err, "admitted workflow tool execution failed");
            let last_task_seq = record_workflow_task_failed(
                actor,
                task_id,
                category,
                "tool execution failed".into(),
            )
            .await?;
            let result = match cancelled_reason {
                Some(reason) => DispatchOutcome::Cancelled(reason),
                None => DispatchOutcome::Failed("tool execution failed".into()),
            };
            Ok(WorkflowToolDispatch {
                task_id,
                first_task_seq,
                last_task_seq: Some(last_task_seq),
                result,
            })
        }
    }
}

/// Records a `TaskFailed` for `task_id` under `actor`'s session, returning
/// the seq `EventWriter::append` assigned it.
///
/// `pub` (rather than private to this module) so `DeliveryExecutor::
/// execute_pending`'s outer-timeout arm can call it directly: when the
/// timeout wins the race against [`dispatch_tool_for_workflow`] but that
/// function's `identity_sink` still reports a real `task_id`, this is what
/// lets the caller append the terminal event itself instead of leaving a
/// non-terminal task behind for `roundhouse_store::recover_interrupted_tasks`
/// to repair at the next daemon boot.
pub async fn record_workflow_task_failed(
    actor: &SessionActor,
    task_id: TaskId,
    category: &str,
    message: String,
) -> Result<u64, String> {
    let failed = actor.runner().record_task_failed(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        TaskError {
            message,
            category: category.into(),
        },
        false,
        1,
    );
    actor
        .writer()
        .append(failed)
        .await
        .map_err(|e| format!("failed to record a dispatched workflow tool call failing: {e}"))
}
