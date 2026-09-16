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

/// What dispatching one workflow `tool:` step for real produced.
///
/// Folds directly into `roundhouse_flow::exec::run_loop::WorkDone`: `Ok`
/// becomes `WorkStatus::Completed` with `output` as the step's real output;
/// `Err` becomes `WorkStatus::Failed { message }`.
pub struct WorkflowToolDispatch {
    pub task_id: TaskId,
    pub first_task_seq: u64,
    pub last_task_seq: Option<u64>,
    pub result: Result<serde_json::Value, String>,
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
pub async fn dispatch_tool_for_workflow(
    actor: &SessionActor,
    task_kind: TaskKind,
    logged_input: serde_json::Value,
    dispatch_input: serde_json::Value,
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
            result: Err(format!(
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
                result: Err(message),
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
            result: Err(message),
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
                    result: Err("tool execution failed".into()),
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
                    result: Err("tool execution failed".into()),
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
            result: Err(format!(
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
                result: Ok(output),
            })
        }
        Err(tool_err) => {
            let category = if matches!(
                &tool_err,
                crate::tool_dispatch::ToolDispatchError::Isolation(_)
            ) {
                "isolation_error"
            } else {
                "tool_error"
            };
            tracing::warn!(error = %tool_err, "admitted workflow tool execution failed");
            let last_task_seq = record_workflow_task_failed(
                actor,
                task_id,
                category,
                "tool execution failed".into(),
            )
            .await?;
            Ok(WorkflowToolDispatch {
                task_id,
                first_task_seq,
                last_task_seq: Some(last_task_seq),
                result: Err("tool execution failed".into()),
            })
        }
    }
}

/// Records a `TaskFailed` for `task_id` under `actor`'s session, returning
/// the seq `EventWriter::append` assigned it.
async fn record_workflow_task_failed(
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
