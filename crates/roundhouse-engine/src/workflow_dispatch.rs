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

use std::sync::Arc;

use crate::agent_loop::now_ts;
use crate::session_actor::{SessionActor, TaskCreateRequest, TaskIsolator};
use crate::tools::agent_spawn_tool::{AgentArgs, SubAgentHost, CHILD_TIER};
use roundhouse_core::{
    IsolationAttestation, Origin, SessionId, TaskError, TaskId, TaskInput, TaskKind, TaskOutput,
    Tier, Usage,
};
use roundhouse_policy::{ProviderId, TaskParams};

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

    // Phase 8 Task 19 lane B, Task 9: a shell step streams real deltas; the
    // four filesystem kinds stay one-shot (`None`). **`writer.clone()` is
    // load-bearing, not incidental** — `writer` here is `actor.writer()`
    // (see this function's own `let writer = actor.writer();` above), the
    // exact `EventWriter` this function's own `TaskCompleted`/`TaskFailed`
    // appends use. `ShellDeltaSink` must hold a `Clone` of that SAME
    // `EventWriter` — a derived `Clone` over the identical underlying
    // `mpsc::Sender<WriteCmd>` — for the Global Constraint
    // (`run_isolated_shell_dispatch`'s own doc comment on `completion` has
    // the full argument) to hold: every delta/progress append and the
    // terminal append must enqueue onto the SAME writer-actor FIFO, or the
    // "whichever enqueues first is processed first" guarantee this relies on
    // does not apply.
    let delta_sink = match &params {
        TaskParams::Shell(_) => Some(crate::tool_dispatch::ShellDeltaSink::new(
            writer.clone(),
            runner,
            actor.session_id(),
            task_id,
            actor.state_dir().to_path_buf(),
        )),
        _ => None,
    };

    match crate::tool_dispatch::execute_builtin(
        &params,
        &extras,
        &dispatch_input,
        Some(actor.subscribe()),
        pre_spawned,
        actor,
        step_timeout,
        delta_sink,
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
                // The five allowlisted kinds (Read/Write/Edit/Find/Shell)
                // are all local execution — nothing here entered context
                // from outside the session.
                roundhouse_core::Trust::Trusted,
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

/// Records a `TaskCompleted` for `task_id` under `actor`'s session, returning
/// the seq `EventWriter::append` assigned it.
///
/// `pub` for the same reason as [`record_workflow_task_failed`]: it is the
/// daemon's own driving loop
/// (`DeliveryExecutor::execute_pending_with_context`,
/// `roundhouse-daemon::scheduler_driver`) that resolves a workflow `agent:`
/// step's spawned child and drives it to a result (Phase 8 Task 25.5's Task
/// 3) — [`dispatch_agent_for_workflow`]'s own doc comment explains why that
/// cannot happen in this crate. `usage` is always [`Usage::default`]: the
/// real per-turn token accounting for a driven child lives on the child's
/// own session log (every turn `run_agent_loop` drove already recorded its
/// own `chat`/`infer` tasks there), not on this synthetic parent-side
/// wrapper task — mirrors `dispatch_tool_for_workflow`'s identical
/// `Usage::default()` for a `tool:` step's own completion.
pub async fn record_workflow_task_completed(
    actor: &SessionActor,
    task_id: TaskId,
    output: serde_json::Value,
) -> Result<u64, String> {
    let completed = actor.runner().record_task_completed(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        TaskOutput::Json(output),
        Usage::default(),
        // This wrapper event's own content (the parent-side synthesis of a
        // driven child's result) is `Trusted` — the child's own turns
        // already recorded their real `Trust` on their own session log, and
        // §6.8's spawn-boundary union is applied separately, by
        // `mark_tainted` on the parent actor when the child returns
        // tainted, not by this event's own field.
        roundhouse_core::Trust::Trusted,
        1,
    );
    actor
        .writer()
        .append(completed)
        .await
        .map_err(|e| format!("failed to record a dispatched workflow agent spawn completing: {e}"))
}

/// The daemon's fallback provider id for a workflow `agent:` step's spawned
/// child, until issue #43 (Phase 8 Task 24) gives this workspace a real,
/// named provider registry
/// (`docs/architecture/06-provider-abstraction.md`'s `HashMap<ProviderId,
/// Arc<dyn Provider>>`). `StepBody::Agent` has no `provider:` field — unlike
/// the model-issued `agent` tool, a workflow step never chooses among
/// providers — so this names the one provider the daemon boots today
/// (`main.rs`'s `AnthropicMessagesProvider::new()`) for the purpose of
/// `TaskParams::Agent`'s policy predicate, which structurally requires
/// *some* `ProviderId` to check against. Not a permanent architectural
/// choice: whoever builds the registry replaces this with a real lookup.
const WORKFLOW_AGENT_PROVIDER_ID: &str = "anthropic";

/// What spawning one `agent:` workflow step's child produced.
#[derive(Debug, Clone)]
pub enum AgentSpawnOutcome {
    /// A real child session now exists. Not yet a result — driving it to
    /// completion is the daemon's own job (see this function's own doc
    /// comment) — so the parent task this call started stays `Running`.
    Spawned { child_session_id: SessionId },
    /// An ordinary failure: no `SubAgentHost`, admission refused, or
    /// `spawn_child` itself refused (depth/fan-out/budget/team). Becomes
    /// `WorkStatus::Failed { message }`.
    Failed(String),
}

/// What dispatching one workflow `agent:` step's spawn produced.
pub struct WorkflowAgentDispatch {
    pub task_id: TaskId,
    pub first_task_seq: u64,
    pub last_task_seq: Option<u64>,
    pub result: AgentSpawnOutcome,
}

/// Spawns one `agent:` workflow step's child session: mints and records the
/// parent's `TaskCreated`/`TaskStarted` lifecycle under `actor`'s own
/// session (`Origin::System`, `parent: None` — matching
/// [`dispatch_tool_for_workflow`]'s identical shape for a `tool:` step, and
/// for the same reason ruling P33 requires the redacted/dispatch split this
/// function's two prompt/model parameters already carry), admits the spawn
/// through the real `SessionActor::admit_task` gate, and reuses
/// [`crate::tools::agent_spawn_tool::spawn_child`] — the *same*
/// reserve→admit→create→commit core the model-issued `agent` tool
/// ([`crate::tools::agent_spawn_tool::dispatch_agent`]) uses, not a second
/// copy of it.
///
/// # This does not drive the child, and does not complete the parent task on success
///
/// Unlike `dispatch_tool_for_workflow`, a **successful** spawn here leaves
/// the parent task `Running` (`last_task_seq: None`) rather than appending a
/// `TaskCompleted`: driving the spawned child to a real result needs a live
/// `SessionActor` resolved from a `SessionRegistry`, which lives in
/// `roundhouse-daemon` — a crate `roundhouse-engine` may not depend on
/// (`AGENTS.md`'s crate-boundary rule). `DeliveryExecutor::
/// execute_pending_with_context` (`roundhouse-daemon::scheduler_driver`) is
/// what resolves the child, drives it, and completes `task_id` with the real
/// result. A **failure** here has no child to drive, so this function
/// appends the parent's own `TaskFailed` itself, exactly like
/// `dispatch_tool_for_workflow`'s refusal arms — there is nothing left for a
/// caller to complete later.
///
/// `logged_prompt` — already interpolated and dual-rendered by
/// `roundhouse-flow` (ruling P33), this function never re-derives it — is
/// only what the parent's `TaskCreated` is minted with. The real
/// `dispatch_prompt` `PendingKind::Agent` also carries is **not** a
/// parameter here: nothing in this function runs the child, so it has
/// nothing to do with the real prompt text; the daemon's own driving loop
/// reads `dispatch_prompt` straight off the same `PendingKind::Agent` this
/// function's caller already destructured, when it drives the child later.
/// `budget_tokens` is the run's real remaining `max_tokens` ceiling
/// (`roundhouse_flow::exec::run_loop::PendingKind::Agent::budget_tokens`'s
/// own doc comment), transferred into the child exactly as
/// `agent_spawn_tool::AgentArgs::budget_tokens` already transfers a
/// model-authored one — a workflow `agent:` step has no authored token
/// budget of its own to validate out of JSON.
pub async fn dispatch_agent_for_workflow(
    actor: &SessionActor,
    host: Option<&Arc<dyn SubAgentHost>>,
    logged_prompt: serde_json::Value,
    model: Option<String>,
    budget_tokens: u64,
) -> Result<WorkflowAgentDispatch, String> {
    let writer = actor.writer();
    let runner = actor.runner();
    let task_id = TaskId::new();

    let created = runner.record_task_created(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        TaskKind::Agent,
        None,
        Origin::System,
        TaskInput::Json(logged_prompt),
        1,
    );
    let first_task_seq = writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record a dispatched workflow agent spawn: {e}"))?;

    let Some(host) = host else {
        let last_task_seq = record_workflow_task_failed(
            actor,
            task_id,
            "sub_agent_host_unavailable",
            "agent spawn failed".into(),
        )
        .await?;
        return Ok(WorkflowAgentDispatch {
            task_id,
            first_task_seq,
            last_task_seq: Some(last_task_seq),
            result: AgentSpawnOutcome::Failed(
                "sub-agent spawning is not available for this session".into(),
            ),
        });
    };

    // §9.9/§6.1: the parent's real policy scope, through the same gate
    // `dispatch_agent`'s model-issued call passes — `TaskParams::Agent`
    // reaches `Predicate::Agent` here and nowhere else. `WORKFLOW_AGENT_PROVIDER_ID`
    // stands in for the `provider:` an `agent:` step's AST has no field for
    // (see that constant's own doc comment).
    let req = TaskCreateRequest {
        kind: TaskKind::Agent,
        origin: Origin::System,
        is_finally_step: false,
        params: TaskParams::Agent {
            provider: ProviderId(WORKFLOW_AGENT_PROVIDER_ID.to_string()),
            model: model.clone().unwrap_or_default(),
            tier_request: CHILD_TIER,
        },
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
        return Ok(WorkflowAgentDispatch {
            task_id,
            first_task_seq,
            // `record_denial` is best-effort about its own appends (see its
            // own doc comment) and does not hand back the seq it assigned —
            // matches `dispatch_tool_for_workflow`'s identical admission-
            // denial arm.
            last_task_seq: None,
            result: AgentSpawnOutcome::Failed(message),
        });
    }

    let started = runner.record_task_started(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        // The spawn itself runs in-process; the CHILD gets its own real
        // isolation once the daemon drives it. Matches `dispatch_agent`'s
        // identical placeholder for the identical reason.
        IsolationAttestation {
            tier: Tier::None,
            digest: String::new(),
            net_enforced: false,
        },
        None,
        1,
    );
    writer.append(started).await.map_err(|e| {
        format!("failed to record the dispatched workflow agent spawn starting: {e}")
    })?;

    let args = AgentArgs {
        provider: WORKFLOW_AGENT_PROVIDER_ID.to_string(),
        budget_tokens,
        model: model.unwrap_or_default(),
        // A workflow-spawned agent is not on any team — `host.team()` is
        // `None` for a workflow's root `SubAgentHost` (the same as a socket
        // client's), which already skips every team fence in `agent_spawn`.
        role: None,
    };
    match crate::tools::agent_spawn_tool::spawn_child(actor, host, &args).await {
        Ok(spawned) => Ok(WorkflowAgentDispatch {
            task_id,
            first_task_seq,
            last_task_seq: None,
            result: AgentSpawnOutcome::Spawned {
                child_session_id: spawned.child,
            },
        }),
        Err(refusal) => {
            tracing::warn!(
                session_id = %actor.session_id(),
                category = refusal.category,
                detail = %refusal.detail,
                "a workflow agent spawn was refused"
            );
            let last_task_seq = record_workflow_task_failed(
                actor,
                task_id,
                refusal.category,
                "agent spawn failed".into(),
            )
            .await?;
            Ok(WorkflowAgentDispatch {
                task_id,
                first_task_seq,
                last_task_seq: Some(last_task_seq),
                result: AgentSpawnOutcome::Failed(refusal.model_message),
            })
        }
    }
}
