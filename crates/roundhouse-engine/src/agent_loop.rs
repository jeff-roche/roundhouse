//! Phase 7, Task 5 — the real agentic tool-dispatch loop: the first code in
//! the workspace that maps a model-issued `ContentBlock::ToolUse` onto a
//! `TaskParams`/executor call. Before this module, [`crate::run_chat_turn`]
//! returned after exactly one provider round-trip and nothing called it
//! again with tool results appended — `roundhouse-daemon`'s `demo.rs`
//! hard-coded its one `edit_file(..)` call as an explicitly-disclaimed
//! stand-in for this dispatcher.
//!
//! # Scope — read before extending this module
//!
//! **Built-in arm (`read`/`write`/`edit`/`find`/`shell`): fully wired.**
//! Every dispatched call is admitted through the real
//! `SessionActor::admit_task` gate — `PolicyEngine::decide_sealed` against
//! the session's own live `SealedContext` (built from its actual
//! `mcp_resolved` set and isolation attestation, re-read on every call, not
//! a stale snapshot) — before [`crate::tool_dispatch::execute_builtin`] ever
//! runs the real `roundhouse-tools` executor. A denial surfaces to the model
//! as a real `ContentBlock::ToolResult { is_error: true, .. }`, never a
//! panic or a silent skip. Every admitted call is also recorded through the
//! same `TaskCreated`/`TaskStarted`/`TaskCompleted`|`TaskFailed` lifecycle
//! every other real task in this workspace goes through (S-LOG-1) — a
//! dispatched tool call is queryable in the session's event log, not a
//! bypass around it.
//!
//! **MCP arm: deliberately NOT wired, by design, not oversight.**
//! `roundhouse_mcp::executor::McpExecutor`'s real dispatch (`impl
//! TaskExecutor::execute`, `executor.rs:506`) needs a `TaskInput::Mcp {
//! server: ServerId, tool, args }`, and `execute` uses that `server` field
//! *directly* for its policy gate (`executor.rs:531`) — it is **not**
//! derived from resolving `tool`. The only authoritative source of the
//! right `ServerId` for a given namespaced tool name is
//! `ToolNamespace::resolve` (`namespace.rs:113`), and `McpExecutor.namespace`
//! is private with no accessor; `McpHost` exposes only
//! `tool_defs()`/`shutdown()` (`host.rs:212-330`). There is therefore no
//! honest way, from this crate, to build a correct `TaskInput::Mcp` for an
//! arbitrary namespaced tool name.
//!
//! Two things this module deliberately does **not** do to work around that:
//! it does not parse a `ServerId` out of the namespaced name (the
//! sanitization scheme in `roundhouse_mcp::namespace` makes that silently
//! wrong, not merely imprecise — see [`crate::tool_catalog::ToolTarget`]'s
//! doc comment), and it does not substitute a permissive policy to make MCP
//! dispatch "work" (exactly the failure carry-forward CF-7 item 2 warns
//! against). Instead, an MCP-targeted tool call always fails closed with a
//! named, honest `ToolResult { is_error: true }` explaining why — see
//! [`mcp_dispatch_refusal`]. This is reported BLOCKED, with this evidence,
//! in Task 5's report (`.superpowers/sdd/W1/task-5-report.md`); per that
//! task's brief, landing the built-in arm correctly and reporting the MCP
//! arm's gap explicitly is the intended outcome of this dispatch, not a
//! shortfall.
//!
//! # Unbounded results fold into context uncapped (carry-forward CF-7 item 4)
//! `run_agent_loop` folds every dispatched tool's result — built-in or
//! (were it wired) MCP — into `transcript` and into the next turn's
//! `request.messages` below with no size cap of its own. Combined with
//! `tool_dispatch`'s own note (see that module's doc comment) that none of
//! the built-in executors cap their output either, a call against a very
//! large file or a chatty shell command grows this loop's context
//! unboundedly, exactly the shape CF-7 item 4 flags for the MCP arm's
//! `stdio.rs:206`. Pre-existing/inherited, not introduced by this task; a
//! cap would belong here or in `tool_dispatch::execute_builtin`, whichever
//! task adds one.

use crate::session_actor::{SessionActor, TaskCreateRequest};
use crate::tool_catalog::{resolve_tool_target, ToolTarget};
use roundhouse_core::{
    IsolationAttestation, Origin, TaskError, TaskId, TaskInput, TaskKind, TaskOutput, TaskRunner,
    Tier, Timestamp, Usage,
};
use roundhouse_provider::{
    ChatRequest, ContentBlock, Message, MessageRole, Provider, RequestCtx, ToolCallId, ToolDef,
    ToolResultPart,
};
use roundhouse_store::EventWriter;

/// A hard ceiling on how many tool-call turns one [`run_agent_loop`] call may
/// take. The loop terminates on "no `ToolUse` blocks left" OR this many
/// dispatch turns having been used — never unconditionally — so a provider
/// scripted (or genuinely malfunctioning) to always return another
/// `ToolUse` cannot spin the loop forever.
pub struct AgentLoopConfig {
    pub max_turns: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentLoopError {
    #[error("chat turn failed: {0}")]
    Chat(#[from] crate::chat::AgentError),
    #[error("exceeded the maximum number of tool-call turns ({0}) in one agent loop")]
    MaxTurnsExceeded(u32),
}

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
/// Mirrors the identical helper in `chat.rs`/`session_actor.rs`/`mcp_spawner.rs`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Runs the agentic tool-dispatch loop: calls [`crate::run_chat_turn`], and
/// for every `ContentBlock::ToolUse` the model returns, admits and
/// dispatches it through the real executor, folds the (possibly `is_error`)
/// result back into the next turn's messages, and calls the provider again
/// — until the model stops asking for tools or `config.max_turns` is
/// exhausted.
///
/// Returns the full, in-order transcript of every `ContentBlock` produced
/// across the whole loop (every turn's assistant output AND every
/// dispatched tool's `ToolResult`), not just the final turn's blocks — so a
/// denial or an intermediate tool result is visible to the caller even when
/// the loop goes on to a further turn afterward.
pub async fn run_agent_loop(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    tools: &[ToolDef],
    mcp: Option<&roundhouse_mcp::executor::McpExecutor>,
    mut request: ChatRequest,
    config: AgentLoopConfig,
) -> Result<Vec<ContentBlock>, AgentLoopError> {
    request.tools = tools.to_vec();
    let mut turns: u32 = 0;
    let mut transcript: Vec<ContentBlock> = Vec::new();

    loop {
        let blocks = crate::run_chat_turn(
            writer,
            runner,
            provider,
            ctx,
            actor.session_id(),
            request.clone(),
        )
        .await?;

        let tool_uses: Vec<(ToolCallId, String, serde_json::Value)> = blocks
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolUse {
                    id, name, input, ..
                } => Some((id.clone(), name.clone(), input.clone())),
                _ => None,
            })
            .collect();

        transcript.extend(blocks.iter().cloned());

        if tool_uses.is_empty() {
            return Ok(transcript);
        }

        turns += 1;
        if turns > config.max_turns {
            return Err(AgentLoopError::MaxTurnsExceeded(config.max_turns));
        }

        let mut tool_results = Vec::with_capacity(tool_uses.len());
        for (id, name, input) in tool_uses {
            let outcome = dispatch_one_tool_call(actor, writer, runner, mcp, &name, &input).await;
            let block = match outcome {
                Ok(content) => ContentBlock::ToolResult {
                    tool_use_id: id,
                    content,
                    is_error: false,
                    cache: None,
                },
                Err(message) => ContentBlock::ToolResult {
                    tool_use_id: id,
                    content: vec![ToolResultPart { text: message }],
                    is_error: true,
                    cache: None,
                },
            };
            tool_results.push(block);
        }

        transcript.extend(tool_results.iter().cloned());

        request.messages.push(Message {
            role: MessageRole::Assistant,
            content: blocks,
        });
        request.messages.push(Message {
            role: MessageRole::User,
            content: tool_results,
        });
    }
}

/// Resolves and dispatches one tool call. Returns `Ok(content)` on success
/// or `Err(message)` on any failure (unknown tool, denied admission, or a
/// real executor error) — the caller turns `Err` into a
/// `ContentBlock::ToolResult { is_error: true }`, never a panic or a
/// silently-dropped call.
async fn dispatch_one_tool_call(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &TaskRunner,
    mcp: Option<&roundhouse_mcp::executor::McpExecutor>,
    name: &str,
    input: &serde_json::Value,
) -> Result<Vec<ToolResultPart>, String> {
    match resolve_tool_target(name) {
        Some(ToolTarget::Builtin(kind)) => {
            dispatch_builtin(actor, writer, runner, kind, input).await
        }
        Some(ToolTarget::Mcp { namespaced_name }) => {
            Err(mcp_dispatch_refusal(mcp, &namespaced_name))
        }
        None => Err(format!(
            "unknown tool `{name}` — not in this session's tool catalog"
        )),
    }
}

/// See this module's doc comment ("MCP arm: deliberately NOT wired") for the
/// full evidence trail. This never touches `mcp` beyond checking whether a
/// host is configured at all — it never calls `McpExecutor::execute`, never
/// guesses a `ServerId`, and never substitutes a permissive policy to make
/// the denial go away.
fn mcp_dispatch_refusal(
    mcp: Option<&roundhouse_mcp::executor::McpExecutor>,
    namespaced_name: &str,
) -> String {
    match mcp {
        None => {
            format!("no MCP servers are configured for this session (tool `{namespaced_name}`)")
        }
        Some(_) => format!(
            "MCP tool dispatch for `{namespaced_name}` is not wired in this build: resolving the \
             authoritative ServerId this tool's policy gate requires needs a `roundhouse-mcp` \
             accessor (a public reader over McpExecutor's private tool namespace) that does not \
             exist yet — refusing to guess a server id rather than silently bypassing that gate \
             (see Task 5's report, carry-forward CF-3 STRENGTHENED)"
        ),
    }
}

/// Admits and dispatches one builtin (`read`/`write`/`edit`/`find`/`shell`)
/// tool call, recording its full task lifecycle exactly like every other
/// real task in this workspace (S-LOG-1) — **including a denial.** A tool
/// call the model asked for is minted as a real `TaskCreated` event BEFORE
/// admission runs, mirroring `McpExecutor::gate`'s own precedent
/// (`executor.rs:339-378`: mint first, then `record_decision`, then
/// terminal): a denied call is still a real, queryable attempt in the
/// session's append-only log, not a silent non-event — a reviewer asking
/// "why does `write ~/.ssh/authorized_keys` leave no trace?" would be
/// asking about a real gap this ordering closes. Must never run the real
/// executor ([`crate::tool_dispatch::execute_builtin`]) before `admit_task`
/// has returned `Ok`.
async fn dispatch_builtin(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &TaskRunner,
    kind: TaskKind,
    input: &serde_json::Value,
) -> Result<Vec<ToolResultPart>, String> {
    let params =
        crate::tool_dispatch::task_params_for(kind.clone(), input).map_err(|e| e.to_string())?;

    // S-LOG-1: mint and durably record the real task this dispatch is
    // ATTEMPTING, before admission decides its fate — see this function's
    // own doc comment for why a denied call must still be queryable.
    let task_id = TaskId::new();
    let created = runner.record_task_created(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        kind.clone(),
        None,
        Origin::Model,
        TaskInput::Json(input.clone()),
        1,
    );
    writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record the dispatched tool call: {e}"))?;

    let req = TaskCreateRequest {
        kind: kind.clone(),
        origin: Origin::Model,
        is_finally_step: false,
        params: params.clone(),
    };

    // The real §6.2 admission gate: PolicyEngine::decide_sealed against this
    // session's own live SealedContext. A denial here must reach the model
    // as a real, visible tool error — not a panic, not a silently-dropped
    // call — so it is turned into `Err` and never causes this function (or
    // its caller) to unwind. It must also be durably recorded as a real
    // `TaskDecided`/`TaskFailed` pair, not left dangling at `TaskCreated`.
    if let Err(admit_err) = actor.admit_task(&req).await {
        return Err(record_denial(writer, runner, actor.session_id(), task_id, admit_err).await);
    }

    let started = runner.record_task_started(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        // This dispatch runs the real `roundhouse-tools` executor in-process,
        // not (yet) through the session's `Isolate::spawn` — see this
        // module's own doc comment on scope. Mirrors `chat.rs`'s identical
        // placeholder attestation for the same reason: nothing here claims a
        // sandbox tier this call didn't actually run under.
        IsolationAttestation {
            tier: Tier::None,
            digest: String::new(),
            net_enforced: false,
        },
        None,
        1,
    );
    writer
        .append(started)
        .await
        .map_err(|e| format!("failed to record the dispatched tool call starting: {e}"))?;

    match crate::tool_dispatch::execute_builtin(&params, input).await {
        Ok(parts) => {
            let summary = parts
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let completed = runner.record_task_completed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                TaskOutput::Text(summary),
                Usage::default(),
                1,
            );
            writer.append(completed).await.map_err(|e| {
                format!("failed to record the dispatched tool call completing: {e}")
            })?;
            Ok(parts)
        }
        Err(tool_err) => {
            let message = tool_err.to_string();
            let failed = runner.record_task_failed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                TaskError {
                    message: message.clone(),
                    category: "tool_error".into(),
                },
                false,
                1,
            );
            writer
                .append(failed)
                .await
                .map_err(|e| format!("failed to record the dispatched tool call failing: {e}"))?;
            Err(message)
        }
    }
}

/// Records a denied/refused admission as a real `TaskDecided`
/// (when the refusal names an actual policy outcome) followed by a
/// `TaskFailed` — mirroring `McpExecutor::gate`'s
/// `record_decision`-then-terminal precedent — and returns the message the
/// caller turns into a `ContentBlock::ToolResult { is_error: true }`.
///
/// `roundhouse_policy::engine::RuleId` (carried by `AdmitError::Denied`) and
/// `roundhouse_core::RuleId` (what `record_task_decided` accepts) are
/// deliberately different types of the same name — see
/// `AdmitError::Denied`'s own doc comment — so the policy-crate rule id
/// cannot be losslessly forwarded here; `record_task_decided` is called with
/// `rule: None`, the same choice `EngineTaskSpawner::record_decision` already
/// makes for the identical reason (`PolicyDecision` itself carries no rule
/// id on any variant).
async fn record_denial(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: roundhouse_core::SessionId,
    task_id: TaskId,
    admit_err: crate::session_actor::AdmitError,
) -> String {
    use crate::session_actor::AdmitError;

    let decision = match &admit_err {
        AdmitError::Denied(_) => Some(roundhouse_core::PolicyDecision::Deny),
        AdmitError::RequiresApproval => Some(roundhouse_core::PolicyDecision::Ask),
        AdmitError::SessionCancelling
        | AdmitError::SessionSuspended
        | AdmitError::SessionClosed
        | AdmitError::UnsealedAuditFailed(_) => None,
    };
    if let Some(decision) = decision {
        let decided =
            runner.record_task_decided(session_id, 0, now_ts(), task_id, decision, None, 1);
        // Best-effort: a failed append here must not prevent the TaskFailed
        // record below (or the model-visible denial) from also being
        // attempted — this mirrors `EngineTaskSpawner::record_decision`'s
        // own "every method has a real implementation" posture rather than
        // aborting the whole denial path on a secondary record's failure.
        if let Err(e) = writer.append(decided).await {
            tracing::warn!(error = %e, "failed to record TaskDecided for a denied dispatch");
        }
    }

    let category = match &admit_err {
        AdmitError::Denied(_) => "policy_denied",
        AdmitError::RequiresApproval => "requires_approval",
        AdmitError::SessionCancelling
        | AdmitError::SessionSuspended
        | AdmitError::SessionClosed => "session_not_running",
        AdmitError::UnsealedAuditFailed(_) => "store_error",
    };
    let message = format!("tool call denied: {admit_err}");
    let failed = runner.record_task_failed(
        session_id,
        0,
        now_ts(),
        task_id,
        TaskError {
            message: message.clone(),
            category: category.into(),
        },
        false,
        1,
    );
    if let Err(e) = writer.append(failed).await {
        tracing::warn!(error = %e, "failed to record TaskFailed for a denied dispatch");
    }

    message
}
