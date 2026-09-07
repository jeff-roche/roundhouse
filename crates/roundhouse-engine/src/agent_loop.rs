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
//! **MCP arm: wired as of fix round C2.** Rounds A/B/C1 left it deliberately
//! unwired: `roundhouse_mcp::executor::McpExecutor`'s real dispatch (`impl
//! TaskExecutor::execute`) needs a `TaskInput::Mcp {
//! server: ServerId, tool, args }`, and `execute` uses that `server` field
//! *directly* for its policy gate — it is **not**
//! derived from resolving `tool`, and `McpExecutor` exposed no way to
//! resolve a namespaced tool name to its authoritative `ServerId` (CF-3) or
//! to tell which servers had actually completed a handshake as opposed to
//! merely being configured (CF-9, the CF-8(b) sealed-context-bypass shape).
//! Round C2 closed both with two narrow, additive `McpExecutor` accessors —
//! [`roundhouse_mcp::executor::McpExecutor::resolve`] and
//! [`roundhouse_mcp::executor::McpExecutor::resolved_servers`] — and this
//! module's [`dispatch_mcp`] now builds a real `TaskInput::Mcp` using
//! `resolve`'s **`server`** half: `TaskInput::Mcp.tool` is set to the
//! namespaced name unchanged, because `execute` re-resolves `tool` itself
//! internally and would reject an already-resolved original name as unknown.
//! `execute` never re-derives `server` and uses whatever the caller passed
//! directly for its policy gate. This module never parses a `ServerId` out of
//! the namespaced name itself and never substitutes a permissive policy (the
//! two things this module always refused to do to fake "working" MCP
//! dispatch — CF-7 item 2).
//!
//! **Fix round D closed the four ways this arm was still weaker than the
//! built-in arm** (rulings W1-R80/W1-R81):
//! - It now passes through the same `SessionActor::admit_task` gate — with
//!   `resolve`'s **other** half, the ORIGINAL tool name, in its
//!   `TaskParams::Mcp`, because that is what `McpExecutor::gate` matches on
//!   and `Predicate::Mcp` compares tool names by exact string equality. That
//!   restores the session-lifecycle guard, the actor's own live
//!   `SealedContext`, and the `--unsealed` per-task audit `Note` that `gate`
//!   — holding an `Arc<dyn Policy>`, which has no `unsealed()` — could never
//!   have recorded. `SessionActor::register_mcp` is what makes that gate
//!   meaningful rather than a blanket denial; see its doc comment.
//! - A mid-dispatch session cancellation now aborts the call instead of
//!   letting it run to the full wall-clock bound, and the spawned dispatch is
//!   held in an [`AbortOnDrop`] guard so a torn-down session cannot leave a
//!   detached `execute()` appending events into a closing log.
//! - A `PolicyDecision::Ask` — the DEFAULT whenever no rule matches — now
//!   records a real terminal event instead of leaving the task suspended
//!   forever at `TaskDecided(Ask)`, and tells the model it is pending
//!   *approval* rather than mislabelling it an elicitation.
//! - `run_agent_loop` takes a [`crate::mcp_spawner::SessionMcp`], not a bare
//!   `Arc<McpExecutor>`, so the sealed floor behind the MCP gate is a
//!   compile-time property of this boundary rather than a convention one
//!   layer up.
//!
//! An MCP call still fails closed with a named
//! `ToolResult { is_error: true }` when: no MCP host is configured for the
//! session; the namespaced name doesn't resolve to any known server/tool;
//! admission or the executor's own gate refuses it; the dispatch panics (a
//! spawned-task boundary — see [`dispatch_mcp`]'s doc comment); the session
//! is cancelled mid-call; it exceeds its wall-clock bound; or the server
//! returns an `InputRequired`/elicitation result — the MRTR retry loop is
//! explicitly OUT OF SCOPE for this round (see [`dispatch_mcp`]'s
//! `Suspended` arms), so a suspended MCP task is reported honestly rather
//! than silently hung or faked as failed.
//!
//! # Unbounded results are now capped for the MCP arm; still uncapped for built-ins
//! `run_agent_loop` folds every dispatched tool's result into `transcript`
//! and into the next turn's `request.messages`. [`dispatch_mcp`] caps the
//! rendered text it returns (see [`MAX_MCP_RESULT_TEXT_BYTES`]) — CF-7 item
//! 4's own concern, since `StdioMcpTransport::spawn`'s stdout reader task
//! reads with no cap of its own and
//! `TaskInput::Json` has no size cap either, so an untrusted server could
//! otherwise grow context unboundedly on every subsequent turn. The
//! built-in arm's own executors (`tool_dispatch`'s own doc comment) still
//! cap NOTHING of their own beyond the shell arm's stdout/stderr byte cap
//! (round B's I1/M2 fix) — a `read` against a very large file still grows
//! this loop's context unboundedly. Pre-existing/inherited for the
//! built-in arm, not introduced by this round; closing it there belongs to
//! whichever task next touches `tool_dispatch::execute_builtin`.

use crate::session_actor::{SessionActor, TaskCreateRequest, TaskIsolator};
use crate::tool_catalog::{resolve_tool_target, ToolTarget};
use roundhouse_core::{
    IsolationAttestation, Origin, TaskError, TaskId, TaskInput, TaskKind, TaskOutput, TaskRunner,
    Tier, Timestamp, Usage,
};
use roundhouse_mcp::executor::TaskExecutor as _;
use roundhouse_provider::{
    ChatRequest, ContentBlock, Message, MessageRole, Provider, RequestCtx, ToolCallId, ToolDef,
    ToolResultPart,
};
use roundhouse_store::EventWriter;
use std::sync::Arc;
use std::time::Duration;

/// A hard ceiling on how many tool-call turns one [`run_agent_loop`] call may
/// take. The loop terminates on "no `ToolUse` blocks left" OR this many
/// dispatch turns having been used — never unconditionally — so a provider
/// scripted (or genuinely malfunctioning) to always return another
/// `ToolUse` cannot spin the loop forever.
pub struct AgentLoopConfig {
    pub max_turns: u32,
    /// Fix round A, SHOULD item F7: `max_turns` bounds provider round-trips
    /// only — a single response carrying an unbounded number of `ToolUse`
    /// blocks would otherwise dispatch all of them within one turn. Each
    /// call is still individually gated through `admit_task` (this is a
    /// resource bound, not an authorization gap — nothing here weakens
    /// admission), but an unbounded fan-out per turn is its own
    /// resource-exhaustion vector this ceiling closes.
    pub max_tool_calls_per_turn: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum AgentLoopError {
    #[error("chat turn failed: {0}")]
    Chat(#[from] crate::chat::AgentError),
    #[error("one turn issued {0} tool calls, exceeding the per-turn ceiling of {1}")]
    TooManyToolCallsInOneTurn(usize, u32),
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
///
/// **No separate `writer` parameter (fix round A, ruling W1-R60):** every
/// append this loop makes goes through `actor.writer()` — the session's own
/// `EventWriter` — rather than a second, independently-suppliable one. An
/// earlier version took `writer: &EventWriter` as its own parameter with
/// nothing checking it was the same instance `actor` was constructed with;
/// a caller could pass one whose `set_redactor` was never called, silently
/// un-redacting every event this loop appends. Sourcing it from `actor`
/// makes that mismatch structurally unrepresentable instead of merely
/// asserted against.
pub async fn run_agent_loop(
    actor: &SessionActor,
    runner: &'static TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    tools: &[ToolDef],
    mcp: Option<crate::mcp_spawner::SessionMcp>,
    mut request: ChatRequest,
    config: AgentLoopConfig,
) -> Result<Vec<ContentBlock>, AgentLoopError> {
    let writer = actor.writer();
    request.tools = tools.to_vec();
    let mut turns: u32 = 0;
    let mut transcript: Vec<ContentBlock> = Vec::new();

    loop {
        let (chat_task_id, blocks) = crate::run_chat_turn(
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
        if tool_uses.len() as u64 > u64::from(config.max_tool_calls_per_turn) {
            return Err(AgentLoopError::TooManyToolCallsInOneTurn(
                tool_uses.len(),
                config.max_tool_calls_per_turn,
            ));
        }

        let mut tool_results = Vec::with_capacity(tool_uses.len());
        for (id, name, input) in tool_uses {
            let outcome = dispatch_one_tool_call(
                actor,
                writer,
                runner,
                mcp.as_ref(),
                &name,
                &input,
                chat_task_id,
            )
            .await;
            let (content, is_error) = match outcome {
                Ok(content) => (content, false),
                Err(message) => (vec![ToolResultPart { text: message }], true),
            };
            // Fix round A, ruling W1-R59 ("redact, don't ask" — the `Ask`
            // escalation the frozen `SecretLeak` behavior calls for needs
            // lane W5's approval hook, out of this lane's charter): every
            // tool result is scanned through the SAME live redactor this
            // session's own `EventWriter` already applies at the
            // persistence boundary, BEFORE it is folded into the next
            // turn's `request.messages` — the direct path a leaked secret
            // (e.g. F1's `ANTHROPIC_API_KEY` reproduction) would otherwise
            // cross the network boundary to the provider on the very next
            // call.
            let content: Vec<ToolResultPart> = content
                .into_iter()
                .map(|part| ToolResultPart {
                    text: writer.redact_outbound(&part.text).0,
                })
                .collect();
            tool_results.push(ContentBlock::ToolResult {
                tool_use_id: id,
                content,
                is_error,
                cache: None,
            });
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
///
/// `parent` is the `chat` task id of the turn that issued this call (fix
/// round B, ruling W1-R53/W1-R64) — threaded into every task this dispatch
/// mints, so the session's task log is a real tree (a tool call is a child
/// of the turn that asked for it), not the flat list it was before this
/// round.
async fn dispatch_one_tool_call(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &'static TaskRunner,
    mcp: Option<&crate::mcp_spawner::SessionMcp>,
    name: &str,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    match resolve_tool_target(name) {
        Some(ToolTarget::Builtin(kind)) => {
            dispatch_builtin(actor, writer, runner, kind, input, parent).await
        }
        Some(ToolTarget::ShellCommand) => {
            dispatch_shell_command(actor, writer, runner, input, parent).await
        }
        Some(ToolTarget::Mcp { namespaced_name }) => match mcp {
            Some(mcp) => {
                dispatch_mcp(actor, writer, runner, mcp, &namespaced_name, input, parent).await
            }
            None => {
                // Fix round A, SHOULD item F10 (audit asymmetry): a built-in
                // denial mints a real TaskCreated/TaskFailed pair (see
                // `dispatch_builtin`'s doc comment), but this MCP-refusal arm
                // previously minted nothing at all — a model probing for MCP
                // tool names left zero trace. `TaskKind::Mcp` is the honest
                // categorization here (this IS a namespaced MCP-shaped tool
                // call, just not one this session has any server for).
                let message = format!(
                    "no MCP servers are configured for this session (tool `{namespaced_name}`)"
                );
                let recorded = record_unadmitted_refusal(
                    writer,
                    runner,
                    actor.session_id(),
                    TaskKind::Mcp,
                    parent,
                    input,
                    "mcp_not_configured",
                    message,
                )
                .await;
                // fix round B, ruling W1-R65: whichever string comes back —
                // the original refusal message (`Ok`) or a description of
                // the primary `TaskCreated` append itself failing (`Err`) —
                // this arm is always a refusal, so it always becomes `Err`
                // to the caller.
                Err(recorded.unwrap_or_else(|e| e))
            }
        },
        None => {
            // The unknown-tool case has no natural `TaskKind` to record
            // under (unlike the MCP arm above) — recording it as some
            // other kind would misclassify it, which is worse than the
            // residual audit gap. Left as a named, deliberate partial (see
            // fix round A's report) rather than guessed at.
            Err(format!(
                "unknown tool `{name}` — not in this session's tool catalog"
            ))
        }
    }
}

/// Classifies a model-provided shell string, rejects unsupported redirections,
/// and dispatches each resolved node through the ordinary admission/execution
/// path. Each node gets its own `TaskKind::Shell` task and policy decision.
async fn dispatch_shell_command(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &'static TaskRunner,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    let command = match input.get("command").and_then(serde_json::Value::as_str) {
        Some(command) => command,
        None => {
            return refuse_shell_command(
                writer,
                runner,
                actor,
                input,
                parent,
                "bad_args",
                "the `shell_command` tool call is missing or has an invalid `command` argument"
                    .to_string(),
            )
            .await;
        }
    };
    let cwd = match input.get("cwd").and_then(serde_json::Value::as_str) {
        Some(cwd) => cwd,
        None => {
            return refuse_shell_command(
                writer,
                runner,
                actor,
                input,
                parent,
                "bad_args",
                "the `shell_command` tool call is missing or has an invalid `cwd` argument"
                    .to_string(),
            )
            .await;
        }
    };
    let env = roundhouse_policy::shell::classify::SessionEnv::default();
    let classification = roundhouse_policy::shell::opaque::classify_shell(command, &env);
    let parsed = match classification {
        roundhouse_policy::shell::opaque::ShellClassification::HardDeny(hint) => {
            return refuse_shell_command(
                writer,
                runner,
                actor,
                input,
                parent,
                "shell_command_opaque",
                hint.hint,
            )
            .await
        }
        roundhouse_policy::shell::opaque::ShellClassification::Program(parsed) => parsed,
    };
    if roundhouse_policy::shell::pipeline::contains_unresolved_glob(command) {
        return refuse_shell_command(
            writer,
            runner,
            actor,
            input,
            parent,
            "shell_command_glob",
            "unresolved shell globs are not supported by this tool".to_string(),
        )
        .await;
    }
    if let Some(syntax) =
        roundhouse_policy::shell::pipeline::unsupported_shell_syntax(&parsed.program_ast)
    {
        let (category, message) = match syntax {
            roundhouse_policy::shell::pipeline::UnsupportedShellSyntax::CommandList => (
                "shell_command_command_list",
                "shell command lists are not supported by this tool".to_string(),
            ),
            roundhouse_policy::shell::pipeline::UnsupportedShellSyntax::Pipeline => (
                "shell_command_pipeline",
                "shell pipelines are not supported by this tool".to_string(),
            ),
            roundhouse_policy::shell::pipeline::UnsupportedShellSyntax::Compound => (
                "shell_command_control_flow",
                "shell compound syntax is not supported by this tool".to_string(),
            ),
        };
        return refuse_shell_command(writer, runner, actor, input, parent, category, message).await;
    }
    let decision = actor.shell_command_decision(command, &env);
    if decision.outcome == roundhouse_policy::Outcome::Deny {
        return refuse_shell_command(
            writer,
            runner,
            actor,
            input,
            parent,
            "policy_denied",
            "the shell command was denied by policy".to_string(),
        )
        .await;
    }
    let nodes = roundhouse_policy::shell::pipeline::resolve_nodes(&parsed.program_ast);
    if nodes.is_empty() {
        return refuse_shell_command(
            writer,
            runner,
            actor,
            input,
            parent,
            "shell_command_empty",
            "the shell command did not contain an executable command".to_string(),
        )
        .await;
    }
    if nodes.iter().any(|node| !node.redirections.is_empty()) {
        return refuse_shell_command(
            writer,
            runner,
            actor,
            input,
            parent,
            "shell_command_redirection",
            "shell redirections are not supported by this tool".to_string(),
        )
        .await;
    }

    let mut output = Vec::new();
    for node in nodes {
        let node_input = serde_json::json!({
            "program": node.resolved_program,
            "argv": node.argv,
            "cwd": cwd,
        });
        output.extend(
            dispatch_builtin(actor, writer, runner, TaskKind::Shell, &node_input, parent).await?,
        );
    }
    Ok(output)
}

async fn refuse_shell_command(
    writer: &EventWriter,
    runner: &'static TaskRunner,
    actor: &SessionActor,
    input: &serde_json::Value,
    parent: TaskId,
    category: &'static str,
    message: String,
) -> Result<Vec<ToolResultPart>, String> {
    let recorded = record_unadmitted_refusal(
        writer,
        runner,
        actor.session_id(),
        TaskKind::Shell,
        parent,
        input,
        category,
        message,
    )
    .await;
    Err(recorded.unwrap_or_else(|error| error))
}

/// Records a refusal that never reached `admit_task` at all as a real
/// `TaskCreated` followed unconditionally by `TaskFailed`, mirroring
/// `dispatch_builtin`'s own "a refused call is still a real, queryable
/// attempt" posture for the built-in arm.
///
/// Three callers, all refusing before any policy decision exists — so
/// neither records a `TaskDecided`, unlike `record_denial`:
///
/// 1. the MCP arm of [`dispatch_one_tool_call`], where the refusal is that
///    a real dispatch capability doesn't exist for this session;
/// 2. [`dispatch_builtin`]'s containment rejections (ruling W1-R131), where
///    `task_params_for` refused to build `TaskParams` at all — a `cwd` or
///    `program` outside the workspace root, or malformed arguments.
/// 3. [`refuse_shell_command`], where parsing or the model-facing shell
///    decision rejects the command before any node reaches admission.
///
/// `message` must be the caller's already-sanitized, model-safe text — for
/// case 2 that is `ToolDispatchError::unadmitted_refusal`'s, never the
/// error's own `Display`, since this string is BOTH written to the event
/// log and returned to the model.
///
/// **Fix round B, ruling W1-R65:** the primary `TaskCreated` append's
/// failure is now propagated (`Err`) rather than logged-and-continued —
/// this helper exists specifically to make F10's "a refused call is still
/// a real, queryable attempt" guarantee hold, so silently proceeding past a
/// failure to record that attempt would defeat the fix's own point (and was
/// inconsistent with `dispatch_builtin`'s sibling append at
/// `dispatch_builtin`, which already propagates via `?`). The `TaskFailed`
/// append is also propagated, so a refusal never reports
/// success after only its `TaskCreated` event was persisted.
async fn record_unadmitted_refusal(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: roundhouse_core::SessionId,
    kind: TaskKind,
    parent: TaskId,
    input: &serde_json::Value,
    category: &str,
    message: String,
) -> Result<String, String> {
    let task_id = TaskId::new();
    let created = runner.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        kind,
        Some(parent),
        Origin::Model,
        TaskInput::Json(input.clone()),
        1,
    );
    writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record an unadmitted refusal: {e}"))?;

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
    writer
        .append(failed)
        .await
        .map_err(|e| format!("failed to record TaskFailed for an unadmitted refusal: {e}"))?;

    Ok(message)
}

/// Wall-clock bound on one MCP tool-call dispatch (fix round C2, CF-7 item
/// 2): `McpExecutor::execute` takes no cancellation token of its own and
/// `stdio.rs`'s tool-call path has no timeout either, so a hostile or
/// merely-wedged server that never replies would otherwise hang this
/// dispatch (and, absent the spawned-task boundary below, the whole
/// session actor) forever — the same shape fix round B's I1 closed for the
/// shell arm. Same value as [`crate::tool_dispatch`]'s `SHELL_TIMEOUT`: no
/// evidence favors a different bound for a tool-call round trip over a
/// shell command's. Dropping the timed-out `execute` future stops US from
/// waiting on it, but does not confirm the transport itself has abandoned
/// the in-flight request the way `cancel_running_shell` confirms a killed
/// process group — a residual gap noted, not solved, here (closing it
/// belongs to `roundhouse-mcp`, out of this lane's charter).
const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(120);

/// Bound on how many bytes of rendered MCP tool-result TEXT this arm folds
/// into the next turn's `request.messages` (fix round C2, CF-7 item 4):
/// `StdioMcpTransport::spawn`'s stdout reader task reads an MCP server's
/// response with an unbounded `BufReader::lines()` and
/// `TaskInput`/`TaskOutput::Json` has no size cap
/// of its own, so an untrusted server could otherwise grow this loop's
/// context without bound on every subsequent turn — the same shape fix
/// round B's shell-output cap and M2's JSON-depth cap already closed
/// elsewhere in this lane. Deliberately much smaller than
/// `tool_dispatch::MAX_SHELL_OUTPUT_BYTES` (10 MiB): that cap bounds bytes
/// retained in a `ToolResultPart` of their own, not text folded into the
/// model's own context window on every remaining turn of this loop — this
/// codebase has no existing precedent sizing a context-bound text cap, so
/// 256 KiB is a conservative, explicitly-documented judgment call for this
/// round, not a measured constant.
const MAX_MCP_RESULT_TEXT_BYTES: usize = 256 * 1024;

/// Renders MCP result content blocks down to the plain text a
/// `ToolResultPart` can carry, capped at [`MAX_MCP_RESULT_TEXT_BYTES`] with
/// a visible truncation marker appended when the cap is hit (never silent
/// — mirrors M2's own "truncation must be visible" principle).
///
/// `Text` blocks render verbatim. `Document` blocks whose `mime_type`
/// starts with `text/` (`McpExecutor::decode_content`'s own shape for a
/// resource that carried inline text, e.g. `text/plain`/`text/uri-list`)
/// render their real text too, prefixed with `title` when present — this
/// is genuinely useful information a model asked for, not something to
/// throw away out of excess caution. Every other block (`Image`, and any
/// `Document` whose `mime_type` is NOT `text/*` — i.e. carries real binary
/// data) renders as a short, honest placeholder instead of being inlined:
/// base64-encoding raw image/binary bytes into the model's text context is
/// enormous (roughly 4/3 the original size) for a shape most models cannot
/// usefully consume as inline text anyway, and it is exactly the kind of
/// unbounded-growth vector this function's own cap exists to bound.
/// `ToolUse`/`ToolResult`/`Thinking`/`Opaque` never appear here in
/// practice (`decode_content` only ever produces `Text`/`Image`/
/// `Document`), but are handled with the same placeholder fallback rather
/// than a panic, since this function's input ultimately traces back to
/// untrusted server output.
fn render_mcp_content(content: Vec<(ContentBlock, roundhouse_core::Provenance)>) -> String {
    let mut rendered = String::new();
    let mut truncated = false;
    for (block, _provenance) in content {
        // §6.8: every block here is `Trust::Untrusted` regardless of
        // provenance details — nothing about `_provenance` changes how a
        // block is rendered, so it is intentionally unused beyond being
        // part of `decode_content`'s real return shape.
        let piece = match block {
            ContentBlock::Text { text, .. } => text,
            ContentBlock::Document { source, title, .. }
                if source.mime_type.starts_with("text/") =>
            {
                let text = String::from_utf8_lossy(&source.data);
                match title {
                    Some(title) => format!("[{title}]\n{text}"),
                    None => text.into_owned(),
                }
            }
            ContentBlock::Image { source, .. } => {
                format!(
                    "[image: {}, {} bytes — not rendered into context]",
                    source.mime_type,
                    source.data.len()
                )
            }
            ContentBlock::Document { source, title, .. } => format!(
                "[document: {}, {} bytes{} — not rendered into context]",
                source.mime_type,
                source.data.len(),
                title.map(|t| format!(", title: {t}")).unwrap_or_default()
            ),
            other => format!("[unsupported MCP content block: {other:?}]"),
        };
        if truncated {
            continue;
        }
        if !rendered.is_empty() {
            rendered.push('\n');
        }
        if rendered.len() + piece.len() > MAX_MCP_RESULT_TEXT_BYTES {
            let remaining = MAX_MCP_RESULT_TEXT_BYTES.saturating_sub(rendered.len());
            // Never split a UTF-8 char boundary — floor(remaining) to the
            // nearest valid boundary rather than panic on a mid-codepoint
            // cut.
            let mut cut = remaining.min(piece.len());
            while cut > 0 && !piece.is_char_boundary(cut) {
                cut -= 1;
            }
            rendered.push_str(&piece[..cut]);
            truncated = true;
        } else {
            rendered.push_str(&piece);
        }
    }
    if truncated {
        rendered.push_str(&format!(
            "\n[MCP result truncated at {MAX_MCP_RESULT_TEXT_BYTES} bytes]"
        ));
    }
    rendered
}

/// Admits and dispatches one MCP tool call through the real
/// `roundhouse_mcp::executor::McpExecutor::execute` (fix round C2 — see
/// this module's own doc comment for the CF-3/CF-9 accessors that made this
/// possible, and everything it still refuses to do).
///
/// **S-LOG-1, mirroring `dispatch_builtin`'s own precedent:** `TaskCreated`
/// is minted and durably appended BEFORE dispatch, so an unresolvable
/// namespaced name or a spawned-task panic still leaves a real, queryable
/// attempt in the log rather than nothing at all.
///
/// **The spawned-task boundary (CF-7 item 1):** `execute` runs inside
/// `tokio::spawn`, and this function `.await`s the `JoinHandle` rather than
/// calling `execute` in-process. `execute`'s internal writes all go through
/// the SAME `EngineTaskSpawner` this `McpExecutor` was constructed with
/// (`mcp_spawner.rs`), which PANICS on a failed `EventWriter` append by
/// design (see that module's own doc comment) rather than swallowing it.
///
/// **How load-bearing that boundary is (corrected in fix round D, M2):** an
/// earlier version of this comment named `suspend_for_elicitation`'s appends
/// as the *sole* internal panic condition, i.e. something only an
/// `InputRequired` result could reach. That understated it, and understating
/// it invites a later reader to "simplify" the boundary away as
/// elicitation-only. `gate` calls `task_spawner.record_decision` on **every**
/// dispatch — before the `Allow`/`Ask`/`Deny` match, so
/// on all three outcomes — and `EngineTaskSpawner::record_decision`
/// `.expect()`s on a failed append. So the panic
/// path is reachable from the very first thing `execute` does with the
/// spawner, on the ordinary allow path, not just from the rare elicitation
/// one. `suspend_for_elicitation`'s `spawn_task`/`suspend_task` appends
/// (reached only on an `InputRequired` result) are additional such sites,
/// not the only ones. Without the spawned-task boundary,
/// that panic would unwind straight through this function into whatever
/// called `run_agent_loop` — the session actor itself. `tokio::spawn`
/// catches it as an `Err(JoinError)` on the handle instead, so ONE
/// dispatch panicking fails only that dispatch: this function still
/// records a real `TaskFailed` for the task it minted (a panic mid-`execute`
/// leaves no guarantee ANY terminal state was recorded for THIS task,
/// unlike `Completed`/`Failed`/`Suspended`, all of which are fully resolved
/// before `execute` ever returns) and returns an honest error to the model,
/// rather than the whole session actor going down.
///
/// **`Suspended` splits on its reason (fix round D, finding I1).** Only
/// `AwaitingElicitation` is already durably recorded: `execute`'s
/// `suspend_for_elicitation` path calls `task_spawner.suspend_task`
/// synchronously before returning, so writing
/// another terminal event for it here would be a double-write. `gate`'s
/// `Ask` arm does **not** — it records a `TaskDecided(Ask)` and returns
/// `Suspended { AwaitingApproval }` with no `suspend_task` call — so that
/// reason (and, fail-closed, every other) gets a real `TaskFailed
/// { category: "requires_approval" }` here, matching `record_denial`'s own
/// `AdmitError::RequiresApproval` arm on the built-in side. The MRTR retry
/// loop (resuming a suspended MCP task with
/// `ResumptionInput::ElicitationAnswers` once a human answers the
/// elicitation) is explicitly OUT OF SCOPE for this round: nothing in
/// `run_agent_loop` today re-visits a suspended task, so both arms report
/// an honest `is_error: true` result naming what the call is actually
/// waiting on, rather than silently hanging or mischaracterizing one kind
/// of suspension as the other.
///
/// # Turns a spawned MCP dispatch's `JoinHandle` result into an `ExecutorOutcome`
/// Split out from [`dispatch_mcp`] so the CF-7 item 1 boundary — what
/// happens when the spawned task panicked or was aborted instead of
/// returning normally — is independently unit-testable without needing to
/// reproduce a real internal panic condition inside `McpExecutor` (an
/// `EventWriter` append failure inside `EngineTaskSpawner`, which this
/// crate has no clean way to force from outside `roundhouse-mcp`). `join_result` is accepted as a plain
/// parameter rather than a `JoinHandle` for exactly this reason: a test can
/// hand it the result of `tokio::spawn(async { panic!(..) }).await` — an
/// artificially panicking task, unrelated to any real MCP internals — and
/// still be testing the REAL logic this function shares with production.
///
/// `pub`, not private (fix round C2): the only way to exercise this branch
/// from a test is to hand it a genuine `Err(JoinError)` from an
/// artificially panicking task, and every `#[test]`/`#[tokio::test]` in
/// this crate's OWN `--lib` binary shares one process with
/// `session_actor.rs`'s single `TaskRunner::bootstrap()` call (which panics
/// on a second call per process) — a second internal unit test bootstrapping
/// its own `TaskRunner` would collide with it. Exposing this one narrow,
/// already-self-contained seam lets `tests/agent_loop_dispatch.rs` (its own,
/// independent process, with its own `static RUNNER`) test it directly
/// instead.
/// Aborts the wrapped spawned task when dropped (fix round D, ruling
/// W1-R81 finding I2 level 3). `tokio::spawn` detaches: dropping a
/// `JoinHandle` abandons the handle, **not the task**, which keeps running
/// to completion. For an MCP dispatch that means a session torn down
/// mid-call leaves an `execute()` still holding the session's
/// `EngineTaskSpawner` and still able to append events into a closing
/// session's log. A one-field guard with a `Drop` impl is the smallest fix
/// that covers the *drop* case, which no `select!` arm can — by definition
/// nothing of ours is running to observe it.
///
/// Deliberately local rather than `tokio_util::task::AbortOnDropHandle`:
/// `roundhouse-engine` does not depend on `tokio-util` and this is four
/// lines.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn resolve_mcp_join_result(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: roundhouse_core::SessionId,
    task_id: TaskId,
    join_result: Result<roundhouse_mcp::executor::ExecutorOutcome, tokio::task::JoinError>,
) -> Result<roundhouse_mcp::executor::ExecutorOutcome, String> {
    match join_result {
        Ok(outcome) => Ok(outcome),
        Err(join_err) => {
            // CF-7 item 1: the spawned dispatch panicked (or was
            // cancelled) — this task never reached a terminal state on its
            // own, so record one now rather than leaving it dangling at
            // `TaskStarted` forever.
            //
            // Fix round D: the two causes are now told apart rather than
            // both being logged as a panic. `is_cancelled()` here means
            // `dispatch_mcp` aborted the task because the owning session was
            // cancelled/suspended/closed mid-call (finding I2 level 2), which
            // is a routine, operator-initiated outcome — recording it under
            // `mcp_dispatch_panic` would put a false panic in the audit log
            // every time a user hits cancel.
            let (message, category) = if join_err.is_cancelled() {
                (
                    "MCP tool call dispatch was cancelled: the owning session was \
                     cancelled/suspended/closed while the call was in flight"
                        .to_string(),
                    "session_cancelled",
                )
            } else {
                (
                    format!("MCP tool call dispatch panicked: {join_err}"),
                    "mcp_dispatch_panic",
                )
            };
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
                tracing::warn!(
                    error = %e,
                    "failed to record TaskFailed for a panicked MCP dispatch"
                );
            }
            Err(message)
        }
    }
}

/// The real MCP dispatch arm (fix round C2; gated and cancellable as of fix
/// round D). Resolves `namespaced_name` via
/// [`roundhouse_mcp::executor::McpExecutor::resolve`] and uses BOTH halves:
/// the authoritative `server` for `execute`'s policy gate, and the ORIGINAL
/// tool name for `admit_task`'s `TaskParams::Mcp`. `TaskInput::Mcp.tool`
/// still carries `namespaced_name` itself, unchanged, because `execute`
/// re-resolves `tool` internally and rejects an already-resolved original
/// name as unknown (see this module's top-level doc comment, and the comment
/// at the `resolve` call below, for the full explanation of that three-way
/// split).
///
/// The event sequence is `dispatch_builtin`'s, exactly: `TaskCreated`, then
/// `SessionActor::admit_task`, then — only if admission passed —
/// `TaskStarted`, the dispatch, and a `TaskCompleted`/`TaskFailed`, per
/// S-LOG-1. A refusal at admission goes through the same [`record_denial`]
/// helper the built-in arm uses, so a denied MCP call is as queryable as a
/// denied `write`.
///
/// CF-7 item 1 — the spawned-task boundary: the actual `execute` call runs
/// inside `tokio::spawn`, wrapped in a `MCP_CALL_TIMEOUT` timeout, so that an
/// `EventWriter` append panic inside `McpExecutor`'s injected `TaskSpawner`
/// (which panics by design on a failed append — see `mcp_spawner.rs`) is
/// caught as an `Err(JoinError)` on the `JoinHandle` rather than unwinding
/// into the session actor and killing every other task in flight.
/// [`resolve_mcp_join_result`] turns that `Err` into a durable `TaskFailed`
/// so the task never dangles at `TaskStarted` forever.
async fn dispatch_mcp(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &'static TaskRunner,
    mcp: &crate::mcp_spawner::SessionMcp,
    namespaced_name: &str,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    // CF-3: the only authoritative source of the ServerId `execute`'s
    // policy gate uses directly — never parsed out of the namespaced name.
    //
    // **Both halves of this resolution are load-bearing, for different
    // consumers (fix round D, ruling W1-R80).** `server` is what `execute`'s
    // gate uses directly and never re-derives. `original_tool` is a DECOY for
    // `TaskInput::Mcp.tool` — `execute` re-resolves that field itself
    // and would reject an already-resolved original
    // name as unknown — but it is exactly the right input for `admit_task`'s
    // `TaskParams::Mcp.tool` below, because `execute` resolves the namespaced
    // name to `original_tool` BEFORE calling `gate`, and
    // `gate` builds its own `TaskParams::Mcp` with that original name
    // from that original name. `Predicate::Mcp` matches `tool` by exact
    // string equality, so feeding `admit_task` the
    // namespaced name instead would make the two gates silently disagree in
    // both directions — a rule allowing `search` would match one and not the
    // other.
    let (server, original_tool) = match mcp.executor().resolve(namespaced_name) {
        Some((server, original_tool)) => (server.clone(), original_tool.to_string()),
        None => {
            let message = format!(
                "unknown MCP tool `{namespaced_name}` — no server registered this namespaced \
                 name, refusing to forward an unresolved name to the transport"
            );
            let recorded = record_unadmitted_refusal(
                writer,
                runner,
                actor.session_id(),
                TaskKind::Mcp,
                parent,
                input,
                "mcp_unresolved_tool",
                message,
            )
            .await;
            return Err(recorded.unwrap_or_else(|e| e));
        }
    };

    // S-LOG-1: mint and durably record the real task this dispatch is
    // ATTEMPTING before dispatch runs — see this function's own doc
    // comment for why a panic mid-dispatch must not leave this task
    // permanently dangling with no terminal record.
    let task_id = TaskId::new();
    let recorded_input = serde_json::json!({ "tool": namespaced_name, "args": input });
    let created = runner.record_task_created(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        TaskKind::Mcp,
        Some(parent),
        Origin::Model,
        TaskInput::Json(recorded_input),
        1,
    );
    writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record the dispatched MCP tool call: {e}"))?;

    // Fix round D, ruling W1-R80 (finding I2 level 1, plus I3): the SAME
    // `SessionActor::admit_task` gate the built-in arm goes through. Until
    // this round the MCP arm skipped it entirely, so it lost three things
    // `McpExecutor::gate` structurally cannot provide:
    //
    //   * the session-lifecycle guard — a session already `Cancelling`/
    //     `Suspended`/`Closed` could still have a fresh MCP dispatch started;
    //   * the `--unsealed` per-task audit `Note`, which `admit_task` records
    //     for every task and **fails admission closed** if it cannot append.
    //     `gate` holds an `Arc<dyn Policy>`, which has no `unsealed()`
    //     method, so it could never have recorded one — meaning under
    //     `round daemon --unsealed` an MCP call to a server that never
    //     completed a handshake was allowed with no per-task record that the
    //     floor was off;
    //   * the actor's OWN live `SealedContext` (its real isolation
    //     attestation, re-read per call).
    //
    // The resulting double-gate (`decide_sealed` runs here and again in
    // `gate`) is redundant and fail-closed, not harmful: grants are
    // `CompiledRule`s and `decide` is pure over `self.rules`, so nothing is
    // double-decremented; `admit_task` emits no `TaskDecided` of its own, so
    // there is no duplicate event; and the TOCTOU window between the two
    // drifts only toward Deny.
    let req = TaskCreateRequest {
        kind: TaskKind::Mcp,
        origin: Origin::Model,
        is_finally_step: false,
        params: roundhouse_policy::TaskParams::Mcp {
            server: server.clone(),
            // The ORIGINAL tool name, matching what `gate` builds — see the
            // `resolve` call above. NOT `namespaced_name`.
            tool: original_tool,
            args: input.clone(),
        },
    };
    if let Err(admit_err) = actor.admit_task(&req).await {
        return Err(record_denial(writer, runner, actor.session_id(), task_id, admit_err).await);
    }

    let started = runner.record_task_started(
        actor.session_id(),
        0,
        now_ts(),
        task_id,
        // Mirrors `dispatch_builtin`'s identical placeholder attestation:
        // this dispatch runs the MCP transport in-process (a subprocess
        // the daemon itself spawned at MCP-host-startup time, not a fresh
        // sandboxed child per call), not through `Isolate::spawn` — nothing
        // here claims a sandbox tier this call didn't actually run under.
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
        .map_err(|e| format!("failed to record the dispatched MCP tool call starting: {e}"))?;

    // Taint: `Taint::Tainted` (the conservative of the two values §6.8
    // defines) — this codebase has no live per-session taint tracker today
    // (nothing populates one across turns), so this is a fail-closed
    // default for a field some future config rule may consult, not a
    // measured "this session is untrustworthy" judgment. Revisit once a
    // real taint tracker exists.
    let ctx = roundhouse_mcp::executor::TaskCtx {
        task: task_id,
        session: actor.session_id(),
        parent: Some(parent),
        taint: roundhouse_policy::Taint::Tainted,
    };
    let mcp_input = roundhouse_mcp::executor::TaskInput::Mcp {
        server,
        // The NAMESPACED name, not an already-resolved original one —
        // `execute` resolves `tool` itself, internally, to find the
        // original tool name it actually dispatches to the transport.
        tool: namespaced_name.to_string(),
        args: input.clone(),
    };

    let mcp_for_task = Arc::clone(mcp.executor());
    // Fix round D, ruling W1-R81 finding I2 level 3: `tokio` does NOT abort a
    // spawned task when its `JoinHandle` is dropped. Before this guard, if
    // `run_agent_loop`'s own future was dropped mid-dispatch (session
    // teardown), the detached `execute()` kept running — still holding an
    // `Arc<McpExecutor>` and through it the `EngineTaskSpawner` — and could
    // append a `TaskDecided`, a `TaskSuspended`, or a whole elicitation
    // `TaskCreated` into a session that was closing. Dropping this guard
    // aborts the task instead.
    let mut dispatch = AbortOnDrop(tokio::spawn(async move {
        match tokio::time::timeout(
            MCP_CALL_TIMEOUT,
            mcp_for_task.execute(&ctx, &mcp_input, None),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => roundhouse_mcp::executor::ExecutorOutcome::Failed {
                error: TaskError {
                    message: format!(
                        "MCP tool call exceeded its {MCP_CALL_TIMEOUT:?} wall-clock bound"
                    ),
                    category: "mcp_timeout".into(),
                },
                retryable: true,
            },
        }
    }));

    // Fix round D, ruling W1-R81 finding I2 level 2: the built-in arm passes
    // `Some(actor.subscribe())` into `execute_builtin`, so a mid-dispatch
    // `cancel()` reaches the running call. This arm passed no cancellation
    // channel at all, so a cancelled session's MCP call ran on to the full
    // `MCP_CALL_TIMEOUT` regardless. `McpExecutor::execute` takes no
    // cancellation token of its own, so cancellation is enforced at this
    // boundary: abort the spawned dispatch and let `resolve_mcp_join_result`
    // record the resulting `JoinError` as a real terminal event.
    let mut cancel = Some(actor.subscribe());
    let join_result = tokio::select! {
        joined = &mut dispatch.0 => joined,
        () = crate::tool_dispatch::wait_for_session_cancel(&mut cancel) => {
            dispatch.0.abort();
            (&mut dispatch.0).await
        }
    };

    let outcome =
        resolve_mcp_join_result(writer, runner, actor.session_id(), task_id, join_result).await?;

    match outcome {
        roundhouse_mcp::executor::ExecutorOutcome::Completed { output, usage } => {
            let roundhouse_mcp::executor::TaskOutput::Mcp { content, is_error } = output;
            let rendered = render_mcp_content(content);
            let completed = runner.record_task_completed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                TaskOutput::Text(rendered.clone()),
                usage,
                1,
            );
            writer.append(completed).await.map_err(|e| {
                format!("failed to record the dispatched MCP tool call completing: {e}")
            })?;
            if is_error {
                Err(rendered)
            } else {
                Ok(vec![ToolResultPart { text: rendered }])
            }
        }
        roundhouse_mcp::executor::ExecutorOutcome::Failed { error, retryable } => {
            let message = error.message.clone();
            // Fix round D, M1: `retryable` is forwarded, not discarded and
            // hardcoded `false`. The timeout arm above explicitly constructs
            // `retryable: true`, and `McpExecutor`'s own transport-error path
            // does too — dropping the flag here made
            // the log contradict itself, recording a retryable failure as
            // non-retryable in the very same dispatch that produced it.
            let failed = runner.record_task_failed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                error,
                retryable,
                1,
            );
            writer.append(failed).await.map_err(|e| {
                format!("failed to record the dispatched MCP tool call failing: {e}")
            })?;
            Err(message)
        }
        // Fix round D, ruling W1-R81 finding I1 — an S-LOG-1 violation on
        // the DEFAULT path. `execute` durably writes a `TaskSuspended` for
        // exactly ONE of these two reasons, and the pre-fix code appended
        // nothing for either:
        //
        //   * `suspend_for_elicitation` calls `task_spawner.suspend_task`
        //     before returning — so `AwaitingElicitation`
        //     really is already recorded, and a second write here would be a
        //     double-write for the same task;
        //   * `gate`'s `Ask` arm records only a
        //     `TaskDecided(Ask)` via `record_decision` and returns
        //     `Suspended { AwaitingApproval }` **without** calling
        //     `suspend_task`. That left `TaskCreated -> TaskStarted ->
        //     TaskDecided(Ask) -> nothing`: a task permanently in flight.
        //
        // And `Ask` is not an edge case: `PolicyEngine::decide` returns `Ask`
        // whenever no rule matches, so every MCP call
        // without an operator-written allow rule lands here. The model was
        // additionally told the call needed "an elicitation" when what it
        // actually needed was a human approval.
        roundhouse_mcp::executor::ExecutorOutcome::Suspended {
            reason: roundhouse_core::SuspendReason::AwaitingElicitation { .. },
        } => {
            // Already durably recorded by `execute` itself — see this
            // function's own doc comment. Nothing more to append here.
            Err(format!(
                "MCP tool `{namespaced_name}` requires additional input (an elicitation) this \
                 dispatch loop cannot yet resume — the task is suspended, not failed, but MRTR \
                 resume is out of this round's scope"
            ))
        }
        // Every other suspension reason — `AwaitingApproval` today, and any
        // future variant — gets a real terminal event. Deliberately a
        // catch-all rather than a second exact arm: the elicitation case is
        // the only one this crate can prove is already durably recorded, so
        // anything else must fail closed toward "record a terminal" rather
        // than toward "assume someone else did."
        roundhouse_mcp::executor::ExecutorOutcome::Suspended { reason } => {
            let message = match &reason {
                roundhouse_core::SuspendReason::AwaitingApproval { .. } => format!(
                    "MCP tool `{namespaced_name}` is pending approval: the executor's §6.2 policy \
                     gate returned Ask, and no approval workflow is wired to this dispatch loop \
                     yet — the call was not made"
                ),
                other => format!(
                    "MCP tool `{namespaced_name}` suspended for a reason this dispatch loop \
                     cannot resume ({other:?}) — the call was not made"
                ),
            };
            // `gate` already recorded the `TaskDecided(Ask)`; what was
            // missing is the terminal. This mirrors `record_denial`'s own
            // `AdmitError::RequiresApproval` arm on the built-in side —
            // same `requires_approval` category — so the two arms are no
            // longer asymmetric on the approval path.
            //
            // **The `params_digest` is DISCARDED here, not persisted**
            // (ruling W1-R88): `SuspendReason::AwaitingApproval` carries a
            // `rule` and a `params_digest` — §6.2/§6.4's grant-scope
            // provenance, the blake3 over the canonicalized `TaskParams` that
            // an approval grant would have to match — and `TaskFailed` has
            // nowhere to put either. Recording a terminal is the right
            // fail-closed choice for S-LOG-1 (the alternative is a task in
            // flight forever), but it FORECLOSES a later approval for this
            // task rather than parking it: once this event is written, the
            // model must re-issue the call and a fresh digest is computed.
            // A future approval-workflow task must NOT assume the digest is
            // recoverable from the event log — it is not. If resumable
            // approvals are wanted, this arm needs a real `TaskSuspended`
            // carrying the reason, plus something that can later resume it.
            let failed = runner.record_task_failed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                TaskError {
                    message: message.clone(),
                    category: "requires_approval".into(),
                },
                false,
                1,
            );
            writer.append(failed).await.map_err(|e| {
                format!("failed to record the suspended MCP tool call's terminal state: {e}")
            })?;
            Err(message)
        }
    }
}

/// Admits and dispatches one builtin (`read`/`write`/`edit`/`find`/`shell`)
/// tool call, recording its full task lifecycle exactly like every other
/// real task in this workspace (S-LOG-1) — **including a denial.** A tool
/// call the model asked for is minted as a real `TaskCreated` event BEFORE
/// admission runs, mirroring `McpExecutor::gate`'s own precedent
/// (`McpExecutor::gate`: mint first, then `record_decision`, then
/// terminal): a denied call is still a real, queryable attempt in the
/// session's append-only log, not a silent non-event — a reviewer asking
/// "why does `write ~/.ssh/authorized_keys` leave no trace?" would be
/// asking about a real gap this ordering closes. Must never run the real
/// executor ([`crate::tool_dispatch::execute_builtin`]) before `admit_task`
/// has returned `Ok`.
///
/// **One refusal is raised even earlier than that minting, and is recorded
/// anyway (ruling W1-R131):** `task_params_for` rejects a `shell` `cwd` or
/// `program` outside the workspace root — and malformed arguments — before
/// there is a `TaskParams` to admit at all. That arm routes through
/// [`record_unadmitted_refusal`], which mints its own `TaskCreated`/
/// `TaskFailed` pair, so the "no silent non-event" guarantee above covers
/// containment rejections too, not only policy denials.
async fn dispatch_builtin(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &TaskRunner,
    kind: TaskKind,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    let (params, extras) = match crate::tool_dispatch::task_params_for(kind.clone(), input) {
        Ok(resolved) => resolved,
        Err(err) => {
            // **Ruling W1-R131.** This arm used to be `?` — the error
            // propagated straight back to the model BEFORE `task_id` was
            // minted below, so every shell/fs containment rejection
            // (`ShellCwdRejected`, `ShellProgramRejected`, `BadArgs`)
            // returned with ZERO events in the append-only log. That is
            // exactly the F10 audit asymmetry ruling W1-R81 closed for the
            // MCP arm via `record_unadmitted_refusal`; the built-in arm was
            // never covered, because that ruling's own text said "MCP and
            // unknown-tool refusals."
            //
            // Unlike the MCP arm, there is no categorization to guess at
            // here: `kind` IS the real `TaskKind` the model asked for, so
            // the refusal is recorded under the kind it actually attempted.
            //
            // `unadmitted_refusal` — never `err.to_string()` — supplies the
            // model-visible text, for the disclosure half of the same
            // ruling: the `Display` of these variants embeds the daemon's
            // own workspace root and `std::io::Error`'s text for an
            // attacker-chosen path (a filesystem existence-and-permission
            // oracle, evaluated before `admit_task` so the fail-closed
            // policy default never sees it). The same `err.kind()`-not-`err`
            // discipline ruling W1-R112 forced on config errors, for the
            // identical reason. The detail is not lost: it goes to the
            // daemon's own log below, and the refusal's `TaskCreated`
            // carries the model's verbatim `input`.
            let (category, message) = err.unadmitted_refusal();
            // `%err` is a tracing FIELD value, which `tracing-subscriber`'s
            // 0.3.20 escaping fix does NOT cover (it escapes the message
            // body only — see this workspace's pin comments). It is safe
            // here because every `ToolDispatchError` variant that embeds a
            // model-supplied string does so with `{:?}`, and `Debug` for
            // `str` escapes control characters (an ANSI `\u{1b}` included);
            // the only `{}`-interpolated payloads are `std::io::Error`
            // renderings, which the model does not control. A new variant
            // that interpolates model input with `{}` would break that.
            tracing::warn!(
                error = %err,
                "refusing a builtin tool call before admission"
            );
            let recorded = record_unadmitted_refusal(
                writer,
                runner,
                actor.session_id(),
                kind,
                parent,
                input,
                category,
                message,
            )
            .await;
            // Mirrors the MCP arm exactly (ruling W1-R65): whichever string
            // comes back — the refusal itself (`Ok`) or a description of the
            // `TaskCreated` append failing (`Err`) — this is always a
            // refusal, so it always becomes `Err` to the caller.
            return Err(recorded.unwrap_or_else(|e| e));
        }
    };
    // S-LOG-1: mint and durably record the real task this dispatch is
    // ATTEMPTING, before admission decides its fate — see this function's
    // own doc comment for why a denied call must still be queryable.
    // `parent` (fix round B, W1-R53/W1-R64) links this task back to the
    // chat turn that issued it, making the session's task log a real tree.
    let task_id = TaskId::new();
    let created = runner.record_task_created(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        kind.clone(),
        Some(parent),
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

    // Start shell children before TaskStarted so its attestation reflects the
    // live process that will execute the admitted task. The child is handed to
    // the executor below; it is not spawned a second time.
    let pre_spawned = if let roundhouse_policy::TaskParams::Shell(cmd) = &params {
        let cwd = match extras.shell_cwd.as_deref() {
            Some(cwd) => cwd,
            None => {
                let failed = runner.record_task_failed(
                    actor.session_id(),
                    0,
                    now_ts(),
                    task_id,
                    TaskError {
                        message: "tool execution failed".into(),
                        category: "isolation_error".into(),
                    },
                    false,
                    1,
                );
                writer.append(failed).await.map_err(|append_err| {
                    format!("failed to record the dispatched tool call failing: {append_err}")
                })?;
                return Err("tool execution failed".into());
            }
        };
        match actor
            .spawn_isolated(crate::tool_dispatch::isolated_shell_command(cmd, cwd))
            .await
        {
            Ok(child) => Some(child),
            Err(err) => {
                tracing::warn!(error = %err, "admitted builtin isolation spawn failed");
                let failed = runner.record_task_failed(
                    actor.session_id(),
                    0,
                    now_ts(),
                    task_id,
                    TaskError {
                        message: "tool execution failed".into(),
                        category: "isolation_error".into(),
                    },
                    false,
                    1,
                );
                writer.append(failed).await.map_err(|append_err| {
                    format!("failed to record the dispatched tool call failing: {append_err}")
                })?;
                return Err("tool execution failed".into());
            }
        }
    } else {
        None
    };

    let started = runner.record_task_started(
        actor.session_id(),
        0, // ignored — EventWriter::append assigns the real per-session seq
        now_ts(),
        task_id,
        // Only shell tasks cross the process isolation boundary. Filesystem
        // helpers remain in-process and must not inherit the session's shell
        // attestation in their per-task event.
        {
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
            }
        },
        None,
        1,
    );
    if let Err(err) = writer.append(started).await {
        if let Some(child) = pre_spawned.as_ref() {
            if let Err(cleanup_err) = child.cancel().await {
                tracing::error!(
                    error = %cleanup_err,
                    "failed to clean up an isolated child after TaskStarted append failure"
                );
            }
        }
        let failed = runner.record_task_failed(
            actor.session_id(),
            0,
            now_ts(),
            task_id,
            TaskError {
                message: "tool execution failed".into(),
                category: "event_error".into(),
            },
            false,
            1,
        );
        return match writer.append(failed).await {
            Ok(_) => Err(format!(
                "failed to record the dispatched tool call starting: {err}"
            )),
            Err(terminal_err) => Err(format!(
                "failed to record the dispatched tool call starting ({err}) and its terminal \
                 failure ({terminal_err})"
            )),
        };
    }

    match crate::tool_dispatch::execute_builtin(
        &params,
        &extras,
        input,
        Some(actor.subscribe()),
        pre_spawned,
        actor,
    )
    .await
    {
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
            // A post-admission executor error can carry an `io::Error`, and
            // therefore an absolute host path. This message is folded into the
            // next provider turn, so retain no executor payload on that path.
            let message = "tool execution failed".to_string();
            let category = if matches!(
                &tool_err,
                crate::tool_dispatch::ToolDispatchError::Isolation(_)
            ) {
                "isolation_error"
            } else {
                "tool_error"
            };
            tracing::warn!(error = %tool_err, "admitted builtin execution failed");
            let failed = runner.record_task_failed(
                actor.session_id(),
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
