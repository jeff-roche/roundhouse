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
//! TaskExecutor::execute`, `executor.rs:506`) needs a `TaskInput::Mcp {
//! server: ServerId, tool, args }`, and `execute` uses that `server` field
//! *directly* for its policy gate (`executor.rs:531`) — it is **not**
//! derived from resolving `tool`, and `McpExecutor` exposed no way to
//! resolve a namespaced tool name to its authoritative `ServerId` (CF-3) or
//! to tell which servers had actually completed a handshake as opposed to
//! merely being configured (CF-9, the CF-8(b) sealed-context-bypass shape).
//! Round C2 closed both with two narrow, additive `McpExecutor` accessors —
//! [`roundhouse_mcp::executor::McpExecutor::resolve`] and
//! [`roundhouse_mcp::executor::McpExecutor::resolved_servers`] — and this
//! module's [`dispatch_mcp`] now builds a real `TaskInput::Mcp` using
//! `resolve`'s **`server`** half only: `tool` is set to the namespaced name
//! unchanged, because `execute` re-resolves `tool` itself internally
//! (`executor.rs:517`) and would reject an already-resolved original name as
//! unknown. `resolve` exists solely so the caller can learn `server` —
//! `execute` never re-derives it and uses whatever the caller passed
//! directly for its policy gate (`executor.rs:531`). This module never
//! parses a `ServerId` out of the namespaced name itself and never
//! substitutes a permissive policy (the two things this module always
//! refused to do to fake "working" MCP dispatch — CF-7 item 2). An MCP call
//! still fails
//! closed with a named `ToolResult { is_error: true }` when: no MCP host is
//! configured for the session; the namespaced name doesn't resolve to any
//! known server/tool; the dispatch panics (a spawned-task boundary — see
//! [`dispatch_mcp`]'s doc comment); it exceeds its wall-clock bound; or the
//! server itself returns an `InputRequired`/elicitation result — the MRTR
//! retry loop is explicitly OUT OF SCOPE for this round (see
//! [`dispatch_mcp`]'s `Suspended` arm), so a suspended MCP task is reported
//! honestly rather than silently hung or faked as failed.
//!
//! # Unbounded results are now capped for the MCP arm; still uncapped for built-ins
//! `run_agent_loop` folds every dispatched tool's result into `transcript`
//! and into the next turn's `request.messages`. [`dispatch_mcp`] caps the
//! rendered text it returns (see [`MAX_MCP_RESULT_TEXT_BYTES`]) — CF-7 item
//! 4's own concern, since `stdio.rs:206` reads with no cap of its own and
//! `TaskInput::Json` has no size cap either, so an untrusted server could
//! otherwise grow context unboundedly on every subsequent turn. The
//! built-in arm's own executors (`tool_dispatch`'s own doc comment) still
//! cap NOTHING of their own beyond the shell arm's stdout/stderr byte cap
//! (round B's I1/M2 fix) — a `read` against a very large file still grows
//! this loop's context unboundedly. Pre-existing/inherited for the
//! built-in arm, not introduced by this round; closing it there belongs to
//! whichever task next touches `tool_dispatch::execute_builtin`.

use crate::session_actor::{SessionActor, TaskCreateRequest};
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
    mcp: Option<Arc<roundhouse_mcp::executor::McpExecutor>>,
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
    mcp: Option<&Arc<roundhouse_mcp::executor::McpExecutor>>,
    name: &str,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    match resolve_tool_target(name) {
        Some(ToolTarget::Builtin(kind)) => {
            dispatch_builtin(actor, writer, runner, kind, input, parent).await
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

/// Records a refusal that never reached `admit_task` at all (no policy
/// decision was made — there is nothing to gate here, only a real dispatch
/// capability that doesn't exist) as a real `TaskCreated` followed
/// unconditionally by `TaskFailed`, mirroring `dispatch_builtin`'s own
/// "a refused call is still a real, queryable attempt" posture for the
/// built-in arm.
///
/// **Fix round B, ruling W1-R65:** the primary `TaskCreated` append's
/// failure is now propagated (`Err`) rather than logged-and-continued —
/// this helper exists specifically to make F10's "a refused call is still
/// a real, queryable attempt" guarantee hold, so silently proceeding past a
/// failure to record that attempt would defeat the fix's own point (and was
/// inconsistent with `dispatch_builtin`'s sibling append at
/// `dispatch_builtin`, which already propagates via `?`). The secondary
/// `TaskFailed` append stays best-effort, matching `record_denial`'s
/// existing pattern.
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
    if let Err(e) = writer.append(failed).await {
        tracing::warn!(error = %e, "failed to record TaskFailed for an unadmitted refusal");
    }

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
/// `stdio.rs:206` reads an MCP server's response with an unbounded
/// `BufReader::lines()` and `TaskInput`/`TaskOutput::Json` has no size cap
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
/// calling `execute` in-process. `execute`'s only internal writes
/// (`suspend_for_elicitation`'s `spawn_task`/`suspend_task` calls, reached
/// only on an `InputRequired` result) go through the SAME `EngineTaskSpawner`
/// this `McpExecutor` was constructed with (`mcp_spawner.rs`), which PANICS
/// on a failed `EventWriter` append by design (see that module's own doc
/// comment) rather than swallowing it. Without the spawned-task boundary,
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
/// **`Suspended` (an `InputRequired`/elicitation result): reports honestly,
/// records nothing further.** `execute`'s `suspend_for_elicitation` path
/// already durably wrote `TaskSuspended` for this task (via the injected
/// `TaskSpawner`, synchronously, before returning) — writing another
/// terminal event here would be a double-write for the same task. The
/// MRTR retry loop (resuming a suspended MCP task with
/// `ResumptionInput::ElicitationAnswers` once a human answers the
/// elicitation) is explicitly OUT OF SCOPE for this round: nothing in
/// `run_agent_loop` today re-visits a suspended task, so this arm reports
/// an honest `is_error: true` result explaining that the tool call requires
/// input this loop cannot yet supply, rather than silently hanging or
/// mischaracterizing a genuine suspension as a failure.
///
/// # Turns a spawned MCP dispatch's `JoinHandle` result into an `ExecutorOutcome`
/// Split out from [`dispatch_mcp`] so the CF-7 item 1 boundary — what
/// happens when the spawned task panicked or was cancelled instead of
/// returning normally — is independently unit-testable without needing to
/// reproduce the one real internal condition that can trigger it inside
/// `McpExecutor` (an `EventWriter` append failure inside
/// `suspend_for_elicitation`, which this crate has no clean way to force
/// from outside `roundhouse-mcp`). `join_result` is accepted as a plain
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
            let message = format!("MCP tool call dispatch panicked or was cancelled: {join_err}");
            let failed = runner.record_task_failed(
                session_id,
                0,
                now_ts(),
                task_id,
                TaskError {
                    message: message.clone(),
                    category: "mcp_dispatch_panic".into(),
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

/// The real MCP dispatch arm (fix round C2). Resolves `namespaced_name` via
/// [`roundhouse_mcp::executor::McpExecutor::resolve`] to learn the
/// authoritative `server` for `execute`'s policy gate — but passes
/// `namespaced_name` itself, unchanged, as `TaskInput::Mcp.tool`, because
/// `execute` re-resolves `tool` internally and rejects an already-resolved
/// original name as unknown (see this module's top-level doc comment for the
/// full explanation of that split). Records `TaskCreated`/`TaskStarted`
/// before dispatch and `TaskCompleted`/`TaskFailed` after, per S-LOG-1.
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
    mcp: &Arc<roundhouse_mcp::executor::McpExecutor>,
    namespaced_name: &str,
    input: &serde_json::Value,
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    // CF-3: the only authoritative source of the ServerId `execute`'s
    // policy gate uses directly — never parsed out of the namespaced name.
    // Only `server` is needed from this resolution: `execute` takes the
    // NAMESPACED name as `TaskInput::Mcp.tool` and resolves it to the
    // original tool name AGAIN, internally, for its own dispatch
    // (`executor.rs:517`) — this call exists solely to learn the
    // authoritative `server`, which `execute` uses directly and never
    // re-derives itself.
    let server = match mcp.resolve(namespaced_name) {
        Some((server, _original_tool)) => server.clone(),
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
        // `execute` resolves `tool` itself (`executor.rs:517`) to find the
        // original tool name it actually dispatches to the transport.
        tool: namespaced_name.to_string(),
        args: input.clone(),
    };

    let mcp_for_task = Arc::clone(mcp);
    let join_result = tokio::spawn(async move {
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
    })
    .await;

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
        roundhouse_mcp::executor::ExecutorOutcome::Failed { error, .. } => {
            let message = error.message.clone();
            let failed = runner.record_task_failed(
                actor.session_id(),
                0,
                now_ts(),
                task_id,
                error,
                false,
                1,
            );
            writer.append(failed).await.map_err(|e| {
                format!("failed to record the dispatched MCP tool call failing: {e}")
            })?;
            Err(message)
        }
        roundhouse_mcp::executor::ExecutorOutcome::Suspended { .. } => {
            // Already durably recorded by `execute` itself — see this
            // function's own doc comment. Nothing more to append here.
            Err(format!(
                "MCP tool `{namespaced_name}` requires additional input (an elicitation) this \
                 dispatch loop cannot yet resume — the task is suspended, not failed, but MRTR \
                 resume is out of this round's scope"
            ))
        }
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
    parent: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    let (params, extras) =
        crate::tool_dispatch::task_params_for(kind.clone(), input).map_err(|e| e.to_string())?;

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

    match crate::tool_dispatch::execute_builtin(&params, &extras, input, Some(actor.subscribe()))
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
