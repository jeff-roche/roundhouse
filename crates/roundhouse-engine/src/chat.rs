//! The `chat` -> `infer` task tree: S-LOOP-1's "exactly one Task record per
//! action," concretely — a user-facing `chat` turn spawns exactly one child
//! `infer` task that actually talks to the provider, both recorded through
//! `TaskRunner`'s sealed `record_task_*` constructors (never a raw `Event`
//! struct literal — `Event` is sealed in `roundhouse-core`; see
//! `roundhouse_core::task_runner` for why).

use roundhouse_core::{
    Handle, IsolationAttestation, Origin, SessionId, TaskError, TaskId, TaskInput, TaskKind,
    TaskOutput, TaskRunner, Tier, Timestamp, Usage,
};
use roundhouse_provider::{ChatRequest, ContentBlock, Provider, ProviderError, RequestCtx};
use roundhouse_store::{EventWriter, StoreError};

use crate::infer::fold_stream_to_blocks;

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Errors from running one chat turn: either the provider failed, or the
/// event-store append failed.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("provider error: {0}")]
    Provider(#[from] ProviderError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

/// Runs one chat turn: records a `chat` task, spawns one child `infer` task
/// that streams from `provider`, folds the stream into final `ContentBlock`s,
/// and records both tasks completed. Returns this turn's own `chat` task id
/// alongside the folded content blocks.
///
/// **Fix round B (Phase 7, Task 5, ruling W1-R53/W1-R64):** the returned
/// `TaskId` lets a caller like `agent_loop::run_agent_loop` link a
/// model-issued tool call back to the turn that produced it (as the
/// dispatched task's `parent`) — before this fix, every dispatched tool
/// call was recorded with `parent: None`, so the session's task log was a
/// flat list rather than the queryable tree this repo's core bet
/// (`AGENTS.md`) describes. Additive: every existing caller just needs to
/// destructure the new tuple.
pub async fn run_chat_turn(
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    session_id: SessionId,
    request: ChatRequest,
) -> Result<(TaskId, Vec<ContentBlock>), AgentError> {
    let chat_task_id = TaskId::new();
    // The `chat` task is the user-facing turn; `Origin::User` reflects that.
    append_created(
        writer,
        runner,
        session_id,
        chat_task_id,
        TaskKind::Chat,
        None,
        Origin::User,
    )
    .await?;
    append_started(writer, runner, session_id, chat_task_id).await?;

    let infer_task_id = TaskId::new();
    // The `infer` task is the model actually generating a response;
    // `Origin::Model` reflects that (distinct from the parent `chat` task's
    // `Origin::User`).
    append_created(
        writer,
        runner,
        session_id,
        infer_task_id,
        TaskKind::Infer,
        Some(chat_task_id),
        Origin::Model,
    )
    .await?;
    append_started(writer, runner, session_id, infer_task_id).await?;

    let stream = match provider.stream_chat(&request, ctx).await {
        Ok(stream) => stream,
        Err(provider_err) => {
            return fail_turn_on_provider_error(
                writer,
                runner,
                session_id,
                infer_task_id,
                chat_task_id,
                provider_err,
            )
            .await
        }
    };
    // A mid-stream `Err` item (Task 1's fallible `ChatStream`) is a real
    // provider failure, not a clean end of stream — Task 4 makes the fold
    // itself fallible so this takes the exact same failure branch as a
    // `stream_chat` call that fails outright above, rather than folding a
    // truncated stream into a silently short success.
    let blocks = match fold_stream_to_blocks(stream).await {
        Ok(blocks) => blocks,
        Err(provider_err) => {
            return fail_turn_on_provider_error(
                writer,
                runner,
                session_id,
                infer_task_id,
                chat_task_id,
                provider_err,
            )
            .await
        }
    };

    append_completed(writer, runner, session_id, infer_task_id).await?;
    append_completed(writer, runner, session_id, chat_task_id).await?;

    Ok((chat_task_id, blocks))
}

/// The `infer`/`chat` failure branch shared by a `provider.stream_chat` call
/// that fails outright and a `fold_stream_to_blocks` call that fails
/// mid-stream (Task 4): innermost first, `infer` fails because of the
/// provider, which is why the parent `chat` task fails too.
async fn fail_turn_on_provider_error(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    infer_task_id: TaskId,
    chat_task_id: TaskId,
    provider_err: ProviderError,
) -> Result<(TaskId, Vec<ContentBlock>), AgentError> {
    let error = TaskError {
        message: provider_err.to_string(),
        category: "provider_error".into(),
    };
    append_failed(
        writer,
        runner,
        session_id,
        infer_task_id,
        error.clone(),
        false,
    )
    .await?;
    append_failed(writer, runner, session_id, chat_task_id, error, false).await?;
    Err(AgentError::Provider(provider_err))
}

async fn append_created(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    kind: TaskKind,
    parent: Option<TaskId>,
    origin: Origin,
) -> Result<(), StoreError> {
    let event = runner.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        kind,
        parent,
        origin,
        // TaskInput has no Default — construct explicitly.
        TaskInput::Text(String::new()),
        1,
    );
    writer.append(event).await?;
    Ok(())
}

async fn append_started(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<(), StoreError> {
    let event = runner.record_task_started(
        session_id,
        0,
        now_ts(),
        task_id,
        // IsolationAttestation has no Default either — construct explicitly.
        // Phase 1's chat/infer tasks run in-process (no sandbox tier), so
        // `Tier::None`/no network enforcement is the accurate attestation here.
        IsolationAttestation {
            tier: Tier::None,
            digest: String::new(),
            net_enforced: false,
        },
        None::<Handle>,
        1,
    );
    writer.append(event).await?;
    Ok(())
}

async fn append_completed(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
) -> Result<(), StoreError> {
    let event = runner.record_task_completed(
        session_id,
        0,
        now_ts(),
        task_id,
        // TaskOutput has no Default either — same fix; Usage does derive Default.
        TaskOutput::Text(String::new()),
        Usage::default(),
        // A chat turn's own generated text is not an external-ingestion
        // taint source (see the taint-fold's own doc comment) — only a
        // real MCP/http result, or a returning child's merged taint,
        // taints the session.
        roundhouse_core::Trust::Trusted,
        1,
    );
    writer.append(event).await?;
    Ok(())
}

async fn append_failed(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    error: TaskError,
    retryable: bool,
) -> Result<(), StoreError> {
    let event = runner.record_task_failed(session_id, 0, now_ts(), task_id, error, retryable, 1);
    writer.append(event).await?;
    Ok(())
}
