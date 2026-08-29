//! The `chat` -> `infer` task tree: S-LOOP-1's "exactly one Task record per
//! action," concretely — a user-facing `chat` turn spawns exactly one child
//! `infer` task that actually talks to the provider, both recorded through
//! `TaskRunner`'s sealed `record_task_*` constructors (never a raw `Event`
//! struct literal — `Event` is sealed in `roundhouse-core`; see
//! `roundhouse_core::task_runner` for why).

use roundhouse_core::{
    Handle, IsolationAttestation, Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput,
    TaskRunner, Tier, Timestamp, Usage,
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
/// and records both tasks completed. Returns the folded content blocks.
///
/// `runner` is the sole authority (`TaskRunner::bootstrap()`, called exactly
/// once per process by `roundhouse-engine`) that can mint the `Event`s this
/// function appends — see `roundhouse_core::TaskRunner`'s doc comment.
pub async fn run_chat_turn(
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    session_id: SessionId,
    request: ChatRequest,
) -> Result<Vec<ContentBlock>, AgentError> {
    let chat_task_id = TaskId::new();
    append_created(writer, runner, session_id, chat_task_id, TaskKind::Chat, None).await?;
    append_started(writer, runner, session_id, chat_task_id).await?;

    let infer_task_id = TaskId::new();
    append_created(writer, runner, session_id, infer_task_id, TaskKind::Infer, Some(chat_task_id)).await?;
    append_started(writer, runner, session_id, infer_task_id).await?;

    let stream = provider.stream_chat(&request, ctx).await?;
    let blocks = fold_stream_to_blocks(stream).await;

    append_completed(writer, runner, session_id, infer_task_id).await?;
    append_completed(writer, runner, session_id, chat_task_id).await?;

    Ok(blocks)
}

async fn append_created(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    kind: TaskKind,
    parent: Option<TaskId>,
) -> Result<(), StoreError> {
    let event = runner.record_task_created(
        session_id,
        0,
        now_ts(),
        task_id,
        kind,
        parent,
        Origin::Model,
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
        IsolationAttestation { tier: Tier::None, digest: String::new(), net_enforced: false },
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
        1,
    );
    writer.append(event).await?;
    Ok(())
}
