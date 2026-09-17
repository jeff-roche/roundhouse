//! The `chat` -> `infer` task tree: S-LOOP-1's "exactly one Task record per
//! action," concretely — a user-facing `chat` turn spawns exactly one child
//! `infer` task that actually talks to the provider, both recorded through
//! `TaskRunner`'s sealed `record_task_*` constructors (never a raw `Event`
//! struct literal — `Event` is sealed in `roundhouse-core`; see
//! `roundhouse_core::task_runner` for why).

use futures::StreamExt;
use std::time::Instant;

use roundhouse_core::{
    Delta, Handle, IsolationAttestation, Origin, SessionId, TaskError, TaskId, TaskInput, TaskKind,
    TaskOutput, TaskRunner, Tier, Timestamp, Usage,
};
use roundhouse_provider::{
    ChatRequest, ContentBlock, Provider, ProviderError, RequestCtx, StreamEvent,
};
use roundhouse_store::{EventWriter, StoreError};

use crate::delta_sink::{DeltaCoalescer, SplitFn};
use crate::infer::StreamFold;

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Injectable monotonic-time source for [`run_chat_turn_with_clock`]'s internal
/// `DeltaCoalescer` (Phase 8 Task 19 lane B, Task 7) — the coalescer's flush-interval
/// cadence (`delta_sink::FLUSH_INTERVAL`) takes an explicit `Instant` rather than reading
/// the wall clock itself, and this is what supplies it across an `.await`-laden streaming
/// loop. [`run_chat_turn`] — the crate's public, signature-frozen entry point that
/// `agent_loop::run_agent_loop` calls — always passes [`SystemClock`]; a test drives a fake
/// implementation instead, per this repo's no-wall-clock-timing-tests rule (AGENTS.md /
/// `feedback_no_clock_timing_tests`): no sleeps, deterministic `Instant` arithmetic only.
pub trait MonotonicClock: Send + Sync {
    fn now(&self) -> Instant;
}

/// The real, wall-clock-backed [`MonotonicClock`] [`run_chat_turn`] passes to
/// [`run_chat_turn_with_clock`].
pub struct SystemClock;

impl MonotonicClock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
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
///
/// **Kept signature-frozen (Phase 8 Task 19 lane B, Task 7):** always passes
/// [`SystemClock`] to [`run_chat_turn_with_clock`], which does the real work — see that
/// function's doc comment for what changed (real `TaskDelta` events, minted from the same
/// stream that folds into `blocks`, rather than the stream's incremental content being
/// discarded once folded).
pub async fn run_chat_turn(
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    session_id: SessionId,
    request: ChatRequest,
) -> Result<(TaskId, Vec<ContentBlock>), AgentError> {
    run_chat_turn_with_clock(
        writer,
        runner,
        provider,
        ctx,
        session_id,
        request,
        &SystemClock,
    )
    .await
}

/// Does the real work behind [`run_chat_turn`] (which always passes [`SystemClock`]) — split
/// out (Phase 8 Task 19 lane B, Task 7) so a test can drive the internal `DeltaCoalescer`'s
/// flush-interval cadence with a fake [`MonotonicClock`] instead of real wall-clock sleeps.
///
/// **Real `TaskDelta` events, not a discarded stream (Task 7's own point):** every
/// `BlockDelta`/`BlockStop` the provider's stream produces is fed into a `DeltaCoalescer`
/// (Task 6), and every `Delta` it releases is recorded through `runner.record_task_delta`
/// and appended via `writer.append`, awaited inline (never a background writer task — this
/// preserves per-session `seq` order and pushes backpressure onto the provider socket, same
/// as every other append in this function). The `SplitFn` the coalescer is built with is a
/// closure over a cloned `EventWriter`, calling its `redaction_split_for_coalescer` —
/// a single `ArcSwap` load per split decision, so one flush sees one consistent redactor
/// snapshot for both the holdback and the split point (mirroring `redaction_split_for_flush`'s
/// own race-closing precedent).
///
/// The stream is consumed exactly once: the same loop that mints deltas via
/// `DeltaCoalescer::push`/`block_stop` also feeds each event into a `StreamFold`
/// (`infer.rs`), which is what ultimately produces this function's returned `Vec<ContentBlock>`
/// — `fold_stream_to_blocks` is not called from here at all.
///
/// **Ordering is the contract, on BOTH paths:** every infer `TaskDelta` this turn produces
/// is appended before that infer task's terminal event. On the success path, the loop calls
/// `coalescer.finish()` and flushes whatever it returns before `append_completed`. On the
/// failure path (a `stream_chat` call that fails outright, or a mid-stream `Err` item), the
/// SAME `finish()`-then-flush happens before `fail_turn_on_provider_error` appends
/// `TaskFailed` for the infer task (and then the parent `chat` task).
pub async fn run_chat_turn_with_clock(
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    session_id: SessionId,
    request: ChatRequest,
    clock: &dyn MonotonicClock,
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

    let mut stream = match provider.stream_chat(&request, ctx).await {
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

    let splitter: SplitFn = {
        let writer = writer.clone();
        Box::new(move |bytes: &[u8], max: usize, final_flush: bool| {
            writer.redaction_split_for_coalescer(bytes, max, final_flush)
        })
    };
    let mut coalescer = DeltaCoalescer::new(splitter);
    let mut fold = StreamFold::new();
    let mut usage = Usage::default();

    while let Some(item) = stream.next().await {
        // A mid-stream `Err` item (Task 1's fallible `ChatStream`) is a real provider
        // failure, not a clean end of stream — this takes the exact same failure branch as
        // a `stream_chat` call that fails outright above, rather than folding a truncated
        // stream into a silently short success. Whatever the coalescer has pending must
        // still reach the store, in order, before the infer task's `TaskFailed`.
        let event = match item {
            Ok(event) => event,
            Err(provider_err) => {
                let final_deltas = coalescer.finish();
                append_deltas(writer, runner, session_id, infer_task_id, final_deltas).await?;
                return fail_turn_on_provider_error(
                    writer,
                    runner,
                    session_id,
                    infer_task_id,
                    chat_task_id,
                    provider_err,
                )
                .await;
            }
        };

        let now = clock.now();
        match &event {
            StreamEvent::BlockDelta { delta, .. } => {
                let deltas = coalescer.push(delta.clone(), now);
                append_deltas(writer, runner, session_id, infer_task_id, deltas).await?;
            }
            StreamEvent::BlockStop { .. } => {
                let deltas = coalescer.block_stop(now);
                append_deltas(writer, runner, session_id, infer_task_id, deltas).await?;
            }
            StreamEvent::UsageDelta {
                input_tokens,
                output_tokens,
                cache_read_tokens,
            } => {
                if let Some(v) = input_tokens {
                    usage.input_tokens = *v;
                }
                if let Some(v) = output_tokens {
                    usage.output_tokens = *v;
                }
                if let Some(v) = cache_read_tokens {
                    usage.cache_read_tokens = *v;
                }
            }
            StreamEvent::BlockStart { .. } => {}
            StreamEvent::MessageStop => {}
        }

        let is_message_stop = matches!(event, StreamEvent::MessageStop);
        fold.accept(event);
        if is_message_stop {
            break;
        }
    }

    let final_deltas = coalescer.finish();
    append_deltas(writer, runner, session_id, infer_task_id, final_deltas).await?;

    let blocks = fold.finish();

    append_completed(writer, runner, session_id, infer_task_id, usage).await?;
    append_completed(writer, runner, session_id, chat_task_id, Usage::default()).await?;

    Ok((chat_task_id, blocks))
}

/// Records `deltas` (in order) as real `TaskDelta` events for `task_id`, awaiting each
/// append inline before minting the next — deliberate (Task 7 brief): it preserves
/// per-session `seq` order and pushes backpressure onto the provider socket rather than
/// racing several appends or buffering them in a background task. An empty `deltas` (the
/// common case — most stream events don't trigger a flush) is a harmless no-op loop.
async fn append_deltas(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    deltas: Vec<Delta>,
) -> Result<(), StoreError> {
    for delta in deltas {
        let event = runner.record_task_delta(session_id, 0, now_ts(), task_id, delta, 1);
        writer.append(event).await?;
    }
    Ok(())
}

/// The `infer`/`chat` failure branch shared by a `provider.stream_chat` call
/// that fails outright and a mid-stream `Err` item from the stream (Task 4):
/// innermost first, `infer` fails because of the
/// provider, which is why the parent `chat` task fails too. Any `TaskDelta` events this
/// turn produced before the failure were already appended by the caller (Task 7) — this
/// function only ever appends the two `TaskFailed` terminals, after that.
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

/// `usage` is the infer task's own accumulated `Usage` (folded from the stream's
/// `StreamEvent::UsageDelta` events, Task 7's optional item) for the infer task's
/// completion, or `Usage::default()` for the parent `chat` task's completion, which carries
/// no token usage of its own.
async fn append_completed(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    usage: Usage,
) -> Result<(), StoreError> {
    let event = runner.record_task_completed(
        session_id,
        0,
        now_ts(),
        task_id,
        // TaskOutput has no Default either — same fix.
        TaskOutput::Text(String::new()),
        usage,
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
