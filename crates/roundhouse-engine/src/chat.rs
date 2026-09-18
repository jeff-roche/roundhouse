//! The `chat` -> `infer` task tree: S-LOOP-1's "exactly one Task record per
//! action," concretely — a user-facing `chat` turn spawns exactly one child
//! `infer` task that actually talks to the provider, both recorded through
//! `TaskRunner`'s sealed `record_task_*` constructors (never a raw `Event`
//! struct literal — `Event` is sealed in `roundhouse-core`; see
//! `roundhouse_core::task_runner` for why).

use futures::StreamExt;
use std::collections::HashSet;
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

/// Every task [`run_chat_turn_with_clock`] has opened so far, and which of those already had
/// a terminal-event append attempted — the bookkeeping [`Self::settle_after_append_failure`]
/// needs to answer "which of this turn's tasks can I still safely fail out" (#89).
struct TurnTasks {
    /// In creation order — `chat` first, then `infer`. `settle_after_append_failure` walks
    /// this in REVERSE (innermost/last-opened first), so a failed `infer` settles before its
    /// parent `chat` does, matching the ordering `fail_turn_on_provider_error` already uses
    /// for the success-path provider-error case.
    opened: Vec<TaskId>,
    /// A task lands here the moment ITS OWN terminal append (`TaskCompleted`/`TaskFailed`)
    /// is ATTEMPTED, whether or not that attempt actually succeeds — see
    /// `settle_after_append_failure`'s doc comment for why an attempt that itself failed
    /// still counts.
    terminal_attempted: HashSet<TaskId>,
}

impl TurnTasks {
    fn new() -> Self {
        TurnTasks {
            opened: Vec::new(),
            terminal_attempted: HashSet::new(),
        }
    }

    /// Best-effort `TaskFailed{category: "turn_append_failed"}` for every task this turn
    /// opened whose terminal append was never attempted, innermost (last opened) first —
    /// #89, overturning Controller ruling R23 for exactly the tasks it's safe to settle
    /// (constraints.md Decision 3).
    ///
    /// A task whose terminal WAS attempted is skipped even if that very attempt is what just
    /// failed: `AppendFault::DropReplyAfterCommit` (`roundhouse_store::test_util`) exists
    /// precisely because a failed `EventWriter::append` may have committed anyway (its own
    /// doc comment), and `tasks_view::upsert_for_event` has no transition check to reject a
    /// second terminal landing on a task that already has one — a follow-up `TaskFailed`
    /// here could silently clobber a real `TaskCompleted` the store already durably holds.
    ///
    /// No-op when `cause` is `StoreError::SessionClosed`: `EventWriter::close_session`'s own
    /// sweep already cancelled every task this session had open (including this turn's)
    /// before minting the `SessionClosed` terminator, so there is nothing left to settle —
    /// a follow-up append here would either hit the same closed tail guard for nothing, or
    /// land on a task the sweep already terminated.
    ///
    /// Its own append failures are logged (`tracing::error!`) and swallowed, never
    /// propagated — this function is already the best-effort fallback path, and must never
    /// become a second, unhandled point of failure for the turn.
    async fn settle_after_append_failure(
        &self,
        writer: &EventWriter,
        runner: &TaskRunner,
        session_id: SessionId,
        cause: &StoreError,
    ) {
        if matches!(cause, StoreError::SessionClosed(_)) {
            return;
        }
        for &task_id in self.opened.iter().rev() {
            if self.terminal_attempted.contains(&task_id) {
                continue;
            }
            let error = TaskError {
                message: format!("turn aborted after a failed append: {cause}"),
                category: "turn_append_failed".into(),
            };
            let event =
                runner.record_task_failed(session_id, 0, now_ts(), task_id, error, false, 1);
            if let Err(settle_err) = writer.append(event).await {
                tracing::error!(
                    task_id = %task_id,
                    session_id = %session_id,
                    error = %settle_err,
                    "settle_after_append_failure: best-effort TaskFailed append also failed \
                     (#89) -- this task stays open for recovery::recover_interrupted_tasks"
                );
            }
        }
    }
}

/// The single funnel every fallible append in [`run_chat_turn_with_clock`] and
/// [`fail_turn_on_provider_error`] goes through instead of a bare `?` (#89): on `Err`, calls
/// [`TurnTasks::settle_after_append_failure`] before returning the SAME `result` unchanged,
/// so the caller's own `?` still raises the original error exactly as before. Centralizing
/// this here, rather than repeating the same `if let Err(_) = &result { settle(...).await }`
/// at every call site, is what makes "every `?` on a `StoreError` goes through one wrapper"
/// true by construction rather than by each call site remembering to do it.
async fn append_or_settle<T>(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    tasks: &TurnTasks,
    result: Result<T, StoreError>,
) -> Result<T, StoreError> {
    if let Err(cause) = &result {
        tasks
            .settle_after_append_failure(writer, runner, session_id, cause)
            .await;
    }
    result
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
/// a single `ArcSwap` load per split QUERY, so one query's own holdback and split point always
/// agree (mirroring `redaction_split_for_flush`'s own race-closing precedent). **Not** a claim
/// that one whole flush decision (which can make several such queries — a size-shrink loop, or
/// `carve_final_chunk`'s R13 growth-plus-bisection search) sees a single redactor snapshot
/// throughout: a `set_redactor` landing between two queries within the same flush is not
/// serialized against this closure. Append-time redaction does not paper over that —
/// `Redactor::redact_event_payload` runs per payload and cannot see a match straddling two
/// of them, which is exactly what `Redactor::safe_split_len`'s caller contract exists to
/// prevent. What makes it safe is structural: this session's `writer` is its own
/// `EventWriter`, `create_session_with_egress` runs `wire_redaction_for_session` on it once
/// at session creation before any streaming, and the only writer that sees repeated
/// `set_redactor` calls is the daemon's shared `proxy_writer`
/// (`roundhouse_daemon`'s `register_proxy_secrets`), through which no deltas stream. So
/// there is no mid-stream rotation in production today; if a future change calls
/// `set_redactor` on a session's own writer mid-turn, this breaks. See
/// `EventWriter::redaction_split_for_coalescer`'s own doc comment for the full account.
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
///
/// **Best-effort settlement after a failed append (#89, overturning Controller ruling R23
/// for the tasks it's safe to settle — constraints.md Decision 3):** every `?` on a
/// `StoreError` in this function and in `fail_turn_on_provider_error` funnels through
/// `append_or_settle`, which calls `TurnTasks::settle_after_append_failure` before
/// re-raising the original error unchanged. That never changes what THIS turn returns — the
/// append failure (or, on the mid-stream provider-error path, the provider error itself, if
/// the pending deltas still make it out) still ends the turn exactly as before. What changes
/// is what happens to the tasks this turn already opened: instead of staying open with no
/// terminal event at all until `recovery::recover_interrupted_tasks` sweeps them on the next
/// daemon start, each one that never got a terminal-event append attempt gets a same-turn
/// `TaskFailed{category: "turn_append_failed"}` instead.
pub async fn run_chat_turn_with_clock(
    writer: &EventWriter,
    runner: &TaskRunner,
    provider: &dyn Provider,
    ctx: &RequestCtx,
    session_id: SessionId,
    request: ChatRequest,
    clock: &dyn MonotonicClock,
) -> Result<(TaskId, Vec<ContentBlock>), AgentError> {
    let mut tasks = TurnTasks::new();

    let chat_task_id = TaskId::new();
    // The `chat` task is the user-facing turn; `Origin::User` reflects that.
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_created(
            writer,
            runner,
            session_id,
            chat_task_id,
            TaskKind::Chat,
            None,
            Origin::User,
        )
        .await,
    )
    .await?;
    tasks.opened.push(chat_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_started(writer, runner, session_id, chat_task_id).await,
    )
    .await?;

    let infer_task_id = TaskId::new();
    // The `infer` task is the model actually generating a response;
    // `Origin::Model` reflects that (distinct from the parent `chat` task's
    // `Origin::User`).
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_created(
            writer,
            runner,
            session_id,
            infer_task_id,
            TaskKind::Infer,
            Some(chat_task_id),
            Origin::Model,
        )
        .await,
    )
    .await?;
    tasks.opened.push(infer_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_started(writer, runner, session_id, infer_task_id).await,
    )
    .await?;

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
                &mut tasks,
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
                let append_result =
                    append_deltas(writer, runner, session_id, infer_task_id, final_deltas).await;
                if let Err(store_err) = &append_result {
                    // #89: this append's failure is about to replace `provider_err` as the
                    // error this function actually returns -- the `?` below never reaches
                    // `fail_turn_on_provider_error` at all, so log the provider error here
                    // rather than letting it disappear without a trace.
                    tracing::error!(
                        session_id = %session_id,
                        provider_error = %provider_err,
                        store_error = %store_err,
                        "chat turn: provider error superseded by a failed delta append (#89)"
                    );
                }
                append_or_settle(writer, runner, session_id, &tasks, append_result).await?;
                return fail_turn_on_provider_error(
                    writer,
                    runner,
                    session_id,
                    infer_task_id,
                    chat_task_id,
                    provider_err,
                    &mut tasks,
                )
                .await;
            }
        };

        let now = clock.now();
        match &event {
            StreamEvent::BlockDelta { delta, .. } => {
                let deltas = coalescer.push(delta.clone(), now);
                append_or_settle(
                    writer,
                    runner,
                    session_id,
                    &tasks,
                    append_deltas(writer, runner, session_id, infer_task_id, deltas).await,
                )
                .await?;
            }
            StreamEvent::BlockStop { .. } => {
                let deltas = coalescer.block_stop(now);
                append_or_settle(
                    writer,
                    runner,
                    session_id,
                    &tasks,
                    append_deltas(writer, runner, session_id, infer_task_id, deltas).await,
                )
                .await?;
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
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_deltas(writer, runner, session_id, infer_task_id, final_deltas).await,
    )
    .await?;

    let blocks = fold.finish();

    tasks.terminal_attempted.insert(infer_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_completed(writer, runner, session_id, infer_task_id, usage).await,
    )
    .await?;
    tasks.terminal_attempted.insert(chat_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &tasks,
        append_completed(writer, runner, session_id, chat_task_id, Usage::default()).await,
    )
    .await?;

    Ok((chat_task_id, blocks))
}

/// Records `deltas` (in order) as real `TaskDelta` events for `task_id`, awaiting each
/// append inline before minting the next — deliberate (Task 7 brief): it preserves
/// per-session `seq` order and pushes backpressure onto the provider socket rather than
/// racing several appends or buffering them in a background task. An empty `deltas` (the
/// common case — most stream events don't trigger a flush) is a harmless no-op loop.
///
/// **A failed append here is FATAL to the turn, deliberately (Controller ruling R23) — but
/// no longer fatal to the infer task's own eventual resolution (#89).** It still propagates
/// via `?`, ending the turn right here rather than folding a gap in the stored delta log
/// into an apparently-normal completion — R23's "fatal" was always about the TURN ending,
/// never about how long the tasks it opened are left unresolved. What changed is that
/// latter half: the `?` here now goes through `run_chat_turn_with_clock`'s
/// `append_or_settle` wrapper, which gives the infer task (and its parent chat task, if
/// neither has a terminal-event append attempt yet) a same-turn, best-effort `TaskFailed`
/// (`TurnTasks::settle_after_append_failure`) instead of leaving them open for
/// `recovery::recover_interrupted_tasks` to sweep on the next daemon start. The shell delta
/// pump does the opposite —
/// `tool_dispatch::flush_stream`'s callers swallow a failure (`let _ =`) and count the
/// bytes as lag while the tool call completes normally. The asymmetry is the point, not a
/// discrepancy to unify: a dropped shell delta loses enrichment only, because the shell
/// tool's authoritative output still reaches the log in its `TaskCompleted`, whereas
/// streamed assistant text has NO other record before the infer task's terminal event —
/// dropping it silently would leave a completed task whose stored log is missing content
/// the model actually produced. The pump has a second reason to stay best-effort that does
/// not apply here: it must never let a slow store stall a child process's pipes, whereas
/// this loop's inline await deliberately does apply that backpressure — to the provider
/// socket, which tolerates it.
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
///
/// `tasks` is the SAME `TurnTasks` the caller has been threading through every other append
/// in the turn (#89): each `append_failed` call below marks its own task in
/// `terminal_attempted` before attempting it, then goes through the same `append_or_settle`
/// wrapper as everywhere else — so a failure appending EITHER terminal here still gives this
/// turn's other, not-yet-attempted task a best-effort `TaskFailed` rather than leaving it
/// open with no attempt at all.
async fn fail_turn_on_provider_error(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    infer_task_id: TaskId,
    chat_task_id: TaskId,
    provider_err: ProviderError,
    tasks: &mut TurnTasks,
) -> Result<(TaskId, Vec<ContentBlock>), AgentError> {
    let error = TaskError {
        message: provider_err.to_string(),
        category: "provider_error".into(),
    };
    tasks.terminal_attempted.insert(infer_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &*tasks,
        append_failed(
            writer,
            runner,
            session_id,
            infer_task_id,
            error.clone(),
            false,
        )
        .await,
    )
    .await?;
    tasks.terminal_attempted.insert(chat_task_id);
    append_or_settle(
        writer,
        runner,
        session_id,
        &*tasks,
        append_failed(writer, runner, session_id, chat_task_id, error, false).await,
    )
    .await?;
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
