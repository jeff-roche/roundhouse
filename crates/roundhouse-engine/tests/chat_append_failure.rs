//! Phase 8 Task 21, Task 6 (#89): "If an append fails partway through a stream,
//! `run_chat_turn` returns an error and neither the infer nor the chat task ever gets a
//! terminal event. They stay open until `recovery::recover_interrupted_tasks` sweeps them on
//! the next daemon start." This pins `run_chat_turn_with_clock`'s new best-effort settlement
//! (`TurnTasks::settle_after_append_failure`, `chat.rs`) against a REAL writer over a temp
//! store, using `roundhouse_store::test_util::{AppendFault, spawn_faulting_writer}` to land a
//! fault on one specific append without disturbing the rest of the turn.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use roundhouse_core::{
    Event, EventPayload, SessionId, SessionOutcome, TaskId, TaskKind, TaskRunner, Timestamp,
};
use roundhouse_engine::{run_chat_turn_with_clock, AgentError, MonotonicClock};
use roundhouse_provider::{
    BlockDelta, BlockKind, Capabilities, ChatRequest, ChatStream, ModelId, ModelInfo, Params, Plan,
    Provider, ProviderError, ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy,
    ResponseFormat, StreamEvent, TokenCount, ToolChoice,
};
use roundhouse_store::test_util::{spawn_faulting_writer, AppendFault};
use roundhouse_store::{open, session_events, spawn_writer, StoreError, StoredEvent};
use tokio::sync::oneshot;

/// `TaskRunner::bootstrap()` panics if called more than once per process -- this test binary
/// is one process, and every test below calls `run_chat_turn_with_clock`, so they must share
/// one bootstrapped instance rather than each trying to bootstrap its own.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

/// `Timestamp` has no `now()` (see `roundhouse_engine::chat`'s own private helper of the same
/// name) -- this test needs its own to drive `EventWriter::close_session` directly.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A `MonotonicClock` that never advances on its own -- none of this file's tests need to
/// cross `delta_sink::FLUSH_INTERVAL`, so a clock that only ever reads a fixed `Instant` keeps
/// every flush triggered by a real non-time rule (`BlockStop`/`finish`), never by wall-clock
/// happenstance (this repo's no-clock-timing-tests rule, AGENTS.md).
struct FixedClock {
    now: Instant,
}

impl FixedClock {
    fn new() -> Self {
        FixedClock {
            now: Instant::now(),
        }
    }
}

impl MonotonicClock for FixedClock {
    fn now(&self) -> Instant {
        self.now
    }
}

struct NoopTransport;
impl roundhouse_provider::HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: roundhouse_provider::HttpRequest,
    ) -> futures::future::BoxFuture<
        'a,
        Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
    > {
        unreachable!("test providers never call the transport directly")
    }
}

fn test_ctx() -> RequestCtx {
    RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: "test".into(),
        credentials: None,
    }
}

fn test_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// Streams one small text block to completion -- just enough to exercise `run_chat_turn`'s
/// success path (`BlockStop` flushes the buffered "hello" as a real `TaskDelta`, well before
/// `MessageStop`), so a fault landing on a specific downstream append is what fails the turn,
/// never the provider itself.
struct ScriptedProvider;

impl Provider for ScriptedProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("hello".into()),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::MessageStop,
            ];
            Ok(ChatStream::from_events(events))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async move { Ok(vec![]) })
    }
}

/// Streams a partial text delta, then a mid-stream `Err` item -- the provider-error path
/// (mirrors `chat_infer_deltas.rs`'s provider of the same name).
struct MidStreamErrorAfterDeltasProvider;

impl Provider for MidStreamErrorAfterDeltasProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let results = vec![
                Ok(StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                }),
                Ok(StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("partial output".into()),
                }),
                Err(ProviderError::StreamInterrupted {
                    partial: "partial output".into(),
                }),
            ];
            Ok(ChatStream::from_results(results))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async move { Ok(vec![]) })
    }
}

/// Signals `ready_tx` the instant `stream_chat` is actually invoked -- which, in
/// `run_chat_turn_with_clock`'s own sequential code, can only happen AFTER both the chat and
/// infer tasks' `TaskCreated`/`TaskStarted` have already been durably appended (each awaited
/// via `?` beforehand) -- then blocks on `go_rx` before producing any stream item. This is
/// what lets [`session_closed_append_attempts_no_follow_up`] close the session at a
/// deterministic point strictly between "both tasks started" and "the first delta append",
/// with no sleep (this repo's no-clock-timing-tests rule).
struct SignalOnStartProvider {
    ready_tx: Mutex<Option<oneshot::Sender<()>>>,
    go_rx: Mutex<Option<oneshot::Receiver<()>>>,
}

impl Provider for SignalOnStartProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        let ready_tx = self
            .ready_tx
            .lock()
            .unwrap()
            .take()
            .expect("stream_chat is called exactly once per turn");
        let go_rx = self
            .go_rx
            .lock()
            .unwrap()
            .take()
            .expect("stream_chat is called exactly once per turn");
        Box::pin(async move {
            let _ = ready_tx.send(());
            go_rx.await.expect("the driver must send the go signal");
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("hello".into()),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::MessageStop,
            ];
            Ok(ChatStream::from_events(events))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async move { Ok(vec![]) })
    }
}

/// An in-process `tracing` sink, built directly on the `tracing` crate (already a regular
/// dependency of this crate) rather than pulling in `tracing-subscriber` as a new dev-only
/// Cargo edge just for one test's log assertion (constraints.md's "no new Cargo edges" rule).
/// Captures every event's fields via `Debug`, which is enough to substring-match a message.
#[derive(Clone, Default)]
struct CapturingSubscriber {
    buf: Arc<Mutex<String>>,
}

impl tracing::Subscriber for CapturingSubscriber {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Collector<'a>(&'a mut String);
        impl tracing::field::Visit for Collector<'_> {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, "{}={value:?} ", field.name());
            }
        }
        let mut buf = self.buf.lock().unwrap();
        event.record(&mut Collector(&mut buf));
        buf.push('\n');
    }
    fn enter(&self, _span: &tracing::span::Id) {}
    fn exit(&self, _span: &tracing::span::Id) {}
}

fn find_task_id(events: &[StoredEvent], kind: TaskKind) -> TaskId {
    events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated { kind: k, .. } if *k == kind => e.task_id,
            _ => None,
        })
        .unwrap_or_else(|| panic!("a {kind:?} TaskCreated event was recorded"))
}

/// Every `TaskCompleted`/`TaskFailed` event recorded for `task_id`, in store order.
fn terminal_events_for(events: &[StoredEvent], task_id: TaskId) -> Vec<&EventPayload> {
    events
        .iter()
        .filter(|e| e.task_id == Some(task_id))
        .map(|e| &e.payload)
        .filter(|p| {
            matches!(
                p,
                EventPayload::TaskCompleted { .. } | EventPayload::TaskFailed { .. }
            )
        })
        .collect()
}

#[tokio::test]
async fn failed_delta_append_fails_infer_then_chat() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_faulting_writer(store, AppendFault::FailBeforeCommit, |event: &Event| {
        matches!(event.payload, EventPayload::TaskDelta { .. })
    })
    .await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let result = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &ScriptedProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await;
    assert!(
        matches!(result, Err(AgentError::Store(_))),
        "expected a store error, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();
    let infer_task_id = find_task_id(&events, TaskKind::Infer);
    let chat_task_id = find_task_id(&events, TaskKind::Chat);

    let infer_terminals = terminal_events_for(&events, infer_task_id);
    let chat_terminals = terminal_events_for(&events, chat_task_id);
    assert_eq!(
        infer_terminals.len(),
        1,
        "infer must have exactly one terminal event: {infer_terminals:?}"
    );
    assert_eq!(
        chat_terminals.len(),
        1,
        "chat must have exactly one terminal event: {chat_terminals:?}"
    );
    for (label, terminals) in [("infer", &infer_terminals), ("chat", &chat_terminals)] {
        match terminals[0] {
            EventPayload::TaskFailed { error, .. } => {
                assert_eq!(error.category, "turn_append_failed")
            }
            other => panic!("expected {label} TaskFailed, got {other:?}"),
        }
    }

    let infer_failed_seq = events
        .iter()
        .find(|e| {
            e.task_id == Some(infer_task_id) && matches!(e.payload, EventPayload::TaskFailed { .. })
        })
        .expect("infer TaskFailed recorded")
        .seq;
    let chat_failed_seq = events
        .iter()
        .find(|e| {
            e.task_id == Some(chat_task_id) && matches!(e.payload, EventPayload::TaskFailed { .. })
        })
        .expect("chat TaskFailed recorded")
        .seq;
    assert!(
        infer_failed_seq < chat_failed_seq,
        "infer must settle before its parent chat (innermost first): infer={infer_failed_seq}, \
         chat={chat_failed_seq}"
    );
}

#[tokio::test]
async fn failed_infer_completion_append_fails_both() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_faulting_writer(store, AppendFault::FailBeforeCommit, |event: &Event| {
        matches!(event.payload, EventPayload::TaskCompleted { .. })
    })
    .await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let result = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &ScriptedProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await;
    assert!(
        matches!(result, Err(AgentError::Store(_))),
        "expected a store error, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();
    let infer_task_id = find_task_id(&events, TaskKind::Infer);
    let chat_task_id = find_task_id(&events, TaskKind::Chat);

    // Infer's OWN TaskCompleted attempt is the one the fault rejected before it ever
    // committed. Its terminal was still "attempted" (`TurnTasks` marks that before the append,
    // not after), so `settle_after_append_failure` deliberately leaves it alone: no terminal
    // event at all, open for `recovery::recover_interrupted_tasks` -- exactly the residual gap
    // constraints.md Decision 3 keeps on purpose (a `dropped-reply`-shaped fault could have
    // committed anyway; this function does not special-case which fault kind occurred).
    assert!(
        terminal_events_for(&events, infer_task_id).is_empty(),
        "infer must have no terminal event -- its own completion attempt is the one that failed"
    );

    // Chat's terminal was never attempted -- it gets a best-effort TaskFailed.
    let chat_terminals = terminal_events_for(&events, chat_task_id);
    assert_eq!(chat_terminals.len(), 1, "{chat_terminals:?}");
    match chat_terminals[0] {
        EventPayload::TaskFailed { error, .. } => assert_eq!(error.category, "turn_append_failed"),
        other => panic!("expected chat TaskFailed, got {other:?}"),
    }
}

#[tokio::test]
async fn dropped_reply_on_infer_completed_does_not_double_terminate() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer =
        spawn_faulting_writer(store, AppendFault::DropReplyAfterCommit, |event: &Event| {
            matches!(event.payload, EventPayload::TaskCompleted { .. })
        })
        .await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let result = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &ScriptedProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await;
    assert!(
        matches!(result, Err(AgentError::Store(_))),
        "expected a store error, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();
    let infer_task_id = find_task_id(&events, TaskKind::Infer);
    let chat_task_id = find_task_id(&events, TaskKind::Chat);

    // The fault's whole point: infer's TaskCompleted actually committed even though the
    // caller (`run_chat_turn_with_clock`) saw `Err`. `settle_after_append_failure` must not
    // append a SECOND terminal event on top of that real one.
    let infer_terminals = terminal_events_for(&events, infer_task_id);
    assert_eq!(
        infer_terminals.len(),
        1,
        "infer must have exactly one terminal event, not a double-terminate: {infer_terminals:?}"
    );
    assert!(
        matches!(infer_terminals[0], EventPayload::TaskCompleted { .. }),
        "infer's one terminal event must be the TaskCompleted that actually committed: {:?}",
        infer_terminals[0]
    );

    let chat_terminals = terminal_events_for(&events, chat_task_id);
    assert_eq!(chat_terminals.len(), 1, "{chat_terminals:?}");
    assert!(
        matches!(chat_terminals[0], EventPayload::TaskFailed { .. }),
        "chat must get a best-effort TaskFailed: {:?}",
        chat_terminals[0]
    );
}

#[tokio::test]
async fn session_closed_append_attempts_no_follow_up() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let (ready_tx, ready_rx) = oneshot::channel();
    let (go_tx, go_rx) = oneshot::channel();
    let provider = SignalOnStartProvider {
        ready_tx: Mutex::new(Some(ready_tx)),
        go_rx: Mutex::new(Some(go_rx)),
    };

    let ctx = test_ctx();
    let turn = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &provider,
        &ctx,
        session_id,
        test_request(),
        &clock,
    );
    let driver = async {
        ready_rx
            .await
            .expect("the provider signals readiness once both tasks are created and started");
        writer
            .close_session(&RUNNER, session_id, now_ts(), SessionOutcome::Cancelled)
            .await
            .expect("closing a genuinely open session must succeed");
        go_tx
            .send(())
            .expect("the turn future must still be waiting on the go signal");
    };

    let (result, ()) = tokio::join!(turn, driver);

    assert!(
        matches!(result, Err(AgentError::Store(StoreError::SessionClosed(_)))),
        "expected the store's tail guard to reject the post-close append, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();

    assert!(
        matches!(
            events.last().expect("session has events").payload,
            EventPayload::SessionClosed { .. }
        ),
        "the log must end in SessionClosed, not a follow-up settle attempt: {:?}",
        events.last().map(|e| &e.payload)
    );
    assert!(
        !events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "turn_append_failed"
        )),
        "settle_after_append_failure must be a no-op for a SessionClosed cause: {events:?}"
    );
}

#[tokio::test]
async fn provider_error_then_failed_append_still_settles() {
    let log = Arc::new(Mutex::new(String::new()));
    let subscriber = CapturingSubscriber {
        buf: Arc::clone(&log),
    };
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_faulting_writer(store, AppendFault::FailBeforeCommit, |event: &Event| {
        matches!(event.payload, EventPayload::TaskDelta { .. })
    })
    .await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let result = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &MidStreamErrorAfterDeltasProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await;

    // The store error, not the provider error, is what this call actually returns: the
    // provider error never reaches `fail_turn_on_provider_error` because the coalescer's
    // `finish()`-flush that was supposed to precede it fails first.
    assert!(
        matches!(result, Err(AgentError::Store(_))),
        "expected a store error, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();
    let infer_task_id = find_task_id(&events, TaskKind::Infer);
    let chat_task_id = find_task_id(&events, TaskKind::Chat);

    // Even though the RETURNED error is a store error, the turn still settles both tasks --
    // neither had a terminal-event append attempt yet when the delta append failed.
    let infer_terminals = terminal_events_for(&events, infer_task_id);
    let chat_terminals = terminal_events_for(&events, chat_task_id);
    assert_eq!(infer_terminals.len(), 1, "{infer_terminals:?}");
    assert_eq!(chat_terminals.len(), 1, "{chat_terminals:?}");
    for (label, terminals) in [("infer", &infer_terminals), ("chat", &chat_terminals)] {
        match terminals[0] {
            EventPayload::TaskFailed { error, .. } => {
                assert_eq!(error.category, "turn_append_failed")
            }
            other => panic!("expected {label} TaskFailed, got {other:?}"),
        }
    }

    let captured = log.lock().unwrap().clone();
    assert!(
        captured.contains("provider error superseded by a failed delta append"),
        "the provider error must be logged before it's lost to the store error that replaces \
         it as this call's return value: {captured}"
    );
}
