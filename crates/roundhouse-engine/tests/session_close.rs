//! Phase 8, T19a Task 4: `SessionActor::close(outcome)` — the one ordered path that
//! cooperatively cancels a session, waits for its work to unwind, closes its children, and
//! durably writes the `SessionClosed` terminator.
//!
//! Fixtures mirror `agent_loop_dispatch.rs`'s own `new_actor`/`TestIsolate` pattern (there is
//! no `SessionActor::spawn_test_with` helper anywhere in this workspace), kept minimal and
//! local to this file since these tests need a custom `EventWriter` per test (an ordinary
//! one, or a gated one from `roundhouse_store::test_util`), which the shared helpers in
//! `agent_loop_dispatch.rs` don't take.

use std::sync::{Arc, Mutex as StdMutex};

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{
    EventPayload, OnDegrade, Origin, SessionId, SessionOutcome, SessionSpec, SessionState,
    TaskKind, TeamId, Tier, Timestamp,
};
use roundhouse_engine::agent_spawn::Budget;
use roundhouse_engine::tools::agent_spawn_tool::{
    ChildSessionError, ChildSessionRequest, SubAgentHost,
};
use roundhouse_engine::{AdmitError, SessionActor, TaskCreateRequest};
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_policy::{ParsedCommand, TaskParams};
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
};
use roundhouse_store::test_util::{spawn_gated_writer, CloseGate};
use roundhouse_store::{open, session_events, spawn_writer, CloseReceipt, EventWriter, StorePool};

/// `TaskRunner::bootstrap()` panics on a second call per-process, and every test in this
/// binary shares one process.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert. Matches the
/// identical helper elsewhere in this crate/`roundhouse-store`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A minimal, host-independent `Isolate` double — these tests never dispatch a real shell,
/// so `spawn` is deliberately unreachable.
struct TestIsolate;

#[async_trait::async_trait]
impl Isolate for TestIsolate {
    fn declared(&self) -> Tier {
        Tier::Sandbox
    }

    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: Tier::Sandbox,
            degradations: vec![],
        }
    }

    async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
        Ok(Handle {
            id: "test-isolate".into(),
        })
    }

    async fn spawn(
        &self,
        _handle: &Handle,
        _command: CommandSpec,
    ) -> Result<Child, IsolationError> {
        unreachable!("session_close tests never dispatch a real shell")
    }

    fn attest(&self, _handle: &Handle) -> Attestation {
        Attestation {
            tier: Tier::Sandbox,
            digest: "test-isolate".into(),
            net_enforced: false,
        }
    }

    async fn teardown(&self, _handle: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

/// Builds a real `SessionActor` (state `Running`) over a caller-supplied `writer` — the
/// caller picks an ordinary or gated one, per test.
async fn new_actor(dir: &std::path::Path, writer: EventWriter) -> (SessionActor, SessionId) {
    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let session_id = SessionId::new();
    let policy = Arc::new(PolicyEngine::from_rules(vec![]));

    let actor = SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.join("state"),
        dir.join("daemon-binary"),
        dir.canonicalize().unwrap(),
        isolate,
        handle,
        spec,
        vec![],
    );

    (actor, session_id)
}

/// Drives one task to `Running` (`TaskCreated` + `TaskStarted`) — an open task for
/// `close_session`'s sweep to actually cancel. Mirrors `roundhouse-store/tests/
/// close_session.rs`'s identical helper.
async fn task_left_running(writer: &EventWriter, session_id: SessionId) -> roundhouse_core::TaskId {
    let task_id = roundhouse_core::TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Shell,
            None,
            Origin::Model,
            roundhouse_core::TaskInput::Text("sleep 100".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_started(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::IsolationAttestation {
                tier: Tier::None,
                digest: "test".to_string(),
                net_enforced: false,
            },
            None,
            1,
        ))
        .await
        .unwrap();
    task_id
}

/// A trivial, always-admissible-shaped `TaskCreateRequest` — `admit_task`'s `SessionState`
/// gate refuses on `Cancelling`/`Closed` before `params` is ever consulted, so its exact
/// contents don't matter for these tests.
fn shell_request() -> TaskCreateRequest {
    TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Shell(ParsedCommand {
            program: "true".to_string(),
            argv: vec![],
        }),
    }
}

/// A `SubAgentHost` whose only real job is `close_children`: recording every call, together
/// with whether `SessionClosed` had already been appended for `parent` at the moment it ran
/// (nothing else in this file registers a host at all, so without this nothing pins that
/// `close()`'s step 4 is called, called with the right session, called exactly once even
/// under two racing closers, or called BEFORE the terminator). Every other
/// `SubAgentHost` method is a real, `agent_tool_spawn.rs`-style implementation over a fresh
/// `SpawnTree`/`TeamRegistry` — these tests never spawn a sub-agent, so `create_child_session`
/// is deliberately unreachable.
struct RecordingHost {
    tree: Arc<SpawnTree>,
    teams: TeamRegistry,
    budget: Arc<StdMutex<Budget>>,
    store: StorePool,
    calls: StdMutex<Vec<(SessionId, bool)>>,
}

impl RecordingHost {
    fn new(store: StorePool) -> Self {
        RecordingHost {
            tree: Arc::new(SpawnTree::new()),
            teams: TeamRegistry::new(),
            budget: Arc::new(StdMutex::new(Budget {
                remaining_tokens: 0,
            })),
            store,
            calls: StdMutex::new(Vec::new()),
        }
    }

    /// Every `close_children` call so far, as `(parent, session_closed_already_appended)`.
    fn calls(&self) -> Vec<(SessionId, bool)> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl SubAgentHost for RecordingHost {
    fn spawn_tree(&self) -> &Arc<SpawnTree> {
        &self.tree
    }
    fn teams(&self) -> &TeamRegistry {
        &self.teams
    }
    fn budget(&self) -> Arc<StdMutex<Budget>> {
        Arc::clone(&self.budget)
    }
    fn depth(&self) -> u8 {
        0
    }
    fn team(&self) -> Option<TeamId> {
        None
    }
    async fn create_child_session(
        &self,
        _req: ChildSessionRequest,
    ) -> Result<(), ChildSessionError> {
        unreachable!("session_close tests never spawn a sub-agent")
    }
    async fn close_children(&self, parent: SessionId) {
        let events_so_far = session_events(&self.store, parent).await.unwrap();
        let already_closed = events_so_far
            .iter()
            .any(|e| matches!(e.payload, EventPayload::SessionClosed { .. }));
        self.calls.lock().unwrap().push((parent, already_closed));
    }
}

/// Nothing else in this file registers a `SubAgentHost` on its actor, so without this
/// test nothing pins that `close()`'s step 4
/// (`close_children`) is called at all, called with the right session id, called exactly
/// once, or called BEFORE the terminator is durably appended.
#[tokio::test]
async fn close_calls_close_children_once_with_this_session_before_the_terminator_is_appended() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let (actor, session_id) = new_actor(dir.path(), writer).await;
    let host = Arc::new(RecordingHost::new(open(&db_path).await.unwrap()));
    actor.register_sub_agent_host(Arc::clone(&host) as Arc<dyn SubAgentHost>);

    let receipt = actor.close(SessionOutcome::Cancelled).await.unwrap();
    assert_eq!(receipt, CloseReceipt::Closed { swept: 0 });

    let calls = host.calls();
    assert_eq!(
        calls.len(),
        1,
        "close_children must be called exactly once by a single close(): {calls:?}"
    );
    let (called_with, already_closed) = calls[0];
    assert_eq!(
        called_with, session_id,
        "close_children must be called with THIS session's id"
    );
    assert!(
        !already_closed,
        "close_children must run BEFORE the SessionClosed terminator is appended, but the \
         persisted log already had one at call time"
    );
}

#[tokio::test]
async fn close_transitions_cancelling_then_task_cancelled_then_session_closed_then_watch_shows_closed(
) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let (actor, session_id) = new_actor(dir.path(), writer.clone()).await;

    // One open task for the sweep to actually cancel — the ordering claim only means
    // something if there's a real `TaskCancelled` in between.
    task_left_running(&writer, session_id).await;

    // Observe every state-watch transition `close()` drives, with no wall-clock wait:
    // `watch::Receiver::changed()` resolves exactly when a new value is published.
    let mut rx = actor.subscribe();
    let observed = tokio::spawn(async move {
        let mut states = vec![];
        while rx.changed().await.is_ok() {
            let state = rx.borrow().clone();
            let done = state == SessionState::Closed;
            states.push(state);
            if done {
                break;
            }
        }
        states
    });

    let receipt = actor.close(SessionOutcome::Cancelled).await.unwrap();
    assert_eq!(receipt, CloseReceipt::Closed { swept: 1 });
    assert_eq!(actor.state(), SessionState::Closed);

    let states = observed.await.unwrap();
    assert_eq!(
        states,
        vec![SessionState::Cancelling, SessionState::Closed],
        "close() must be observed transitioning Running -> Cancelling -> Closed, nothing else \
         in between"
    );

    // Persisted order: the swept TaskCancelled strictly precedes the SessionClosed
    // terminator, which is the very last event.
    let query_store = open(&db_path).await.unwrap();
    let events = session_events(&query_store, session_id).await.unwrap();
    let payloads: Vec<&EventPayload> = events.iter().map(|e| &e.payload).collect();
    let cancelled_idx = payloads
        .iter()
        .position(|p| matches!(p, EventPayload::TaskCancelled { .. }))
        .expect("expected a TaskCancelled event from the sweep");
    let closed_idx = payloads
        .iter()
        .position(|p| matches!(p, EventPayload::SessionClosed { .. }))
        .expect("expected a SessionClosed terminator");
    assert!(
        cancelled_idx < closed_idx,
        "TaskCancelled must precede SessionClosed: {payloads:?}"
    );
    assert_eq!(
        closed_idx,
        payloads.len() - 1,
        "SessionClosed must be the last event: {payloads:?}"
    );
}

/// The store's `close_session` is already idempotent
/// inside its own `BEGIN IMMEDIATE` — the tail guard alone would still produce exactly one
/// `SessionClosed` even with `close_lock` deleted (on the interleaving where both callers'
/// `cancel()` win/lose against each other via `EventWriter::append`'s own retry, or lose
/// outright with an `unwrap` panic on `StoreError::SessionClosed`, which is failing for the
/// WRONG reason — a panic, not a clean second `AlreadyClosed`). This test now asserts the
/// two observables `close_lock` actually protects instead: exactly one persisted
/// `SessionStateChanged{Cancelling}` (the same log filter `a_failing_writer_leaves_the_actor_
/// cancelling_and_a_retry_succeeds` already uses — two racing, un-serialized callers could
/// each observe `cancel_recorded == false` and each append their own Cancelling transition),
/// and exactly one `close_children` invocation on a recording host (two un-serialized
/// callers could each pass their own `state() != Closed` check and each run steps 3/4).
#[tokio::test]
async fn two_concurrent_closes_produce_exactly_one_terminator() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let (actor, session_id) = new_actor(dir.path(), writer).await;
    let actor = Arc::new(actor);
    let host = Arc::new(RecordingHost::new(open(&db_path).await.unwrap()));
    actor.register_sub_agent_host(Arc::clone(&host) as Arc<dyn SubAgentHost>);

    let a = Arc::clone(&actor);
    let b = Arc::clone(&actor);
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { a.close(SessionOutcome::Cancelled).await }),
        tokio::spawn(async move { b.close(SessionOutcome::Completed).await }),
    );
    let r1 = r1.unwrap().unwrap();
    let r2 = r2.unwrap().unwrap();
    let receipts = [r1, r2];

    let closed_count = receipts
        .iter()
        .filter(|r| matches!(r, CloseReceipt::Closed { .. }))
        .count();
    let already_count = receipts
        .iter()
        .filter(|r| matches!(r, CloseReceipt::AlreadyClosed))
        .count();
    assert_eq!(
        closed_count, 1,
        "exactly one of two concurrent closers must have actually closed the session: \
         {receipts:?}"
    );
    assert_eq!(
        already_count, 1,
        "the other concurrent closer must observe AlreadyClosed, not a second Closed: \
         {receipts:?}"
    );
    assert_eq!(actor.state(), SessionState::Closed);

    let query_store = open(&db_path).await.unwrap();
    let events = session_events(&query_store, session_id).await.unwrap();
    let closed_events = events
        .iter()
        .filter(|e| matches!(e.payload, EventPayload::SessionClosed { .. }))
        .count();
    assert_eq!(
        closed_events, 1,
        "exactly one SessionClosed terminator must ever be appended for this session"
    );

    let cancelling_events = events
        .iter()
        .filter(|e| {
            matches!(
                &e.payload,
                EventPayload::SessionStateChanged { state, .. } if *state == SessionState::Cancelling
            )
        })
        .count();
    assert_eq!(
        cancelling_events, 1,
        "close_lock must serialize the two closers so only one ever calls cancel(): {events:?}"
    );

    assert_eq!(
        host.calls().len(),
        1,
        "close_lock must serialize the two closers so close_children runs exactly once, not \
         once per racing caller"
    );
}

#[tokio::test]
async fn a_failing_writer_leaves_the_actor_cancelling_and_a_retry_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let (actor, session_id) = new_actor(dir.path(), writer).await;

    gate.fail_next().await;
    let close_err = actor.close(SessionOutcome::Cancelled).await.unwrap_err();
    let _ = close_err;
    assert_eq!(
        actor.state(),
        SessionState::Cancelling,
        "a failed close_session must leave the actor Cancelling, never Closed"
    );

    let query_store = open(&db_path).await.unwrap();
    let events_after_failure = session_events(&query_store, session_id).await.unwrap();
    assert!(
        !events_after_failure
            .iter()
            .any(|e| matches!(e.payload, EventPayload::SessionClosed { .. })),
        "no SessionClosed terminator may exist after a failed close: {events_after_failure:?}"
    );
    let cancelling_count = events_after_failure
        .iter()
        .filter(|e| {
            matches!(
                &e.payload,
                EventPayload::SessionStateChanged { state, .. } if *state == SessionState::Cancelling
            )
        })
        .count();
    assert_eq!(
        cancelling_count, 1,
        "cancel()'s own append must have succeeded exactly once despite close_session failing"
    );

    // Retry: the gate reverted to Open automatically after being consumed once.
    let receipt = actor.close(SessionOutcome::Cancelled).await.unwrap();
    assert_eq!(receipt, CloseReceipt::Closed { swept: 0 });
    assert_eq!(actor.state(), SessionState::Closed);

    let query_store = open(&db_path).await.unwrap();
    let events_after_retry = session_events(&query_store, session_id).await.unwrap();
    let cancelling_count_after = events_after_retry
        .iter()
        .filter(|e| {
            matches!(
                &e.payload,
                EventPayload::SessionStateChanged { state, .. } if *state == SessionState::Cancelling
            )
        })
        .count();
    assert_eq!(
        cancelling_count_after, 1,
        "the retry must not re-append a second Cancelling transition, since the first one \
         already durably succeeded"
    );
    let closed_count_after = events_after_retry
        .iter()
        .filter(|e| matches!(e.payload, EventPayload::SessionClosed { .. }))
        .count();
    assert_eq!(closed_count_after, 1);
}

#[tokio::test]
async fn admit_task_refuses_while_cancelling_and_after_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let (actor, _session_id) = new_actor(dir.path(), writer).await;
    let actor = Arc::new(actor);

    // Pause close_session so the actor is observably Cancelling for as long as we hold the
    // gate — deterministic via hold()/release(), no sleep.
    gate.hold().await;
    let mut rx = actor.subscribe();
    let closing = tokio::spawn({
        let actor = Arc::clone(&actor);
        async move { actor.close(SessionOutcome::Cancelled).await }
    });

    // The first observable signal that close() has entered cancel(): `SessionActor::cancel`
    // publishes `Cancelling` to the state watch BEFORE it even attempts its own durable
    // append (see `cancel`'s own doc comment), so this proves neither that the append
    // succeeded nor that close() has reached the gated close_session call yet — only that
    // it has started cancel(). That's still enough for this test: calling `release()` below
    // is safe regardless of whether the gated call has reached `admit()` yet, because
    // `CloseGate::hold` pairs a fresh `oneshot::Sender`/`Receiver` and `CloseGate::release`
    // only ever needs the sender half — a `oneshot::Sender::send` succeeds and buffers its
    // value the moment the receiver exists, whether or not that receiver has started
    // awaiting it yet, so a `release()` that runs before `admit()` reaches its own `.await`
    // is not lost (see `CloseGate`'s own doc comment for why this is not built on
    // `Notify`, whose stored-permit behavior did not have this guarantee across separate
    // `hold()` generations).
    rx.changed().await.unwrap();
    assert_eq!(*rx.borrow(), SessionState::Cancelling);

    let err = actor.admit_task(&shell_request()).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::SessionCancelling),
        "expected SessionCancelling while close() is in flight, got {err:?}"
    );

    gate.release().await;
    let receipt = closing.await.unwrap().unwrap();
    assert_eq!(receipt, CloseReceipt::Closed { swept: 0 });
    assert_eq!(actor.state(), SessionState::Closed);

    let err = actor.admit_task(&shell_request()).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::SessionClosed),
        "expected SessionClosed once close() has finished, got {err:?}"
    );

    // Pins a KNOWN, deliberately unaddressed gap: the
    // trusted finally-step bypass arm is matched before `SessionState::Closed`, so a
    // System-origin finally step is still ADMITTED here even after this session has
    // genuinely closed — see `admit_task`'s and `close`'s own doc comments for the full
    // rationale and what backstops it (the store's own tail guard, not this gate). This
    // assertion exists so a future change to that ordering is visible as a failing test
    // here, not a silent behavior change.
    let finally_step = TaskCreateRequest {
        is_finally_step: true,
        origin: Origin::System,
        ..shell_request()
    };
    let result = actor.admit_task(&finally_step).await;
    assert!(
        !matches!(result, Err(AdmitError::SessionClosed)),
        "today's admit_task must not refuse a trusted finally step with SessionClosed even \
         after close() has finished — the bypass arm is matched before the Closed arm — got \
         {result:?}"
    );
}
