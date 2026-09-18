//! Phase 8, T19a Task 8: `ClientRequest::CloseSession` on the wire, and
//! `socket_server::drive_established_session`'s handling of it.
//!
//! Drives `drive_established_session` (the post-handshake half of
//! `drive_session`, factored out by this same task) directly against a
//! hand-registered session, the same shape `deadlock_invariant.rs` already
//! uses for `drive_session` itself — real `SessionRegistry`/`SessionActor`,
//! test-owned channels standing in for the socket. This is what lets
//! [`the_ack_arrives_only_after_the_durable_close_append`] wire a
//! `roundhouse_store::test_util`-gated writer into the actor: the full
//! `CreateSession` handshake (`session_bootstrap::create_real_session`)
//! always spawns its own ordinary writer, with no seam for a test to swap
//! it out.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use roundhouse_core::{EventPayload, SessionId, SessionState};
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::socket_server::{drive_established_session, CLOSE_SESSION_TIMEOUT};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use roundhouse_store::test_util::{spawn_gated_writer, CloseGate};
use tokio::sync::mpsc;

/// An in-process `tracing` sink for
/// [`a_wedged_close_times_out_and_a_retry_is_accepted`] — the same shape
/// `roundhouse-daemon`'s own `scheduler_driver` test module already uses
/// (`CapturingWriter`/`captured_logs`) to assert on a specific log line
/// rather than an external side effect, for a case (a refusal that is
/// otherwise wire-silent by design) with no other observable signal.
#[derive(Clone, Default)]
struct CapturingWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn captured_logs() -> (CapturingWriter, tracing::Dispatch) {
    let captured = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    (captured, tracing::Dispatch::new(subscriber))
}

impl CapturingWriter {
    fn contains(&self, needle: &str) -> bool {
        let rendered = String::from_utf8(self.0.lock().unwrap().clone())
            .expect("the tracing subscriber emits UTF-8");
        rendered.contains(needle)
    }
}

/// **An attached (non-creating) connection is read-only for `CloseSession`
/// too**, exactly as it already is for `SubmitTurn`: its
/// `CloseSession` must be refused — no `Ack`, and the session itself must be
/// left completely undisturbed.
///
/// Deterministic, no wall clock: rather than waiting out a fixed window and
/// asserting nothing arrived, this drops `requests_tx` after sending the
/// refused request and awaits the driver's own `JoinHandle`. `mpsc`
/// preserves send order, so the loop cannot observe this drop
/// (`requests_rx.recv()` returning `None`, ending the loop) until AFTER it
/// has already handled the `CloseSession` send strictly before it — there
/// is no window in which the assertion below could run too early.
#[tokio::test]
async fn an_attached_connections_close_session_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let actor = common::real_actor(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);

    let driver = tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        false, // not the creator
        requests_rx,
        events_tx,
        registry,
        resources,
    ));

    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();
    drop(requests_tx);
    driver
        .await
        .expect("drive_established_session must not panic");

    let reply = events_rx.recv().await;
    assert!(
        reply.is_none(),
        "an attached connection's CloseSession must never be acknowledged, got {reply:?}"
    );
    assert_eq!(
        actor.state(),
        SessionState::Running,
        "an attached connection's CloseSession must have no effect on the session at all"
    );
}

/// A `CloseSession` naming a session other than the one this connection
/// established must be refused — the same "wrong session" guard
/// `SubmitTurn` already enforces — even from the creating connection.
///
/// Deterministic, no wall clock — see the sibling test above for why
/// dropping `requests_tx` and awaiting the driver's `JoinHandle` is a
/// complete, race-free proof rather than a best-effort one.
#[tokio::test]
async fn a_close_naming_a_different_session_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let actor = common::real_actor(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);

    let driver = tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        true, // the creator
        requests_rx,
        events_tx,
        registry,
        resources,
    ));

    let other_session = SessionId::new();
    requests_tx
        .send(ClientRequest::CloseSession {
            session_id: other_session,
        })
        .await
        .unwrap();
    drop(requests_tx);
    driver
        .await
        .expect("drive_established_session must not panic");

    let reply = events_rx.recv().await;
    assert!(
        reply.is_none(),
        "a CloseSession naming a session other than the one this connection established must \
         never be acknowledged, got {reply:?}"
    );
    assert_eq!(
        actor.state(),
        SessionState::Running,
        "a misdirected CloseSession must have no effect on the session actually running here"
    );
}

/// The Ack for a successful `CloseSession` must arrive only after the
/// durable `SessionClosed` append actually completes — never before.
///
/// Routes the actor's writer through `roundhouse_store::test_util::CloseGate`,
/// held open for as long as the test wants: while held, the durable append
/// inside `SessionActor::close` cannot complete no matter how much real time
/// passes, so "no Ack has arrived while the gate is held" is a deterministic
/// property, not a timing guess — checked with a single non-blocking poll
/// (`now_or_never`, never a sleep). Releasing the gate then lets the append
/// (and the Ack that must follow it) proceed.
#[tokio::test]
async fn the_ack_arrives_only_after_the_durable_close_append() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let actor = common::real_actor_with_writer(dir.path(), writer).await;

    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);

    tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        true,
        requests_rx,
        events_tx,
        registry,
        resources,
    ));

    // Held for the rest of this test's first half: `close_session`'s own
    // append blocks on this until `release()` is called below.
    gate.hold().await;

    let mut state_rx = actor.subscribe();
    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();

    // Deterministic sync point, not a sleep: `SessionActor::cancel` (run
    // from inside `close`, strictly before the gated `close_session` append)
    // publishes `Cancelling` to this watch immediately, before even its own
    // append — see `cancel`'s own doc comment. Observing it proves the
    // spawned close has genuinely started.
    loop {
        state_rx.changed().await.unwrap();
        if *state_rx.borrow() == SessionState::Cancelling {
            break;
        }
    }

    // No Ack yet: the durable append is blocked on the held gate, and can
    // stay blocked indefinitely — a single non-blocking poll is a complete
    // proof, not a best-effort one.
    assert!(
        events_rx.recv().now_or_never().is_none(),
        "no Ack may arrive before the durable SessionClosed append completes"
    );

    // The store side of the same claim, checked while the gate is still
    // held: no `SessionClosed` terminator exists yet either.
    let query_store = roundhouse_store::open(&db_path).await.unwrap();
    let events_while_held = roundhouse_store::session_events(&query_store, session_id)
        .await
        .unwrap();
    assert!(
        !events_while_held
            .iter()
            .any(|e| matches!(e.payload, EventPayload::SessionClosed { .. })),
        "no SessionClosed terminator may exist while the durable append is still gated: \
         {events_while_held:?}"
    );

    gate.release().await;

    let event = tokio::time::timeout(Duration::from_secs(5), events_rx.recv())
        .await
        .expect("the Ack must arrive once the durable append is released")
        .expect("the connection must not have ended before sending the Ack");
    assert!(
        matches!(event, ClientEvent::Ack { api_version } if api_version == ApiVersion::CURRENT),
        "expected an Ack, got {event:?}"
    );
    assert_eq!(actor.state(), SessionState::Closed);

    let query_store = roundhouse_store::open(&db_path).await.unwrap();
    let events = roundhouse_store::session_events(&query_store, session_id)
        .await
        .unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e.payload, EventPayload::SessionClosed { .. })),
        "the durable SessionClosed terminator must already exist by the time the Ack is \
         observed: {events:?}"
    );
}

/// A `CloseSession` whose durable append is wedged forever (the gate above,
/// never released during the timed-out half of this test) must not hang this
/// connection forever: `CLOSE_SESSION_TIMEOUT` must actually elapse, report
/// the close as failed, and reset `close_task` to `None` so a *second*
/// `CloseSession` on the same connection is accepted rather than refused.
///
/// `#[tokio::test(start_paused = true)]` + `tokio::time::advance`, exactly
/// like `session_manager`'s own
/// `close_and_teardown_abandons_a_wedged_close_after_the_timeout_and_tears_down_anyway`
/// — chosen over a real sleep for the same reason: deterministic, no flake
/// budget, no real wall-clock wait for what is nominally a 30s timeout.
///
/// Proving "accepted, not refused" needs care about exactly *when* it is
/// checked, and cannot rely on the retried close fully completing as its
/// only signal: `roundhouse_store::test_util::CloseGate::admit`'s `Waiting`
/// branch, once entered, awaits its own oneshot forever even after `state`
/// flips back to `Open` — so `spawn_gated_writer`'s single writer task stays
/// wedged servicing the FIRST `close_session` command even after this
/// test's own `tokio::time::timeout` (inside the daemon) abandons waiting on
/// it. A second `CloseSession`, if accepted, is queued behind that wedged
/// command — genuinely accepted, but not yet observably different from a
/// "hung" state via an Ack alone, since nothing distinguishes "queued
/// behind a wedged writer" from "silently refused" by watching `events_rx`
/// before the gate is ever released. This is why the acceptance check below
/// runs BEFORE `gate.release()`, using [`CapturingWriter`] to look at the
/// one signal that genuinely differs the instant this connection decides
/// whether to accept or refuse: `drive_established_session`'s own
/// `"a close is already in flight"` refusal log, which fires synchronously
/// (no gate, no writer, no await) if and only if `close_task.is_some() ||
/// close_ack_pending` is still true.
///
/// Releasing the gate afterward drains the wedged FIRST command (durably
/// recording `SessionClosed`), which does NOT retroactively complete the
/// daemon's own already-abandoned `close()` call (that `Future` was dropped
/// by the timeout, so it never reaches its own
/// `state_tx.send_replace(Closed)`) — the actor stays `Cancelling` until the
/// SECOND, already-accepted close (queued earlier, now unblocked) runs its
/// own fresh `SessionActor::close`: past the `Closed` short-circuit (state
/// is `Cancelling`, not `Closed`), past `cancel_recorded` (already `true`,
/// so no second cancel append), through `wait_idle` (immediate, no live
/// work), to a `writer.close_session` call that now finds `SessionClosed`
/// already durably present and returns `CloseReceipt::AlreadyClosed` —
/// which `SessionActor::close` still treats as success, setting `state_tx`
/// to `Closed` for the first time. That gives this test a second, complete
/// proof beyond the log: a real Ack for the retried close.
#[tokio::test(start_paused = true)]
async fn a_wedged_close_times_out_and_a_retry_is_accepted() {
    let (captured, dispatch) = captured_logs();
    let _log_guard = tracing::dispatcher::set_default(&dispatch);

    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let actor = common::real_actor_with_writer(dir.path(), writer).await;

    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);

    tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        true,
        requests_rx,
        events_tx,
        registry,
        resources,
    ));

    // Held for this test's first half: the first close's own durable append
    // blocks on this forever, modeling a genuinely wedged close.
    gate.hold().await;

    let mut state_rx = actor.subscribe();
    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();

    // Deterministic sync point: proves the spawned close has genuinely
    // started before the clock is advanced, exactly as the sibling test
    // above uses it.
    loop {
        state_rx.changed().await.unwrap();
        if *state_rx.borrow() == SessionState::Cancelling {
            break;
        }
    }

    // Deterministic: the paused clock only moves when told to. This jumps
    // straight past CLOSE_SESSION_TIMEOUT without any real time elapsing,
    // driving the runtime through whatever else is ready to run along the
    // way (per `tokio::time::advance`'s own contract) — including the
    // daemon's own `tokio::time::timeout` around `actor.close(..)`, which
    // must now elapse and report the close as failed.
    tokio::time::advance(CLOSE_SESSION_TIMEOUT + Duration::from_millis(1)).await;

    // Deterministic settle, not a sleep: the timer firing above wakes the
    // spawned close_task's `JoinHandle`, but `drive_established_session`'s
    // own `select!` loop still needs to be POLLED again to observe that
    // resolution and reset `close_task` to `None` — a scheduler hop
    // `advance` itself does not guarantee has already happened by the time
    // it returns control here. There is no externally observable signal for
    // "close_task has been reset" to loop on (the timeout path is silent on
    // the wire, by design — see `CLOSE_SESSION_TIMEOUT`'s own doc comment),
    // so this settles with a fixed, generous number of `yield_now` calls
    // instead of a conditional retry loop: each costs no real or virtual
    // time, it only lets an already-woken task in this same runtime actually
    // run, and the resolution chain here is only two scheduler hops deep.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    assert!(
        events_rx.recv().now_or_never().is_none(),
        "a merely-timed-out close must not send an Ack — it failed, it did not succeed"
    );
    assert_eq!(
        actor.state(),
        SessionState::Cancelling,
        "a timed-out close must leave the actor stuck in Cancelling — neither Closed (the \
         abandoned call never reached its own state_tx.send_replace) nor Running"
    );
    // Positive control for the negative assertion below: proves `captured`
    // is actually wired up and capturing this connection's own log output,
    // so `!captured.contains("a close is already in flight")` further down
    // means "that warning genuinely did not fire," not "the log capture
    // silently captured nothing" — which a reworded warning message could
    // otherwise make true forever without this line ever failing.
    assert!(
        captured.contains("CloseSession did not durably append within the timeout"),
        "expected the timeout's own log line to have fired"
    );

    // Sent BEFORE releasing the gate, and checked via the captured log
    // rather than `events_rx` — see this test's own doc comment for why an
    // Ack alone cannot yet distinguish "accepted, now queued behind the
    // still-wedged writer" from "refused." `close_task` must have reset to
    // `None` (and `close_ack_pending` must still be `false`) for this send
    // to reach `registry.actor` at all rather than hit the synchronous
    // refusal branch.
    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !captured.contains("a close is already in flight"),
        "the retried CloseSession must be accepted, not refused, once close_task has reset to \
         None — a refusal here means the timeout failed to unlatch this connection's own \
         bookkeeping"
    );

    // Unwedge the writer's own still-in-flight admit() for the FIRST
    // close_session command — see this test's own doc comment for exactly
    // why this is necessary and what it does (and does not) complete. Only
    // now does the already-accepted second close (queued above) get a
    // chance to actually finish.
    gate.release().await;

    let event = events_rx
        .recv()
        .await
        .expect("the connection must not have ended before sending the retried close's Ack");
    assert!(
        matches!(event, ClientEvent::Ack { api_version } if api_version == ApiVersion::CURRENT),
        "expected an Ack for the retried close, got {event:?}"
    );
    assert_eq!(
        actor.state(),
        SessionState::Closed,
        "the retried close must be the one that finally drives the actor to Closed"
    );
}

/// Builds a `ClientEvent::TaskEvent` carrying a distinct `Delta::Text`
/// marker, for tests that need to tell two published events apart without
/// `ClientEvent`/`EventPayload`/`Delta` implementing `PartialEq` (none of
/// the three do).
fn text_event(session_id: SessionId, marker: &str) -> ClientEvent {
    ClientEvent::TaskEvent {
        session_id,
        task_id: None,
        payload: Box::new(EventPayload::TaskDelta {
            delta: roundhouse_core::Delta::Text {
                text: marker.to_string(),
            },
        }),
    }
}

fn text_event_marker(event: &ClientEvent) -> Option<&str> {
    match event {
        ClientEvent::TaskEvent { payload, .. } => match payload.as_ref() {
            EventPayload::TaskDelta {
                delta: roundhouse_core::Delta::Text { text },
            } => Some(text.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// The `Ack` for a successful `CloseSession` must never overtake a session
/// event that arrived first — the specific race
/// `drive_established_session`'s own `pending_event.is_none()` guard on its
/// close-ack arm exists to prevent (see that guard's own comment, next to
/// the `permit = events_tx.reserve(), if close_ack_pending &&
/// pending_event.is_none()` arm): "an event already dequeued out of
/// `session_events` into `pending_event` could lose [the `select!`] race to
/// a ready `Ack`... with the client seeing the `Ack` ahead of an event it
/// was already due."
///
/// Built with a capacity-1 `events_tx` so `"second"` is provably still
/// sitting in `pending_event` (not yet resident in the channel) rather than
/// merely "sent very quickly, in the right order, by luck": `"first"` is
/// published and settles all the way into the channel (filling its one
/// slot — `yield_now`, not a sleep, just lets the already-spawned driver
/// task actually run), THEN `"second"` is published — `session_events.recv()`
/// still dequeues it into `pending_event`, but the arm that would flush it
/// into the channel cannot get a permit until this test drains `"first"`.
/// Only once both events are fully settled is `CloseSession` even sent, so
/// there is no additional race between the events' own placement and the
/// close's own completion to reason about: `close_ack_pending` becoming
/// `true` while `"second"` is still parked is the exact contested state the
/// guard exists for, constructed here deterministically rather than hoped
/// for.
#[tokio::test]
async fn the_ack_never_overtakes_an_event_already_parked_ahead_of_it() {
    let dir = tempfile::tempdir().unwrap();
    let actor = common::real_actor(dir.path()).await;
    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    // Capacity 1: the mechanism this test needs to force "second" to sit in
    // `pending_event`, unflushed, rather than flow straight through.
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(1);

    tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        true,
        requests_rx,
        events_tx,
        registry.clone(),
        resources,
    ));

    registry.publish(session_id, text_event(session_id, "first"));
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    registry.publish(session_id, text_event(session_id, "second"));
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    let mut state_rx = actor.subscribe();
    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();

    // Deterministic: wait for the close to genuinely finish — proving
    // `close_ack_pending` becomes `true` while `"second"` is *definitely*
    // still parked (never drained by this test yet), rather than hoping the
    // close is merely slower than a couple of `yield_now` calls. Without
    // this wait, draining `"first"` immediately after sending `CloseSession`
    // risks the close's own real durable append (genuine file I/O) simply
    // not having finished yet — passing this test for the wrong reason (no
    // actual contention for the guard to resolve) rather than the right one.
    loop {
        if actor.state() == SessionState::Closed {
            break;
        }
        state_rx.changed().await.unwrap();
    }
    // A further settle: `actor.state()` reaching `Closed` happens inside
    // the spawned close task itself; `drive_established_session`'s own
    // `select!` loop still needs to be polled again to observe that task's
    // `JoinHandle` resolving and set `close_ack_pending = true` — see the
    // identical reasoning in
    // `a_wedged_close_times_out_and_a_retry_is_accepted`, above.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    let got_first = events_rx
        .recv()
        .await
        .expect("the connection must not have ended before delivering the first event");
    assert_eq!(
        text_event_marker(&got_first),
        Some("first"),
        "expected the first published event first, got {got_first:?}"
    );

    let got_second = events_rx
        .recv()
        .await
        .expect("the connection must not have ended before delivering the second event");
    assert_eq!(
        text_event_marker(&got_second),
        Some("second"),
        "the second published event — already parked in pending_event before the close even \
         started — must be delivered before the Ack, never after: got {got_second:?}"
    );

    let got_third = events_rx
        .recv()
        .await
        .expect("the connection must not have ended before sending the Ack");
    assert!(
        matches!(got_third, ClientEvent::Ack { api_version } if api_version == ApiVersion::CURRENT),
        "expected the Ack third, got {got_third:?}"
    );
}

/// A `SubmitTurn` arriving while a `CloseSession` on the same connection is
/// still gated (blocked on the durable append, not yet even reported success
/// or failure) must be refused — the `close_task.is_some() || \
/// close_ack_pending` guard's own `close_task.is_some()` half. Checked via
/// the captured log line, the same shape `a_wedged_close_times_out_and_a_\
/// retry_is_accepted` uses for its own "accepted, not refused" half: a
/// refusal here is silent on the wire (no distinct wire NAK exists for
/// `SubmitTurn` either — same limitation `DaemonClient::close_session`'s own
/// doc comment describes for `CloseSession`), so there is no other
/// observable signal to assert on.
#[tokio::test]
async fn a_submit_turn_is_refused_while_a_close_is_gated() {
    let (captured, dispatch) = captured_logs();
    let _log_guard = tracing::dispatcher::set_default(&dispatch);

    let dir = tempfile::tempdir().unwrap();
    let store = roundhouse_store::open(&dir.path().join("events.db"))
        .await
        .unwrap();
    let gate = CloseGate::new();
    let writer = spawn_gated_writer(store, Arc::clone(&gate)).await;
    let actor = common::real_actor_with_writer(dir.path(), writer).await;

    let registry = Arc::new(SessionRegistry::new());
    let (session_id, subscription, session_events) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");
    let resources = common::real_resources(dir.path()).await;

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(8);

    tokio::spawn(drive_established_session(
        session_id,
        subscription,
        session_events,
        true,
        requests_rx,
        events_tx,
        registry,
        resources,
    ));

    // Held for this whole test: the close's own durable append never
    // completes, so `close_task` stays `Some` throughout.
    gate.hold().await;

    let mut state_rx = actor.subscribe();
    requests_tx
        .send(ClientRequest::CloseSession { session_id })
        .await
        .unwrap();

    // Deterministic sync point: proves the spawned close has genuinely
    // started (and is therefore genuinely gated) before SubmitTurn is sent.
    loop {
        state_rx.changed().await.unwrap();
        if *state_rx.borrow() == SessionState::Cancelling {
            break;
        }
    }

    requests_tx
        .send(ClientRequest::SubmitTurn {
            session_id,
            text: "hello".to_string(),
        })
        .await
        .unwrap();
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }

    assert!(
        captured.contains("refusing SubmitTurn: a CloseSession is already in flight"),
        "a SubmitTurn arriving while a CloseSession is gated must be refused"
    );
    assert!(
        events_rx.recv().now_or_never().is_none(),
        "no reply of any kind is expected yet — the close is still gated, and the refused \
         SubmitTurn produces no event"
    );
}
