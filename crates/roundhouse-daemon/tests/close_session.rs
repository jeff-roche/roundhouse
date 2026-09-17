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
use roundhouse_daemon::socket_server::drive_established_session;
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use roundhouse_store::test_util::{spawn_gated_writer, CloseGate};
use tokio::sync::mpsc;

/// **Ruling W1-R37, applied to `CloseSession`.** An attached (non-creating)
/// connection is read-only, exactly as it already is for `SubmitTurn`: its
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
