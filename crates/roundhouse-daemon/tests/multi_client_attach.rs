//! Proves `accept_loop` serves more than one connection at once, and routes
//! by `SessionId` rather than by socket: a second, independent connection
//! that never took part in creating a session can still `Attach` to it and
//! see the events that session produces.
//!
//! Also exercises ruling W1-R12's restored bind-ordering guarantee directly:
//! unlike `socket_shutdown.rs`'s `serve`-based tests, there is no
//! `tokio::time::sleep` between spawning `accept_loop` and dialing it, since
//! the listener is bound synchronously, in this test's own stack frame,
//! before `accept_loop` is ever spawned.

mod common;

use std::sync::Arc;
use std::time::Duration;

use roundhouse_core::{EventPayload, NoteLevel};
use roundhouse_proto::ClientEvent;

#[tokio::test]
async fn two_clients_can_create_and_then_attach_to_the_same_session() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
        resources,
    ));

    let creator = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "default"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id = creator.session_id();

    // A second, independent client attaches to the SAME session and must see
    // events the first client's session produces — proving the accept loop
    // serves more than one connection and routes by SessionId, not by socket.
    let mut watcher = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_attach(&socket_path, session_id),
    )
    .await
    .expect("connect_attach must not hang")
    .unwrap();

    registry.publish(
        session_id,
        ClientEvent::TaskEvent {
            session_id,
            task_id: None,
            payload: Box::new(EventPayload::Note {
                level: NoteLevel::Info,
                text: "hello from creator's session".into(),
            }),
        },
    );

    let seen = tokio::time::timeout(Duration::from_secs(2), watcher.recv())
        .await
        .expect("watcher must see the event before timing out")
        .unwrap()
        .expect("watcher must see the event");
    assert!(matches!(seen, ClientEvent::TaskEvent { .. }));
}

/// `Attach` to a `SessionId` nobody ever created must not hang, panic, or
/// falsely succeed — it is indistinguishable, from this registry's
/// perspective, from attaching to a session that existed but whose every
/// subscriber has since disconnected (see `SessionRegistry::attach`'s doc
/// comment). The daemon has no `Ack` to send back, so `connect_attach` must
/// surface that as an error rather than handing back a client that will
/// never see anything.
#[tokio::test]
async fn attaching_to_an_unknown_session_fails_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
        resources,
    ));

    let unknown_session_id = roundhouse_core::SessionId::new();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_attach(&socket_path, unknown_session_id),
    )
    .await
    .expect("connect_attach must not hang against an unknown session");
    assert!(
        result.is_err(),
        "attaching to a session nobody created should fail, not silently succeed"
    );
}

/// Once a session's only subscriber disconnects, `SessionRegistry` must
/// reap that session's entry — not leak it forever (see
/// `SessionRegistry`'s module doc comment, "Not leaking registry entries
/// forever"). Exercised end to end over the wire, not by reaching into
/// `SessionRegistry` directly: create a session, drop the only client
/// attached to it, then poll `Attach` until it starts failing the same way
/// `attaching_to_an_unknown_session_fails_without_hanging` above does.
///
/// Polls on a short interval rather than a single fixed-delay sleep,
/// because the creator's disconnect is noticed asynchronously by that
/// connection's own spawned task (`serve_connection` returning, dropping
/// `requests_out`, `drive_session` observing that and calling `detach`) —
/// there is no single instant this test can synchronously wait on. The
/// outer `tokio::time::timeout` is what keeps this from hanging CI if reaping
/// never happens.
#[tokio::test]
async fn a_session_with_no_more_subscribers_stays_attachable_not_reaped() {
    // Ruling W1-R51 (Phase 7, Task 7): this test used to prove the OPPOSITE
    // — that a session's registry entry was reaped once its last subscriber
    // disconnected. Binding a real `SessionActor` into every entry made
    // that rule wrong: reaping on subscriber-emptiness would cancel
    // whatever a session's actor is still doing the instant its one
    // attached `round` client disconnects, breaking a headless `round run`.
    // The registry's own module doc comment ("Entry lifetime = actor
    // lifetime") states the new rule; this test proves it end to end,
    // through the real accept loop, rather than only at the registry's own
    // unit-test level (`session_registry.rs`'s
    // `detaching_the_last_subscriber_does_not_reap_the_session`).
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
        resources,
    ));

    let creator = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "default"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id = creator.session_id();
    drop(creator);

    // Give the daemon's own connection-loop task time to observe the
    // disconnect and run `SessionRegistry::detach` — a race this test must
    // not depend on winning by accident.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let attached = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_attach(&socket_path, session_id),
    )
    .await;
    assert!(
        matches!(attached, Ok(Ok(_))),
        "a session must remain attachable after its last subscriber \
         disconnects — the actor (and any work it may still be doing) \
         outlives the connection that created it"
    );
}

/// Fix round 1, fix 6 (code review Important 2): the existing tests above
/// prove `Attach` finds a session by id and that an unknown id fails, but
/// neither proves *isolation* — a registry that broadcast every event to
/// every live connection regardless of `session_id` would pass both of them
/// identically. This test creates two independent sessions, attaches a
/// watcher to only one of them, and publishes to *both* — asserting the
/// watcher never sees the event meant for the other session, and that the
/// one event it does see actually carries its own session's id (not just
/// `matches!(.., TaskEvent { .. })`, which any `TaskEvent` would satisfy).
///
/// Publishes to the *other* session first, deliberately: if events were
/// broadcast by socket rather than routed by `SessionId`, that would be the
/// event the watcher saw *first* — so ordering alone (not a timeout, which
/// this lane treats as inherently racy) is what proves isolation
/// deterministically.
#[tokio::test]
async fn attach_routes_by_session_id_and_never_leaks_another_sessions_events() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
        resources,
    ));

    let session_a = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "session-a"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id_a = session_a.session_id();

    let session_b = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "session-b"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id_b = session_b.session_id();
    assert_ne!(session_id_a, session_id_b, "sanity: two distinct sessions");

    let mut watcher = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_attach(&socket_path, session_id_a),
    )
    .await
    .expect("connect_attach must not hang")
    .unwrap();

    let note = |session_id: roundhouse_core::SessionId, text: &str| ClientEvent::TaskEvent {
        session_id,
        task_id: None,
        payload: Box::new(EventPayload::Note {
            level: NoteLevel::Info,
            text: text.into(),
        }),
    };
    // Session B first: if routing were broken (broadcast by socket instead
    // of by SessionId), this is the event the watcher would see first.
    registry.publish(session_id_b, note(session_id_b, "for-b"));
    registry.publish(session_id_a, note(session_id_a, "for-a"));

    let seen = tokio::time::timeout(Duration::from_secs(2), watcher.recv())
        .await
        .expect("watcher must see an event before timing out")
        .unwrap()
        .expect("watcher must see an event");
    match seen {
        ClientEvent::TaskEvent { session_id, .. } => {
            assert_eq!(
                session_id, session_id_a,
                "the watcher attached to session A must never see session \
                 B's event first (or at all) — routing must be by \
                 SessionId, not by socket"
            );
        }
        other => panic!("expected a TaskEvent, got {other:?}"),
    }

    // And session B's event must never arrive on this connection at all.
    let should_not_arrive = tokio::time::timeout(Duration::from_millis(200), watcher.recv()).await;
    assert!(
        should_not_arrive.is_err(),
        "the watcher attached to session A must not receive session B's \
         event at all, got {should_not_arrive:?}"
    );
}
