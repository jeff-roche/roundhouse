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
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
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
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
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
async fn a_session_with_no_more_subscribers_is_reaped_rather_than_kept_forever() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
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

    let reaped = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if roundhouse_tui::connect_attach(&socket_path, session_id)
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        reaped.is_ok(),
        "the session's registry entry should be reaped once its only \
         subscriber disconnects, not linger forever"
    );
}
