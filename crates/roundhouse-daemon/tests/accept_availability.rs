//! Fix round 1, fixes 3–5 (security review Important 2/3/4, ruling W1-R33
//! and W1-R34): `accept_loop` survives a transient `accept()` error, refuses
//! connections cleanly once at a cap rather than accepting unbounded work,
//! times out a silent peer's handshake, and verifies every peer against
//! this process's own uid rather than a mutable filesystem attribute.
//!
//! Fix 3 (`accept()` surviving `EMFILE`/etc.) is proven at the unit level in
//! `socket_server`'s own `classify_accept_error_tests` module — the
//! reviewer's `ulimit -n 200` reproduction is an end-to-end, by-hand
//! exercise this suite does not automate; see that module's doc comment.

mod common;

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::socket_server::{accept_loop_with, bind_socket, AcceptLimits};
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

/// This test process's own uid, via the same `/proc/self` idiom
/// `socket_server::current_process_uid` uses internally (private to that
/// module, so duplicated here at the test level — this is setup, not the
/// behavior under test).
fn own_uid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

#[tokio::test]
async fn too_many_concurrent_connections_are_refused_but_the_loop_keeps_running() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = bind_socket(&socket_path).unwrap();
    let limits = AcceptLimits {
        max_connections: 1,
        handshake_timeout: Duration::from_secs(5),
    };
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(accept_loop_with(
        listener,
        registry.clone(),
        resources,
        Ok(own_uid()),
        limits,
    ));

    // Takes the only connection slot and holds it open without ever
    // completing a handshake — the slot is claimed at accept time, not at
    // handshake time.
    let first = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
        .await
        .expect("connect must not hang")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // At the cap: a new connection must be closed promptly, not left open
    // or left to hang.
    let mut second =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
            .await
            .expect("connect must not hang")
            .unwrap();
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "at the connection cap, a new connection must be refused (closed), got {read:?}"
    );

    // The loop itself must still be running: freeing the first connection's
    // slot lets a subsequent connection succeed.
    drop(first);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let third = tokio::time::timeout(
        Duration::from_secs(2),
        roundhouse_tui::connect_create(&socket_path, "default"),
    )
    .await;
    assert!(
        matches!(third, Ok(Ok(_))),
        "the accept loop must keep serving connections after the cap was \
         hit and then freed"
    );
}

#[tokio::test]
async fn a_connection_that_never_sends_a_handshake_request_is_closed_after_the_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = bind_socket(&socket_path).unwrap();
    let limits = AcceptLimits {
        max_connections: 8,
        handshake_timeout: Duration::from_millis(100),
    };
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(accept_loop_with(
        listener,
        registry.clone(),
        resources,
        Ok(own_uid()),
        limits,
    ));

    let mut client =
        tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
            .await
            .expect("connect must not hang")
            .unwrap();
    // Deliberately never send anything — the slowloris shape fix 4 closes.
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "a silently-connected peer must be closed once the handshake \
         timeout elapses, not held open forever, got {read:?}"
    );
}

#[tokio::test]
async fn a_peer_uid_mismatch_is_refused_but_the_loop_keeps_running() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = bind_socket(&socket_path).unwrap();
    // Deliberately wrong: this test process's peer_cred will never match.
    let wrong_uid = own_uid().wrapping_add(1);
    let resources = common::real_resources(dir.path()).await;
    tokio::spawn(accept_loop_with(
        listener,
        registry.clone(),
        resources,
        Ok(wrong_uid),
        AcceptLimits::default(),
    ));

    for _ in 0..2 {
        let mut client =
            tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&socket_path))
                .await
                .expect("connect must not hang")
                .unwrap();
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0))),
            "a uid mismatch must be refused (closed), not accepted or left \
             hanging, got {read:?}"
        );
    }
}

#[tokio::test]
async fn an_undeterminable_own_uid_refuses_to_accept_anything() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let registry = Arc::new(SessionRegistry::new());
    let listener = bind_socket(&socket_path).unwrap();
    let undeterminable = std::io::Error::new(std::io::ErrorKind::Unsupported, "test: no /proc");
    let resources = common::real_resources(dir.path()).await;

    // Must return an error promptly, before ever calling `accept()` — never
    // silently downgrade to "skip the check" (ruling W1-R34).
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        accept_loop_with(
            listener,
            registry,
            resources,
            Err(undeterminable),
            AcceptLimits::default(),
        ),
    )
    .await;
    assert!(
        matches!(result, Ok(Err(_))),
        "an undeterminable uid must make accept_loop_with return an error \
         immediately rather than accept connections unauthenticated, got {result:?}"
    );
}

#[tokio::test]
async fn session_registry_refuses_create_once_at_max_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SessionRegistry::with_limits(1, 64);
    let actor_a = common::real_actor(dir.path()).await;
    let actor_b = common::real_actor(dir.path()).await;
    assert!(
        registry.create(actor_a, None, None).is_some(),
        "the first session, under the cap, must succeed"
    );
    assert!(
        registry.create(actor_b, None, None).is_none(),
        "a session past max_sessions must be refused, not silently minted"
    );
}

#[tokio::test]
async fn session_registry_refuses_attach_once_at_max_subscribers_per_session() {
    let dir = tempfile::tempdir().unwrap();
    let registry = SessionRegistry::with_limits(64, 1);
    let actor = common::real_actor(dir.path()).await;
    let (session_id, _creator_subscription, _creator_events) =
        registry.create(actor, None, None).unwrap();
    // The creator itself already counts as the one subscriber this
    // registry allows for this session.
    assert!(
        registry.attach(session_id).is_none(),
        "an attach past max_subscribers_per_session must be refused, not \
         silently registered — publish clones the event per subscriber, so \
         this bounds a real per-event memory/CPU amplifier"
    );
}
