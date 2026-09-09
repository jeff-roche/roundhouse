//! Fix round 1, fix 1 (rulings W1-R31/W1-R32/W1-R38): proves the
//! cross-channel deadlock between `drive_session` and `serve_connection` is
//! closed, without relying on a full, racy end-to-end wedge.
//!
//! `handle_connection` wires these two functions together via `tokio::join!`
//! over two independent bounded `mpsc` channels, forming a cycle: each
//! function's read arm used to send into the *other* channel from inside its
//! own branch body, which — once `tokio::select!` commits to a branch — is
//! no longer racing the other arm. A full end-to-end reproduction would need
//! to interleave three channels (the registry's own subscriber channel, the
//! `events_tx`/`events_in` pair, and `requests_tx`/`requests_rx`) and would
//! only wedge *sometimes*, depending on scheduling — a flaky test here would
//! be worse than none. Instead, each half is driven directly, alone, with
//! its own test-owned channels of a deliberately small capacity, proving the
//! invariant ("neither half may block on a channel send while it is also
//! responsible for draining the channel its peer's send depends on") one
//! function at a time.
//!
//! The two `*_is_stuck_full` tests below are the ones that actually
//! reproduce ruling W1-R31's bug and fail against `e43834d` (verified via
//! `git stash` before this fix landed). The two `*_while_idle` tests guard a
//! *different* hazard the brief calls out explicitly — the "obvious"
//! `reserve()` fix that awaits the paired channel's `recv()` inside the
//! `reserve()` arm's own body, which merely relocates the bug to the idle
//! case. Because the original bug only manifests once an actual send is
//! attempted against an already-full channel, the idle-case tests do **not**
//! fail against unfixed `e43834d` — that code's first arm is itself a
//! `recv()`, which blocks harmlessly, uncommitted, while nothing has
//! happened yet. They exist to catch a regression into the *naive*
//! alternative fix, not the original bug; see this lane's fix-round report
//! for why that distinction matters and is called out rather than
//! papered over.

mod common;

use std::sync::Arc;
use std::time::Duration;

use roundhouse_core::{EventPayload, NoteLevel};
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::socket_server::{
    drive_session, serve_connection, FailedConstructionLimiter,
};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// How long to let a spawned driver actually run before the test acts on
/// its state. Long enough on any real scheduler for a handful of `.await`
/// points to resolve; short enough not to make the suite slow. Settling
/// here — rather than sending the contested message immediately — matters:
/// without it, the two channels involved could both be simultaneously
/// "ready" the instant the driver polls, and `tokio::select!`'s fair random
/// choice could pick the non-buggy arm often enough to make even the
/// pre-fix test flaky instead of reliably red.
const SETTLE: Duration = Duration::from_millis(50);

#[tokio::test]
async fn drive_session_keeps_draining_requests_while_events_tx_is_stuck_full() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(SessionRegistry::new());
    let resources = common::real_resources(dir.path()).await;
    let (requests_tx, requests_rx) = tokio::sync::mpsc::channel::<ClientRequest>(1);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<ClientEvent>(1);

    tokio::spawn(drive_session(
        requests_rx,
        events_tx,
        registry.clone(),
        resources,
        Duration::from_secs(5),
        0,
        Arc::new(FailedConstructionLimiter::default()),
        Arc::new(tokio::sync::Semaphore::new(64)),
    ));

    // Handshake: mint a session, and read back its one reply frame to learn
    // the session id. This also drains the capacity-1 events channel back
    // to empty, which the next step relies on.
    requests_tx
        .send(ClientRequest::CreateSession {
            workspace_name: "default".into(),
        })
        .await
        .unwrap();
    let created = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
        .await
        .expect("handshake reply must not hang")
        .expect("handshake reply must arrive");
    let session_id = match created {
        ClientEvent::TaskEvent { session_id, .. } => session_id,
        other => panic!("expected the SessionCreated handshake frame, got {other:?}"),
    };

    // From here on nothing ever reads `events_rx` again — standing in for a
    // `serve_connection` that is busy elsewhere, exactly the condition
    // ruling W1-R31 identifies. Publish two events: the first fits in the
    // now-empty capacity-1 channel; the second cannot be buffered, forcing
    // `drive_session` to actually attempt (and, pre-fix, block on) a second
    // send into an already-full channel.
    let note = |text: &str| ClientEvent::TaskEvent {
        session_id,
        task_id: None,
        payload: Box::new(EventPayload::Note {
            level: NoteLevel::Info,
            text: text.into(),
        }),
    };
    registry.publish(session_id, note("one"));
    registry.publish(session_id, note("two"));

    tokio::time::sleep(SETTLE).await;

    // Fill the capacity-1 requests channel — room is available regardless
    // of `drive_session`'s state, so this send proves nothing by itself.
    requests_tx
        .send(ClientRequest::CreateSession {
            workspace_name: "unused-a".into(),
        })
        .await
        .unwrap();

    // This send is the one that actually exercises the invariant: it needs
    // `drive_session` to have called `requests_rx.recv()` to free the one
    // slot this channel has. Pre-fix, `drive_session` is permanently parked
    // sending "two" into the full, unread `events_tx` and never reaches
    // that `recv()` again — this send times out. Post-fix, `drive_session`
    // keeps polling `requests_rx` even while a pending event awaits
    // `events_tx` capacity, so this completes well within the timeout.
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        requests_tx.send(ClientRequest::CreateSession {
            workspace_name: "unused-b".into(),
        }),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "drive_session must keep draining requests_rx even while a session \
         event is stuck waiting for events_tx capacity (rulings W1-R31/W1-R32) \
         — this send timed out, meaning the cross-channel deadlock is back"
    );
}

#[tokio::test]
async fn serve_connection_keeps_draining_events_while_requests_out_is_stuck_full() {
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let (requests_tx, _requests_rx) = tokio::sync::mpsc::channel::<ClientRequest>(1);
    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<ClientEvent>(4);

    // Pre-fill the capacity-1 requests channel *before* `serve_connection`
    // is even spawned, so there is no race to win: the very first line this
    // connection reads must already find the channel full.
    requests_tx
        .try_send(ClientRequest::CreateSession {
            workspace_name: "prime".into(),
        })
        .unwrap();

    tokio::spawn(serve_connection(server_stream, requests_tx, events_rx));

    let (client_read, mut client_write) = client_stream.into_split();
    let mut client_reader = BufReader::new(client_read);

    // One request line: `serve_connection`'s read arm parses it and tries
    // to forward it — pre-fix that send happens inside the read arm's own
    // branch body, blocking immediately since the channel is already full.
    let line = serde_json::to_string(&ClientRequest::CreateSession {
        workspace_name: "test".into(),
    })
    .unwrap();
    client_write.write_all(line.as_bytes()).await.unwrap();
    client_write.write_all(b"\n").await.unwrap();

    tokio::time::sleep(SETTLE).await;

    // `serve_connection`'s events channel has spare capacity, so this send
    // succeeds regardless of `serve_connection`'s own state — what is
    // actually contested is whether `serve_connection` ever picks the event
    // back up and writes it to the socket.
    events_tx
        .send(ClientEvent::Ack {
            api_version: ApiVersion::CURRENT,
        })
        .await
        .unwrap();

    let mut received_line = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        client_reader.read_line(&mut received_line),
    )
    .await;
    assert!(
        matches!(read, Ok(Ok(n)) if n > 0),
        "serve_connection must keep draining events_in even while its own \
         requests_out.send is stuck waiting for capacity (rulings W1-R31/W1-R32) \
         — the client never saw the event, meaning the cross-channel deadlock is back"
    );
    assert!(
        received_line.contains("Ack"),
        "expected the Ack event's serialized form, got {received_line:?}"
    );
}

#[tokio::test]
async fn drive_session_keeps_draining_requests_while_the_session_is_idle() {
    // Guards the "obvious `reserve()` fix" trap the brief calls out: naively
    // selecting on `events_tx.reserve()` and then `.await`ing
    // `session_events.recv()` *inside that arm's body* would grab a permit
    // speculatively the moment the loop starts (since `events_tx` has spare
    // capacity below), then block forever with nothing to send — starving
    // `requests_rx` even though nothing about `events_tx` is actually full.
    // A correct fix never reserves capacity until it already has a
    // concrete event to send, so this never happens.
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(SessionRegistry::new());
    let actor = common::real_actor(dir.path()).await;
    let (session_id, _creator_subscription, _creator_events) =
        registry.create(actor, None, None).unwrap();

    let resources = common::real_resources(dir.path()).await;
    let (requests_tx, requests_rx) = tokio::sync::mpsc::channel::<ClientRequest>(1);
    let (events_tx, _events_rx) = tokio::sync::mpsc::channel::<ClientEvent>(8);

    tokio::spawn(drive_session(
        requests_rx,
        events_tx,
        registry.clone(),
        resources,
        Duration::from_secs(5),
        0,
        Arc::new(FailedConstructionLimiter::default()),
        Arc::new(tokio::sync::Semaphore::new(64)),
    ));

    // Attach (rather than create) so there is no handshake reply to drain
    // here — `_events_rx` is simply never read for the whole test, and the
    // session never emits anything past this point.
    requests_tx
        .send(ClientRequest::Attach { session_id })
        .await
        .unwrap();

    // Give `drive_session` time to finish the handshake and enter its idle
    // loop before probing it.
    tokio::time::sleep(SETTLE).await;

    // Fill the capacity-1 requests channel, then send one more with a
    // timeout — proving `drive_session` is still actually calling
    // `requests_rx.recv()` (freeing the slot), not just that there was room
    // to buffer into.
    requests_tx
        .send(ClientRequest::Attach { session_id })
        .await
        .unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        requests_tx.send(ClientRequest::Attach { session_id }),
    )
    .await;
    assert!(
        outcome.is_ok(),
        "drive_session must keep draining requests while the session is \
         idle, even with events_tx capacity available — a reserve() grabbed \
         speculatively before there is anything to send would starve this"
    );
}

#[tokio::test]
async fn serve_connection_drains_pending_events_while_idle() {
    // The `serve_connection`-side mirror of the test above: guards against
    // speculatively reserving `requests_out` capacity before a line has
    // even been read, which would stall `events_in` draining the moment the
    // peer goes quiet.
    let (server_stream, client_stream) = UnixStream::pair().unwrap();
    let (requests_tx, _requests_rx) = tokio::sync::mpsc::channel::<ClientRequest>(8);
    let (events_tx, events_rx) = tokio::sync::mpsc::channel::<ClientEvent>(4);

    tokio::spawn(serve_connection(server_stream, requests_tx, events_rx));

    // The peer never sends anything — `lines.next()` sits idle for the
    // whole test.
    let (client_read, _client_write) = client_stream.into_split();
    let mut client_reader = BufReader::new(client_read);

    events_tx
        .send(ClientEvent::Ack {
            api_version: ApiVersion::CURRENT,
        })
        .await
        .unwrap();

    let mut received_line = String::new();
    let read = tokio::time::timeout(
        Duration::from_secs(2),
        client_reader.read_line(&mut received_line),
    )
    .await;
    assert!(
        matches!(read, Ok(Ok(n)) if n > 0),
        "serve_connection must keep writing events to the socket while the \
         read side is idle, even with requests_out capacity available"
    );
}
