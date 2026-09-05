//! The real server half of `roundhouse-tui`'s `DaemonClient`: one Unix
//! socket, real bidirectional NDJSON traffic in `roundhouse-proto`'s wire
//! types.
//!
//! Phase 1 built this against `roundhouse_tui::ServerMessage`, a hand-rolled,
//! daemon-pre-summarized wire type that could only ever carry a flattened
//! text delta or session summary — not an MCP tool call, a policy denial, or
//! a sub-agent spawn event. Phase 7 Task 2 retires it: this module now reads
//! `ClientRequest` lines and writes `ClientEvent` lines, `roundhouse-proto`'s
//! real, versioned client↔daemon wire types.

use roundhouse_core::{EventPayload, OnDegrade, SessionSpec, Tier, WorkspaceId};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::session_registry::SessionRegistry;

/// How many in-flight `ClientRequest`s one connection's driver will buffer
/// before applying backpressure to that connection's read side. Generous
/// relative to the handshake-only traffic Task 2 exercised, small enough
/// that a truly stuck consumer still bounds memory per connection.
const REQUEST_CHANNEL_CAPACITY: usize = 64;
/// Matches [`crate::session_registry`]'s per-subscriber depth — the
/// handshake-created channel a connection's driver forwards into its own
/// socket via [`serve_connection`] has no reason to buffer more than a
/// subscriber channel already does.
const EVENT_CHANNEL_CAPACITY: usize = 64;

/// Binds a Unix socket at `socket_path` and tightens its permissions to
/// owner-only, but accepts nothing — that is [`serve`]'s or [`accept_loop`]'s
/// job, not this one's.
///
/// Split out specifically so [`accept_loop`]'s caller can bind — and chmod —
/// *synchronously*, before ever spawning anything, restoring the guarantee
/// Phase 1's `serve_ndjson` had and [`serve`] (an `async fn` that binds only
/// once polled) weakened: see [`accept_loop`]'s doc comment for the full
/// story. `serve` itself now also calls this rather than duplicating the
/// bind/chmod pair inline.
///
/// # Errors
/// Returns the `bind` error if the path is already in use, unwritable, or too
/// long for `sockaddr_un`, or the `set_permissions` error if the socket's mode
/// can't be tightened.
pub fn bind_socket(socket_path: impl AsRef<Path>) -> std::io::Result<UnixListener> {
    let socket_path = socket_path.as_ref();
    let listener = UnixListener::bind(socket_path)?;
    // `bind` creates the socket with `0777 & ~umask`, which on a permissive
    // umask is world-connectable. Tighten it to owner-only.
    //
    // There is an unavoidable window between `bind` and this call, and
    // `set_permissions` *follows symlinks* — so if the socket path sits
    // somewhere an attacker can write, they could replace it with a symlink in
    // that window and have this line chmod an arbitrary file of their choosing
    // to 0600. For the default path that is fully mitigated by the 0700 parent
    // directory (nobody else can create anything in it, so there is nothing to
    // swap). It is *not* mitigated for an operator-supplied `$ROUND_SOCKET`
    // pointing at a shared directory — the parent directory is the real barrier
    // here, and this chmod is only defense in depth behind it.
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Binds a Unix socket, accepts exactly one connection, and runs the real
/// bidirectional wire loop for it via [`serve_connection`].
///
/// A production daemon serves many concurrent attached clients (§11.3) —
/// that is [`accept_loop`] below, built on the same [`serve_connection`].
/// This function survives Task 3 only because `main.rs`'s single-session demo
/// and this crate's existing `socket_wire_format`/`socket_shutdown` tests
/// still exercise the one-connection shape directly; new call sites should
/// prefer `bind_socket` + [`accept_loop`].
///
/// `bind_socket` (bind, then the `set_permissions` chmod) runs as the first
/// statement in this function's body, before any `.await` point — so
/// whichever task actually polls this future runs it eagerly, in one step,
/// before yielding at `listener.accept().await`. That is a weaker guarantee
/// than Phase 1's `serve_ndjson` had (a plain, non-async function that bound
/// synchronously *before returning control to its caller*, because it did its
/// own internal `tokio::spawn`): here, the caller is the one who spawns
/// `serve` (see `main.rs`'s startup wiring and this crate's
/// `socket_wire_format` test), so there is now a scheduling gap between
/// `tokio::spawn(serve(..))` returning and this function's body actually
/// running. Callers that need the old hard guarantee should not rely on
/// `serve`'s return value the way they could rely on `serve_ndjson`'s
/// `JoinHandle` — a client that dials immediately after `tokio::spawn` may
/// still race the bind. [`accept_loop`] restores the hard guarantee instead,
/// by taking an already-bound `UnixListener`.
///
/// The spawned connection's loop exits the moment *either* direction ends —
/// the peer disconnects (or a read errors), or `events_in` closes (the
/// normal shutdown order once whatever owns the sender, e.g. a finished
/// `run_demo_session` or Task 3's session registry tearing down, drops it) —
/// tearing the whole connection down rather than waiting for both to finish.
/// See [`serve_connection`]'s doc comment for why "wait for both" was a real
/// deadlock. Nothing here panics on a hostile or vanished peer.
///
/// This function does **not** perform the peer-credential check
/// [`accept_loop`] does (see that function's doc comment) — it is unchanged
/// from Task 2, kept single-connection, and its one caller (`main.rs`'s demo)
/// already only ever expects the one client the operator starts by hand.
///
/// # Errors
/// Returns the `bind_socket` error if the path is already in use, unwritable,
/// or too long for `sockaddr_un`, or if the socket's mode can't be tightened.
pub async fn serve(
    socket_path: impl AsRef<Path>,
    requests_out: mpsc::Sender<ClientRequest>,
    events_in: mpsc::Receiver<ClientEvent>,
) -> std::io::Result<()> {
    let listener = bind_socket(socket_path)?;

    let Ok((stream, _)) = listener.accept().await else {
        return Ok(());
    };

    serve_connection(stream, requests_out, events_in).await;
    Ok(())
}

/// Runs the bidirectional NDJSON wire loop for one already-accepted
/// connection: reads `ClientRequest` lines off `stream` and forwards each to
/// `requests_out`, and drains `events_in`, writing each `ClientEvent` back to
/// `stream` as one NDJSON line.
///
/// Standalone rather than inlined into [`serve`] so Task 3's real `accept()`
/// loop — one spawned task per connection, keyed into a `SessionId`-keyed
/// registry — can call this directly per connection instead of
/// reimplementing the read/write body. `pub`, not `pub(crate)`: an
/// integration test (its own crate) needs the same visibility a same-crate
/// caller would.
///
/// **Exit-on-first-done, not wait-for-both.** An earlier version of this
/// function tracked independent `read_done`/`write_done` flags and looped
/// until *both* were set — which deadlocked in the single most common
/// shutdown order there is: `events_in`'s sender drops (a session finishing,
/// e.g. `run_demo_session` returning) while the peer is still connected and
/// has nothing more to send. `write_done` went true, `read_done` stayed
/// false forever, the loop never exited, the write half was never closed,
/// and the peer's own blocked `recv()` — waiting on exactly that closure for
/// its clean EOF — hung right alongside it. This version instead returns the
/// instant *either* direction ends, for any reason: peer EOF/error, a
/// forwarding target gone, the event stream closing, or a write failing.
/// Returning drops both split halves together (neither is held anywhere
/// else), which fully closes the underlying socket and gives the peer a
/// clean EOF — the same thing Phase 1's `serve_ndjson` got for free by
/// holding the *unsplit* `stream` in one task and letting `Drop` close it.
/// This also closes the mirror case a "keep serving the direction that still
/// works" fix would reopen: if the peer disconnects first, this function
/// must not sit parked on `events_in.recv()` forever — every sender Task 3's
/// registry hands out lives as long as the registry entry, not as long as
/// any one connection, so "wait for the session to end before this task
/// exits" would leak one blocked task per dropped connection.
///
/// Uses `tokio::select!` so waiting for the *next* line or event on one side
/// never blocks the other. That independence is not absolute, though:
/// `requests_out.send(..).await` and `writer.write_all(..).await` run inside
/// their branch's handler body once a line/event has already arrived, so a
/// full `requests_out` (bounded, and nobody drains it in `main.rs` today —
/// see its own comment) would stall the read side mid-forward. Harmless
/// while at most one handshake request ever flows through it; Task 3's real
/// multi-request registry is what needs to actually drain it. Every write
/// error ends the connection rather than panicking; a `ClientRequest` line
/// that fails to parse, or a `ClientEvent` that fails to serialize, is
/// dropped with a warning and the connection keeps running — those are the
/// two conditions that do **not** end it.
pub async fn serve_connection(
    stream: UnixStream,
    requests_out: mpsc::Sender<ClientRequest>,
    mut events_in: mpsc::Receiver<ClientEvent>,
) {
    let (read_half, write_half) = stream.into_split();
    // `Lines::next_line` (not a bare `BufReader` + `String` +
    // `AsyncBufReadExt::read_line`) specifically because it is documented
    // cancellation-safe: it keeps its partially-read line inside `Lines`
    // across calls, whereas `read_line` takes the caller's `String` by
    // `&mut` and only appends to it on completion. Racing `read_line` inside
    // `tokio::select!` against `events_in.recv()` would drop a half-read
    // `ClientRequest` line on the floor the instant `events_in` won a race
    // mid-line — silently, as a "malformed" line once the tail of it showed
    // up next. `roundhouse-cli/src/main.rs` already documents this exact
    // hazard for `DaemonClient::recv`; this loop is the daemon-side mirror
    // of it, and Task 3 builds its real accept loop directly on this
    // function, so it must not carry the bug forward.
    let mut lines = BufReader::new(read_half).lines();
    let mut writer = write_half;

    loop {
        tokio::select! {
            result = lines.next_line() => {
                match result {
                    Ok(Some(line)) => {
                        match serde_json::from_str::<ClientRequest>(&line) {
                            Ok(request) => {
                                if requests_out.send(request).await.is_err() {
                                    // Nobody is listening for requests anymore
                                    // — nothing left to forward them to, and
                                    // nothing more this connection can do.
                                    return;
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "dropping malformed ClientRequest line"
                                );
                            }
                        }
                    }
                    Ok(None) | Err(_) => {
                        // Clean EOF, or a read error: either way the peer is
                        // gone. Return now rather than sit parked on
                        // `events_in.recv()` for a peer that will never read
                        // anything else.
                        return;
                    }
                }
            }
            maybe_event = events_in.recv() => {
                match maybe_event {
                    Some(event) => {
                        // `ClientEvent` is a plain serde enum, so this cannot
                        // fail in practice — but a serialization bug must
                        // drop one event, not take down the connection.
                        let serialized = match serde_json::to_string(&event) {
                            Ok(line) => line,
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "dropping unserializable ClientEvent"
                                );
                                continue;
                            }
                        };
                        if writer.write_all(serialized.as_bytes()).await.is_err()
                            || writer.write_all(b"\n").await.is_err()
                        {
                            return;
                        }
                    }
                    None => {
                        // The event stream ended — the normal shutdown order
                        // once whatever owned the sender is done with this
                        // connection. Return so the peer gets a clean EOF
                        // instead of a hang.
                        return;
                    }
                }
            }
        }
    }
}

/// Accepts connections from an already-bound `listener` forever, spawning
/// one task per connection against `registry`, until `accept` itself returns
/// an error.
///
/// # Restores Phase 1's synchronous-bind guarantee (ruling W1-R12)
///
/// [`serve`] weakened Phase 1's `serve_ndjson` guarantee that the socket was
/// bound *before the caller regained control* — `serve` is an `async fn`, so
/// its `bind_socket` call only runs once something actually polls it, and
/// `tokio::spawn(serve(..))` returning does not guarantee that has happened
/// yet. This function restores the guarantee by construction instead of by
/// scheduling luck: it takes an already-bound `listener`, so the caller does
/// the (synchronous, non-async) `bind_socket(path)?` call itself, in its own
/// stack frame, before ever spawning this function or anything else. Once
/// that call returns, the socket exists and a client may dial it immediately
/// — no sleep needed, and this crate's `multi_client_attach` test dials
/// immediately after `tokio::spawn(accept_loop(..))` to prove it.
///
/// # Peer-credential verification (the `SO_PEERCRED` TODO, resolved)
///
/// [`serve`]'s single-connection shape carried forward a `TODO(Phase 2)` for
/// `SO_PEERCRED` peer-credential verification
/// (docs/architecture/03-security-and-sandboxing.md §6.4) without ever
/// implementing it, standing on the 0600 socket mode and 0700 parent
/// directory as the only real barrier. That was an acceptable gap for a
/// function that serves *one* connection to whichever single client the
/// operator starts by hand in the same terminal session; it stops being
/// acceptable the moment this function starts accepting an unbounded number
/// of connections from any local process in a loop; the filesystem
/// permissions alone would not tell two connecting local processes apart.
///
/// This function closes the gap using `tokio::net::UnixStream::peer_cred`
/// (a safe wrapper tokio already ships around exactly the `SO_PEERCRED`
/// getsockopt call the frozen contract names — no new dependency, and no
/// `unsafe`) rather than leaving the TODO for a later task: every accepted
/// connection's peer uid is compared against the uid that owns the bound
/// socket path (i.e. this daemon process's own uid, read back off the
/// filesystem rather than via a `/proc`-only trick, so this works on every
/// unix `peer_cred` supports, not just Linux); a mismatch is logged and the
/// connection is dropped before it is ever handed to [`handle_connection`].
/// If the listener was not bound to a filesystem path (`local_addr` has no
/// `as_pathname`) or that path's metadata can't be read, this check is
/// skipped entirely rather than rejecting every connection — a degraded,
/// filesystem-permissions-only posture identical to what `serve` already
/// shipped, not a new failure mode.
///
/// # Errors
/// Returns the first `accept` error, if any — no local process ever caused
/// `serve_connection`'s own errors to escape *this* function, since every
/// per-connection failure is contained inside its own spawned task.
pub async fn accept_loop(
    listener: UnixListener,
    registry: Arc<SessionRegistry>,
) -> std::io::Result<()> {
    let expected_uid = listener
        .local_addr()
        .ok()
        .and_then(|addr| addr.as_pathname().map(Path::to_path_buf))
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|meta| meta.uid());

    if expected_uid.is_none() {
        // Not silent: a caller relying on this check (every real caller —
        // this branch only triggers for a listener bound to something other
        // than a filesystem path, or whose path's metadata is unreadable,
        // neither of which `bind_socket`'s own callers produce) needs to
        // know peer-credential verification is not actually happening for
        // this listener, not discover it later as an unexplained gap.
        tracing::warn!(
            "accept_loop: could not determine the bound socket's owner uid; \
             skipping SO_PEERCRED verification for every connection this \
             listener accepts (falling back to filesystem-permission-only \
             authorization)"
        );
    }

    loop {
        let (stream, _peer_addr) = listener.accept().await?;

        if let Some(expected_uid) = expected_uid {
            match stream.peer_cred() {
                Ok(cred) if cred.uid() == expected_uid => {}
                Ok(cred) => {
                    tracing::warn!(
                        peer_uid = cred.uid(),
                        expected_uid,
                        "rejecting connection: peer uid does not own this socket"
                    );
                    continue;
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "rejecting connection: SO_PEERCRED lookup failed"
                    );
                    continue;
                }
            }
        }

        let registry = registry.clone();
        tokio::spawn(async move {
            handle_connection(stream, registry).await;
        });
    }
}

/// Runs one accepted connection end to end: wires up a fresh pair of
/// request/event channels, hands the socket itself to [`serve_connection`]
/// (unmodified — see that function's doc comment), and hands the channel
/// ends to [`drive_session`], which speaks the `CreateSession`/`Attach`
/// handshake and routes the connection into [`SessionRegistry`].
///
/// Runs both futures concurrently *within this one spawned task* (via
/// `tokio::join!`, not a second `tokio::spawn`) — [`accept_loop`] spawns
/// exactly one task per accepted connection, and this is that task.
/// `serve_connection` and `drive_session` each independently exit on their
/// own first-done condition and, in doing so, close the channel that makes
/// the other one exit too (see both functions' doc comments), so `join!`
/// waiting for both never waits for a connection that has nothing left to
/// do.
async fn handle_connection(stream: UnixStream, registry: Arc<SessionRegistry>) {
    let (requests_tx, requests_rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
    let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    tokio::join!(
        serve_connection(stream, requests_tx, events_rx),
        drive_session(requests_rx, events_tx, registry),
    );
}

/// Reads this connection's first `ClientRequest` to decide whether it is
/// creating a new session or attaching to an existing one (§7's handshake),
/// registers it with `registry` accordingly, then forwards every event the
/// session produces down `events_tx` — which [`serve_connection`] is, at the
/// same time, draining and writing to the socket — until either side ends.
///
/// # This is what actually drains `requests_rx` (carry-forward CF-4)
///
/// Task 2's review flagged that nothing in `main.rs` ever drained
/// `serve_connection`'s `requests_out`, so a full channel there was a latent
/// stall waiting to happen the moment more than a handshake's worth of
/// requests ever flowed through one connection. This function's `select!`
/// loop is that drain: it always has an outstanding `requests_rx.recv()` in
/// flight, so `serve_connection`'s `requests_out.send(..).await` can never
/// find that channel permanently full. Everything received past the
/// handshake is currently discarded (a placeholder — Task 5/7's real
/// `SessionActor` is the eventual consumer, see `SessionRegistry`'s module
/// doc comment), but "discarded immediately" and "never read at all" are
/// very different failure modes for the sender blocked on the other end of
/// that channel.
///
/// # Handshake framing (ruling W1-R6)
///
/// `roundhouse-proto` has no `ClientEvent::SessionCreated` variant to answer
/// a `CreateSession` request with (adding one would be an edit to a frozen
/// Phase 0 crate outside this lane). Instead, on `CreateSession`, this
/// function's first outgoing frame is a
/// `ClientEvent::TaskEvent { session_id, task_id: None, payload:
/// EventPayload::SessionCreated { spec } }` — a variant that already exists
/// for exactly this purpose — and `roundhouse_tui::connect_create` reads the
/// minted `session_id` off of it.
async fn drive_session(
    mut requests_rx: mpsc::Receiver<ClientRequest>,
    events_tx: mpsc::Sender<ClientEvent>,
    registry: Arc<SessionRegistry>,
) {
    let Some(first_request) = requests_rx.recv().await else {
        // The peer vanished before ever sending a handshake request —
        // nothing to register and no one to answer.
        return;
    };

    let (session_id, subscription, mut session_events) = match first_request {
        ClientRequest::CreateSession { workspace_name } => {
            let (session_id, subscription, session_events) =
                registry.create(workspace_name.clone());
            let created = ClientEvent::TaskEvent {
                session_id,
                task_id: None,
                payload: Box::new(EventPayload::SessionCreated {
                    spec: Box::new(placeholder_session_spec(workspace_name)),
                }),
            };
            if events_tx.send(created).await.is_err() {
                // `serve_connection` already gave up on this connection
                // (e.g. the peer disconnected mid-handshake) — tear the
                // just-created registration back down rather than leak it.
                registry.detach(session_id, &subscription);
                return;
            }
            (session_id, subscription, session_events)
        }
        ClientRequest::Attach { session_id } => match registry.attach(session_id) {
            Some((subscription, session_events)) => {
                // `roundhouse_tui::connect_attach` waits for this `Ack`
                // before returning to its caller, specifically so a test (or
                // any other caller) that publishes an event immediately
                // after `connect_attach` resolves cannot race
                // `SessionRegistry::attach`'s own registration — without
                // this, `publish` could run before this branch's
                // `registry.attach` call above, and the event would be
                // fanned out to nobody.
                if events_tx
                    .send(ClientEvent::Ack {
                        api_version: ApiVersion::CURRENT,
                    })
                    .await
                    .is_err()
                {
                    registry.detach(session_id, &subscription);
                    return;
                }
                (session_id, subscription, session_events)
            }
            // Unknown (or no-longer-live) session, and `ClientRequest` has no
            // error-response variant to report that over the wire with — the
            // most honest thing this connection can do is end.
            None => return,
        },
        // `ClientRequest` is `#[non_exhaustive]`; any future variant is not a
        // valid *first* line for this handshake.
        _ => return,
    };

    loop {
        tokio::select! {
            maybe_event = session_events.recv() => {
                match maybe_event {
                    Some(event) => {
                        if events_tx.send(event).await.is_err() {
                            break;
                        }
                    }
                    // Every `Sender` for this subscription was dropped —
                    // only possible via `registry` itself being dropped
                    // entirely, since this loop is the only thing that ever
                    // detaches this subscription's own `Sender`.
                    None => break,
                }
            }
            maybe_request = requests_rx.recv() => {
                match maybe_request {
                    // Placeholder: Task 5/7's real `SessionActor` is what
                    // turns a post-handshake `ClientRequest` (a new task, a
                    // cancellation, ...) into anything. Draining it here,
                    // unconditionally, is what keeps `requests_out` from
                    // ever backing up and wedging `serve_connection`'s read
                    // side — see this function's doc comment.
                    Some(_request) => {}
                    None => break,
                }
            }
        }
    }

    registry.detach(session_id, &subscription);
}

/// A placeholder `SessionSpec` good enough to satisfy the `SessionCreated`
/// handshake frame (ruling W1-R6) before a real `SessionActor` exists to
/// supply one.
///
/// Task 5/7's real per-session wiring constructs the actual spec (from a
/// real workspace lookup, tier negotiation, etc.); `SessionRegistry`
/// explicitly does not construct a `SessionActor` at all yet (see its module
/// doc comment), so this function's only job is giving `connect_create`
/// *something* valid to read the minted `session_id` off of.
fn placeholder_session_spec(workspace_name: String) -> SessionSpec {
    SessionSpec {
        workspace: WorkspaceId::new(),
        name: Some(workspace_name),
        requested_tier: Tier::Sandbox,
        on_degrade: OnDegrade::Refuse,
    }
}
