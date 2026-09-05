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

use futures::StreamExt;
use roundhouse_core::{EventPayload, OnDegrade, SessionSpec, Tier, WorkspaceId};
use roundhouse_proto::{ApiVersion, ClientEvent, ClientRequest};
use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_util::codec::{FramedRead, LinesCodec, LinesCodecError};

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

/// Maximum length, in bytes, of a single NDJSON line this daemon will accept
/// on either direction of the wire before closing that one connection
/// (security review Important 1 / ruling W1-R33): `BufReader::lines()`
/// (the pre-fix read side) accumulated an **uncapped** `String`, and the
/// reviewer measured 512 MiB of no-newline input driving RSS from
/// 3,764 KiB to 529,228 KiB against the process holding every live session's
/// registry state — 1:1 attacker-controlled amplification with no ceiling.
///
/// 1 MiB, matching the precedent this workspace already set for exactly this
/// kind of cap (`roundhouse_acp::registry::MAX_RESPONSE_BYTES`). Generous
/// enough that no current frame comes close — `ClientRequest::CreateSession`
/// only carries a `workspace_name`, and `placeholder_session_spec` echoes it
/// straight back in the handshake reply, so the cap must not be so tight it
/// breaks a legitimate (if unusually long) workspace name — while still
/// bounding the worst case to a fixed, small multiple of one connection's own
/// buffering, not to whatever an attacker is willing to send.
///
/// **The aggregate, not just the per-connection cap, is what's bounded**
/// (fix round 2, M3): at [`DEFAULT_MAX_CONNECTIONS`] connections each
/// retaining one frame near this cap, the worst case is on the order of
/// `DEFAULT_MAX_CONNECTIONS × MAX_FRAME_BYTES` ≈ 256 MiB (measured ~1.05 MiB
/// retained per connection once `FramedRead`'s own buffering overhead is
/// included, so closer to ~267 MiB in practice) — a known, fixed ceiling
/// rather than something that scales with how many peers happen to connect.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Default ceiling on concurrent accepted connections one `accept_loop` will
/// serve at once (security review Important 3 / ruling W1-R33). Bounds the
/// worst-case fd and per-connection memory (two 64-slot channels, one task)
/// a hostile or merely enthusiastic set of peers can force this daemon to
/// hold, while sitting comfortably below the default `ulimit -n` on any
/// system that would actually run this daemon (leaving headroom for the
/// listener itself, the store, and log files) — this is a circuit breaker,
/// not an expected operational ceiling.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Default timeout on a freshly accepted connection's *first* request
/// (security review Important 3 / ruling W1-R33): without one, a peer that
/// connects and sends nothing parks a task forever holding an fd — classic
/// slowloris, and the direct feeder for accept()'s own `EMFILE` (fix 3).
/// 30 seconds is generous for a human-driven client dialing in over a local
/// Unix socket (no network latency to account for) while still bounding how
/// long one silent peer can hold a connection slot open.
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Smallest backoff `accept_loop` sleeps after a transient `accept()` error
/// (security review Important 2 / ruling W1-R33) before retrying.
const MIN_ACCEPT_BACKOFF: Duration = Duration::from_millis(10);
/// Largest backoff `accept_loop` will back off to; doubles from
/// [`MIN_ACCEPT_BACKOFF`] on each consecutive transient error, capped here so
/// a sustained fd-exhaustion episode still retries roughly once a second
/// rather than drifting arbitrarily slow.
const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

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
/// never blocks the other — and, since a fix round (ruling W1-R31/W1-R32),
/// that independence is now actually load-bearing rather than aspirational.
///
/// # No branch body ever blocks on `requests_out` (rulings W1-R31/W1-R32/W1-R38)
///
/// An earlier version of this function sent a freshly parsed `ClientRequest`
/// via `requests_out.send(..).await` **inside** the read arm's branch body.
/// Once `tokio::select!` commits to a branch, that branch's body is no
/// longer racing the other arm — a task parked in that `.await` has stopped
/// polling `events_in.recv()` entirely. Paired with `drive_session`
/// (`socket_server.rs`'s other half of this same connection, joined in
/// [`handle_connection`]) blocking symmetrically on `events_tx.send(..)`
/// inside *its* own branch body, the two form a circular wait: this
/// function stops draining `events_in` (which `drive_session` needs to send
/// into), and `drive_session` stops draining `requests_rx` (which this
/// function needs to send into) — both parked forever, inside one
/// `tokio::join!`, with 64 slots on each side. The connection wedges
/// permanently and never observes peer EOF; see `drive_session`'s doc
/// comment for the registry-level consequence (a subscription that is never
/// `detach`ed because `publish` sees `Full`, not `Closed`).
///
/// The fix holds a parsed request in a `pending_request: Option<..>` slot
/// instead of sending it immediately, and only *reserves* capacity —
/// `mpsc::Sender::reserve()`, cancel-safe and awaited as its own `select!`
/// **arm**, gated by `if pending_request.is_some()` — rather than blocking
/// on `send()` in a body. Reserving is fair: it competes with `events_in`'s
/// own arm on equal footing, so `events_in` keeps draining for the entire
/// time this function is waiting for `requests_out` capacity. Once a permit
/// resolves, handing the pending value to it (`Permit::send`) is
/// synchronous and cannot block. The naive alternative — reserve, then
/// `.await` the *next* line inside that same arm's body — merely moves the
/// bug: it stops draining `events_in`'s counterpart in the idle case
/// instead (see `drive_session`'s doc comment for why that trap matters,
/// and this crate's `serve_connection_drains_pending_events_while_idle`
/// test for the regression it would otherwise reintroduce silently).
///
/// **This is a property of the loop's shape, not a one-time patch**
/// (ruling W1-R38): today, `drive_session` discards every post-handshake
/// request as a no-op, so nothing in *this* function's own body ever blocks
/// indefinitely either. The invariant that must survive whoever replaces
/// that no-op: no `select!` branch body in this connection's loop may await
/// anything that can block indefinitely — hand the work to a spawned task,
/// or reserve capacity as a `select!` arm the way this function now does.
///
/// Every write error ends the connection rather than panicking; a
/// `ClientRequest` line that fails to parse, or a `ClientEvent` that fails
/// to serialize, is dropped with a warning and the connection keeps running
/// — those are the two conditions that do **not** end it. An over-length
/// line (see [`MAX_FRAME_BYTES`]) does end the connection — closing this one
/// peer's connection, not the accept loop — since there is no way to resync
/// to the next line boundary inside a frame that was itself rejected for
/// having none.
pub async fn serve_connection(
    stream: UnixStream,
    requests_out: mpsc::Sender<ClientRequest>,
    mut events_in: mpsc::Receiver<ClientEvent>,
) {
    let (read_half, write_half) = stream.into_split();
    // `FramedRead` + `LinesCodec` (not a bare `BufReader` + `String` +
    // `AsyncBufReadExt::read_line`, and not the unbounded `Lines` this
    // function used before fix 2) for two reasons at once: `LinesCodec`
    // enforces [`MAX_FRAME_BYTES`] (security review Important 1 / ruling
    // W1-R33) instead of accumulating an uncapped `String`, and — just like
    // `Lines::next_line` before it — `FramedRead` keeps its
    // partially-decoded buffer inside itself across polls, so racing it
    // inside `tokio::select!` against `events_in.recv()` cannot drop a
    // half-read `ClientRequest` line on the floor the instant `events_in`
    // wins a race mid-line. `roundhouse-cli/src/main.rs` already documents
    // this exact hazard for `DaemonClient::recv`; this loop is the
    // daemon-side mirror of it, and Task 3 builds its real accept loop
    // directly on this function, so it must not carry the bug forward.
    let mut lines = FramedRead::new(read_half, LinesCodec::new_with_max_length(MAX_FRAME_BYTES));
    let mut writer = write_half;
    // Holds one parsed request between "read it" and "forward it" so this
    // function never blocks on `requests_out.send(..)` inside a branch body
    // — see this function's doc comment.
    let mut pending_request: Option<ClientRequest> = None;

    loop {
        tokio::select! {
            result = lines.next(), if pending_request.is_none() => {
                match result {
                    Some(Ok(line)) => {
                        match serde_json::from_str::<ClientRequest>(&line) {
                            Ok(request) => {
                                pending_request = Some(request);
                            }
                            Err(err) => {
                                tracing::warn!(
                                    error = %err,
                                    "dropping malformed ClientRequest line"
                                );
                            }
                        }
                    }
                    Some(Err(LinesCodecError::MaxLineLengthExceeded)) => {
                        tracing::warn!(
                            max_frame_bytes = MAX_FRAME_BYTES,
                            "closing connection: ClientRequest line exceeded the maximum frame length"
                        );
                        return;
                    }
                    Some(Err(LinesCodecError::Io(_))) | None => {
                        // Clean EOF, or a read error: either way the peer is
                        // gone. Return now rather than sit parked on
                        // `events_in.recv()` for a peer that will never read
                        // anything else.
                        return;
                    }
                }
            }
            permit = requests_out.reserve(), if pending_request.is_some() => {
                match permit {
                    Ok(permit) => {
                        let request = pending_request.take().expect(
                            "select! arm guarded by pending_request.is_some()"
                        );
                        permit.send(request);
                    }
                    Err(_) => {
                        // Nobody is listening for requests anymore — nothing
                        // left to forward them to, and nothing more this
                        // connection can do.
                        return;
                    }
                }
            }
            maybe_event = events_in.recv() => {
                match maybe_event {
                    Some(event) => {
                        if write_event(&mut writer, &event).await.is_err() {
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

/// Serializes `event` as one NDJSON line and writes it to `writer`.
///
/// A serialization failure drops just this one event with a warning rather
/// than ending the connection (`ClientEvent` is a plain serde enum, so this
/// cannot fail in practice, but a bug here must not be allowed to take the
/// connection down); a write failure is the caller's signal to end the
/// connection, since the socket itself is no longer usable.
async fn write_event(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    event: &ClientEvent,
) -> std::io::Result<()> {
    let serialized = match serde_json::to_string(event) {
        Ok(line) => line,
        Err(err) => {
            tracing::warn!(error = %err, "dropping unserializable ClientEvent");
            return Ok(());
        }
    };
    writer.write_all(serialized.as_bytes()).await?;
    writer.write_all(b"\n").await
}

/// Classifies an `accept()` error as transient (worth retrying after a
/// backoff) or fatal (worth propagating) — security review Important 2 /
/// ruling W1-R33, and `code Minor 2` independently.
///
/// Standalone and free of any actual I/O so it can be unit-tested directly
/// against synthetic `io::Error`s rather than only via an end-to-end
/// reproduction. The reviewer proved the pre-fix failure mode under
/// `ulimit -n 200`: 94 connections accepted, then `EMFILE`, propagated
/// straight out of the old `accept_loop` via `?` — the loop **terminated**,
/// and once every client fd was released a fresh connect returned
/// `ECONNREFUSED` **permanently**. The process was still alive with its
/// socket file still on disk: to an operator that is indistinguishable from
/// a crash, `boot`/recovery never runs again, and no session is ever cleaned
/// up.
///
/// `EMFILE`/`ENFILE` (this process, or the whole system, is out of file
/// descriptors), `ENOMEM`/`ENOBUFS` (transient kernel memory/buffer
/// exhaustion — `accept(2)` documents both alongside `EMFILE`/`ENFILE` as
/// conditions a caller should retry, not treat as fatal; fix round 1's list
/// omitted them), and `ConnectionAborted`/`Interrupted`/`WouldBlock` (a
/// connection that died between the kernel accepting it and this call
/// returning, a signal interrupting the syscall, or a spurious non-blocking
/// wakeup — tokio already absorbs `WouldBlock` internally before this
/// function ever sees it, but classifying it as `Retry` here rather than
/// falling through to `Fatal` costs nothing and removes any doubt) are all
/// conditions that resolve themselves as load eases or the interrupted call
/// is retried. Everything else is treated as fatal: busy-looping `accept()`
/// against a listener that is genuinely broken (e.g. its underlying fd was
/// closed out from under it) would be its own, worse availability problem
/// than returning.
fn classify_accept_error(err: &std::io::Error) -> AcceptDisposition {
    match err.kind() {
        ErrorKind::ConnectionAborted | ErrorKind::Interrupted | ErrorKind::WouldBlock => {
            AcceptDisposition::Retry
        }
        _ => match err.raw_os_error() {
            // EMFILE (24) / ENFILE (23) / ENOMEM (12) / ENOBUFS (105) —
            // stable across Linux and every other unix this daemon targets,
            // but none of the four has a stable `ErrorKind` variant, hence
            // matching the raw errno.
            Some(24) | Some(23) | Some(12) | Some(105) => AcceptDisposition::Retry,
            _ => AcceptDisposition::Fatal,
        },
    }
}

/// [`classify_accept_error`]'s verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptDisposition {
    /// Transient: log, back off, and try `accept()` again without tearing
    /// the listener down.
    Retry,
    /// Not recoverable: propagate the error and let the caller decide.
    Fatal,
}

/// Availability limits [`accept_loop`] enforces (security review
/// Important 3 / ruling W1-R33): a cap on concurrently accepted connections
/// and a timeout on a freshly accepted connection's first request.
///
/// `Default` gives the production values ([`DEFAULT_MAX_CONNECTIONS`],
/// [`DEFAULT_HANDSHAKE_TIMEOUT`]); tests that need to actually observe a
/// limit being hit construct one directly with much smaller numbers rather
/// than needing thousands of connections to exercise
/// [`DEFAULT_MAX_CONNECTIONS`].
///
/// # This is a test seam, not production API (fix round 2, M4)
///
/// `pub`, and its fields `pub`, only because this crate's integration tests
/// (a separate crate) need to construct one with small numbers — see
/// [`accept_loop_with`]'s own doc comment. `#[doc(hidden)]` keeps it out of
/// rendered docs and off the surface a downstream consumer of this crate
/// would discover by browsing: nothing about this type is hardened against
/// misuse (`AcceptLimits { max_connections: usize::MAX, .. }` panics inside
/// `Semaphore::new` before `accept_loop_with` ever reaches its loop), and it
/// is not meant to be tuned by anything other than a test.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct AcceptLimits {
    pub max_connections: usize,
    pub handshake_timeout: Duration,
}

impl Default for AcceptLimits {
    fn default() -> Self {
        AcceptLimits {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

/// Reads this process's own uid via `/proc/self` — the same dependency-free
/// idiom `main.rs`'s `check_owned_by_current_user` already uses for the
/// runtime directory ownership check (see its doc comment for why
/// `/proc/self`, and why `metadata` rather than `symlink_metadata`, is the
/// right call). Linux-only for the same reason that function is: there is no
/// `/proc` to read on other unix platforms without taking on `libc`/`rustix`
/// for one syscall.
#[cfg(target_os = "linux")]
fn current_process_uid() -> std::io::Result<u32> {
    Ok(std::fs::metadata("/proc/self")?.uid())
}

/// Non-Linux fallback: there is no `/proc/self` to read. Returning an error
/// here (rather than, say, `Ok(0)` or skipping the check) is exactly the
/// point of ruling W1-R34 — see [`accept_loop_with`]'s doc comment.
#[cfg(not(target_os = "linux"))]
fn current_process_uid() -> std::io::Result<u32> {
    Err(std::io::Error::new(
        ErrorKind::Unsupported,
        "cannot determine this process's own uid without /proc (non-Linux platform)",
    ))
}

/// Accepts connections from an already-bound `listener` forever, spawning
/// one task per connection against `registry`, until a fatal `accept` error
/// occurs or this process's own uid cannot be determined.
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
/// This is a thin, non-configurable wrapper over [`accept_loop_with`] using
/// [`current_process_uid`] and [`AcceptLimits::default`] — see that
/// function's doc comment for the peer-credential fix, the connection cap,
/// and the handshake timeout.
///
/// # Errors
/// See [`accept_loop_with`].
pub async fn accept_loop(
    listener: UnixListener,
    registry: Arc<SessionRegistry>,
) -> std::io::Result<()> {
    accept_loop_with(
        listener,
        registry,
        current_process_uid(),
        AcceptLimits::default(),
    )
    .await
}

/// [`accept_loop`]'s real body, with the two things a test would otherwise
/// need root or a `/proc`-less platform to exercise made injectable:
/// `expected_uid` (so a test can force the "undeterminable" branch) and
/// `limits` (so a test can hit a cap with a handful of connections instead
/// of [`DEFAULT_MAX_CONNECTIONS`]). `pub`, not `pub(crate)`, for the same
/// reason [`serve_connection`] is: this crate's integration tests are their
/// own crate.
///
/// # Peer-credential verification, fixed at the root (security review
/// Important 4 / ruling W1-R34)
///
/// An earlier version of this check computed its expected uid from the
/// *bound socket path's owner* (a mutable filesystem attribute), read once,
/// inside this spawned future. Three branches followed: a uid mismatch and a
/// `peer_cred()` error both correctly `continue`d — real, fail-**closed**
/// denies, and this fix leaves both exactly as they were. But the third
/// branch — the path's metadata being unreadable — skipped the *entire*
/// `if let Some(expected_uid)` check, silently, for every connection that
/// listener would ever accept: fail-**open**, for the listener's whole
/// lifetime. The trigger was not even adversarial: `main.rs`'s
/// `remove_stale_socket` unlinks whatever sits at the configured path before
/// a fresh `bind`, so a *second* daemon starting at the same path silently
/// disarmed the *first* one's peer-credential check while its listener kept
/// serving — a mutable-filesystem-attribute dependency is simply the wrong
/// root of trust for "who am I."
///
/// The fix compares against **this process's own uid** (`expected_uid`,
/// `std::io::Result<u32>` — computed once by [`accept_loop`] via
/// [`current_process_uid`]'s `/proc/self` idiom) instead, and refuses to run
/// at all when it cannot be determined: an `Err` here returns **before this
/// function ever calls `accept()`**, rather than silently downgrading to
/// "skip the check." There is no more fail-open branch — every connection
/// this function accepts is peer-credential checked, or nothing is accepted.
///
/// # Availability limits (security review Important 3 / ruling W1-R33)
///
/// `grep -rn "Semaphore\|max_conn\|MAX_\|timeout\|limit"` over this crate
/// once returned nothing: connections were accepted without bound, and a
/// peer that connected and sent nothing parked a task on the handshake read
/// forever, holding an fd open — slowloris, and the direct feeder for the
/// `EMFILE` [`classify_accept_error`]'s doc comment describes. This function
/// now holds a `Semaphore` sized to `limits.max_connections` (acquired via
/// `try_acquire_owned`, never an awaited `acquire` — see the inline comment
/// at that call for why blocking here would just move the hang rather than
/// fix it) and threads `limits.handshake_timeout` into [`drive_session`] to
/// bound that first read. `SessionRegistry`'s own `max_sessions` and
/// `max_subscribers_per_session` caps close the remaining two gaps the
/// review named (unbounded sessions, and `publish`'s per-subscriber clone
/// being an unbounded amplifier).
///
/// # Errors
/// Returns immediately if `expected_uid` is `Err` — this process's own uid
/// could not be determined, and running an unauthenticated listener is worse
/// than not running one. Otherwise returns the first *fatal* `accept` error
/// (see [`classify_accept_error`]); transient errors are logged and retried
/// with an exponential backoff rather than ending the loop. No local
/// process ever caused `serve_connection`'s own errors to escape *this*
/// function, since every per-connection failure is contained inside its own
/// spawned task.
///
/// `#[doc(hidden)]` (fix round 2, M4): this exists purely as a test seam so
/// [`accept_loop`]'s two otherwise-hard-to-drive branches (an undeterminable
/// uid, a hit connection/handshake limit) can be exercised directly with
/// small numbers. It is not meant to be a tuned production entry point —
/// [`accept_loop`] is — and `#[doc(hidden)]` keeps it (and [`AcceptLimits`])
/// off the API surface a downstream consumer would discover browsing docs,
/// without needing a `test-support` Cargo feature just for this.
#[doc(hidden)]
pub async fn accept_loop_with(
    listener: UnixListener,
    registry: Arc<SessionRegistry>,
    expected_uid: std::io::Result<u32>,
    limits: AcceptLimits,
) -> std::io::Result<()> {
    let expected_uid = expected_uid.map_err(|err| {
        tracing::error!(
            error = %err,
            "accept_loop: could not determine this process's own uid; \
             refusing to accept any connection rather than run without \
             SO_PEERCRED verification"
        );
        err
    })?;

    let connection_slots = Arc::new(Semaphore::new(limits.max_connections));
    let mut backoff = MIN_ACCEPT_BACKOFF;

    loop {
        let (stream, _peer_addr) = match listener.accept().await {
            Ok(pair) => {
                // A successful accept means the listener is healthy again;
                // do not let a stale, larger backoff linger into the next
                // unrelated transient error.
                backoff = MIN_ACCEPT_BACKOFF;
                pair
            }
            Err(err) => match classify_accept_error(&err) {
                AcceptDisposition::Retry => {
                    tracing::warn!(
                        error = %err,
                        backoff_ms = backoff.as_millis() as u64,
                        "accept() failed transiently; backing off and retrying \
                         rather than ending the accept loop"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(MAX_ACCEPT_BACKOFF);
                    continue;
                }
                AcceptDisposition::Fatal => return Err(err),
            },
        };

        match stream.peer_cred() {
            Ok(cred) if cred.uid() == expected_uid => {}
            Ok(cred) => {
                tracing::warn!(
                    peer_uid = cred.uid(),
                    expected_uid,
                    "rejecting connection: peer uid does not match this process's own uid"
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

        // `try_acquire_owned`, never an awaited `acquire`: at capacity,
        // awaiting would park this very loop — leaving every further peer
        // queued in the kernel's listen backlog with nothing ever calling
        // `accept()` again — which is a hang, not the clean per-connection
        // refusal this cap exists to provide. The permit moves into the
        // spawned task and is dropped (freeing the slot) whenever that
        // connection ends, for any reason.
        let Ok(permit) = connection_slots.clone().try_acquire_owned() else {
            tracing::warn!(
                max_connections = limits.max_connections,
                "rejecting connection: at the concurrent connection limit"
            );
            continue;
        };

        let registry = registry.clone();
        let handshake_timeout = limits.handshake_timeout;
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(stream, registry, handshake_timeout).await;
        });
    }
}

/// Runs one accepted connection end to end: wires up a fresh pair of
/// request/event channels, hands the socket itself to [`serve_connection`],
/// and hands the channel ends to [`drive_session`], which speaks the
/// `CreateSession`/`Attach` handshake and routes the connection into
/// [`SessionRegistry`].
///
/// Runs both futures concurrently *within this one spawned task* (via
/// `tokio::join!`, not a second `tokio::spawn`) — [`accept_loop`] spawns
/// exactly one task per accepted connection, and this is that task.
/// `serve_connection` and `drive_session` each independently exit on their
/// own first-done condition and, in doing so, close the channel that makes
/// the other one exit too (see both functions' doc comments), so `join!`
/// waiting for both never waits for a connection that has nothing left to
/// do.
async fn handle_connection(
    stream: UnixStream,
    registry: Arc<SessionRegistry>,
    handshake_timeout: Duration,
) {
    let (requests_tx, requests_rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
    let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    tokio::join!(
        serve_connection(stream, requests_tx, events_rx),
        drive_session(requests_rx, events_tx, registry, handshake_timeout),
    );
}

/// Reads this connection's first `ClientRequest` to decide whether it is
/// creating a new session or attaching to an existing one (§7's handshake),
/// registers it with `registry` accordingly, then forwards every event the
/// session produces down `events_tx` — which [`serve_connection`] is, at the
/// same time, draining and writing to the socket — until either side ends.
///
/// # No branch body ever blocks on `events_tx` (rulings W1-R31/W1-R32/W1-R38)
///
/// **This carry-forward corrects an earlier version of this very doc
/// comment.** That version claimed: "this function's `select!` loop ...
/// always has an outstanding `requests_rx.recv()` in flight, so
/// `serve_connection`'s `requests_out.send(..).await` can never find that
/// channel permanently full." That claim is false, and it is exactly the
/// mechanism a security-lens review round independently asserted (as CF-4
/// being closed) and this lane's adjudication (ruling W1-R31) rejected after
/// reading the source directly: the loop's first arm sent a received session
/// event via `events_tx.send(event).await` **inside that arm's branch
/// body**. Once `tokio::select!` commits to a branch, the body is no longer
/// racing the other arm — a task parked in that `.await` is *not* polling
/// `requests_rx.recv()` at all, "outstanding" or not, for as long as the
/// send is pending. Paired with `serve_connection` blocking symmetrically on
/// `requests_out.send(..)` inside its own read-arm body, the two form a
/// circular wait — both parked forever, inside one `tokio::join!`
/// ([`handle_connection`]), 64 slots deep on each side: this function stops
/// draining `requests_rx` (which `serve_connection` needs to send into), and
/// `serve_connection` stops draining `events_in` (which this function needs
/// to send into). The connection wedges permanently and never observes peer
/// EOF — and the sharp registry-level consequence is that this
/// subscription's `detach` (below) never runs, while `publish` sees the
/// subscriber channel as `Full`, not `Closed`, so it is never pruned either:
/// a zombie registry entry that `attach` keeps succeeding against.
///
/// The fix (mirroring [`serve_connection`]'s own, symmetric fix) holds a
/// received session event in a `pending_event: Option<..>` slot and only
/// *reserves* `events_tx` capacity — `reserve()`, cancel-safe, awaited as
/// its own `select!` **arm**, gated by `if pending_event.is_some()` — rather
/// than blocking on `send()` in a body. `requests_rx.recv()` stays a live,
/// unconditional arm the entire time, so `serve_connection`'s
/// `requests_out.send(..)` (a `reserve()`+permit pair, post-fix) can always
/// make progress. The naive alternative — reserve, then `.await`
/// `session_events.recv()` inside that same arm's body — merely relocates
/// the bug: it starves `requests_rx` draining the moment the session goes
/// idle with `events_tx` capacity available, since the permit is grabbed
/// speculatively before there is anything to send (see this crate's
/// `drive_session_keeps_draining_requests_while_the_session_is_idle` test).
///
/// **This is a property of the loop's shape, not a one-time patch**
/// (ruling W1-R38). Everything received past the handshake is *currently*
/// discarded (see the `Some(_request)` arm below) — a placeholder, since
/// Task 5/7's real `SessionActor` is the eventual consumer. That no-op is
/// exactly why nothing in this loop's body can block indefinitely *today*.
/// The invariant that must survive whoever replaces it: no `select!` branch
/// body in this loop may await anything that can block indefinitely — hand
/// the work to a spawned task, or reserve capacity as a `select!` arm the
/// way this function now does for `events_tx`.
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
///
/// # Handshake timeout (security review Important 3 / ruling W1-R33)
///
/// The very first `requests_rx.recv()` below is wrapped in
/// `tokio::time::timeout(handshake_timeout, ..)`: without it, a peer that
/// connects and never sends anything parks this task forever, holding an fd
/// open — slowloris, and the direct feeder for `accept()`'s own `EMFILE`
/// (see [`classify_accept_error`]'s doc comment). A timeout here fires
/// before any registration has happened, so there is nothing to `detach`;
/// returning simply ends this function, which (via [`handle_connection`]'s
/// `join!`) drops `events_tx`, which is exactly the signal
/// `serve_connection` already treats as "end this connection."
///
/// `pub`, not `pub(crate)`, for the same reason [`serve_connection`] is:
/// fix round 1's deadlock-invariant tests drive this function directly, with
/// test-owned channels of a deliberately small capacity, rather than through
/// the full three-channel `accept_loop`/`handle_connection` stack — a full
/// end-to-end wedge would interleave three channels and be racy (see this
/// crate's `deadlock_invariant` test file for why).
pub async fn drive_session(
    mut requests_rx: mpsc::Receiver<ClientRequest>,
    events_tx: mpsc::Sender<ClientEvent>,
    registry: Arc<SessionRegistry>,
    handshake_timeout: Duration,
) {
    let first_request = match tokio::time::timeout(handshake_timeout, requests_rx.recv()).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            // The peer vanished before ever sending a handshake request —
            // nothing to register and no one to answer.
            return;
        }
        Err(_) => {
            tracing::warn!(
                ?handshake_timeout,
                "closing connection: no handshake request received within the timeout"
            );
            return;
        }
    };

    let (session_id, subscription, mut session_events) = match first_request {
        ClientRequest::CreateSession { workspace_name } => {
            let Some((session_id, subscription, session_events)) =
                registry.create(workspace_name.clone())
            else {
                // At `max_sessions` (security review Important 3 / ruling
                // W1-R33) — `ClientRequest` has no error-response variant to
                // report that over the wire with (the same constraint ruling
                // W1-R6 already accepted for "unknown session"), so ending
                // the connection is the most honest thing left to do.
                return;
            };
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
        // # Attach is authenticated, not authorized (security review
        // Important 5 / ruling W1-R35 — escalated to the operator, not a
        // Task 3 defect) — the frozen design
        // (`docs/architecture/03-security-and-sandboxing.md:174`) intends
        // approvals to broadcast to every attached client, "first responder
        // wins". `registry.attach(session_id)` is a bare, unauthenticated
        // map lookup: any local peer that learns a `SessionId` (a UUIDv4, so
        // not enumerable, but not secret either — `main.rs` logs it, and the
        // unredacted event stream that follows is not access-controlled
        // beyond that) can attach to it. That is bounded *today* only
        // because this function discards every post-handshake request
        // below as a no-op — see the `Some(_request)` arm's own comment for
        // why replacing that discard with a real `SessionActor` must not be
        // done without an attach capability distinct from the routing key,
        // or an explicit operator decision to accept broadcast-approval.
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
            // Unknown/no-longer-live session, or already at
            // `max_subscribers_per_session` (security review Important 3 /
            // ruling W1-R33) — `ClientRequest` has no error-response variant
            // to report either over the wire with; the most honest thing
            // this connection can do is end, the same as `SessionRegistry::
            // attach`'s doc comment already documents for the first two
            // cases.
            None => return,
        },
        // `ClientRequest` is `#[non_exhaustive]`; any future variant is not a
        // valid *first* line for this handshake.
        _ => return,
    };

    let mut pending_event: Option<ClientEvent> = None;
    loop {
        tokio::select! {
            maybe_event = session_events.recv(), if pending_event.is_none() => {
                match maybe_event {
                    Some(event) => {
                        pending_event = Some(event);
                    }
                    // Every `Sender` for this subscription is either the one
                    // `registry` stores in this session's subscriber list
                    // (removed only by *this* function's own `detach` call
                    // below, which does not run until this loop returns) or
                    // the one wrapped in `subscription`, held by this very
                    // stack frame and not dropped until this function
                    // returns. Nothing else ever touches either clone while
                    // this loop runs, so `None` here is unreachable for the
                    // loop's whole lifetime — not, as an earlier version of
                    // this comment claimed, because `registry` would need to
                    // be dropped entirely (`drive_session` holds an
                    // `Arc<SessionRegistry>` for its whole lifetime, so that
                    // can never happen either — true, but not the operative
                    // reason).
                    None => break,
                }
            }
            permit = events_tx.reserve(), if pending_event.is_some() => {
                match permit {
                    Ok(permit) => {
                        let event = pending_event.take().expect(
                            "select! arm guarded by pending_event.is_some()"
                        );
                        permit.send(event);
                    }
                    // `serve_connection` already gave up on this connection.
                    Err(_) => break,
                }
            }
            maybe_request = requests_rx.recv() => {
                match maybe_request {
                    // Placeholder: Task 5/7's real `SessionActor` is what
                    // turns a post-handshake `ClientRequest` (a new task, a
                    // cancellation, ...) into anything. Draining it here,
                    // unconditionally, is what keeps `requests_out` from
                    // ever backing up and wedging `serve_connection`'s read
                    // side (see this function's doc comment) — and, per the
                    // `Attach` comment above, it is also what keeps `Attach`
                    // read-only today. Ruling W1-R37 pre-rules the safe
                    // default the next implementer inherits: an attached
                    // connection's post-handshake requests must stay
                    // refused (it still *receives* the broadcast the frozen
                    // design mandates) — only the connection that ran
                    // `CreateSession` gets its requests honored, until W5
                    // makes "first responder wins among attached responders"
                    // a deliberate decision rather than something this lane
                    // concedes by defaulting this open.
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

#[cfg(test)]
mod classify_accept_error_tests {
    //! Unit-level proof for fix 3 (security review Important 2 / ruling
    //! W1-R33): the reviewer's end-to-end reproduction ran `ulimit -n 200`
    //! by hand against a real listener, which is not something this suite
    //! automates. `classify_accept_error` is pulled out specifically so the
    //! *decision* — which errors are worth retrying — can be proven
    //! directly against synthetic `io::Error`s instead.

    use super::*;

    #[test]
    fn emfile_and_enfile_are_retried_not_fatal() {
        // 24 = EMFILE, 23 = ENFILE on Linux and every other unix this
        // daemon targets.
        assert_eq!(
            classify_accept_error(&std::io::Error::from_raw_os_error(24)),
            AcceptDisposition::Retry,
            "EMFILE must be retried — this is the exact error that took the \
             pre-fix accept loop down permanently under `ulimit -n 200`"
        );
        assert_eq!(
            classify_accept_error(&std::io::Error::from_raw_os_error(23)),
            AcceptDisposition::Retry
        );
    }

    #[test]
    fn connection_aborted_and_interrupted_are_retried() {
        assert_eq!(
            classify_accept_error(&std::io::Error::from(ErrorKind::ConnectionAborted)),
            AcceptDisposition::Retry
        );
        assert_eq!(
            classify_accept_error(&std::io::Error::from(ErrorKind::Interrupted)),
            AcceptDisposition::Retry
        );
    }

    #[test]
    fn other_errors_are_fatal() {
        // EBADF (9): a genuinely broken listener. Busy-looping `accept()`
        // against it forever would be its own, worse availability problem.
        assert_eq!(
            classify_accept_error(&std::io::Error::from_raw_os_error(9)),
            AcceptDisposition::Fatal
        );
        assert_eq!(
            classify_accept_error(&std::io::Error::from(ErrorKind::PermissionDenied)),
            AcceptDisposition::Fatal
        );
    }

    /// Fix round 2, M1: `accept(2)` documents `ENOMEM`/`ENOBUFS` as
    /// transient kernel resource exhaustion alongside `EMFILE`/`ENFILE` —
    /// fix round 1's list omitted them, and `Fatal` here means the same
    /// permanent-`ECONNREFUSED` zombie `EMFILE` used to cause.
    #[test]
    fn enomem_and_enobufs_are_retried_not_fatal() {
        assert_eq!(
            classify_accept_error(&std::io::Error::from_raw_os_error(12)),
            AcceptDisposition::Retry,
            "ENOMEM (12) must be retried, not treated as fatal"
        );
        assert_eq!(
            classify_accept_error(&std::io::Error::from_raw_os_error(105)),
            AcceptDisposition::Retry,
            "ENOBUFS (105) must be retried, not treated as fatal"
        );
    }

    #[test]
    fn would_block_is_retried() {
        assert_eq!(
            classify_accept_error(&std::io::Error::from(ErrorKind::WouldBlock)),
            AcceptDisposition::Retry
        );
    }
}
