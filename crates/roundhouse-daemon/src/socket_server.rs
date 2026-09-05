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
use roundhouse_core::EventPayload;
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

use crate::session_bootstrap::{self, DaemonResources};
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

/// Maximum length, in bytes, of `ClientRequest::CreateSession`'s
/// `workspace_name` (CF-14). `drive_session` echoes it straight back inside
/// `SessionCreated`'s `SessionSpec.name`, so an unbounded `workspace_name`
/// approaching [`MAX_FRAME_BYTES`] would produce a reply *larger* than that
/// same cap — which the client's own equal cap
/// (`roundhouse_tui::client::MAX_FRAME_BYTES`) then rejects. Self-inflicted
/// and harmless at any realistic length (nobody names a workspace
/// megabytes-long), but the honest fix is a bound at the point this value is
/// parsed, not a bigger client-side cap to accommodate an unbounded one.
/// 4 KiB is generous for a human-chosen name while leaving enormous headroom
/// under [`MAX_FRAME_BYTES`] even after JSON-escaping and the rest of the
/// envelope.
const MAX_WORKSPACE_NAME_BYTES: usize = 4096;

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

/// Bounds `session_bootstrap::create_real_session` as a whole (fix round 1,
/// SHOULD item): that function's own `handshake_timeout` — the one wrapping
/// `requests_rx.recv()` above — has ALREADY resolved (successfully) by the
/// time this runs, since a `CreateSession` request was, by definition,
/// received. Real isolation `prepare()` and — when this session has any
/// configured MCP servers — `McpHost::start` (spawning a real child process
/// and awaiting its `discover()` handshake) run inside it, and neither is
/// bounded by anything else: a wedged MCP server, or a `bwrap`/landlock
/// probe that hangs, would otherwise park this connection's whole handling
/// task forever with nothing else timing it out. 30 seconds matches
/// [`DEFAULT_HANDSHAKE_TIMEOUT`]'s own generous-for-a-human,
/// bounded-for-a-hang reasoning.
const SESSION_CONSTRUCTION_TIMEOUT: Duration = Duration::from_secs(30);

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

/// Fix round 2, MUST 2 (remainder): bounds how many FAILED `CreateSession`
/// constructions one peer can trigger inside a trailing window, before
/// `construct_real_session_bounded` — not after.
///
/// `SessionRegistry::is_full`'s pre-check (`drive_session`, just above where
/// this is consulted) only counts *registered*, successfully built sessions
/// — it does nothing to bound a peer that loops `CreateSession` against a
/// host where construction always fails (e.g. this daemon's own documented
/// default, `OnDegrade::Refuse`, on a host with no working isolation
/// mechanism at all). Every such attempt still runs a real `Isolate::
/// prepare`/`probe` and appends a `Degradation` note to the append-only
/// `events` table before failing — restoring `Refuse` as the default (fix
/// round 1) fixed a worse bug but did not, by itself, bound what a failing
/// attempt costs. This does: once a peer accumulates `max_failures` failed
/// constructions inside `window`, further attempts are refused immediately,
/// with no `prepare()`/`probe()`/event append at all, until the window
/// rolls over. A successful construction clears that peer's streak — only
/// *sustained* failure loops are throttled, not an operator's normal mix of
/// working sessions with the occasional unrelated failure.
///
/// Keyed by peer uid, not a single hardcoded global bucket: today
/// `accept_loop_with`'s own peer-credential check means every connection
/// this daemon accepts already shares exactly one uid (this process's own —
/// see that function's doc comment), so this reduces to one bucket in
/// practice. Keying by uid keeps the mechanism correct instead of merely
/// adequate if that check is ever relaxed to admit more than one uid, at no
/// extra cost today.
///
/// `pub`, and `#[doc(hidden)]`, for the same reason [`AcceptLimits`] is:
/// [`drive_session`] takes one as a parameter, and this crate's integration
/// tests (`tests/deadlock_invariant.rs`, a separate crate) call
/// `drive_session` directly rather than through the full `accept_loop`
/// stack, so they must be able to construct one too.
#[doc(hidden)]
pub struct FailedConstructionLimiter {
    max_failures: u32,
    window: Duration,
    state: std::sync::Mutex<std::collections::HashMap<u32, (u32, std::time::Instant)>>,
}

impl FailedConstructionLimiter {
    fn new(max_failures: u32, window: Duration) -> Self {
        FailedConstructionLimiter {
            max_failures,
            window,
            state: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// `true` if `peer_uid` is still within its failure budget for the
    /// current window — a `CreateSession` attempt may proceed. `false` if it
    /// has already hit `max_failures` failures inside the trailing `window`
    /// and must be refused before any real construction work starts.
    fn allow(&self, peer_uid: u32, now: std::time::Instant) -> bool {
        let state = self
            .state
            .lock()
            .expect("FailedConstructionLimiter mutex poisoned");
        match state.get(&peer_uid) {
            Some((count, window_start)) if now.duration_since(*window_start) < self.window => {
                *count < self.max_failures
            }
            _ => true,
        }
    }

    /// Records one failed construction for `peer_uid`, starting a fresh
    /// window if the previous one has already elapsed.
    fn record_failure(&self, peer_uid: u32, now: std::time::Instant) {
        let mut state = self
            .state
            .lock()
            .expect("FailedConstructionLimiter mutex poisoned");
        let entry = state.entry(peer_uid).or_insert((0, now));
        if now.duration_since(entry.1) >= self.window {
            *entry = (0, now);
        }
        entry.0 += 1;
    }

    /// Clears `peer_uid`'s failure streak entirely — called after a
    /// successful construction, so only *sustained* failure loops are ever
    /// throttled.
    fn record_success(&self, peer_uid: u32) {
        let mut state = self
            .state
            .lock()
            .expect("FailedConstructionLimiter mutex poisoned");
        state.remove(&peer_uid);
    }
}

impl Default for FailedConstructionLimiter {
    /// 5 failed constructions per peer per 10 seconds — generous enough not
    /// to interfere with an operator's own legitimate retries, tight enough
    /// that a tight failure loop cannot run more than a handful of real
    /// `prepare()`/`probe()` calls (and `Degradation` event appends) before
    /// being cut off.
    fn default() -> Self {
        FailedConstructionLimiter::new(5, Duration::from_secs(10))
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
    resources: Arc<DaemonResources>,
) -> std::io::Result<()> {
    accept_loop_with(
        listener,
        registry,
        resources,
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
    resources: Arc<DaemonResources>,
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
    let failed_construction_limiter = Arc::new(FailedConstructionLimiter::default());
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

        let peer_uid = match stream.peer_cred() {
            Ok(cred) if cred.uid() == expected_uid => cred.uid(),
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
        };

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
        let resources = resources.clone();
        let handshake_timeout = limits.handshake_timeout;
        let failed_construction_limiter = failed_construction_limiter.clone();
        tokio::spawn(async move {
            let _permit = permit;
            handle_connection(
                stream,
                registry,
                resources,
                handshake_timeout,
                peer_uid,
                failed_construction_limiter,
            )
            .await;
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
    resources: Arc<DaemonResources>,
    handshake_timeout: Duration,
    peer_uid: u32,
    failed_construction_limiter: Arc<FailedConstructionLimiter>,
) {
    let (requests_tx, requests_rx) = mpsc::channel(REQUEST_CHANNEL_CAPACITY);
    let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
    tokio::join!(
        serve_connection(stream, requests_tx, events_rx),
        drive_session(
            requests_rx,
            events_tx,
            registry,
            resources,
            handshake_timeout,
            peer_uid,
            failed_construction_limiter,
        ),
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
///
/// Every successful `CreateSession` branch also spawns [`spawn_session_reaper`]
/// — see that function's own doc comment for why (ruling W1-R99, the
/// previously-unwired half of W1-R51).
pub async fn drive_session(
    mut requests_rx: mpsc::Receiver<ClientRequest>,
    events_tx: mpsc::Sender<ClientEvent>,
    registry: Arc<SessionRegistry>,
    resources: Arc<DaemonResources>,
    handshake_timeout: Duration,
    peer_uid: u32,
    failed_construction_limiter: Arc<FailedConstructionLimiter>,
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

    // W1-R37/W1-R52: only the connection that ran `CreateSession` ever gets
    // its post-handshake requests honored — see the `Some(_request)` arm,
    // below, for the full rationale and the documented limitation this
    // implies for `Attach`.
    let (session_id, subscription, mut session_events, is_creator) = match first_request {
        ClientRequest::CreateSession { workspace_name } => {
            // CF-14: bound at the protocol boundary, not by making the
            // client's own frame cap bigger. `SessionCreated`, below, echoes
            // `workspace_name` straight back — an unbounded value here could
            // produce a reply larger than [`MAX_FRAME_BYTES`], which the
            // client's OWN equal cap (`roundhouse_tui::client::MAX_FRAME_BYTES`)
            // would then reject. Self-inflicted and harmless at any
            // realistic workspace name length, but the honest fix is a
            // bound on the input, not a bigger cap on the reply.
            if workspace_name.len() > MAX_WORKSPACE_NAME_BYTES {
                tracing::warn!(
                    len = workspace_name.len(),
                    max = MAX_WORKSPACE_NAME_BYTES,
                    "closing connection: CreateSession workspace_name exceeds the maximum length"
                );
                return;
            }

            // Fix round 1 (SHOULD item): a cheap pre-check before the
            // expensive work below (real isolation `prepare`, proxy
            // registration, potentially a real `McpHost::start` subprocess
            // spawn) — see `SessionRegistry::is_full`'s own doc comment for
            // exactly what this does and does not close.
            if registry.is_full() {
                tracing::warn!("closing connection: at max_sessions, refusing before doing any real session-construction work");
                return;
            }

            // Fix round 2, MUST 2 (remainder): a second cheap pre-check,
            // ahead of `is_full`'s own — `is_full` only bounds *registered*
            // sessions, so it does nothing against a peer that loops
            // `CreateSession` against a host where construction always
            // fails (every attempt still runs a real `Isolate::prepare`/
            // `probe` and appends a `Degradation` note to the append-only
            // `events` table before failing). See
            // `FailedConstructionLimiter`'s own doc comment.
            if !failed_construction_limiter.allow(peer_uid, std::time::Instant::now()) {
                tracing::warn!(
                    peer_uid,
                    "closing connection: this peer has exceeded its failed-session-construction \
                     budget for the current window; refusing before doing any real \
                     session-construction work"
                );
                return;
            }

            let real_session = match construct_real_session_bounded(&resources, workspace_name)
                .await
            {
                Ok(real_session) => {
                    failed_construction_limiter.record_success(peer_uid);
                    real_session
                }
                Err(ConstructionOutcome::Failed(err)) => {
                    failed_construction_limiter.record_failure(peer_uid, std::time::Instant::now());
                    // No `ClientRequest`/`ClientEvent` error variant exists to
                    // report this over the wire with (the same constraint
                    // ruling W1-R6 already accepted for "unknown session");
                    // logging and ending the connection is the most honest
                    // thing left to do. Never includes `err`'s `Display` in
                    // anything sent to the client — `StartSessionMcpError`/
                    // `CreateSessionError` are daemon-local operator
                    // diagnostics, not client-facing payloads.
                    tracing::error!(error = %err, "failed to construct a real session; refusing CreateSession");
                    return;
                }
                Err(ConstructionOutcome::TimedOut) => {
                    failed_construction_limiter.record_failure(peer_uid, std::time::Instant::now());
                    // Fix round 1 (SHOULD item), refined in fix round 2
                    // (MUST 2): a wedged MCP server startup (or a hung
                    // isolation probe) must not park this connection's whole
                    // handling task forever — see
                    // `construct_real_session_bounded`'s own doc comment for
                    // why this does NOT cancel the construction itself
                    // (which would leak a real isolation handle) and instead
                    // lets it finish and self-teardown in the background.
                    tracing::error!(
                        timeout = ?SESSION_CONSTRUCTION_TIMEOUT,
                        "session construction did not complete within the timeout; refusing \
                         CreateSession (construction continues in the background and will be \
                         torn down on completion, not left running)"
                    );
                    return;
                }
                Err(ConstructionOutcome::TaskEnded) => {
                    failed_construction_limiter.record_failure(peer_uid, std::time::Instant::now());
                    tracing::error!(
                        "session construction task ended unexpectedly (panicked or was \
                         dropped) before reporting an outcome; refusing CreateSession"
                    );
                    return;
                }
            };
            let spec = real_session.actor.session_spec().clone();
            // Cloned BEFORE the actor/mcp_host move into `registry.create`
            // below, so both the "lost the `is_full` race" teardown path
            // AND the reaper spawned after a successful `create` have their
            // own independent copies of exactly what they each need,
            // regardless of what `registry`/`session_events` do with theirs.
            let actor_for_reaper = real_session.actor.clone();
            let mcp_host_for_reaper = real_session.mcp_host.clone();
            let proxy_token_for_reaper = real_session.proxy_handle.token().to_string();

            let Some((session_id, subscription, session_events)) =
                registry.create(real_session.actor, real_session.mcp_host)
            else {
                // At `max_sessions` (security review Important 3 / ruling
                // W1-R33) — same "no wire error variant" constraint as
                // above. Fix round 2, MUST 2: this used to leak the
                // isolation handle/MCP host/proxy registration
                // `real_session` had already built (a real, if rare, gap —
                // this is the daemon's least-realistic failure path, hit
                // only at ten thousand concurrently live sessions); now
                // torn down explicitly via the same clones the reaper would
                // otherwise have used.
                tracing::warn!(
                    "lost the race against max_sessions after real session construction \
                     already completed; tearing down rather than leaking the isolation \
                     handle/MCP host/proxy registration"
                );
                let discarded = session_bootstrap::RealSession {
                    actor: actor_for_reaper,
                    mcp_host: mcp_host_for_reaper,
                    proxy_handle: real_session.proxy_handle,
                };
                session_bootstrap::teardown_real_session(&resources.proxy, discarded).await;
                return;
            };
            // Ruling W1-R99 (fix round 1): the "do-reap-when-the-actor-ends"
            // half of W1-R51 — `SessionRegistry::remove` existed but had no
            // production caller, so entry lifetime was actually
            // daemon-process lifetime, not actor lifetime. This is the
            // caller: watches this session's own `SessionState` for
            // `Closed` and reaps the registry entry the moment it's
            // observed, independent of this connection's (or any
            // connection's) own lifetime. Fix round 2, MUST 2: also tears
            // down the actor's real isolation handle and shuts down its MCP
            // host (previously only `SessionRegistry::remove`/
            // `LoopbackProxy::deregister_session` ran here — the bookkeeping
            // was cleared, but the real resources behind it were not).
            spawn_session_reaper(
                registry.clone(),
                session_id,
                actor_for_reaper,
                mcp_host_for_reaper,
                resources.proxy.clone(),
                proxy_token_for_reaper,
            );
            let created = ClientEvent::TaskEvent {
                session_id,
                task_id: None,
                payload: Box::new(EventPayload::SessionCreated {
                    spec: Box::new(spec),
                }),
            };
            if events_tx.send(created).await.is_err() {
                // `serve_connection` already gave up on this connection
                // (e.g. the peer disconnected mid-handshake) — tear the
                // just-created subscriber registration back down rather
                // than leak it. The actor itself is NOT torn down (see the
                // module doc comment, "Entry lifetime = actor lifetime") —
                // it stays registered, attachable by session id, exactly as
                // if this connection had detached normally after a
                // successful handshake.
                registry.detach(session_id, &subscription);
                return;
            }
            (session_id, subscription, session_events, true)
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
        // beyond that) can attach to it. That is bounded by `is_creator`
        // below: an attached connection's post-handshake requests are
        // always refused, so an attacker who merely learns a `SessionId`
        // can watch, never act.
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
                (session_id, subscription, session_events, false)
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
                    // # Rulings W1-R37/W1-R52 — attached connections are
                    // READ-ONLY, by design, and this is the discard site
                    // that enforces it
                    //
                    // `ClientRequest` carries exactly two variants today
                    // (`CreateSession`, `Attach` — both only valid as the
                    // FIRST line of a connection, matched above); there is
                    // currently no variant that names "do something inside
                    // an already-established session" at all, so this arm
                    // is unreachable in ordinary operation regardless of
                    // `is_creator`, and both a creator's and an attached
                    // connection's post-handshake frames are, today,
                    // identically discarded below. `is_creator` is threaded
                    // this far anyway (see the `let _ = is_creator;` inside
                    // this arm) so the binding decision this ruling records
                    // is visible at the exact discard site a future real
                    // handler replaces, not left implicit: `docs/architecture/
                    // 03-security-and-sandboxing.md:174` ("approvals
                    // broadcast to every attached client, first responder
                    // wins") governs what an attached client may SEE, not
                    // what it may SEND — defaulting the latter open the
                    // moment a real request variant exists would make
                    // unauthenticated `Attach` an approval-hijack primitive.
                    // Only the creating connection's future requests may
                    // ever be honored; an attached connection's must stay
                    // refused even once a real handler exists.
                    //
                    // **Known, deliberate limitation (W1-R52):** once the
                    // creating connection disconnects, this session has NO
                    // controller left — `round attach --session ID` from a
                    // fresh terminal is a VIEWER, never able to send a
                    // request that will be honored, even though the session
                    // (per ruling W1-R51) is still very much alive and
                    // running. That is fail-closed by design, not a bug to
                    // work around by honoring an attached connection's
                    // requests "to make attach feel complete" — doing so
                    // would silently reopen exactly what this ruling closed.
                    //
                    // **W1-R38 — this remains a property of the loop's
                    // shape, not a one-time patch.** The moment a real
                    // variant exists and handling it needs to `await` a
                    // `SessionActor` (`registry.actor(session_id)`, already
                    // available for exactly this), that work must be handed
                    // to a spawned task or gated behind its own `select!`
                    // arm reserving capacity — never awaited inside this
                    // arm's own body — for the identical reason
                    // `events_tx`/`requests_out` already aren't: doing so
                    // would stop this arm from polling `session_events.recv()`
                    // for as long as the await is pending, recreating the
                    // exact circular wait W1-R31 fixed.
                    Some(_request) => {
                        // `is_creator` is read here — rather than left an
                        // unused tuple element — specifically so the future
                        // call site (routing to `registry.actor(session_id)`
                        // only when `is_creator` is `true`) has an obvious
                        // place to grow into. There is no `ClientRequest`
                        // variant to route yet, so this is a no-op either
                        // way today.
                        let _ = is_creator;
                    }
                    None => break,
                }
            }
        }
    }

    registry.detach(session_id, &subscription);
}

/// Why [`construct_real_session_bounded`] exists, in one line: real session
/// construction must be BOUNDED without ever being CANCELLED.
///
/// [`ConstructionOutcome`] distinguishes the two non-success outcomes so
/// `drive_session` can log each honestly rather than collapsing both into
/// one message.
enum ConstructionOutcome {
    /// `session_bootstrap::create_real_session` itself returned `Err` —
    /// its own error paths are responsible for tearing down whatever they
    /// had already built (see that function's own doc comments; fix round
    /// 2, MUST 2 closed the one gap that existed there).
    Failed(session_bootstrap::CreateRealSessionError),
    /// Construction did not report an outcome within
    /// [`SESSION_CONSTRUCTION_TIMEOUT`]. It is still running in the
    /// background and will tear itself down on completion — see this
    /// function's own doc comment.
    TimedOut,
    /// The construction task ended (panicked, or was somehow dropped)
    /// without ever sending a result.
    TaskEnded,
}

/// Runs `session_bootstrap::create_real_session` to completion in its own
/// spawned task and returns its outcome, bounded by
/// [`SESSION_CONSTRUCTION_TIMEOUT`] — WITHOUT ever cancelling the
/// construction future itself (fix round 2, MUST 2).
///
/// An earlier version of this function raced `create_real_session` directly
/// inside a `tokio::time::timeout`, which — on elapse — DROPS the losing
/// future mid-`.await`. That is unsound for this specific future:
/// `Isolate::prepare`'s real implementation (`BwrapLandlockIsolate`) inserts
/// a handle into its own internal map BEFORE the async work backing it
/// fully resolves, so a future dropped between that insert and its own
/// return leaves an orphaned entry — a real resource with no `Handle` this
/// process ever hands back to anyone, so nothing can ever call
/// `Isolate::teardown` on it. The fix is not to make `prepare` itself
/// cancellation-safe (`roundhouse-sandbox` is lane W5's crate, not this
/// lane's) — it is to never cancel it from here: this function spawns
/// `create_real_session` as an independent task that always runs to
/// completion, and races only a [`tokio::sync::oneshot`] receiver (never
/// the construction future itself) against the timeout. If the timeout
/// wins, the spawned task keeps running; when it eventually finishes, it
/// notices its `oneshot::Sender::send` failed (the receiver was dropped
/// with the elapsed `timeout`) and tears down whatever it built via
/// [`session_bootstrap::teardown_real_session`] instead of leaking it.
async fn construct_real_session_bounded(
    resources: &Arc<DaemonResources>,
    workspace_name: String,
) -> Result<session_bootstrap::RealSession, ConstructionOutcome> {
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let construction_resources = resources.clone();
    tokio::spawn(async move {
        let outcome =
            session_bootstrap::create_real_session(&construction_resources, workspace_name).await;
        match outcome {
            Ok(real_session) => {
                if let Err(Ok(real_session)) = result_tx.send(Ok(real_session)) {
                    tracing::warn!(
                        "session construction finished after its caller gave up on the \
                         timeout; tearing down the real session it built instead of leaking it"
                    );
                    session_bootstrap::teardown_real_session(
                        &construction_resources.proxy,
                        real_session,
                    )
                    .await;
                }
            }
            Err(err) => {
                // A construction error carries no real resource for THIS
                // function to tear down: `create_real_session`'s own error
                // paths already tear down whatever they had built before
                // returning `Err` (fix round 2, MUST 2). Best-effort send —
                // if nobody's listening either, there is nothing further
                // to do with the error but drop it.
                let _ = result_tx.send(Err(err));
            }
        }
    });

    match tokio::time::timeout(SESSION_CONSTRUCTION_TIMEOUT, result_rx).await {
        Ok(Ok(Ok(real_session))) => Ok(real_session),
        Ok(Ok(Err(err))) => Err(ConstructionOutcome::Failed(err)),
        Ok(Err(_recv_error)) => Err(ConstructionOutcome::TaskEnded),
        Err(_elapsed) => Err(ConstructionOutcome::TimedOut),
    }
}

/// The "do-reap-when-the-actor-ends" half of ruling W1-R51 (fix round 1,
/// ruling W1-R99): watches `session_id`'s own `SessionState` for its
/// terminal `Closed` value and calls [`SessionRegistry::remove`] the moment
/// it's observed.
///
/// Spawned once per successfully created session, independent of any one
/// connection's lifetime — it must keep running after the connection that
/// called `CreateSession` (and `drive_session` itself) has returned, since a
/// session's actor can outlive every connection that ever touched it (that
/// is the entire point of `SessionEntry`'s "entry lifetime = actor
/// lifetime" rule this reaper closes the other half of).
///
/// Nothing in this crate currently drives an actor to `SessionState::Closed`
/// (there is no live work-submission path yet — see `main.rs`'s own module
/// doc comment), so this loop simply never observes that value today and the
/// task sits parked on `state.changed()` for the daemon's whole life,
/// exactly as inert as `remove`'s previous zero-caller state was loud about
/// being unwired. The difference is that the mechanism is now real and
/// wired at the one call site that creates a session, so the moment a
/// future task adds a real terminal transition, this reaper closes the loop
/// with no further wiring needed.
fn spawn_session_reaper(
    registry: Arc<SessionRegistry>,
    session_id: roundhouse_core::SessionId,
    actor: Arc<roundhouse_engine::SessionActor>,
    mcp_host: Option<Arc<roundhouse_mcp::host::McpHost>>,
    proxy: Arc<roundhouse_net::proxy::LoopbackProxy>,
    proxy_token: String,
) {
    let mut state = actor.subscribe();
    tokio::spawn(async move {
        loop {
            if *state.borrow() == roundhouse_core::SessionState::Closed {
                registry.remove(session_id);
                // Fix round 2, MUST 2: before this, only the BOOKKEEPING
                // was cleared here (the registry entry, the proxy's
                // session-token map entry) — the REAL resources behind
                // them (a real bwrap isolation handle, real MCP child
                // processes) were never torn down on this path at all.
                actor.teardown().await;
                if let Some(host) = &mcp_host {
                    if let Err(err) = host.shutdown().await {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %err,
                            "failed to shut down this session's MCP host"
                        );
                    }
                }
                proxy.deregister_session(&proxy_token);
                return;
            }
            if state.changed().await.is_err() {
                // The actor's own `state_tx` sender has been dropped — the
                // actor itself is gone. If that happened through some other
                // path than reaching `Closed`, there is nothing meaningful
                // left to watch; just stop.
                return;
            }
        }
    });
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

/// Fix round 2, MUST 2 (remainder): direct, fast unit coverage of
/// `FailedConstructionLimiter`'s own logic — window rollover and the
/// success-clears-the-streak rule — separate from
/// `tests/failed_construction_rate_limit.rs`'s slower, real-`Isolate`
/// end-to-end proof that this type is actually wired into `drive_session`.
#[cfg(test)]
mod failed_construction_limiter_tests {
    use super::*;

    #[test]
    fn refuses_once_the_budget_is_exhausted_within_the_window() {
        let limiter = FailedConstructionLimiter::new(3, Duration::from_secs(10));
        let t0 = std::time::Instant::now();
        assert!(limiter.allow(1, t0));
        limiter.record_failure(1, t0);
        assert!(limiter.allow(1, t0));
        limiter.record_failure(1, t0);
        assert!(limiter.allow(1, t0));
        limiter.record_failure(1, t0);
        assert!(
            !limiter.allow(1, t0),
            "a 4th attempt within the window must be refused after 3 recorded failures"
        );
    }

    #[test]
    fn a_different_peer_has_its_own_independent_budget() {
        let limiter = FailedConstructionLimiter::new(1, Duration::from_secs(10));
        let t0 = std::time::Instant::now();
        assert!(limiter.allow(1, t0));
        limiter.record_failure(1, t0);
        assert!(!limiter.allow(1, t0), "peer 1 exhausted its own budget");
        assert!(
            limiter.allow(2, t0),
            "peer 2's budget must be independent of peer 1's"
        );
    }

    #[test]
    fn the_window_rolls_over_and_the_budget_resets() {
        let limiter = FailedConstructionLimiter::new(1, Duration::from_secs(10));
        let t0 = std::time::Instant::now();
        limiter.record_failure(1, t0);
        assert!(!limiter.allow(1, t0));
        let after_window = t0 + Duration::from_secs(11);
        assert!(
            limiter.allow(1, after_window),
            "the budget must reset once the window has elapsed"
        );
    }

    #[test]
    fn a_successful_construction_clears_the_failure_streak() {
        let limiter = FailedConstructionLimiter::new(1, Duration::from_secs(10));
        let t0 = std::time::Instant::now();
        limiter.record_failure(1, t0);
        assert!(!limiter.allow(1, t0));
        limiter.record_success(1);
        assert!(
            limiter.allow(1, t0),
            "a successful construction must clear the peer's failure streak, even \
             within the same window"
        );
    }
}

#[cfg(test)]
mod session_reaper_tests {
    //! Ruling W1-R99 (fix round 1): `spawn_session_reaper` is the
    //! previously-unwired "do-reap-when-the-actor-ends" half of W1-R51.
    //! Nothing in production code transitions a `SessionActor` to
    //! `SessionState::Closed` yet (there is no live work-submission path —
    //! see `main.rs`'s own module doc comment), so these tests construct an
    //! actor already `Closed` at birth (`SessionActor::new`'s own
    //! `initial_state` parameter) rather than driving a real one there —
    //! the reaper's own logic doesn't care how `Closed` was reached, only
    //! that it observes it.

    use super::*;
    use crate::test_support::{real_actor_with_state, runner};
    use roundhouse_net::policy::EgressPolicy;
    use roundhouse_net::proxy::LoopbackProxy;

    /// A real `LoopbackProxy`, actually `serve()`d (so `register_session`
    /// can succeed — it requires a bound address), plus one real, freshly
    /// registered session token. Fix round 2, MUST 5: the previous version
    /// of both tests below passed the literal `"test-token"`, never
    /// registered with the proxy at all — `deregister_session` on an
    /// unknown token is a harmless no-op, so those tests passed regardless
    /// of whether the reaper ever called it. This helper makes the
    /// registration real so the tests can assert on its actual removal.
    async fn real_proxy_with_registered_token(
        dir: &std::path::Path,
    ) -> (Arc<LoopbackProxy>, String) {
        let proxy = Arc::new(LoopbackProxy::new());
        let store = roundhouse_store::open(&dir.join("proxy-events.db"))
            .await
            .unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        proxy.clone().serve(runner(), writer).await.unwrap();
        let handle = proxy
            .register_session(
                roundhouse_core::SessionId::new(),
                EgressPolicy {
                    allowed_hosts: vec![],
                },
            )
            .unwrap();
        let token = handle.token().to_string();
        (proxy, token)
    }

    #[tokio::test]
    async fn a_session_already_closed_at_registration_is_reaped_promptly() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(SessionRegistry::new());
        let actor = real_actor_with_state(dir.path(), roundhouse_core::SessionState::Closed).await;
        let actor_for_reaper = actor.clone();
        let (session_id, _subscription, _events) = registry.create(actor, None).unwrap();

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;
        assert!(
            proxy.is_registered(&token),
            "sanity: the token is really registered"
        );
        spawn_session_reaper(
            registry.clone(),
            session_id,
            actor_for_reaper,
            None,
            proxy.clone(),
            token.clone(),
        );

        let reaped = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if registry.attach(session_id).is_none() {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(
            reaped.is_ok(),
            "an already-Closed session must be reaped by spawn_session_reaper, \
             not left registered forever"
        );
        // MUST 5: proves the reaper actually called `deregister_session`,
        // not merely that a no-op on an unregistered token didn't panic.
        assert!(
            !proxy.is_registered(&token),
            "the reaper must deregister this session's real proxy token"
        );
    }

    /// The mirror case: an actor that never reaches `Closed` must NOT be
    /// reaped — proving the reaper doesn't just remove everything on a
    /// timer, only sessions that actually reach the terminal state.
    #[tokio::test]
    async fn a_session_that_never_closes_is_never_reaped() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(SessionRegistry::new());
        let actor = real_actor_with_state(dir.path(), roundhouse_core::SessionState::Running).await;
        let actor_for_reaper = actor.clone();
        let (session_id, _subscription, _events) = registry.create(actor, None).unwrap();

        let (proxy, token) = real_proxy_with_registered_token(dir.path()).await;
        spawn_session_reaper(
            registry.clone(),
            session_id,
            actor_for_reaper,
            None,
            proxy.clone(),
            token.clone(),
        );

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            registry.attach(session_id).is_some(),
            "a session that never reaches Closed must remain attachable"
        );
        assert!(
            proxy.is_registered(&token),
            "a session that never reaches Closed must not have its proxy token deregistered \
             either"
        );
    }
}
