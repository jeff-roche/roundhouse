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

use roundhouse_proto::{ClientEvent, ClientRequest};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

/// Binds a Unix socket, accepts exactly one connection, and runs the real
/// bidirectional wire loop for it via [`serve_connection`].
///
/// A production daemon serves many concurrent attached clients (§11.3); this
/// phase's exit criterion only needs one, to prove the wire format round-trips
/// end to end with real `roundhouse-proto` types. Task 3's real `accept()`
/// loop spawns one [`serve_connection`] per connection against a
/// `SessionId`-keyed registry instead of this function's single-connection
/// shape — [`serve_connection`] is written standalone (not inlined here)
/// specifically so that loop can reuse it without reimplementing the
/// read/write body.
///
/// `bind` and the `set_permissions` chmod below run as the first two
/// statements in this function's body, before any `.await` point — so
/// whichever task actually polls this future runs both eagerly, in one step,
/// before yielding at `listener.accept().await`. That is a weaker guarantee
/// than Phase 1's `serve_ndjson` had (a plain, non-async function that bound
/// synchronously *before returning control to its caller*, because it did its
/// own internal `tokio::spawn`): here, the caller is the one who spawns
/// `serve` (see the doctest-style caller in `main.rs` and this crate's
/// `socket_wire_format` test), so there is now a scheduling gap between
/// `tokio::spawn(serve(..))` returning and this function's body actually
/// running. Callers that need the old hard guarantee should not rely on
/// `serve`'s return value the way they could rely on `serve_ndjson`'s
/// `JoinHandle` — a client that dials immediately after `tokio::spawn` may
/// still race the bind.
///
/// The spawned connection's loop exits when both the read half hits EOF (or
/// errors) and `events_in` closes (or every write to the peer fails); nothing
/// here panics on a hostile or vanished peer.
///
/// # Errors
/// Returns the `bind` error if the path is already in use, unwritable, or too
/// long for `sockaddr_un`, or the `set_permissions` error if the socket's mode
/// can't be tightened.
pub async fn serve(
    socket_path: impl AsRef<Path>,
    requests_out: mpsc::Sender<ClientRequest>,
    events_in: mpsc::Receiver<ClientEvent>,
) -> std::io::Result<()> {
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

    // TODO(Phase 2): implement SO_PEERCRED peer-credential verification per
    // docs/architecture/03-security-and-sandboxing.md §6.4 "Approvals" ("The
    // Unix socket uses peer-credential checks (SO_PEERCRED)"). This demo server
    // accepts any local connection with no authentication whatsoever — the
    // 0600 socket mode and 0700 parent directory above are what currently
    // stand in for it, and they are a filesystem-permission approximation,
    // not the credential check the frozen contract requires. Still not picked
    // up as of Task 2; carried forward verbatim rather than silently dropped
    // in this rewrite (Task 3's real accept loop is where this belongs, if
    // anywhere).
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
/// reimplementing the read/write body.
///
/// Uses `tokio::select!` between the read and write halves so a slow or
/// absent peer on one side (e.g. a client that never sends a second request)
/// can never block delivery on the other (the `events_in` → socket
/// direction), and vice versa. Every write error ends its half of the loop
/// rather than panicking; a `ClientRequest` line that fails to parse, or a
/// `ClientEvent` that fails to serialize, is dropped with a warning instead
/// of taking the connection down.
pub(crate) async fn serve_connection(
    stream: UnixStream,
    requests_out: mpsc::Sender<ClientRequest>,
    mut events_in: mpsc::Receiver<ClientEvent>,
) {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    let mut line = String::new();
    let mut read_done = false;
    let mut write_done = false;

    while !(read_done && write_done) {
        tokio::select! {
            result = reader.read_line(&mut line), if !read_done => {
                match result {
                    Ok(0) => {
                        // Clean EOF: the peer closed its write half.
                        read_done = true;
                    }
                    Ok(_) => {
                        let parsed: Result<ClientRequest, _> =
                            serde_json::from_str(line.trim_end());
                        line.clear();
                        match parsed {
                            Ok(request) => {
                                if requests_out.send(request).await.is_err() {
                                    // Nobody is listening for requests anymore
                                    // — nothing left to forward them to.
                                    read_done = true;
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
                    Err(_) => {
                        read_done = true;
                    }
                }
            }
            maybe_event = events_in.recv(), if !write_done => {
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
                            write_done = true;
                        }
                    }
                    None => {
                        write_done = true;
                    }
                }
            }
        }
    }
}
