//! Unix socket client for attaching to the daemon.
//!
//! Phase 7 Task 2 makes this speak `roundhouse-proto`'s real
//! `ClientRequest`/`ClientEvent` wire types instead of the retired
//! `ServerMessage`: `connect` now performs a real handshake by sending a
//! `ClientRequest` (see [`ConnectIntent`]) over a write half it actually
//! keeps, and [`DaemonClient::recv`] decodes the daemon's `ClientEvent`
//! frames rather than a daemon-pre-summarized shape.

use std::path::Path;
use std::time::Duration;

use roundhouse_core::{EventPayload, SessionId};
use roundhouse_proto::{ClientEvent, ClientRequest};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use crate::protocol::TuiError;

/// Maximum length, in bytes, of a single NDJSON line [`DaemonClient::recv`]
/// will accept before treating the connection as unusable (security review
/// Minor 7 / ruling W1-R33): this is the client-side mirror of
/// `roundhouse-daemon`'s `socket_server::MAX_FRAME_BYTES` fix for the
/// identical unbounded-`read_line` shape, pre-existing but put on this
/// crate's new `connect_create`/`connect_attach` path by this diff — and
/// `connect_create`'s `Some(_) => continue` loop reads frames indefinitely,
/// so an unbounded daemon reply would drive this client's memory the same
/// way an unbounded client request drove the daemon's.
///
/// `roundhouse-tui` does not depend on `tokio-util` (unlike
/// `roundhouse-daemon`, which added its `codec` feature for this exact
/// problem), so this bounds `read_until` directly via `AsyncReadExt::take`
/// rather than pulling in a new dependency for one crate to save one
/// `Vec`/`String` allocation shape. Same value as the daemon side
/// (1 MiB, matching `roundhouse_acp::registry::MAX_RESPONSE_BYTES`'s
/// precedent) for the same reason: generous enough for any real
/// `ClientEvent` frame (including `SessionCreated`'s echoed
/// `workspace_name`), while still bounding the worst case to a fixed
/// multiple of this client's own buffering.
const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Bounds [`DaemonClient::close_session`]'s wait for the `Ack`. Every
/// refusal path `roundhouse_daemon::socket_server::
/// drive_established_session` designs for `CloseSession` (wrong connection,
/// wrong session, a close already in flight, the session no longer being
/// live, or a failed durable append) is deliberately silent on the wire —
/// no frame at all, connection kept open, retryable — so without a bound
/// here, a well-formed `CloseSession` sent from a connection that can never
/// have it honored (e.g. one built via `connect_attach`, not
/// `connect_create`) hangs this call forever. Chosen with margin over the
/// daemon's own close budget (`roundhouse_daemon::socket_server::
/// CLOSE_SESSION_TIMEOUT`, 30s — not reusable directly, since this crate
/// does not depend on `roundhouse-daemon`) so a close that is genuinely
/// progressing, just slowly, is not mistaken for a silently refused one.
const CLOSE_SESSION_ACK_TIMEOUT: Duration = Duration::from_secs(40);

/// What `connect` should announce itself as on a fresh handshake: mint a new
/// session, or attach to one that already exists.
///
/// `connect` takes this as a parameter rather than hardcoding
/// `ClientRequest::Attach` or `ClientRequest::CreateSession` so that Task 3's
/// `connect_create`/`connect_attach` convenience wrappers can each supply
/// their own variant without `connect` itself needing to change.
#[derive(Debug, Clone)]
pub enum ConnectIntent {
    /// Ask the daemon to mint a brand new session in the named workspace.
    CreateSession {
        /// The workspace the new session belongs to.
        workspace_name: String,
    },
    /// Ask the daemon to attach to an already-existing session.
    Attach {
        /// The session to attach to.
        session_id: SessionId,
    },
    /// Ask the daemon to attach to an already-existing session and replay
    /// only the events after `after_seq` (Phase 8 Task 21).
    Resume {
        /// The session to resume.
        session_id: SessionId,
        /// The last `seq` this client already has.
        after_seq: u64,
    },
}

impl From<ConnectIntent> for ClientRequest {
    fn from(intent: ConnectIntent) -> Self {
        match intent {
            ConnectIntent::CreateSession { workspace_name } => {
                ClientRequest::CreateSession { workspace_name }
            }
            ConnectIntent::Attach { session_id } => ClientRequest::Attach { session_id },
            ConnectIntent::Resume {
                session_id,
                after_seq,
            } => ClientRequest::Resume {
                session_id,
                after_seq,
            },
        }
    }
}

/// A client connection to the daemon, exchanging NDJSON `roundhouse-proto`
/// messages over a Unix socket.
///
/// Created by [`connect`], and used to receive a stream of [`ClientEvent`]s
/// via [`recv`](Self::recv), or to send further [`ClientRequest`]s via
/// [`send`](Self::send).
pub struct DaemonClient {
    /// Buffered reader wrapping the socket's read half.
    reader: BufReader<OwnedReadHalf>,
    /// The socket's write half. Phase 1 discarded this (`let (read_half,
    /// _write_half) = stream.into_split();`) because nothing was ever sent;
    /// Task 2 keeps it, since `connect` now sends a real `ClientRequest` and
    /// future callers may send more.
    writer: OwnedWriteHalf,
    /// The session this client is bound to, once known. `None` for a plain
    /// [`connect`] (which has no opinion on session identity), set by
    /// [`connect_create`] once it reads the session id off the daemon's
    /// `SessionCreated` handshake frame, and set immediately by
    /// [`connect_attach`]/[`connect_resume`], which already knew it from
    /// their caller.
    session_id: Option<SessionId>,
    /// Set once a [`Self::recv`] call may have been dropped mid-read (Phase
    /// 8, T19a Task 8) — currently only [`Self::close_session`]'s
    /// `tokio::time::timeout`, which cancels its own `recv` loop on elapse.
    /// `recv`'s own doc comment explains why that is not cancel-safe: a
    /// dropped `read_until` can have already consumed bytes off the
    /// underlying `BufReader` into a local buffer that is then discarded,
    /// permanently losing them without ever un-consuming them from
    /// `self.reader`. Once set, `recv` refuses to read again rather than let
    /// a caller silently decode whatever bytes happen to follow as a
    /// spurious `TuiError::Json` (or worse, a well-formed but wrong frame).
    /// There is no way to clear it: a client in this state must be
    /// discarded, not reused.
    ///
    /// Read this field's name as "unreadable," not "bytes were definitely
    /// lost": it is set unconditionally on every `close_session` timeout,
    /// including the common silent-refusal case where the cancelled `recv`
    /// was still waiting for the first byte of a fresh line and nothing was
    /// actually consumed. There is no cheap way to tell, after the fact,
    /// which case occurred, so this errs conservative and burns the client
    /// either way rather than risk the rare case silently. It says nothing
    /// about `self.writer` — the write half is entirely unaffected.
    read_desynchronized: bool,
    /// The `seq` of the last `ClientEvent::Committed` [`Self::recv`]
    /// returned (Phase 8 Task 21) — the cursor to hand [`connect_resume`]
    /// after a reconnect. Starts at `None`, or at the resumed-from cursor for
    /// a client built by [`connect_resume`].
    last_seq: Option<u64>,
}

/// Connect to the daemon's Unix socket at `socket_path`, then immediately
/// send `intent` (converted to a `ClientRequest`) as the connection's first
/// NDJSON line.
///
/// # Errors
/// Returns `TuiError::Io` if the connection fails, or if writing the initial
/// request fails. Returns `TuiError::Json` if the request somehow fails to
/// serialize (not reachable for `ClientRequest`'s current shape, but not
/// ruled out for a future variant).
pub async fn connect(socket_path: &Path, intent: ConnectIntent) -> Result<DaemonClient, TuiError> {
    let stream = UnixStream::connect(socket_path).await?;
    let (read_half, write_half) = stream.into_split();
    let mut client = DaemonClient {
        reader: BufReader::new(read_half),
        writer: write_half,
        session_id: None,
        read_desynchronized: false,
        last_seq: None,
    };
    client.send(&intent.into()).await?;
    Ok(client)
}

/// [`connect`] with [`ConnectIntent::CreateSession`], then read the daemon's
/// first reply frame to learn the `SessionId` it minted.
///
/// `ClientEvent` carries no dedicated "session created" reply. Instead the
/// daemon durably appends the new session's `SessionCreated` as its seq 0 and
/// streams it like every other event, as a `ClientEvent::Committed` (see
/// `roundhouse-daemon`'s `socket_server::drive_session`). This function reads
/// frames until it sees that one, caching the session id it carries so
/// [`DaemonClient::session_id`] can return it afterward, and
/// [`DaemonClient::last_seq`] reports its seq.
///
/// # Errors
/// Returns whatever [`connect`] or [`DaemonClient::recv`] returns. Also
/// returns `TuiError::Io` (`ErrorKind::UnexpectedEof`) if the daemon closes
/// the connection before ever sending a `SessionCreated` frame.
pub async fn connect_create(
    socket_path: &Path,
    workspace_name: &str,
) -> Result<DaemonClient, TuiError> {
    let mut client = connect(
        socket_path,
        ConnectIntent::CreateSession {
            workspace_name: workspace_name.to_string(),
        },
    )
    .await?;

    loop {
        match client.recv().await? {
            Some(ClientEvent::Committed {
                session_id,
                payload,
                ..
            }) if matches!(*payload, EventPayload::SessionCreated { .. }) => {
                client.session_id = Some(session_id);
                return Ok(client);
            }
            // Anything else (an `Ack`, or a `Committed` event of some other
            // kind) arriving before the handshake frame keeps this loop
            // reading rather than misinterpreting it as the reply.
            Some(_) => continue,
            None => {
                return Err(TuiError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "daemon closed the connection before sending SessionCreated",
                )));
            }
        }
    }
}

/// [`connect`] with [`ConnectIntent::Attach`] to an already-known
/// `session_id`, then wait for the daemon's `Ack` confirming the attach
/// succeeded before returning.
///
/// The `Ack` is what tells a caller the handshake succeeded: after it, the
/// daemon streams the session's committed events from seq 0 as
/// `ClientEvent::Committed` frames (Phase 8 Task 21), read from the store, so
/// there is no registration for a caller to race.
///
/// # Errors
/// Returns whatever [`connect`]/[`DaemonClient::recv`] returns. Also returns
/// `TuiError::Io` if the daemon closes the connection instead of
/// acknowledging (e.g. `session_id` names a session with neither a live
/// registry entry nor any stored events), or if the very first frame back is
/// something other than an `Ack`.
pub async fn connect_attach(
    socket_path: &Path,
    session_id: SessionId,
) -> Result<DaemonClient, TuiError> {
    let client = connect(socket_path, ConnectIntent::Attach { session_id }).await?;
    await_viewer_ack(client, session_id, "Attach").await
}

/// [`connect`] with [`ConnectIntent::Resume`]: attach to `session_id` and
/// replay only the events after `after_seq`, typically a previous
/// connection's [`DaemonClient::last_seq`] (Phase 8 Task 21). Waits for the
/// daemon's `Ack` like [`connect_attach`] does.
///
/// # Errors
/// Everything [`connect_attach`] returns, plus `TuiError::Io`
/// (`ErrorKind::InvalidInput`) if the daemon answers
/// `ClientEvent::ResyncRequired`: `after_seq` is past the session's head, so
/// the caller must discard its state and replay from the start (e.g. with
/// [`connect_attach`]).
pub async fn connect_resume(
    socket_path: &Path,
    session_id: SessionId,
    after_seq: u64,
) -> Result<DaemonClient, TuiError> {
    let client = connect(
        socket_path,
        ConnectIntent::Resume {
            session_id,
            after_seq,
        },
    )
    .await?;
    let mut client = await_viewer_ack(client, session_id, "Resume").await?;
    client.last_seq = Some(after_seq);
    Ok(client)
}

/// The shared tail of [`connect_attach`]/[`connect_resume`]: the first frame
/// back must be the daemon's `Ack`.
async fn await_viewer_ack(
    mut client: DaemonClient,
    session_id: SessionId,
    request: &str,
) -> Result<DaemonClient, TuiError> {
    match client.recv().await? {
        Some(ClientEvent::Ack { .. }) => {
            client.session_id = Some(session_id);
            Ok(client)
        }
        Some(ClientEvent::ResyncRequired { head, .. }) => Err(TuiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "the daemon requires a resync: the resume cursor is past this session's \
                     head ({head:?}); replay from the start"
            ),
        ))),
        Some(_) => Err(TuiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("expected an Ack confirming {request}, got a different frame"),
        ))),
        None => Err(TuiError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "daemon closed the connection instead of acknowledging {request} \
                 (the session may not exist)"
            ),
        ))),
    }
}

impl DaemonClient {
    /// The session this client is bound to.
    ///
    /// # Panics
    /// Panics if called on a client created via plain [`connect`] rather
    /// than [`connect_create`]/[`connect_attach`] — those two are the only
    /// constructors that establish a session identity at all, and every
    /// caller of this method already knows which one it used.
    pub fn session_id(&self) -> SessionId {
        self.session_id.expect(
            "session_id() called on a DaemonClient with no known session \
             (use connect_create/connect_attach)",
        )
    }

    /// The `seq` of the last `ClientEvent::Committed` this client has
    /// returned from [`Self::recv`] — or, for a client built by
    /// [`connect_resume`] that has not received one yet, the cursor it
    /// resumed from. `None` before either. Hand it to [`connect_resume`] to
    /// pick up exactly where this connection left off.
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    /// Sends `ClientRequest::CloseSession` for this client's own session,
    /// then waits for the daemon's `Ack` confirming the durable close,
    /// skipping any other frame that arrives first — the same "wait for the
    /// specific reply, not just any frame" shape [`connect_attach`] already
    /// uses for its own `Ack`. `Some(_) => continue` below discards every
    /// non-`Ack` frame while waiting: the daemon streams every committed
    /// event, including the close's own `SessionClosed`, ahead of the `Ack`
    /// (Phase 8 Task 21), and this call drops them rather than buffering
    /// them for a later `recv` (though [`Self::last_seq`] still advances
    /// past them).
    ///
    /// # No wire NAK exists
    ///
    /// A refusal on the daemon side (see `# Errors` below) produces no frame
    /// at all — a distinct wire-level NAK variant would be the durable fix,
    /// but adding one is a frozen-contract (`roundhouse-proto`) change
    /// outside this lane's scope, so this call can only ever distinguish
    /// "the daemon is silently refusing this" from "the close is genuinely
    /// still in progress" by timing out, not by reading an explicit answer.
    ///
    /// # Errors
    /// Returns whatever [`Self::send`]/[`Self::recv`] returns. Returns
    /// `TuiError::Io` (`ErrorKind::UnexpectedEof`) if the daemon closes the
    /// connection without ever sending an `Ack`. Returns `TuiError::Io`
    /// (`ErrorKind::TimedOut`) if no `Ack` arrives within
    /// [`CLOSE_SESSION_ACK_TIMEOUT`] — the case that actually matters in
    /// practice: every refusal `roundhouse_daemon::socket_server::
    /// drive_established_session` designs for `CloseSession` (wrong
    /// connection — e.g. this client having been built via
    /// [`connect_attach`] rather than [`connect_create`] — wrong session, a
    /// close already in flight, the session no longer being live, or a
    /// failed durable append) sends **no frame at all** and leaves the
    /// connection open, so a refusal is observed here as a timeout, never as
    /// a distinct error naming the reason.
    ///
    /// **A `TimedOut` error means this client must be discarded, not
    /// retried.** The internal wait loop above cancels a `Self::recv` call
    /// on timeout, which is not cancel-safe (see `recv`'s own doc comment);
    /// this method marks the client unusable when that happens, so every
    /// later call to [`Self::recv`] fails immediately with `ErrorKind::Other`
    /// rather than risk decoding a truncated frame as a spurious
    /// `TuiError::Json`, or worse, a well-formed but wrong one.
    ///
    /// **This call itself must not be cancelled from the outside** (wrapped
    /// in a caller's own `tokio::time::timeout`, raced in a `select!`
    /// branch, or otherwise dropped before it resolves). Doing so drops this
    /// method's own internal `recv` wait without ever reaching the code
    /// above that marks the client unusable — the safeguard this method
    /// provides for its own internal timeout does not extend to a cancel
    /// imposed on the whole call from outside it.
    ///
    /// # Panics
    /// Panics under the same condition [`Self::session_id`] does: this
    /// client must have been created via [`connect_create`]/[`connect_attach`].
    pub async fn close_session(&mut self) -> Result<(), TuiError> {
        let session_id = self.session_id();
        self.send(&ClientRequest::CloseSession { session_id })
            .await?;
        let wait = async {
            loop {
                match self.recv().await? {
                    Some(ClientEvent::Ack { .. }) => return Ok(()),
                    Some(_) => continue,
                    None => {
                        return Err(TuiError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "daemon closed the connection instead of acknowledging CloseSession",
                        )));
                    }
                }
            }
        };
        match tokio::time::timeout(CLOSE_SESSION_ACK_TIMEOUT, wait).await {
            Ok(result) => result,
            Err(_elapsed) => {
                // The `wait` future above was dropped mid-`recv`, which may
                // have already consumed (and now lost) bytes off the wire —
                // see `read_desynchronized`'s own doc comment. Mark this
                // client unusable rather than let a caller reuse it.
                self.read_desynchronized = true;
                Err(TuiError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "no Ack for CloseSession within {CLOSE_SESSION_ACK_TIMEOUT:?}; the \
                         daemon may be silently refusing it (wrong connection, wrong session, or \
                         the session is no longer live); this client must be discarded, not \
                         reused"
                    ),
                )))
            }
        }
    }

    /// Sends one `ClientRequest` as a single NDJSON line.
    ///
    /// # Errors
    /// Returns `TuiError::Json` if `request` fails to serialize, or
    /// `TuiError::Io` if the write fails.
    pub async fn send(&mut self, request: &ClientRequest) -> Result<(), TuiError> {
        let line = serde_json::to_string(request)?;
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.write_all(b"\n").await?;
        Ok(())
    }

    /// Receive the next NDJSON message from the daemon.
    ///
    /// Each message is one line of JSON, terminated by `\n`.
    /// Reads a line, parses it, and returns the [`ClientEvent`].
    ///
    /// Bounded at [`MAX_FRAME_BYTES`] (security review Minor 7 / ruling
    /// W1-R33): an earlier version of this method used
    /// `AsyncBufReadExt::read_line` directly, which — like the daemon's own
    /// pre-fix read side — grows its `String` without limit until it finds a
    /// `\n`. Wrapping `&mut self.reader` in `AsyncReadExt::take` for the
    /// duration of one call caps how many bytes `read_until` will pull
    /// before giving up, without needing a new dependency (see
    /// [`MAX_FRAME_BYTES`]'s doc comment) and without disturbing
    /// `self.reader`'s own buffered state across calls — `take` here wraps
    /// `&mut self.reader`, not `self.reader` itself, so the next call starts
    /// from wherever this one left off, exactly as `read_line` already did.
    ///
    /// # Cancel safety
    /// Not cancel-safe: dropping this call's `Future` before it resolves can
    /// lose bytes already pulled off `self.reader`'s underlying socket into
    /// this call's own local buffer, desynchronizing this reader from the
    /// wire with no way to recover the lost bytes. [`Self::close_session`] is
    /// the one caller in this crate that cancels a `recv` on timeout, and it
    /// marks the client unusable (`read_desynchronized`) when it does —
    /// any other caller wrapping this in its own `tokio::time::timeout` (or
    /// a `select!` branch) must do the same, or simply discard the client on
    /// cancellation rather than call `recv` again.
    ///
    /// # Returns
    /// - `Ok(Some(event))` if a complete message was read and parsed.
    /// - `Ok(None)` if EOF was reached (the connection closed gracefully)
    ///   before any bytes of a new frame arrived.
    /// - `Err(TuiError)` if I/O fails, the frame exceeds [`MAX_FRAME_BYTES`]
    ///   with no `\n` found, JSON is malformed, or this client was already
    ///   marked `read_desynchronized` by an earlier cancelled `recv`.
    pub async fn recv(&mut self) -> Result<Option<ClientEvent>, TuiError> {
        if self.read_desynchronized {
            return Err(TuiError::Io(std::io::Error::other(
                "this DaemonClient's reader may be desynchronized after a previous cancelled \
                 recv (see close_session's doc comment); it must be discarded rather than reused",
            )));
        }
        let mut buf = Vec::new();
        // `MAX_FRAME_BYTES + 1`: reading exactly one byte past the cap is
        // what lets this method tell "a line that is exactly at the cap,
        // terminated by `\n`" (fine) apart from "a line that hit the cap
        // with no `\n` in sight yet" (over length) — both would otherwise
        // read exactly `MAX_FRAME_BYTES` bytes and be indistinguishable.
        let n = (&mut self.reader)
            .take(MAX_FRAME_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)
            .await?;
        if n == 0 {
            return Ok(None);
        }
        if buf.len() > MAX_FRAME_BYTES && buf.last() != Some(&b'\n') {
            return Err(TuiError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("daemon frame exceeded the {MAX_FRAME_BYTES}-byte limit with no newline"),
            )));
        }
        // `String::from_utf8`, not `_lossy`: `read_line` used to reject
        // invalid UTF-8 as an `io::Error`, and silently substituting
        // replacement characters instead would change what a malformed
        // frame does from "this connection ends with a clear error" to
        // "this connection keeps running against corrupted data."
        let line = String::from_utf8(buf).map_err(|err| {
            TuiError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err))
        })?;
        let event: ClientEvent = serde_json::from_str(line.trim_end())?;
        if let ClientEvent::Committed { seq, .. } = &event {
            self.last_seq = Some(*seq);
        }
        Ok(Some(event))
    }
}
