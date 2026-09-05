//! Unix socket client for attaching to the daemon.
//!
//! Phase 7 Task 2 makes this speak `roundhouse-proto`'s real
//! `ClientRequest`/`ClientEvent` wire types instead of the retired
//! `ServerMessage`: `connect` now performs a real handshake by sending a
//! `ClientRequest` (see [`ConnectIntent`]) over a write half it actually
//! keeps, and [`DaemonClient::recv`] decodes the daemon's `ClientEvent`
//! frames rather than a daemon-pre-summarized shape.

use std::path::Path;

use roundhouse_core::{EventPayload, SessionId};
use roundhouse_proto::{ClientEvent, ClientRequest};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;

use crate::protocol::TuiError;

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
}

impl From<ConnectIntent> for ClientRequest {
    fn from(intent: ConnectIntent) -> Self {
        match intent {
            ConnectIntent::CreateSession { workspace_name } => {
                ClientRequest::CreateSession { workspace_name }
            }
            ConnectIntent::Attach { session_id } => ClientRequest::Attach { session_id },
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
    /// [`connect_attach`], which already knew it from its caller.
    session_id: Option<SessionId>,
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
    };
    client.send(&intent.into()).await?;
    Ok(client)
}

/// [`connect`] with [`ConnectIntent::CreateSession`], then read the daemon's
/// first reply frame to learn the `SessionId` it minted.
///
/// `ClientEvent` carries no dedicated "session created" reply (adding one to
/// `roundhouse-proto` would be a breaking edit to a frozen Phase 0 crate);
/// instead the daemon's first frame on a `CreateSession` handshake is a
/// `ClientEvent::TaskEvent` whose payload is `EventPayload::SessionCreated`
/// (see `roundhouse-daemon`'s `socket_server::drive_session`), and this
/// function is the client-side half of that convention: it reads frames
/// until it sees that one, caching the session id it carries so
/// [`DaemonClient::session_id`] can return it afterward.
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
            Some(ClientEvent::TaskEvent {
                session_id,
                payload,
                ..
            }) if matches!(*payload, EventPayload::SessionCreated { .. }) => {
                client.session_id = Some(session_id);
                return Ok(client);
            }
            // Anything else (an `Ack`, or a `TaskEvent` of some other kind)
            // arriving before the handshake frame keeps this loop reading
            // rather than misinterpreting it as the reply.
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
/// The wait matters, not just the confirmation: `roundhouse-daemon`'s
/// `SessionRegistry::attach` registers this connection's subscriber channel
/// as part of handling the `Attach` request, which does not happen until the
/// daemon actually reads that request off the wire — a delay `connect`
/// itself has no visibility into. A caller that published an event
/// immediately after `connect` returned, with no acknowledgement to wait
/// for, could race that registration and have the event delivered to no
/// one. Waiting for the `Ack` here closes that window: it cannot arrive
/// until `attach` has already run.
///
/// # Errors
/// Returns whatever [`connect`]/[`DaemonClient::recv`] returns. Also returns
/// `TuiError::Io` if the daemon closes the connection instead of
/// acknowledging (e.g. `session_id` names a session `attach` could not find
/// — see `SessionRegistry::attach`'s doc comment for why that is
/// indistinguishable, on the wire, from a session that never existed at
/// all), or if the very first frame back is something other than an `Ack`.
pub async fn connect_attach(
    socket_path: &Path,
    session_id: SessionId,
) -> Result<DaemonClient, TuiError> {
    let mut client = connect(socket_path, ConnectIntent::Attach { session_id }).await?;
    match client.recv().await? {
        Some(ClientEvent::Ack { .. }) => {
            client.session_id = Some(session_id);
            Ok(client)
        }
        Some(_) => Err(TuiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected an Ack confirming Attach, got a different frame",
        ))),
        None => Err(TuiError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "daemon closed the connection instead of acknowledging Attach \
             (the session may not exist)",
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
    /// # Returns
    /// - `Ok(Some(event))` if a complete message was read and parsed.
    /// - `Ok(None)` if EOF was reached (the connection closed gracefully).
    /// - `Err(TuiError)` if I/O fails or JSON is malformed.
    pub async fn recv(&mut self) -> Result<Option<ClientEvent>, TuiError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let event = serde_json::from_str(line.trim_end())?;
        Ok(Some(event))
    }
}
