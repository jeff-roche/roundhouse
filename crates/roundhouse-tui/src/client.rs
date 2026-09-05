//! Unix socket client for attaching to the daemon.
//!
//! Phase 7 Task 2 makes this speak `roundhouse-proto`'s real
//! `ClientRequest`/`ClientEvent` wire types instead of the retired
//! `ServerMessage`: `connect` now performs a real handshake by sending a
//! `ClientRequest` (see [`ConnectIntent`]) over a write half it actually
//! keeps, and [`DaemonClient::recv`] decodes the daemon's `ClientEvent`
//! frames rather than a daemon-pre-summarized shape.

use std::path::Path;

use roundhouse_core::SessionId;
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
    };
    client.send(&intent.into()).await?;
    Ok(client)
}

impl DaemonClient {
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
