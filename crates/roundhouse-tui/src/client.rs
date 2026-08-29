//! Unix socket client for attaching to the daemon.

use std::path::Path;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::unix::OwnedReadHalf;
use tokio::net::UnixStream;

use crate::protocol::{ServerMessage, TuiError};

/// A client connection to the daemon, reading NDJSON messages over a Unix socket.
///
/// Created by [`connect`], and used to receive a stream of [`ServerMessage`]s
/// via [`recv`](Self::recv).
pub struct DaemonClient {
    /// Buffered reader wrapping the socket's read half.
    reader: BufReader<OwnedReadHalf>,
}

/// Connect to the daemon's Unix socket at `socket_path`.
///
/// # Errors
/// Returns `TuiError::Io` if the connection fails.
pub async fn connect(socket_path: &Path) -> Result<DaemonClient, TuiError> {
    let stream = UnixStream::connect(socket_path).await?;
    let (read_half, _write_half) = stream.into_split();
    Ok(DaemonClient {
        reader: BufReader::new(read_half),
    })
}

impl DaemonClient {
    /// Receive the next NDJSON message from the daemon.
    ///
    /// Each message is one line of JSON, terminated by `\n`.
    /// Reads a line, parses it, and returns the [`ServerMessage`].
    ///
    /// # Returns
    /// - `Ok(Some(msg))` if a complete message was read and parsed.
    /// - `Ok(None)` if EOF was reached (the connection closed gracefully).
    /// - `Err(TuiError)` if I/O fails or JSON is malformed.
    pub async fn recv(&mut self) -> Result<Option<ServerMessage>, TuiError> {
        let mut line = String::new();
        let n = self.reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(None);
        }
        let message = serde_json::from_str(line.trim_end())?;
        Ok(Some(message))
    }
}
