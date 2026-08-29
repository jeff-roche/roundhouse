//! The minimal real server half of Task 18's `DaemonClient`: one Unix socket,
//! one attached client, NDJSON out.

use roundhouse_tui::ServerMessage;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Binds a Unix socket, accepts exactly one connection, and forwards every
/// `ServerMessage` sent on `rx` to it as one NDJSON line.
///
/// A production daemon serves many concurrent attached clients (§11.3); this
/// phase's exit criterion only needs one, to prove the wire format round-trips
/// end to end. `bind` runs synchronously *before* this function returns, so the
/// socket exists and is listening the moment the caller gets the `JoinHandle`
/// back — that ordering is load-bearing, since it's what lets a caller dial the
/// socket immediately instead of sleeping and hoping.
///
/// The spawned task exits when `rx` closes, when the peer goes away, or when the
/// accept fails; dropping the stream on the way out is what gives the client a
/// clean EOF rather than a hang. Nothing here panics on a hostile or vanished
/// peer: every write error ends the loop instead.
///
/// # Errors
/// Returns the `bind` error if the path is already in use, unwritable, or too
/// long for `sockaddr_un`.
pub fn serve_ndjson(
    socket_path: impl AsRef<Path>,
    mut rx: mpsc::Receiver<ServerMessage>,
) -> std::io::Result<JoinHandle<()>> {
    let listener = UnixListener::bind(socket_path)?;
    Ok(tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        while let Some(message) = rx.recv().await {
            // `ServerMessage` is a plain serde enum, so this cannot fail in
            // practice — but a serialization bug must drop one message, not take
            // down the daemon's only client connection.
            let line = match serde_json::to_string(&message) {
                Ok(line) => line,
                Err(err) => {
                    tracing::warn!(error = %err, "dropping unserializable ServerMessage");
                    continue;
                }
            };
            if stream.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if stream.write_all(b"\n").await.is_err() {
                break;
            }
        }
    }))
}
