//! Protocol error type for TUI client operations.
//!
//! Used to carry `roundhouse-proto`'s own `ClientRequest`/`ClientEvent` wire
//! types (see `client.rs`). This module used to also define `ServerMessage`,
//! a hand-rolled, daemon-pre-summarized wire type; Phase 7 Task 2 retired it
//! in favor of the real `roundhouse-proto` types, since `ServerMessage`'s two
//! flattened variants could not represent an MCP tool call, a policy denial,
//! or a sub-agent spawn event. `TuiError` survives because it still has real
//! users: `client.rs`'s `send`/`recv`.

/// Error type for TUI client operations.
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    /// I/O error from the Unix socket connection.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON decoding error from malformed NDJSON.
    #[error("json decode error: {0}")]
    Json(#[from] serde_json::Error),
}
