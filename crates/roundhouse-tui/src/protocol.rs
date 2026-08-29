//! Server message types and protocol errors.

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

/// Messages sent by the daemon to the TUI client over NDJSON.
///
/// Each message is a single line of JSON terminated by `\n`.
/// The `type` field determines which variant is deserialized.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// A task changed: new delta, completion, or error.
    #[serde(rename = "task_delta")]
    TaskDelta {
        /// Unique identifier for the task.
        task_id: String,
        /// Human-readable delta text (e.g. "started", "completed: success").
        text: String,
    },
    /// Session-level summary: counts and status.
    #[serde(rename = "session_summary")]
    SessionSummary {
        /// Unique identifier for the session.
        session_id: String,
        /// Number of tasks currently running in this session.
        running_tasks: u32,
        /// True if the session is waiting on something external.
        blocked: bool,
    },
}
