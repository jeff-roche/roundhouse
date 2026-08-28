use thiserror::Error;

/// Shared error surface for pure, synchronous, in-memory operations in
/// `roundhouse-core` (validation, folding, id parsing). Crates that do I/O
/// define their own richer error types and wrap `CoreError` as a source.
#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid id: {0}")]
    InvalidId(String),

    #[error("schema version {found} is newer than the highest known version {max_known}")]
    UnknownSchemaVersion { found: u16, max_known: u16 },

    #[error("task {task} is not in a valid state for this transition: {reason}")]
    InvalidTaskTransition { task: crate::ids::TaskId, reason: String },

    #[error("invalid task state string: {0:?}")]
    InvalidTaskState(String),
}
