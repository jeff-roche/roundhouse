//! Error types for task executors.

/// Error type for executor operations.
#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    /// IO error from the operating system.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Process spawn failed.
    #[error("process spawn failed: {0}")]
    Spawn(String),
}
