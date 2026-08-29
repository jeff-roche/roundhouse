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
    /// No match found for the given search text.
    #[error("no match found for the given search text")]
    NoMatch,
    /// Ambiguous match: multiple occurrences found when exactly one was expected.
    #[error("ambiguous match: {0} occurrences found, expected exactly 1")]
    AmbiguousMatch(usize),
    /// Glob pattern error, covering invalid glob syntax, non-UTF-8 patterns, path containment violations, and I/O errors during glob expansion.
    #[error("glob pattern error: {0}")]
    Glob(String),
}
