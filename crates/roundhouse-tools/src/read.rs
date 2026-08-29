//! File reading executor.

use std::path::Path;

use crate::error::ToolError;

/// Reads a file and returns its contents as a UTF-8 string.
///
/// # Arguments
///
/// * `path` - The path to the file to read.
///
/// # Returns
///
/// Returns `Ok(contents)` with the file contents as a string, or an `Err` containing
/// a `ToolError::Io` if the file cannot be read.
///
/// # Why we return `ToolError::Io` on read failures
///
/// Filesystem operations can fail for reasons like missing files, permission denied,
/// disk errors, etc. These are all IO errors from the operating system. The `ToolError::Io`
/// variant uses `#[from] std::io::Error`, so we can use the `?` operator and any
/// io::Error automatically converts to ToolError::Io, keeping error handling uniform
/// across all task executors.
pub async fn read_file(path: &Path) -> Result<String, ToolError> {
    let contents = tokio::fs::read_to_string(path).await?;
    Ok(contents)
}
