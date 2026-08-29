//! Atomic write executor using temp file + rename.

use std::io::Write;
use std::path::Path;

use crate::error::ToolError;

/// Writes file contents atomically by writing to a temporary file in the same
/// directory as `path`, then atomically renaming it into place.
///
/// This ensures that if a crash or power failure occurs mid-write, the target
/// file is never left in a partially-written state. Same-directory temp file
/// placement is critical: rename() on the same filesystem is atomic at the OS
/// level; a temp file on a different filesystem would require a copy, losing
/// atomicity. See S-TOOL-3.
pub async fn write_file(path: &Path, contents: &[u8]) -> Result<(), ToolError> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();

    tokio::task::spawn_blocking(move || -> Result<(), ToolError> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(&contents)?;
        tmp.flush()?;
        tmp.persist(&path).map_err(|e| ToolError::Io(e.error))?;
        Ok(())
    })
    .await
    .map_err(|e| ToolError::Spawn(e.to_string()))?
}
