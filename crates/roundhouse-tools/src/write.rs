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
///
/// Permission preservation: `NamedTempFile` is created at mode `0600`, and
/// `persist()` is implemented as `rename()`, which replaces the target
/// *inode* outright rather than mutating it in place. Left alone, this would
/// silently reset an existing file's permissions (and drop ownership,
/// xattrs, and hard links) on every write — a `0755` script would silently
/// become non-executable, a `0644` config silently unreadable to whatever
/// consumes it. Before persisting, if `path` already exists, this function
/// reads its mode via `symlink_metadata` (which inspects the link at `path`
/// itself rather than following it — matching exactly what `rename()` is
/// about to replace) and applies that mode to the temp file first, so the
/// on-disk mode survives the edit. If `path` does not yet exist, there is no
/// prior mode to preserve: the new file is created at the temp file's
/// default mode (`0600`, minus umask), same as any other new-file creation.
pub async fn write_file(path: &Path, contents: &[u8]) -> Result<(), ToolError> {
    let path = path.to_path_buf();
    let contents = contents.to_vec();

    tokio::task::spawn_blocking(move || -> Result<(), ToolError> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        tmp.write_all(&contents)?;
        tmp.flush()?;

        #[cfg(unix)]
        if let Ok(existing) = std::fs::symlink_metadata(&path) {
            use std::os::unix::fs::PermissionsExt;
            let mode = existing.permissions().mode();
            // Best-effort: preserving the mode is important, but failing to
            // read/apply it should not abort an otherwise-successful write.
            let _ = tmp
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(mode));
        }

        tmp.persist(&path).map_err(|e| ToolError::Io(e.error))?;
        Ok(())
    })
    .await
    .map_err(|e| ToolError::Spawn(e.to_string()))?
}
