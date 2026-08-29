//! Find files matching a glob pattern rooted at a base directory.

use std::path::{Path, PathBuf};

use crate::error::ToolError;

/// Expands a glob pattern rooted at a base directory and returns matches sorted lexicographically.
///
/// This function performs glob expansion constrained to a specified root directory,
/// enforcing real containment: absolute patterns and parent-directory (`..`) traversals
/// are rejected or filtered out. Glob expansion is CPU-bound and synchronous; callers on
/// the async path should wrap this in `spawn_blocking` if needed.
///
/// Note: matches may include both regular files and directories, matching raw glob
/// semantics; callers that need only files should filter results accordingly.
///
/// # Arguments
///
/// * `root` - The base directory to search within. Must exist and be canonicalizable.
/// * `pattern` - A glob pattern (e.g., `"**/*.rs"`, `"src/*.rs"`) relative to the root.
///   Absolute patterns (e.g., `"/etc/hostname"`) are rejected. Relative patterns with
///   parent-directory (`..`) components are filtered if they resolve outside `root`.
///
/// # Returns
///
/// A vector of sorted paths (relative to the file system root, but only those contained
/// in or below the canonicalized `root`), or a `ToolError` on failure.
///
/// # Errors
///
/// Returns `ToolError::Glob` if:
/// - `root` does not exist or cannot be canonicalized
/// - `pattern` is an absolute path
/// - `pattern` is invalid UTF-8 or contains invalid glob syntax
/// - I/O errors occur during directory traversal
///
/// # Examples
///
/// ```no_run
/// use std::path::Path;
/// use roundhouse_tools::find_files;
///
/// let matches = find_files(Path::new("/path/to/root"), "src/*.rs").unwrap();
/// // Returns sorted paths like ["/path/to/root/src/lib.rs", "/path/to/root/src/main.rs"]
/// ```
pub fn find_files(root: &Path, pattern: &str) -> Result<Vec<PathBuf>, ToolError> {
    // Canonicalize root first to get the real, absolute path (fails if root doesn't exist).
    let canonical_root = root
        .canonicalize()
        .map_err(|e| ToolError::Glob(format!("root directory not accessible: {}", e)))?;

    // Reject absolute patterns to prevent path traversal.
    if Path::new(pattern).is_absolute() {
        return Err(ToolError::Glob(
            "pattern must be relative, not absolute".into(),
        ));
    }

    // Construct the full glob pattern.
    let full_pattern = canonical_root.join(pattern);
    let pattern_str = full_pattern
        .to_str()
        .ok_or_else(|| ToolError::Glob("pattern is not valid UTF-8".into()))?;

    // Expand the glob pattern. Each entry is canonicalized and checked for containment.
    let matches: Result<Vec<PathBuf>, ToolError> = glob::glob(pattern_str)
        .map_err(|e| ToolError::Glob(format!("invalid glob pattern: {}", e)))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ToolError::Glob(format!("I/O error during glob traversal: {}", e)))
        .and_then(|paths| {
            // Canonicalize each match and verify it is contained within canonical_root.
            paths
                .into_iter()
                .filter_map(|path| {
                    match path.canonicalize() {
                        Ok(canonical_path) => {
                            if canonical_path.starts_with(&canonical_root) {
                                Some(Ok(canonical_path))
                            } else {
                                // Drop paths that escape root; don't error, just exclude them.
                                None
                            }
                        }
                        Err(e) => {
                            // Convert I/O errors during canonicalization into ToolError.
                            Some(Err(ToolError::Glob(format!(
                                "failed to canonicalize match: {}",
                                e
                            ))))
                        }
                    }
                })
                .collect()
        });

    let mut matches = matches?;
    matches.sort();
    Ok(matches)
}
