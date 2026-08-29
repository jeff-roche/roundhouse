//! Find files matching a glob pattern rooted at a base directory.

use std::path::{Path, PathBuf};

use crate::error::ToolError;

/// Expands a glob pattern rooted at a base directory and returns matches sorted lexicographically.
///
/// # Arguments
///
/// * `root` - The base directory to search within
/// * `pattern` - A glob pattern (e.g., `"**/*.rs"`, `"src/*.rs"`) relative to the root
///
/// # Returns
///
/// A vector of sorted absolute paths matching the pattern, or a `ToolError` on failure.
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
    let full_pattern = root.join(pattern);
    let pattern_str = full_pattern
        .to_str()
        .ok_or_else(|| ToolError::Glob("pattern is not valid UTF-8".into()))?;

    let mut matches: Vec<PathBuf> = glob::glob(pattern_str)
        .map_err(|e| ToolError::Glob(e.to_string()))?
        .filter_map(Result::ok)
        .collect();
    matches.sort();
    Ok(matches)
}
