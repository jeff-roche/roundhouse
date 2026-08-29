use std::fs;
use std::path::{Path, PathBuf};

/// Walks every `.rs` and `.sql` file under the given root directory, running
/// `pattern_check` against each line. Returns every `(file, message)` hit.
/// Used internally by `scan_workspace_for` and by tests that need to scan
/// isolated directories without interfering with production scanning.
pub fn scan_dir_for(
    root: &Path,
    pattern_check: impl Fn(&str) -> Option<String>,
) -> Vec<(PathBuf, String)> {
    let mut hits = vec![];
    for file in walk_source_files(root) {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            if let Some(message) = pattern_check(line) {
                hits.push((file.clone(), message));
            }
        }
    }
    hits
}

/// Walks every `.rs` and `.sql` file under `crates/` (the workspace's real
/// source, `xtask` and `target` excluded), running `pattern_check` against
/// each line. Returns every `(file, message)` hit. Intended to be called
/// from small, single-purpose tests (see this task's two test files) so a
/// CI failure names exactly which invariant broke, not just "scan failed."
pub fn scan_workspace_for(
    pattern_check: impl Fn(&str) -> Option<String>,
) -> Vec<(PathBuf, String)> {
    let workspace_root = locate_workspace_root();
    let crates_dir = workspace_root.join("crates");
    scan_dir_for(&crates_dir, pattern_check)
}

fn locate_workspace_root() -> PathBuf {
    // xtask's own CARGO_MANIFEST_DIR is `<root>/xtask`; the workspace root
    // is its parent.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one directory below the workspace root")
        .to_path_buf()
}

fn walk_source_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            out.extend(walk_source_files(&path));
        } else if path.extension().is_some_and(|e| e == "rs" || e == "sql") {
            out.push(path);
        }
    }
    out
}
