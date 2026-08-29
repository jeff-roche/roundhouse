use roundhouse_tools::find_files;

#[test]
fn finds_files_matching_glob_rooted_at_base_dir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/main.rs"), "").unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();
    std::fs::write(dir.path().join("README.md"), "").unwrap();

    let mut matches = find_files(dir.path(), "src/*.rs").unwrap();
    matches.sort();

    assert_eq!(
        matches,
        vec![dir.path().join("src/lib.rs"), dir.path().join("src/main.rs")]
    );
}

#[test]
fn recursive_glob_pattern_matches_files_at_any_depth() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src/nested/deep")).unwrap();
    std::fs::write(dir.path().join("main.rs"), "").unwrap();
    std::fs::write(dir.path().join("src/lib.rs"), "").unwrap();
    std::fs::write(dir.path().join("src/nested/mod.rs"), "").unwrap();
    std::fs::write(dir.path().join("src/nested/deep/inner.rs"), "").unwrap();

    let mut matches = find_files(dir.path(), "**/*.rs").unwrap();
    matches.sort();

    assert_eq!(matches.len(), 4);
    assert!(matches.iter().any(|p| p.ends_with("main.rs")));
    assert!(matches.iter().any(|p| p.ends_with("lib.rs")));
    assert!(matches.iter().any(|p| p.ends_with("mod.rs")));
    assert!(matches.iter().any(|p| p.ends_with("inner.rs")));
}

#[test]
fn absolute_pattern_is_rejected_as_security_violation() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.txt"), "").unwrap();

    let result = find_files(dir.path(), "/etc/hostname");
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("relative") || err_msg.contains("absolute"),
        "error should mention pattern must be relative: {}",
        err_msg
    );
}

#[test]
fn parent_directory_escape_attempt_is_filtered() {
    let tmpdir = tempfile::tempdir().unwrap();
    let root = tmpdir.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    // Create a file outside the root directory (a sibling of root).
    let outside_marker = tmpdir.path().join("outside_marker.txt");
    std::fs::write(&outside_marker, "outside").unwrap();

    // Create a file inside root for comparison.
    std::fs::write(root.join("inside.txt"), "inside").unwrap();

    // Try to access the outside file via `..` traversal from within root.
    let result = find_files(&root, "../outside_marker.txt");

    // The result should either be empty (no matches) or an error, but NOT include the outside file.
    match result {
        Ok(matches) => {
            for m in matches {
                assert!(
                    m.starts_with(&root),
                    "matched path should be contained in root, got: {}",
                    m.display()
                );
            }
        }
        Err(_) => {
            // Error is also acceptable (canonicalization might fail during iteration).
        }
    }
}

#[test]
fn invalid_glob_pattern_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.txt"), "").unwrap();

    // Unterminated character class is invalid glob syntax.
    let result = find_files(dir.path(), "test[.txt");
    assert!(
        result.is_err(),
        "invalid glob pattern should return an error"
    );
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("glob") || err_msg.contains("pattern"),
        "error should mention glob or pattern: {}",
        err_msg
    );
}

#[test]
fn nonexistent_root_returns_error() {
    use std::path::Path;

    let nonexistent = Path::new("/this/path/does/not/exist/at/all");
    let result = find_files(nonexistent, "*.txt");
    assert!(result.is_err(), "nonexistent root should return an error");
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("not accessible") || err_msg.contains("root"),
        "error should mention root or accessibility: {}",
        err_msg
    );
}
