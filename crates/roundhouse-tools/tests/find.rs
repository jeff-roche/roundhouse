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
