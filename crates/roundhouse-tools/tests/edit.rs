use roundhouse_tools::{edit_file, ToolError};

#[tokio::test]
async fn unique_match_is_replaced_and_diff_returned() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.rs");
    tokio::fs::write(&path, "fn main() {\n    println!(\"old\");\n}\n").await.unwrap();

    let outcome = edit_file(&path, "println!(\"old\");", "println!(\"new\");").await.unwrap();

    let updated = tokio::fs::read_to_string(&path).await.unwrap();
    assert_eq!(updated, "fn main() {\n    println!(\"new\");\n}\n");
    assert!(outcome.diff.contains("-    println!(\"old\");"));
    assert!(outcome.diff.contains("+    println!(\"new\");"));
}

#[tokio::test]
async fn absent_match_fails_closed_with_file_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.rs");
    let original = "fn main() {}\n";
    tokio::fs::write(&path, original).await.unwrap();

    let result = edit_file(&path, "does not exist anywhere", "replacement").await;

    assert!(matches!(result, Err(ToolError::NoMatch)));
    let on_disk = tokio::fs::read(&path).await.unwrap();
    assert_eq!(on_disk, original.as_bytes(), "file must be byte-for-byte unchanged");
}

#[tokio::test]
async fn ambiguous_match_fails_closed_with_file_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.rs");
    let original = "let x = 1;\nlet x = 1;\n";
    tokio::fs::write(&path, original).await.unwrap();

    let result = edit_file(&path, "let x = 1;", "let x = 2;").await;

    assert!(matches!(result, Err(ToolError::AmbiguousMatch(2))));
    let on_disk = tokio::fs::read(&path).await.unwrap();
    assert_eq!(on_disk, original.as_bytes(), "file must be byte-for-byte unchanged");
}
