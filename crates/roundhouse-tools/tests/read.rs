use roundhouse_tools::read_file;

#[tokio::test]
async fn reads_file_contents_as_utf8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.txt");
    tokio::fs::write(&path, "hello from disk").await.unwrap();

    let contents = read_file(&path).await.unwrap();

    assert_eq!(contents, "hello from disk");
}

#[tokio::test]
async fn missing_file_returns_io_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing.txt");

    let result = read_file(&path).await;

    assert!(matches!(result, Err(roundhouse_tools::ToolError::Io(_))));
}
