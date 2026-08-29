use roundhouse_tools::run_shell;

#[tokio::test]
async fn runs_program_directly_and_captures_stdout() {
    let dir = tempfile::tempdir().unwrap();
    tokio::fs::write(dir.path().join("hello.txt"), b"hello world").await.unwrap();

    let output = run_shell("cat", &["hello.txt".to_string()], dir.path())
        .await
        .unwrap();

    assert_eq!(output.stdout, b"hello world");
    assert_eq!(output.exit_code, Some(0));
}

#[tokio::test]
async fn nonzero_exit_status_is_captured_not_treated_as_error() {
    let dir = tempfile::tempdir().unwrap();

    let output = run_shell("false", &[], dir.path()).await.unwrap();

    assert_eq!(output.exit_code, Some(1));
}
