use roundhouse_tools::write_file;

#[tokio::test]
async fn writes_file_atomically_via_temp_and_rename() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.txt");

    write_file(&path, b"new contents").await.unwrap();

    let on_disk = tokio::fs::read(&path).await.unwrap();
    assert_eq!(on_disk, b"new contents");

    // No leftover temp files after a successful write.
    let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        names.push(entry.file_name());
    }
    assert_eq!(names, vec![std::ffi::OsString::from("out.txt")]);
}

#[tokio::test]
async fn overwrites_existing_file_completely() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("out.txt");
    tokio::fs::write(&path, b"old contents, much longer than the new one")
        .await
        .unwrap();

    write_file(&path, b"new").await.unwrap();

    let on_disk = tokio::fs::read(&path).await.unwrap();
    assert_eq!(on_disk, b"new");
}

#[cfg(unix)]
#[tokio::test]
async fn preserves_existing_file_mode_across_write() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("script.sh");
    tokio::fs::write(&path, b"#!/bin/sh\necho old\n")
        .await
        .unwrap();
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .await
        .unwrap();

    write_file(&path, b"#!/bin/sh\necho new\n").await.unwrap();

    let mode = tokio::fs::metadata(&path)
        .await
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o777,
        0o755,
        "write_file must not reset an existing file's permissions"
    );
}
