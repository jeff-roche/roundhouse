use std::fs;

use roundhouse_core::WorkspaceId;
use roundhouse_daemon::workspace_registry::{
    WorkspaceRegistration, WorkspaceRegistry, WorkspaceRegistryError,
};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

async fn registry(db: &std::path::Path) -> WorkspaceRegistry {
    let store = roundhouse_store::open(db).await.unwrap();
    WorkspaceRegistry::open(store).await.unwrap()
}

async fn registry_with_protected_paths(
    db: &std::path::Path,
    protected_paths: Vec<std::path::PathBuf>,
) -> WorkspaceRegistry {
    let store = roundhouse_store::open(db).await.unwrap();
    WorkspaceRegistry::open_with_protected_paths(store, protected_paths)
        .await
        .unwrap()
}

#[tokio::test]
async fn registered_workspace_keeps_its_id_and_root_across_restart() {
    let state = tempfile::tempdir().unwrap();
    let repository = tempfile::tempdir().unwrap();
    let db = state.path().join("events.db");

    let first = registry(&db).await;
    let registered = first
        .register(WorkspaceRegistration::new(
            "alpha",
            repository.path().to_path_buf(),
        ))
        .await
        .unwrap();

    let second = registry(&db).await;
    let resolved = second.resolve("alpha").unwrap();
    assert_eq!(resolved.id, registered.id);
    assert_eq!(resolved.root, repository.path().canonicalize().unwrap());
}

#[tokio::test]
async fn unknown_workspace_names_are_refused() {
    let state = tempfile::tempdir().unwrap();
    let registry = registry(&state.path().join("events.db")).await;

    assert!(matches!(
        registry.resolve("missing"),
        Err(WorkspaceRegistryError::UnknownWorkspace { .. })
    ));
}

#[tokio::test]
async fn one_root_cannot_be_registered_under_two_names() {
    let state = tempfile::tempdir().unwrap();
    let repository = tempfile::tempdir().unwrap();
    let registry = registry(&state.path().join("events.db")).await;

    registry
        .register(WorkspaceRegistration::new(
            "alpha",
            repository.path().to_path_buf(),
        ))
        .await
        .unwrap();

    let error = registry
        .register(WorkspaceRegistration::new(
            "beta",
            repository.path().to_path_buf(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WorkspaceRegistryError::RootAlreadyRegistered
    ));
}

#[tokio::test]
#[cfg(unix)]
async fn a_changed_symlink_target_is_not_silently_rebound_after_restart() {
    use std::os::unix::fs::symlink;

    let state = tempfile::tempdir().unwrap();
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let link = state.path().join("workspace-link");
    symlink(first_root.path(), &link).unwrap();
    let db = state.path().join("events.db");

    let first = registry(&db).await;
    first
        .register(WorkspaceRegistration::new("alpha", link.clone()))
        .await
        .unwrap();

    fs::remove_file(&link).unwrap();
    symlink(second_root.path(), &link).unwrap();

    let store = roundhouse_store::open(&db).await.unwrap();
    let error = WorkspaceRegistry::open(store).await.unwrap_err();
    assert!(matches!(error, WorkspaceRegistryError::RootIdentityChanged));
}

#[tokio::test]
#[cfg(unix)]
async fn a_replaced_directory_at_the_same_path_is_not_rebound_after_restart() {
    let state = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join("workspace");
    let replacement = parent.path().join("replacement");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&replacement).unwrap();
    let db = state.path().join("events.db");

    let first = registry(&db).await;
    first
        .register(WorkspaceRegistration::new("alpha", root.clone()))
        .await
        .unwrap();

    fs::remove_dir(&root).unwrap();
    fs::rename(&replacement, &root).unwrap();

    assert!(matches!(
        first.resolve("alpha"),
        Err(WorkspaceRegistryError::RootIdentityChanged)
    ));
    let store = roundhouse_store::open(&db).await.unwrap();
    let error = WorkspaceRegistry::open(store).await.unwrap_err();
    assert!(matches!(error, WorkspaceRegistryError::RootIdentityChanged));
}

#[test]
fn registration_does_not_accept_the_filesystem_root() {
    let _ = WorkspaceId::new();
    let error = WorkspaceRegistration::new("root", "/".into()).validate();
    assert!(matches!(
        error,
        Err(WorkspaceRegistryError::FilesystemRootRejected)
    ));
}

#[cfg(unix)]
#[test]
fn registration_rejects_a_system_directory_root() {
    let error = WorkspaceRegistration::new("tmp", "/tmp".into())
        .validate()
        .unwrap_err();
    assert!(matches!(
        error,
        WorkspaceRegistryError::ProtectedRootRejected
    ));
}

#[cfg(unix)]
#[test]
fn registration_rejects_a_subdirectory_of_a_system_directory() {
    let error = WorkspaceRegistration::new("ssl", "/etc/ssl".into())
        .validate()
        .unwrap_err();
    assert!(matches!(
        error,
        WorkspaceRegistryError::ProtectedRootRejected
    ));
}

#[cfg(unix)]
#[test]
fn registration_rejects_a_non_utf8_root() {
    let parent = tempfile::tempdir().unwrap();
    let root = parent.path().join(std::ffi::OsString::from_vec(vec![0x80]));
    std::fs::create_dir(&root).unwrap();
    let error = WorkspaceRegistration::new("non-utf8", root)
        .validate()
        .unwrap_err();
    assert!(matches!(error, WorkspaceRegistryError::NonUtf8Root));
}

#[tokio::test]
async fn registration_rejects_a_root_that_contains_a_protected_daemon_path() {
    let state = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let protected = workspace.path().join("daemon-state");
    std::fs::create_dir(&protected).unwrap();
    let registry =
        registry_with_protected_paths(&state.path().join("events.db"), vec![protected]).await;

    let error = registry
        .register(WorkspaceRegistration::new(
            "workspace",
            workspace.path().to_path_buf(),
        ))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WorkspaceRegistryError::ProtectedRootRejected
    ));
}
