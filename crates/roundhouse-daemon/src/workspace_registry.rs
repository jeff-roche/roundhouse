//! The daemon-owned, persisted mapping from workspace names to filesystem
//! identities.

use roundhouse_core::WorkspaceId;
use roundhouse_store::{insert_workspace, workspace_rows, StoreError, StorePool, WorkspaceRow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

const MAX_WORKSPACE_NAME_BYTES: usize = 4096;
const PROTECTED_SYSTEM_ROOTS: &[&str] = &[
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run", "/sbin", "/sys", "/tmp",
    "/usr", "/var", "/home",
];

/// A workspace registration supplied by an operator at daemon startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRegistration {
    pub name: String,
    pub root: PathBuf,
}

impl WorkspaceRegistration {
    pub fn new(name: impl Into<String>, root: PathBuf) -> Self {
        Self {
            name: name.into(),
            root,
        }
    }

    /// Validates the registration without changing the filesystem or database.
    pub fn validate(&self) -> Result<(), WorkspaceRegistryError> {
        normalized_root(&self.name, &self.root).map(|_| ())
    }
}

/// A validated workspace identity used by session construction and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub name: String,
    pub root: PathBuf,
    pub root_device: Option<i64>,
    pub root_inode: Option<i64>,
}

/// Errors encountered while loading, registering, or resolving workspaces.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceRegistryError {
    #[error("workspace name is empty")]
    EmptyName,
    #[error("workspace name is too long")]
    NameTooLong,
    #[error("workspace root must be an absolute path")]
    RelativeRoot,
    #[error("workspace root is unavailable")]
    RootUnavailable,
    #[error("workspace root is not a directory")]
    RootNotDirectory,
    #[error("workspace root must be valid UTF-8")]
    NonUtf8Root,
    #[error("workspace root '/' is not allowed")]
    FilesystemRootRejected,
    #[error("workspace root overlaps protected daemon or system state")]
    ProtectedRootRejected,
    #[error("protected daemon path is unavailable")]
    ProtectedPathUnavailable,
    #[error("workspace name is already registered to another root")]
    NameAlreadyRegistered,
    #[error("workspace root is already registered under another name")]
    RootAlreadyRegistered,
    #[error("persisted workspace root identity changed after restart")]
    RootIdentityChanged,
    #[error("unknown workspace name")]
    UnknownWorkspace { name: String },
    #[error("persisted workspace id is invalid")]
    InvalidStoredWorkspaceId,
    #[error("workspace registry lock is poisoned")]
    LockPoisoned,
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The in-memory view of the persisted workspace registry.
#[derive(Debug, Clone)]
pub struct WorkspaceRegistry {
    store: StorePool,
    entries: Arc<RwLock<HashMap<String, Workspace>>>,
    registration_lock: Arc<tokio::sync::Mutex<()>>,
    protected_paths: Arc<Vec<PathBuf>>,
}

impl WorkspaceRegistry {
    /// Opens the registry and revalidates every persisted filesystem identity.
    /// A changed symlink target or missing root prevents daemon startup instead
    /// of silently rebinding a name to another repository.
    pub async fn open(store: StorePool) -> Result<Self, WorkspaceRegistryError> {
        Self::open_with_protected_paths(store, Vec::new()).await
    }

    /// Opens the registry with daemon-owned paths that no workspace may contain
    /// or alias. The check is independent of the selected isolation mechanism.
    pub async fn open_with_protected_paths(
        store: StorePool,
        protected_paths: Vec<PathBuf>,
    ) -> Result<Self, WorkspaceRegistryError> {
        let protected_paths = protected_paths
            .into_iter()
            .map(|path| {
                path.canonicalize()
                    .map_err(|_| WorkspaceRegistryError::ProtectedPathUnavailable)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let rows = workspace_rows(&store).await?;
        let mut entries = HashMap::with_capacity(rows.len());
        let mut roots = HashMap::with_capacity(rows.len());
        for row in rows {
            let id = uuid::Uuid::parse_str(&row.id)
                .map(WorkspaceId::from_uuid)
                .map_err(|_| WorkspaceRegistryError::InvalidStoredWorkspaceId)?;
            let configured_root = PathBuf::from(&row.root_path);
            let (_, canonical_root) = normalized_root(&row.name, &configured_root)?;
            ensure_protected_root(&canonical_root, &protected_paths)?;
            if canonical_root.to_string_lossy() != row.canonical_root {
                return Err(WorkspaceRegistryError::RootIdentityChanged);
            }
            if filesystem_identity(&canonical_root) != (row.root_device, row.root_inode) {
                return Err(WorkspaceRegistryError::RootIdentityChanged);
            }
            if roots
                .insert(row.canonical_root.clone(), row.name.clone())
                .is_some()
            {
                return Err(WorkspaceRegistryError::RootAlreadyRegistered);
            }
            if entries
                .insert(
                    row.name.clone(),
                    Workspace {
                        id,
                        name: row.name,
                        root_device: row.root_device,
                        root_inode: row.root_inode,
                        root: canonical_root,
                    },
                )
                .is_some()
            {
                return Err(WorkspaceRegistryError::NameAlreadyRegistered);
            }
        }
        Ok(Self {
            store,
            entries: Arc::new(RwLock::new(entries)),
            registration_lock: Arc::new(tokio::sync::Mutex::new(())),
            protected_paths: Arc::new(protected_paths),
        })
    }

    /// Persists and returns a new workspace identity. Re-registering the same
    /// name and canonical root is idempotent; changing either identity fails.
    pub async fn register(
        &self,
        registration: WorkspaceRegistration,
    ) -> Result<Workspace, WorkspaceRegistryError> {
        let (root_path, canonical_root) = normalized_root(&registration.name, &registration.root)?;
        ensure_protected_root(&canonical_root, &self.protected_paths)?;
        let (root_device, root_inode) = filesystem_identity(&canonical_root);
        let _registration_guard = self.registration_lock.lock().await;
        let workspace = {
            let entries = self
                .entries
                .read()
                .map_err(|_| WorkspaceRegistryError::LockPoisoned)?;
            if let Some(existing) = entries.get(&registration.name) {
                if existing.root == canonical_root {
                    return Ok(existing.clone());
                }
                return Err(WorkspaceRegistryError::NameAlreadyRegistered);
            }
            if entries.values().any(|entry| entry.root == canonical_root) {
                return Err(WorkspaceRegistryError::RootAlreadyRegistered);
            }

            Workspace {
                id: WorkspaceId::new(),
                name: registration.name,
                root: canonical_root.clone(),
                root_device,
                root_inode,
            }
        };
        insert_workspace(
            &self.store,
            &WorkspaceRow {
                id: workspace.id.to_string(),
                name: workspace.name.clone(),
                root_path: root_path.to_string_lossy().into_owned(),
                canonical_root: canonical_root.to_string_lossy().into_owned(),
                root_device,
                root_inode,
            },
        )
        .await?;
        let mut entries = self
            .entries
            .write()
            .map_err(|_| WorkspaceRegistryError::LockPoisoned)?;
        entries.insert(workspace.name.clone(), workspace.clone());
        Ok(workspace)
    }

    /// Resolves a name without consulting process current directory or any
    /// other fallback source.
    pub fn resolve(&self, name: &str) -> Result<Workspace, WorkspaceRegistryError> {
        let workspace = self
            .entries
            .read()
            .map_err(|_| WorkspaceRegistryError::LockPoisoned)?
            .get(name)
            .cloned()
            .ok_or_else(|| WorkspaceRegistryError::UnknownWorkspace {
                name: name.to_string(),
            })?;
        ensure_protected_root(&workspace.root, &self.protected_paths)?;
        if filesystem_identity(&workspace.root) != (workspace.root_device, workspace.root_inode) {
            return Err(WorkspaceRegistryError::RootIdentityChanged);
        }
        Ok(workspace)
    }

    pub fn is_empty(&self) -> Result<bool, WorkspaceRegistryError> {
        Ok(self
            .entries
            .read()
            .map_err(|_| WorkspaceRegistryError::LockPoisoned)?
            .is_empty())
    }
}

fn normalized_root(name: &str, root: &Path) -> Result<(PathBuf, PathBuf), WorkspaceRegistryError> {
    if name.is_empty() {
        return Err(WorkspaceRegistryError::EmptyName);
    }
    if name.len() > MAX_WORKSPACE_NAME_BYTES {
        return Err(WorkspaceRegistryError::NameTooLong);
    }
    if name.contains('\0') {
        return Err(WorkspaceRegistryError::EmptyName);
    }
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        return Err(WorkspaceRegistryError::RelativeRoot);
    };
    let canonical = absolute
        .canonicalize()
        .map_err(|_| WorkspaceRegistryError::RootUnavailable)?;
    if absolute.to_str().is_none() || canonical.to_str().is_none() {
        return Err(WorkspaceRegistryError::NonUtf8Root);
    }
    if !canonical.is_dir() {
        return Err(WorkspaceRegistryError::RootNotDirectory);
    }
    if canonical == Path::new("/") {
        return Err(WorkspaceRegistryError::FilesystemRootRejected);
    }
    if overlaps_protected_system_root(&canonical) {
        return Err(WorkspaceRegistryError::ProtectedRootRejected);
    }
    if let Some(home) = roundhouse_policy::sealed::home_dir() {
        if home.canonicalize().ok().as_deref() == Some(canonical.as_path()) {
            return Err(WorkspaceRegistryError::ProtectedRootRejected);
        }
    }
    Ok((absolute, canonical))
}

fn overlaps_protected_system_root(canonical: &Path) -> bool {
    PROTECTED_SYSTEM_ROOTS.iter().any(|raw| {
        let protected = match Path::new(raw).canonicalize() {
            Ok(path) => path,
            Err(_) => return false,
        };
        canonical == protected
            || (*raw != "/tmp" && *raw != "/home" && canonical.starts_with(protected))
    })
}

fn filesystem_identity(path: &Path) -> (Option<i64>, Option<i64>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if let Ok(metadata) = std::fs::metadata(path) {
            return (Some(metadata.dev() as i64), Some(metadata.ino() as i64));
        }
    }
    (None, None)
}

fn ensure_protected_root(
    workspace_root: &Path,
    protected_paths: &[PathBuf],
) -> Result<(), WorkspaceRegistryError> {
    if protected_paths
        .iter()
        .any(|protected| paths_overlap(workspace_root, protected))
    {
        return Err(WorkspaceRegistryError::ProtectedRootRejected);
    }
    Ok(())
}

fn paths_overlap(a: &Path, b: &Path) -> bool {
    if a.starts_with(b) || b.starts_with(a) {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let Ok(a_metadata) = std::fs::metadata(a) else {
            return true;
        };
        let Ok(b_metadata) = std::fs::metadata(b) else {
            return true;
        };
        a_metadata.dev() == b_metadata.dev() && a_metadata.ino() == b_metadata.ino()
    }
    #[cfg(not(unix))]
    {
        false
    }
}
