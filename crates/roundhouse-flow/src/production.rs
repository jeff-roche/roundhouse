//! Production adapters for durable workflow execution.
//!
//! [`SqliteWorkflowHost`] resolves registered job versions from the same
//! connection that drives a run. [`FileCheckpointer`] stores a restorable copy
//! of the workspace before a run is parked, so the checkpoint reference stays
//! valid after the process exits.

use std::fs;
use std::path::{Component, Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::exec::run_loop::{
    run_workflow, CalledWorkflow, RunLoopError, RunOutcome, SessionTree, WorkflowHost,
    WorkflowHostError,
};
use crate::exec::{RunContext, RunId, TaskSink};
use crate::job::Body;
use crate::job_store::{resolve_job, resolve_job_version, RegisteredJob};
use crate::parking::{CheckpointArtifact, CheckpointError, CheckpointRef, Checkpointer};
use crate::parse::WorkflowDef;
use roundhouse_core::{BlobRef, SessionId, Timestamp};

/// A workflow host backed by registered immutable job versions in SQLite.
///
/// Job resolution is performed against the connection driving the run. This
/// keeps job registration and run execution on one storage view and avoids a
/// second connection that could observe stale or unvalidated job content.
pub struct SqliteWorkflowHost {
    workspace_root: PathBuf,
    checkpointer: FileCheckpointer,
    session_tree: Box<dyn SessionTree>,
}

struct UnconfiguredSessionTree;

impl SessionTree for UnconfiguredSessionTree {
    fn reserve_child(
        &mut self,
        _parent: SessionId,
        _child: SessionId,
    ) -> Result<u32, WorkflowHostError> {
        Err(WorkflowHostError::SessionTreeUnavailable)
    }

    fn release_child(&mut self, _parent: SessionId, _child: SessionId) {}

    fn persist_child_session(
        &mut self,
        _txn: &rusqlite::Transaction<'_>,
        _child: &crate::durability::WorkflowRun,
    ) -> Result<(), WorkflowHostError> {
        Err(WorkflowHostError::SessionTreeUnavailable)
    }

    fn register_child(
        &mut self,
        _parent: SessionId,
        _child: SessionId,
        _job_id: roundhouse_core::JobId,
    ) -> Result<(), WorkflowHostError> {
        Err(WorkflowHostError::SessionTreeUnavailable)
    }

    fn direct_children(&mut self, _parent: SessionId) -> Result<u32, WorkflowHostError> {
        Err(WorkflowHostError::SessionTreeUnavailable)
    }
}

impl SqliteWorkflowHost {
    /// Creates a host that only resolves workflow sources within
    /// `workspace_root`.
    pub fn new(workspace_root: impl Into<PathBuf>) -> Self {
        let workspace_root = workspace_root.into();
        Self {
            checkpointer: FileCheckpointer::new(
                workspace_root.clone(),
                workspace_root
                    .parent()
                    .unwrap_or(&workspace_root)
                    .join(".roundhouse-state"),
            ),
            workspace_root,
            session_tree: Box::new(UnconfiguredSessionTree),
        }
    }

    /// Creates a host with the engine's authoritative session-tree service.
    /// This service must persist the child `SessionCreated` lifecycle event and
    /// include agent children when answering `direct_children`.
    pub fn with_session_tree(
        workspace_root: impl Into<PathBuf>,
        session_tree: Box<dyn SessionTree>,
    ) -> Self {
        let mut host = Self::new(workspace_root);
        host.session_tree = session_tree;
        host
    }

    /// Restores a checkpoint produced by this host's filesystem checkpointer.
    /// Restores the content-addressed checkpoint recorded by a parked run.
    /// This path does not depend on the in-memory manifest directory surviving
    /// a restart.
    pub fn restore_run(&self, conn: &Connection, run_id: RunId) -> Result<(), CheckpointError> {
        let run = crate::durability::recover_run(conn, run_id)
            .map_err(|e| checkpoint_error(&e.to_string()))?
            .run;
        let Some(blob_ref) = run.checkpoint_blob_ref else {
            return Err(checkpoint_error("run has no durable checkpoint blob"));
        };
        self.checkpointer
            .restore_blob(run.session_id, run_id, &blob_ref)
    }

    /// Resolves the latest registered version of `name`.
    pub fn resolve_job(
        &self,
        conn: &Connection,
        name: &str,
    ) -> Result<Option<RegisteredJob>, WorkflowHostError> {
        Ok(resolve_job(conn, &self.workspace_root, name)?)
    }

    /// Loads the exact workflow definition pinned by a durable run.
    pub fn resolve_run_definition(
        &self,
        conn: &Connection,
        run_id: RunId,
    ) -> Result<WorkflowDef, WorkflowHostError> {
        let run = crate::durability::recover_run(conn, run_id)?.run;
        let Some(job) = resolve_job_version(
            conn,
            &self.workspace_root,
            run.job_id,
            run.job_version,
            &run.content_hash,
        )?
        else {
            return Err(WorkflowHostError::JobStore(
                crate::job_store::JobStoreError::MalformedStoredField {
                    field: "workflow run job",
                },
            ));
        };
        let version = job
            .job
            .pinned(run.job_version)
            .ok_or(WorkflowHostError::JobStore(
                crate::job_store::JobStoreError::MalformedStoredField {
                    field: "workflow run version",
                },
            ))?;
        let Body::Workflow { workflow_yaml } = version.body() else {
            return Err(WorkflowHostError::JobStore(
                crate::job_store::JobStoreError::MalformedStoredField {
                    field: "workflow run body",
                },
            ));
        };
        Ok(crate::parse::parse_workflow(workflow_yaml)?)
    }
}

/// Drives a run using its durable pinned workflow definition rather than a
/// caller-provided or latest-resolved definition.
pub fn run_workflow_from_storage(
    conn: &mut Connection,
    run_id: RunId,
    sink: &mut dyn TaskSink,
    host: &mut SqliteWorkflowHost,
    run_ctx: RunContext,
    now: Timestamp,
    resume: Option<crate::exec::run_loop::GateAnswer>,
) -> Result<RunOutcome, RunLoopError> {
    let definition = host.resolve_run_definition(conn, run_id)?;
    run_workflow(conn, &definition, run_id, sink, host, run_ctx, now, resume)
}

impl WorkflowHost for SqliteWorkflowHost {
    fn resolve_call(
        &mut self,
        conn: &Connection,
        workflow: &str,
        _parent: SessionId,
    ) -> Result<Option<CalledWorkflow>, WorkflowHostError> {
        let Some(job) = self.resolve_job(conn, workflow)? else {
            return Ok(None);
        };
        let version = job.job.latest();
        let session_id = SessionId::new();
        Ok(Some(CalledWorkflow {
            job_id: version.job_id(),
            job_version: version.version(),
            content_hash: crate::job::content_hash(version),
            session_id,
        }))
    }

    fn reserve_child_session(
        &mut self,
        parent: SessionId,
        child: &CalledWorkflow,
    ) -> Result<u32, WorkflowHostError> {
        self.session_tree.reserve_child(parent, child.session_id)
    }

    fn release_child_session(&mut self, parent: SessionId, child: &CalledWorkflow) {
        self.session_tree.release_child(parent, child.session_id);
    }

    fn create_child_run(
        &mut self,
        conn: &mut Connection,
        parent: SessionId,
        child: &crate::durability::WorkflowRun,
        called: &CalledWorkflow,
    ) -> Result<(), WorkflowHostError> {
        let txn = roundhouse_store::begin_immediate(conn)?;
        let result = self
            .session_tree
            .persist_child_session(&txn, child)
            .and_then(|()| {
                crate::durability::insert_workflow_run_in_transaction(&txn, child)
                    .map_err(WorkflowHostError::from)
            });
        if let Err(error) = result {
            self.session_tree.release_child(parent, called.session_id);
            return Err(error);
        }
        if let Err(error) = txn.commit() {
            self.session_tree.release_child(parent, called.session_id);
            return Err(error.into());
        }
        self.session_tree
            .register_child(parent, called.session_id, called.job_id)
    }
}

impl Checkpointer for SqliteWorkflowHost {
    fn checkpoint(
        &mut self,
        session_id: SessionId,
        run_id: RunId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        self.checkpointer.checkpoint(session_id, run_id, label)
    }

    fn checkpoint_artifact(
        &mut self,
        session_id: SessionId,
        run_id: RunId,
        label: &str,
    ) -> Result<CheckpointArtifact, CheckpointError> {
        self.checkpointer
            .checkpoint_artifact(session_id, run_id, label)
    }

    fn commit_checkpoint(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        run_id: RunId,
        artifact: &CheckpointArtifact,
        now: Timestamp,
    ) -> Result<(), CheckpointError> {
        self.checkpointer
            .commit_checkpoint(txn, run_id, artifact, now)
    }
}

const CHECKPOINT_FORMAT_VERSION: u16 = 1;
const MAX_CHECKPOINT_FILES: usize = 10_000;
const MAX_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointManifest {
    format_version: u16,
    session_id: SessionId,
    run_id: String,
    label: String,
    files: Vec<CheckpointFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointFile {
    relative_path: PathBuf,
    length: u64,
    digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckpointArchive {
    manifest: CheckpointManifest,
    files: Vec<CheckpointArchiveFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckpointArchiveFile {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

/// A durable workspace snapshotter used by parked workflow runs.
///
/// Checkpoints are content-addressed archives in an explicit state directory;
/// no restorable copy is retained in the workspace.
pub struct FileCheckpointer {
    workspace_root: PathBuf,
    state_dir: PathBuf,
    quota_bytes: Option<u64>,
}

impl FileCheckpointer {
    /// Creates a checkpointer with checkpoint blobs in external `state_dir`.
    pub fn new(workspace_root: impl Into<PathBuf>, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            state_dir: state_dir.into(),
            quota_bytes: None,
        }
    }

    /// Creates a checkpointer with a durable checkpoint quota.
    pub fn with_quota(
        workspace_root: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        quota_bytes: u64,
    ) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            state_dir: state_dir.into(),
            quota_bytes: Some(quota_bytes),
        }
    }

    /// Applies a verified archive only after validating its complete manifest.
    pub fn restore_blob(
        &self,
        expected_session_id: SessionId,
        expected_run_id: RunId,
        blob_ref: &BlobRef,
    ) -> Result<(), CheckpointError> {
        let bytes = roundhouse_store::blobs::read_verified_blob(&self.state_dir, blob_ref)
            .map_err(|e| checkpoint_error(&e.to_string()))?;
        let archive: CheckpointArchive =
            serde_json::from_slice(&bytes).map_err(|e| checkpoint_error(&e.to_string()))?;
        validate_archive(&archive, expected_session_id, expected_run_id)?;
        let workspace_root = self
            .workspace_root
            .canonicalize()
            .map_err(|e| checkpoint_error(&e.to_string()))?;
        for file in &archive.files {
            let destination = workspace_root.join(&file.relative_path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).map_err(|e| checkpoint_error(&e.to_string()))?;
            }
            let temporary =
                destination.with_extension(format!("roundhouse-restore-{}", uuid::Uuid::new_v4()));
            fs::write(&temporary, &file.bytes).map_err(|e| checkpoint_error(&e.to_string()))?;
            fs::rename(&temporary, &destination).map_err(|e| checkpoint_error(&e.to_string()))?;
        }
        Ok(())
    }
}

impl Checkpointer for FileCheckpointer {
    fn checkpoint(
        &mut self,
        session_id: SessionId,
        run_id: RunId,
        label: &str,
    ) -> Result<CheckpointRef, CheckpointError> {
        let artifact = self.checkpoint_artifact(session_id, run_id, label)?;
        Ok(artifact.restore_ref)
    }

    fn checkpoint_artifact(
        &mut self,
        session_id: SessionId,
        run_id: RunId,
        label: &str,
    ) -> Result<CheckpointArtifact, CheckpointError> {
        let workspace_root = self
            .workspace_root
            .canonicalize()
            .map_err(|e| checkpoint_error(&e.to_string()))?;
        let mut files = Vec::new();
        collect_files(&workspace_root, &workspace_root, &mut files)?;
        let manifest = CheckpointManifest {
            format_version: CHECKPOINT_FORMAT_VERSION,
            session_id,
            run_id: run_id.to_string(),
            label: label.to_string(),
            files: files
                .iter()
                .map(|file| CheckpointFile {
                    relative_path: file.relative_path.clone(),
                    length: file.bytes.len() as u64,
                    digest: blake3::hash(&file.bytes).to_hex().to_string(),
                })
                .collect(),
        };
        let bytes = serde_json::to_vec(&CheckpointArchive { manifest, files })
            .map_err(|e| checkpoint_error(&e.to_string()))?;
        let blob_ref = roundhouse_store::blobs::write_blob(
            &self.state_dir,
            &bytes,
            Some("application/vnd.roundhouse.checkpoint+json".to_string()),
        )
        .map_err(|e| checkpoint_error(&e.to_string()))?;
        Ok(CheckpointArtifact {
            restore_ref: CheckpointRef(blob_ref.hash.to_string()),
            blob_ref: Some(blob_ref),
        })
    }

    fn commit_checkpoint(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        run_id: RunId,
        artifact: &CheckpointArtifact,
        now: Timestamp,
    ) -> Result<(), CheckpointError> {
        let Some(blob_ref) = artifact.blob_ref.as_ref() else {
            return Ok(());
        };
        if let Some(quota) = self.quota_bytes {
            let usage: i64 = txn.query_row("SELECT COALESCE(SUM(b.len), 0) FROM workflow_run r JOIN blobs b ON b.hash = json_extract(r.checkpoint_blob_ref, '$.hash') WHERE r.checkpoint_blob_ref IS NOT NULL AND r.id != ?1", [run_id.to_string()], |row| row.get(0))
                .map_err(|e| checkpoint_error(&e.to_string()))?;
            if u64::try_from(usage)
                .unwrap_or(u64::MAX)
                .saturating_add(blob_ref.len)
                > quota
            {
                return Err(checkpoint_error("checkpoint blob quota exceeded"));
            }
        }
        roundhouse_store::blobs::record_blob_write(
            txn,
            &self.state_dir,
            blob_ref,
            now.as_unix_nanos(),
        )
        .map_err(|e| checkpoint_error(&e.to_string()))
    }
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<CheckpointArchiveFile>,
) -> Result<(), CheckpointError> {
    let mut entries = fs::read_dir(current)
        .map_err(|e| checkpoint_error(&e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| checkpoint_error(&e.to_string()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| checkpoint_error("workspace entry is outside root"))?;
        if relative == Path::new(".git") {
            continue;
        }
        let metadata = fs::symlink_metadata(&path).map_err(|e| checkpoint_error(&e.to_string()))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            if files.len() == MAX_CHECKPOINT_FILES {
                return Err(checkpoint_error("checkpoint contains too many files"));
            }
            let bytes = fs::read(&path).map_err(|e| checkpoint_error(&e.to_string()))?;
            let total = files
                .iter()
                .try_fold(0_u64, |sum, file| sum.checked_add(file.bytes.len() as u64))
                .ok_or_else(|| checkpoint_error("checkpoint is too large"))?;
            if total
                .checked_add(bytes.len() as u64)
                .is_none_or(|size| size > MAX_CHECKPOINT_BYTES)
            {
                return Err(checkpoint_error("checkpoint is too large"));
            }
            files.push(CheckpointArchiveFile {
                relative_path: relative.to_path_buf(),
                bytes,
            });
        } else {
            return Err(checkpoint_error(
                "checkpoint contains an unsupported filesystem object",
            ));
        }
    }
    Ok(())
}

fn validate_archive(
    archive: &CheckpointArchive,
    session_id: SessionId,
    run_id: RunId,
) -> Result<(), CheckpointError> {
    if archive.manifest.format_version != CHECKPOINT_FORMAT_VERSION
        || archive.manifest.session_id != session_id
        || archive.manifest.run_id != run_id.to_string()
    {
        return Err(checkpoint_error(
            "checkpoint archive owner or format is invalid",
        ));
    }
    if archive.manifest.files.len() != archive.files.len()
        || archive.files.len() > MAX_CHECKPOINT_FILES
    {
        return Err(checkpoint_error("checkpoint archive is incomplete"));
    }
    let mut total = 0_u64;
    for (manifest, file) in archive.manifest.files.iter().zip(&archive.files) {
        validate_relative_path(&manifest.relative_path)?;
        if manifest.relative_path != file.relative_path
            || manifest.length != file.bytes.len() as u64
            || manifest.digest != blake3::hash(&file.bytes).to_hex().to_string()
        {
            return Err(checkpoint_error(
                "checkpoint archive file does not match its manifest",
            ));
        }
        total = total
            .checked_add(manifest.length)
            .ok_or_else(|| checkpoint_error("checkpoint is too large"))?;
        if total > MAX_CHECKPOINT_BYTES {
            return Err(checkpoint_error("checkpoint is too large"));
        }
    }
    if !archive
        .manifest
        .files
        .windows(2)
        .all(|pair| pair[0].relative_path < pair[1].relative_path)
    {
        return Err(checkpoint_error(
            "checkpoint archive paths are not sorted and unique",
        ));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), CheckpointError> {
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(checkpoint_error(
            "checkpoint path is not workspace-relative",
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, Component::Normal(name) if name == ".git"))
    {
        return Err(checkpoint_error(
            "checkpoint path cannot restore git metadata",
        ));
    }
    Ok(())
}

fn checkpoint_error(message: &str) -> CheckpointError {
    CheckpointError {
        message: message.to_string(),
    }
}
