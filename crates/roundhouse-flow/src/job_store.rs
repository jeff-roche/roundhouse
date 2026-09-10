//! Durable storage for registered jobs and their immutable versions.
//!
//! The tables themselves belong to `roundhouse-store`, but this crate owns the
//! mapping between those rows and [`crate::job::Job`]. A workflow source is
//! canonicalized and checked against its workspace before any row is written;
//! resolution repeats that check so a modified database cannot turn a job into
//! a source outside the workspace.

use std::path::{Path, PathBuf};

use roundhouse_core::JobId;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::compose::input_schema_for_workflow;
use crate::job::{
    content_hash, AddVersionError, Body, InputSchema, Job, JobVersion, SessionTemplate,
};
use crate::parse::parse_workflow;

/// A job loaded from storage, including the source identity used to enforce
/// the workspace boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredJob {
    pub name: String,
    pub source_path: PathBuf,
    pub job: Job,
}

/// Why a job could not be registered or resolved.
#[derive(Debug, Error)]
pub enum JobStoreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Parse(#[from] crate::parse::ParseError),
    #[error("workspace root could not be resolved")]
    WorkspaceUnavailable,
    #[error("workflow source is outside the workspace")]
    SourceOutsideWorkspace,
    #[error("workflow name cannot be empty")]
    EmptyName,
    #[error("workflow name `{name}` is already registered from another source")]
    NameCollision { name: String },
    #[error("job version could not be appended: {0}")]
    InvalidVersion(#[from] AddVersionError),
    #[error("stored job {field} is malformed")]
    MalformedStoredField { field: &'static str },
    #[error("stored job content hash does not match its content")]
    ContentHashMismatch,
    #[error("stored job has no versions")]
    NoVersions,
}

/// Registers the workflow YAML at `source_path`, creating version one or
/// appending the version declared by the file. The source must be a real path
/// inside `workspace_root`; the stored job content remains usable after the
/// source file is later removed.
pub fn register_workflow_file(
    conn: &mut Connection,
    workspace_root: &Path,
    source_path: &Path,
    template: SessionTemplate,
) -> Result<RegisteredJob, JobStoreError> {
    let workspace_root = canonical_workspace(workspace_root)?;
    let source_path = canonical_source(&workspace_root, source_path)?;
    let yaml = std::fs::read_to_string(&source_path)?;
    register_canonical_workflow(conn, &source_path, template, &yaml)
}

/// Registers already-read workflow YAML under a canonicalized source path.
/// This is the testable core used by [`register_workflow_file`] and is also
/// useful to callers that already have a bounded file-reading layer.
pub fn register_workflow(
    conn: &mut Connection,
    workspace_root: &Path,
    source_path: &Path,
    template: SessionTemplate,
    yaml: &str,
) -> Result<RegisteredJob, JobStoreError> {
    let workspace_root = canonical_workspace(workspace_root)?;
    let source_path = canonical_source(&workspace_root, source_path)?;
    register_canonical_workflow(conn, &source_path, template, yaml)
}

fn register_canonical_workflow(
    conn: &mut Connection,
    source_path: &Path,
    template: SessionTemplate,
    yaml: &str,
) -> Result<RegisteredJob, JobStoreError> {
    let definition = parse_workflow(yaml)?;
    if definition.name.is_empty() {
        return Err(JobStoreError::EmptyName);
    }

    let version_number = definition.version;
    let body = Body::Workflow {
        workflow_yaml: yaml.to_string(),
    };
    let input_schema = InputSchema(input_schema_for_workflow(&definition));
    let name = definition.name;

    let tx = conn.transaction()?;
    let registered = match load_job_by_name(&tx, &name)? {
        Some(existing) => {
            if existing.source_path != source_path {
                return Err(JobStoreError::NameCollision { name: name.clone() });
            }
            let mut job = existing.job;
            let version = JobVersion::new(job.id(), version_number, template, body, input_schema);
            if let Some(previous) = job.pinned(version.version()) {
                if content_hash(previous) == content_hash(&version) {
                    return Ok(RegisteredJob {
                        name: existing.name,
                        source_path: source_path.to_path_buf(),
                        job,
                    });
                }
                return Err(JobStoreError::InvalidVersion(
                    AddVersionError::NotMonotonic {
                        latest: job.latest().version(),
                        attempted: version.version(),
                    },
                ));
            }
            job.add_version(version)?;
            insert_version(&tx, job.latest())?;
            RegisteredJob {
                name: existing.name,
                source_path: source_path.to_path_buf(),
                job,
            }
        }
        None => {
            let job_id = JobId::new();
            let version = JobVersion::new(job_id, version_number, template, body, input_schema);
            let job = Job::new(job_id, version);
            tx.execute(
                "INSERT INTO jobs (id, name, source_path) VALUES (?1, ?2, ?3)",
                params![job_id.to_string(), &name, source_path.to_string_lossy()],
            )?;
            insert_version(&tx, job.latest())?;
            RegisteredJob {
                name,
                source_path: source_path.to_path_buf(),
                job,
            }
        }
    };
    tx.commit()?;
    Ok(registered)
}

/// Resolves the latest durable version of `name`, or returns `None` when no
/// job has that name. Resolution verifies the stored source remains within the
/// current workspace before returning any executable content.
pub fn resolve_job(
    conn: &Connection,
    workspace_root: &Path,
    name: &str,
) -> Result<Option<RegisteredJob>, JobStoreError> {
    let workspace_root = canonical_workspace(workspace_root)?;
    let Some(mut job) = load_job_by_name(conn, name)? else {
        return Ok(None);
    };
    job.source_path = canonical_stored_source(&workspace_root, &job.source_path)?;
    Ok(Some(job))
}

/// Resolves the exact immutable version pinned by a workflow run. Unlike
/// [`resolve_job`], this never follows the latest version and verifies the
/// stored content hash before returning executable content.
pub fn resolve_job_version(
    conn: &Connection,
    workspace_root: &Path,
    job_id: JobId,
    version: u32,
    expected_hash: &str,
) -> Result<Option<RegisteredJob>, JobStoreError> {
    let Some(mut job) = load_job_by_id(conn, job_id)? else {
        return Ok(None);
    };
    job.source_path =
        canonical_stored_source(&canonical_workspace(workspace_root)?, &job.source_path)?;
    let Some(pinned) = job.job.pinned(version) else {
        return Err(JobStoreError::MalformedStoredField {
            field: "workflow run version",
        });
    };
    if content_hash(pinned) != expected_hash {
        return Err(JobStoreError::ContentHashMismatch);
    }
    Ok(Some(job))
}

fn canonical_workspace(path: &Path) -> Result<PathBuf, JobStoreError> {
    path.canonicalize()
        .map_err(|_| JobStoreError::WorkspaceUnavailable)
}

fn canonical_source(workspace_root: &Path, source_path: &Path) -> Result<PathBuf, JobStoreError> {
    let source_path = source_path
        .canonicalize()
        .map_err(|_| JobStoreError::SourceOutsideWorkspace)?;
    if !source_path.starts_with(workspace_root) || !source_path.is_file() {
        return Err(JobStoreError::SourceOutsideWorkspace);
    }
    Ok(source_path)
}

fn canonical_stored_source(
    workspace_root: &Path,
    source_path: &Path,
) -> Result<PathBuf, JobStoreError> {
    let source_path = match source_path.canonicalize() {
        Ok(path) => path,
        Err(_) => {
            let parent = source_path
                .parent()
                .ok_or(JobStoreError::SourceOutsideWorkspace)?
                .canonicalize()
                .map_err(|_| JobStoreError::SourceOutsideWorkspace)?;
            let file_name = source_path
                .file_name()
                .ok_or(JobStoreError::SourceOutsideWorkspace)?;
            parent.join(file_name)
        }
    };
    if !source_path.starts_with(workspace_root) {
        return Err(JobStoreError::SourceOutsideWorkspace);
    }
    Ok(source_path)
}

fn load_job_by_name(conn: &Connection, name: &str) -> Result<Option<RegisteredJob>, JobStoreError> {
    let Some((id, name, source_path)) = conn
        .query_row(
            "SELECT id, name, source_path FROM jobs WHERE name = ?1",
            params![name],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    let job_id = id
        .parse::<uuid::Uuid>()
        .map(JobId::from_uuid)
        .map_err(|_| JobStoreError::MalformedStoredField { field: "job id" })?;
    let job = load_versions(conn, &id, job_id)?;
    Ok(Some(RegisteredJob {
        name,
        source_path: PathBuf::from(source_path),
        job,
    }))
}

fn load_job_by_id(
    conn: &Connection,
    job_id: JobId,
) -> Result<Option<RegisteredJob>, JobStoreError> {
    let Some((id, name, source_path)) = conn
        .query_row(
            "SELECT id, name, source_path FROM jobs WHERE id = ?1",
            params![job_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    let stored_id = id
        .parse::<uuid::Uuid>()
        .map(JobId::from_uuid)
        .map_err(|_| JobStoreError::MalformedStoredField { field: "job id" })?;
    let job = load_versions(conn, &id, stored_id)?;
    Ok(Some(RegisteredJob {
        name,
        source_path: PathBuf::from(source_path),
        job,
    }))
}

fn load_versions(conn: &Connection, id: &str, job_id: JobId) -> Result<Job, JobStoreError> {
    let mut versions = conn.prepare(
        "SELECT version, content_hash, template_json, body_json, input_schema_json
           FROM job_versions
          WHERE job_id = ?1
          ORDER BY version ASC",
    )?;
    let rows = versions.query_map(params![id], |row| {
        Ok(StoredVersion {
            version: row.get(0)?,
            content_hash: row.get(1)?,
            template_json: row.get(2)?,
            body_json: row.get(3)?,
            input_schema_json: row.get(4)?,
        })
    })?;

    let mut decoded = Vec::new();
    for row in rows {
        decoded.push(decode_version(job_id, row?)?);
    }
    let first = decoded.drain(..1).next().ok_or(JobStoreError::NoVersions)?;
    let mut job = Job::new(job_id, first);
    for version in decoded {
        job.add_version(version)?;
    }

    Ok(job)
}

#[derive(Debug)]
struct StoredVersion {
    version: i64,
    content_hash: String,
    template_json: String,
    body_json: String,
    input_schema_json: String,
}

fn decode_version(job_id: JobId, row: StoredVersion) -> Result<JobVersion, JobStoreError> {
    let version = u32::try_from(row.version)
        .map_err(|_| JobStoreError::MalformedStoredField { field: "version" })?;
    let version = JobVersion::new(
        job_id,
        version,
        decode_json(&row.template_json, "template")?,
        decode_json(&row.body_json, "body")?,
        decode_json(&row.input_schema_json, "input schema")?,
    );
    if content_hash(&version) != row.content_hash {
        return Err(JobStoreError::ContentHashMismatch);
    }
    Ok(version)
}

fn decode_json<T: DeserializeOwned>(text: &str, field: &'static str) -> Result<T, JobStoreError> {
    serde_json::from_str(text).map_err(|_| JobStoreError::MalformedStoredField { field })
}

fn insert_version(tx: &Transaction<'_>, version: &JobVersion) -> Result<(), JobStoreError> {
    tx.execute(
        "INSERT INTO job_versions
             (job_id, version, content_hash, template_json, body_json, input_schema_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            version.job_id().to_string(),
            i64::from(version.version()),
            content_hash(version),
            serde_json::to_string(version.template())?,
            serde_json::to_string(version.body())?,
            serde_json::to_string(version.input_schema())?,
        ],
    )?;
    Ok(())
}
