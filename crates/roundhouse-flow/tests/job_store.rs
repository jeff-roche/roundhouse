use std::fs;

use roundhouse_core::Tier;
use roundhouse_flow::durability::open_test_db;
use roundhouse_flow::job::{AddVersionError, SessionTemplate};
use roundhouse_flow::job_store::{register_workflow_file, resolve_job, JobStoreError};
use tempfile::tempdir;

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "anthropic".to_string(),
        model: "claude-sonnet".to_string(),
        cwd: "/repo".to_string(),
        tools: vec!["read".to_string()],
        isolation: Tier::Worktree,
        permission_policy_ref: "default".to_string(),
    }
}

fn workflow(version: u32, name: &str) -> String {
    format!(
        "name: {name}\nversion: {version}\npermissions:\n  default: deny\n  unattended:\n    escalate: fail\nsteps: []\n"
    )
}

#[test]
fn registered_workflow_resolves_by_name_and_keeps_prior_versions() {
    let root = tempdir().expect("workspace tempdir");
    let source = root.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "nightly")).expect("write workflow");
    let mut conn = open_test_db();

    let first = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("register first version");
    let repeated = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("re-register unchanged workflow");
    assert_eq!(repeated.job.versions().len(), 1);
    fs::write(&source, workflow(2, "nightly")).expect("update workflow");
    let second = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("register second version");

    assert_eq!(first.name, "nightly");
    assert_eq!(second.job.id(), first.job.id());
    assert_eq!(second.job.latest().version(), 2);
    assert!(second.job.pinned(1).is_some());

    let resolved = resolve_job(&conn, root.path(), "nightly")
        .expect("resolve registered workflow")
        .expect("workflow exists");
    assert_eq!(resolved.job.id(), first.job.id());
    assert_eq!(resolved.job.latest().version(), 2);
    assert_ne!(
        resolved.job.latest().version(),
        resolved.job.pinned(1).unwrap().version()
    );
    fs::remove_file(&source).expect("remove source after registration");
    assert_eq!(
        resolve_job(&conn, root.path(), "nightly")
            .expect("resolve job after source removal")
            .expect("stored workflow exists")
            .job
            .latest()
            .version(),
        2
    );
    assert!(resolve_job(&conn, root.path(), "missing")
        .expect("resolve unknown workflow")
        .is_none());
}

#[test]
fn changed_workflow_cannot_reuse_an_existing_version() {
    let root = tempdir().expect("workspace tempdir");
    let source = root.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "versioned")).expect("write workflow");
    let mut conn = open_test_db();
    register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("register first version");

    fs::write(
        &source,
        format!("{}# changed content\n", workflow(1, "versioned")),
    )
    .expect("change workflow without bumping version");
    let error = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect_err("changed content must not reuse a version");
    assert!(matches!(
        error,
        JobStoreError::InvalidVersion(AddVersionError::NotMonotonic {
            latest: 1,
            attempted: 1
        })
    ));
}

#[test]
fn workflow_source_outside_workspace_is_rejected_before_persistence() {
    let workspace = tempdir().expect("workspace tempdir");
    let outside = tempdir().expect("outside tempdir");
    let source = outside.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "escaped")).expect("write workflow");
    let mut conn = open_test_db();

    let error = register_workflow_file(&mut conn, workspace.path(), &source, template())
        .expect_err("outside workflow must be rejected");
    assert!(matches!(error, JobStoreError::SourceOutsideWorkspace));
    assert!(resolve_job(&conn, workspace.path(), "escaped")
        .expect("resolve rejected workflow")
        .is_none());
}

#[cfg(unix)]
#[test]
fn symlinked_workflow_source_cannot_escape_the_workspace() {
    use std::os::unix::fs::symlink;

    let workspace = tempdir().expect("workspace tempdir");
    let outside = tempdir().expect("outside tempdir");
    let outside_source = outside.path().join("workflow.yaml");
    fs::write(&outside_source, workflow(1, "escaped-link")).expect("write workflow");
    let linked_source = workspace.path().join("workflow.yaml");
    symlink(&outside_source, &linked_source).expect("create workflow symlink");
    let mut conn = open_test_db();

    let error = register_workflow_file(&mut conn, workspace.path(), &linked_source, template())
        .expect_err("symlinked workflow must be rejected");
    assert!(matches!(error, JobStoreError::SourceOutsideWorkspace));
}

#[test]
fn duplicate_workflow_name_from_another_source_is_rejected() {
    let root = tempdir().expect("workspace tempdir");
    let first_source = root.path().join("one.yaml");
    let second_source = root.path().join("two.yaml");
    fs::write(&first_source, workflow(1, "same")).expect("write first workflow");
    fs::write(&second_source, workflow(1, "same")).expect("write second workflow");
    let mut conn = open_test_db();

    register_workflow_file(&mut conn, root.path(), &first_source, template())
        .expect("register first workflow");
    let error = register_workflow_file(&mut conn, root.path(), &second_source, template())
        .expect_err("duplicate workflow name must be rejected");
    assert!(matches!(error, JobStoreError::NameCollision { .. }));
}

#[test]
fn mismatched_stored_content_hash_fails_closed() {
    let root = tempdir().expect("workspace tempdir");
    let source = root.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "hash-corrupt")).expect("write workflow");
    let mut conn = open_test_db();
    let registered = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("register workflow");
    let job_id = uuid::Uuid::new_v4().to_string();
    let version = registered.job.latest();

    conn.execute(
        "INSERT INTO jobs (id, name, source_path) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            job_id,
            "hash-corrupt-copy",
            source.canonicalize().unwrap().to_string_lossy()
        ],
    )
    .expect("insert corrupt job row");
    conn.execute(
        "INSERT INTO job_versions
            (job_id, version, content_hash, template_json, body_json, input_schema_json)
         VALUES (?1, ?2, 'sha256:wrong', ?3, ?4, ?5)",
        rusqlite::params![
            job_id,
            i64::from(version.version()),
            serde_json::to_string(version.template()).unwrap(),
            serde_json::to_string(version.body()).unwrap(),
            serde_json::to_string(version.input_schema()).unwrap(),
        ],
    )
    .expect("insert mismatched version row");

    let error = resolve_job(&conn, root.path(), "hash-corrupt-copy")
        .expect_err("mismatched content hash must fail closed");
    assert!(matches!(error, JobStoreError::ContentHashMismatch));
}

#[test]
fn malformed_stored_version_fails_closed() {
    let root = tempdir().expect("workspace tempdir");
    let source = root.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "corrupt")).expect("write workflow");
    let conn = open_test_db();
    let job_id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO jobs (id, name, source_path) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            job_id,
            "corrupt",
            source.canonicalize().unwrap().to_string_lossy()
        ],
    )
    .expect("insert corrupt job row");
    conn.execute(
        "INSERT INTO job_versions
            (job_id, version, content_hash, template_json, body_json, input_schema_json)
         VALUES (?1, 1, 'sha256:bad', '{}', '{}', '{}')",
        rusqlite::params![job_id],
    )
    .expect("insert corrupt version row");

    let error = resolve_job(&conn, root.path(), "corrupt")
        .expect_err("malformed stored data must fail closed");
    assert!(matches!(
        error,
        JobStoreError::MalformedStoredField { field: "template" }
    ));
}

#[test]
fn registered_jobs_and_versions_are_immutable_in_sqlite() {
    let root = tempdir().expect("workspace tempdir");
    let source = root.path().join("workflow.yaml");
    fs::write(&source, workflow(1, "immutable")).expect("write workflow");
    let mut conn = open_test_db();
    let registered = register_workflow_file(&mut conn, root.path(), &source, template())
        .expect("register workflow");

    let update = conn.execute(
        "UPDATE job_versions SET content_hash = 'sha256:changed' WHERE job_id = ?1",
        rusqlite::params![registered.job.id().to_string()],
    );
    assert!(update.is_err(), "job versions must reject updates");
    let delete = conn.execute(
        "DELETE FROM jobs WHERE id = ?1",
        rusqlite::params![registered.job.id().to_string()],
    );
    assert!(delete.is_err(), "jobs must reject deletes");
    let update = conn.execute(
        "UPDATE jobs SET name = 'changed' WHERE id = ?1",
        rusqlite::params![registered.job.id().to_string()],
    );
    assert!(update.is_err(), "jobs must reject updates");
    let delete = conn.execute(
        "DELETE FROM job_versions WHERE job_id = ?1",
        rusqlite::params![registered.job.id().to_string()],
    );
    assert!(delete.is_err(), "job versions must reject deletes");
}
