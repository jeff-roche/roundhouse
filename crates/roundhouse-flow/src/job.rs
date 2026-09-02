//! `Job`/`JobVersion` — the immutable, versioned, content-addressed unit a
//! trigger binding ultimately fires. §8.3: "a prompt job is defined as
//! sugar for a single-step workflow" — collapsing scheduling and workflows
//! onto one execution path — so `Body::Prompt` is never executed directly;
//! it is always lowered to the same `workflow_yaml` shape `Body::Workflow`
//! carries, via [`Body::to_workflow_yaml`].
//!
//! Editing a job never mutates an existing [`JobVersion`] in place: it
//! appends a new version via [`Job::add_version`], so every prior version
//! stays retrievable via [`Job::pinned`] and a `workflow_run` can pin
//! `(job_id, version, content_hash)` and mean it forever. Immutability is
//! enforced by the type, not just by convention: `JobVersion` and `Job`
//! fields are private, there are no setters, `Job` cannot be constructed
//! without a first version (making the empty-versions state
//! unrepresentable), and `add_version` rejects anything that isn't a
//! strictly higher version number for the same job.

use roundhouse_core::{JobId, Tier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// The session shape a job's run executes under: provider/model selection,
/// working directory, tool allowlist, isolation tier, and a *reference* to
/// a named `PermissionPolicy` resolved through `roundhouse-policy` at
/// run-admission time. Only the reference is carried here, never the policy
/// content itself, so editing the named policy doesn't require minting a
/// new `JobVersion` (and doesn't change `content_hash`) — `roundhouse-flow`
/// has no dependency on `roundhouse-policy` (ruling P7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionTemplate {
    pub provider: String,
    pub model: String,
    pub cwd: String,
    pub tools: Vec<String>,
    pub isolation: Tier,
    pub permission_policy_ref: String,
}

/// A job's executable content. `Prompt` is sugar for a single-step
/// `Workflow` (§8.3) — see [`Body::to_workflow_yaml`] for the lowering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Body {
    Prompt { template: String },
    Workflow { workflow_yaml: String },
}

impl Body {
    /// Lowers this body to the workflow YAML text that
    /// `roundhouse_flow::parse::parse_workflow(yaml: &str) -> Result<WorkflowDef, ParseError>`
    /// (Task 2 of this subsystem) parses. This is the hand-off seam between
    /// the two tasks: `Body::Workflow` already carries raw YAML text
    /// verbatim, and `Body::Prompt` synthesizes YAML text in the same
    /// shape, so either variant's output can be passed to `parse_workflow`
    /// unchanged (`&body.to_workflow_yaml(name, version)`, a `String`
    /// coerces to `&str` at the call site).
    ///
    /// The synthesized YAML for `Prompt` deliberately includes every field
    /// `WorkflowDef` requires without a `#[serde(default)]` — `name`,
    /// `version`, `permissions` (with its own required `default` and
    /// `unattended.escalate`, plus `deadline`/`on_timeout` — Task 2's
    /// `parse_workflow` rejects `escalate: park` without both, per §8.5
    /// point 2, so this lowering must carry them too, not just the bare
    /// `escalate` tag), and `steps` — not just `steps`/`agent`, so a prompt
    /// job's lowering actually round-trips through `parse_workflow` rather
    /// than merely resembling workflow YAML. This is exercised directly by
    /// `tests/job.rs`'s
    /// `prompt_job_lowering_round_trips_through_parse_workflow`, which
    /// calls the real `roundhouse_flow::parse::parse_workflow` (fix round
    /// 1 on Task 10: an earlier version of this method emitted
    /// `escalate: park` alone, which Task 2's own cross-field validation —
    /// added in that same round — then rejected; the only test that
    /// existed at the time parsed the lowering as generic
    /// `serde_yaml::Value`, never through `parse_workflow`, so the break
    /// went undetected).
    pub fn to_workflow_yaml(&self, name: &str, version: u32) -> String {
        match self {
            Body::Workflow { workflow_yaml } => workflow_yaml.clone(),
            Body::Prompt { template } => {
                let indented_prompt = template.replace('\n', "\n        ");
                let mut yaml = String::new();
                yaml.push_str(&format!("name: {name}\n"));
                yaml.push_str(&format!("version: {version}\n"));
                yaml.push_str("permissions:\n");
                yaml.push_str("  default: deny\n");
                yaml.push_str("  unattended:\n");
                yaml.push_str("    escalate: park\n");
                // A prompt job is unattended-by-default sugar (§8.3); a
                // `park` escalation with no deadline/timeout would leave it
                // parked forever with nobody accountable for it, so this
                // lowering picks the same safe values §8.9's example
                // fixture uses for its own `park` escalation.
                yaml.push_str("    deadline: 24h\n");
                yaml.push_str("    on_timeout: deny\n");
                yaml.push_str("steps:\n");
                yaml.push_str("  - id: run\n");
                yaml.push_str("    agent:\n");
                yaml.push_str("      prompt: |\n");
                yaml.push_str(&format!("        {indented_prompt}\n"));
                yaml
            }
        }
    }
}

/// A job's declared input JSON Schema, validated against the run inputs
/// supplied at trigger time. Wrapped rather than a bare `serde_json::Value`
/// so a future task can attach schema-specific behavior without churning
/// every call site.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputSchema(pub serde_json::Value);

/// One immutable version of a `Job`'s content. Fields are private and there
/// are no setters — the only way to get a `JobVersion` is [`JobVersion::new`],
/// and the only way to change one is to build a different one. Editing a
/// job always produces a new `JobVersion` with `version` incremented,
/// appended via [`Job::add_version`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobVersion {
    job_id: JobId,
    version: u32,
    template: SessionTemplate,
    body: Body,
    input_schema: InputSchema,
}

impl JobVersion {
    pub fn new(
        job_id: JobId,
        version: u32,
        template: SessionTemplate,
        body: Body,
        input_schema: InputSchema,
    ) -> Self {
        Self {
            job_id,
            version,
            template,
            body,
            input_schema,
        }
    }

    pub fn job_id(&self) -> JobId {
        self.job_id
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn template(&self) -> &SessionTemplate {
        &self.template
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn input_schema(&self) -> &InputSchema {
        &self.input_schema
    }
}

/// Why [`Job::add_version`] refused a `JobVersion`.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum AddVersionError {
    #[error(
        "version belongs to job {actual}, but this job is {expected} — a JobVersion can only be added to its own job"
    )]
    JobIdMismatch { expected: JobId, actual: JobId },
    #[error(
        "versions must be added in strictly increasing order: latest is {latest}, attempted {attempted}"
    )]
    NotMonotonic { latest: u32, attempted: u32 },
}

/// A job, identified by `id`, retaining every version it has ever had.
/// `versions` is private and append-only (via [`Job::add_version`]) and can
/// never be empty: [`Job::new`] requires a first version, so the
/// no-versions state this type could otherwise represent simply doesn't
/// exist, and [`Job::latest`] never needs to panic to account for it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    id: JobId,
    /// Every prior version is retained; nothing here is ever mutated in
    /// place — see the module docs. Always non-empty; see the type docs.
    versions: Vec<JobVersion>,
}

impl Job {
    /// Creates a job with its first version. There is no way to construct a
    /// `Job` with zero versions.
    pub fn new(id: JobId, first_version: JobVersion) -> Self {
        Self {
            id,
            versions: vec![first_version],
        }
    }

    pub fn id(&self) -> JobId {
        self.id
    }

    /// Every version this job has ever had, oldest first.
    pub fn versions(&self) -> &[JobVersion] {
        &self.versions
    }

    /// Appends a new version. Rejects a version that isn't strictly higher
    /// than every existing version (editing a job must always move forward,
    /// never rewrite or reorder history) or that belongs to a different
    /// job id.
    pub fn add_version(&mut self, version: JobVersion) -> Result<(), AddVersionError> {
        if version.job_id() != self.id {
            return Err(AddVersionError::JobIdMismatch {
                expected: self.id,
                actual: version.job_id(),
            });
        }
        let latest = self.latest().version();
        if version.version() <= latest {
            return Err(AddVersionError::NotMonotonic {
                latest,
                attempted: version.version(),
            });
        }
        self.versions.push(version);
        Ok(())
    }

    /// The highest-numbered version. Never panics: `versions` is guaranteed
    /// non-empty by construction (see the type docs), not merely by
    /// convention.
    pub fn latest(&self) -> &JobVersion {
        self.versions
            .iter()
            .max_by_key(|v| v.version)
            .expect("Job::versions is non-empty by construction — see Job::new/add_version")
    }

    /// Look up a specific, pinned version. Old versions are never removed,
    /// so a `workflow_run` that pinned `(job_id, version, content_hash)` can
    /// always resolve it back.
    pub fn pinned(&self, version: u32) -> Option<&JobVersion> {
        self.versions.iter().find(|v| v.version == version)
    }
}

/// A stable content hash over a `JobVersion`'s content —
/// `template`/`body`/`input_schema`, deliberately excluding the identity
/// fields `job_id`/`version` — so a `workflow_run` can pin
/// `(job_id, version, content_hash)` and answer "did this job's *content*
/// actually change" independent of version bookkeeping.
///
/// # Stability
///
/// This hashes a canonical JSON encoding of the content fields with
/// SHA-256 (`sha2`), a fixed, versioned algorithm this crate pins itself —
/// deliberately NOT `std::collections::hash_map::DefaultHasher` (or any
/// `#[derive(Hash)]` built on it), whose algorithm is explicitly documented
/// as unstable across Rust releases and therefore unusable for
/// content-addressing (Subsystem A hit exactly this defect for
/// `Job`/`Binding` id generation and had to replace it with a
/// fixed-algorithm hash).
///
/// Determinism of the JSON encoding itself — not just the hash algorithm —
/// is also required: struct fields always serialize in their declared
/// order, and this workspace's `serde_json` is used with no
/// `preserve_order` feature anywhere in the dependency graph, so
/// `serde_json::Value::Object` (used by `InputSchema`'s embedded JSON
/// Schema) is backed by a `BTreeMap` and serializes any two
/// structurally-equal values identically regardless of the key insertion
/// order used to build them. Both properties are enforced by tests in
/// `tests/job.rs`, not just asserted here.
pub fn content_hash(job: &JobVersion) -> String {
    let canonical = serde_json::to_vec(&(&job.template, &job.body, &job.input_schema.0))
        .expect("JobVersion's fields are always JSON-serializable");
    let digest = Sha256::digest(&canonical);
    format!("sha256:{digest:x}")
}
