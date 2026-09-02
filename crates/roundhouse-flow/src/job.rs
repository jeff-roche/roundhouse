//! `Job`/`JobVersion` — the immutable, versioned, content-addressed unit a
//! trigger binding ultimately fires. §8.3: "a prompt job is defined as
//! sugar for a single-step workflow" — collapsing scheduling and workflows
//! onto one execution path — so `Body::Prompt` is never executed directly;
//! it is always lowered to the same `workflow_yaml` shape `Body::Workflow`
//! carries, via [`Body::to_workflow_yaml`].
//!
//! Editing a job never mutates an existing [`JobVersion`] in place: it
//! appends a new version to [`Job::versions`], so every prior version stays
//! retrievable via [`Job::pinned`] and a `workflow_run` can pin
//! `(job_id, version, content_hash)` and mean it forever.

use roundhouse_core::{JobId, Tier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    /// `unattended.escalate`), and `steps` — not just `steps`/`agent`, so a
    /// prompt job's lowering actually round-trips through `parse_workflow`
    /// rather than merely resembling workflow YAML.
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

/// One immutable version of a `Job`'s content. Never mutated after creation
/// — editing a job always produces a new `JobVersion` with `version`
/// incremented, appended to `Job::versions`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobVersion {
    pub job_id: JobId,
    pub version: u32,
    pub template: SessionTemplate,
    pub body: Body,
    pub input_schema: InputSchema,
}

/// A job, identified by `id`, retaining every version it has ever had.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: JobId,
    /// Every prior version is retained; nothing here is ever mutated in
    /// place — see the module docs.
    pub versions: Vec<JobVersion>,
}

impl Job {
    /// The highest-numbered version. Panics if `versions` is empty, which
    /// should never happen: a `Job` is never constructed without at least
    /// one version.
    pub fn latest(&self) -> &JobVersion {
        self.versions
            .iter()
            .max_by_key(|v| v.version)
            .expect("job always has >=1 version")
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
