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
use std::convert::TryFrom;
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
                let mut yaml = String::new();
                yaml.push_str(&format!("name: {}\n", yaml_double_quoted(name)));
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
                yaml.push_str(&format!("      prompt: {}\n", yaml_double_quoted(template)));
                yaml
            }
        }
    }
}

/// Escapes `s` as a single-physical-line YAML double-quoted scalar, safe to
/// splice inline at any nesting/indentation depth.
///
/// Fix round 2 on Task 10 ("New Important"): [`Body::to_workflow_yaml`]
/// used to interpolate `name`/`template` into the generated YAML with a
/// bare `format!`, unescaped. A crafted `name` — e.g. `"x\ndefaults:\n
/// isolation: none\nsecrets: [AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN]"` —
/// parsed successfully as a sibling `defaults`/`secrets` key rather than
/// as the literal value of `name`, silently overriding
/// `defaults.isolation` to `none` (`Tier::None`, unsandboxed — directly
/// defeating [`crate::parse::types`]'s `default_isolation`, whose own doc
/// comment says an *omitted* value "must never silently fall back to
/// `None`" — this bypassed that by supplying an explicit one instead) and
/// injecting an attacker-chosen `secrets` list. This was a latent bug
/// predating this diff, but fix round 1 on Task 10 is what made it
/// *reachable*: before that round, every `Body::Prompt` lowering was
/// rejected by `parse_workflow`'s own Park-escalation validation (finding
/// C), so no interpolated content ever reached a real `WorkflowDef`.
///
/// `serde_yaml::to_string` was considered first (a real serializer's
/// escaping is presumptively correct), but its automatic style choice for
/// a multi-line string is a *literal block* (`|-`) indented relative to
/// column 0 — safe to splice only at the document's top level, and
/// silently invalid YAML once spliced under `template`'s actual nesting
/// (`steps[0].agent.prompt`, six columns deep), since a block scalar's
/// body must be indented *more* than its parent, which column-0-relative
/// output isn't once relocated. A hand-rolled double-quoted-scalar
/// escaper avoids that entirely: double-quoted scalars are never
/// indentation-sensitive (embedded newlines become the two-character
/// sequence `\n`, never a literal line break), so the result is always
/// exactly one physical line, splice-safe anywhere. Verified to round-trip
/// exactly (including at a non-trivial nesting depth) before landing this;
/// see `tests/job.rs`'s injection tests for the adversarial cases above.
///
/// # Fix round 3 on Task 10: escape every codepoint that isn't exact
///
/// A security audit swept every codepoint U+0000–U+FFFF (plus samples to
/// U+10FFFF) through `to_workflow_yaml` → `parse_workflow` and found this
/// function's original version — which only escaped `c < 0x20` — let 34
/// codepoints through unescaped that `serde_yaml` itself then either
/// rejected outright or silently mutated:
/// - **DEL (U+007F) and the C1 control range (U+0080–U+009F, minus
///   U+0085)**: not printable YAML characters at all — emitting them
///   literally made `to_workflow_yaml`'s *own* output fail to re-parse
///   with "control characters are not allowed."
/// - **U+0085 (NEL), and separately U+2028 (LINE SEPARATOR) /
///   U+2029 (PARAGRAPH SEPARATOR)**: these three *are* printable YAML
///   characters, but `libyaml` treats each as a line break inside a
///   double-quoted scalar and folds it — verified: `"a\u{0085}b"`
///   round-trips as `"a b"`, i.e. not an injection (the value stays one
///   scalar), but a silent mutation of a security-adjacent field whose
///   whole premise, per this doc comment above, is exactness.
/// - **Unicode noncharacters** (U+FDD0–U+FDEF, and the last two code
///   points of every plane — U+FFFE/U+FFFF and their per-plane
///   equivalents up to U+10FFFE/U+10FFFF): not valid for open
///   interchange, so escaped rather than emitted literally.
///
/// Escaping (rather than emitting literally) sidesteps all three
/// categories — verified empirically that `\xNN`/`\uNNNN`/`\UNNNNNNNN`
/// round-trip to the *exact* original code point, including U+0085 (no
/// line-fold happens when the character is spelled as an escape rather
/// than appearing as a literal control character in the source text).
fn yaml_double_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        let cp = c as u32;
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            _ if cp < 0x20 => out.push_str(&format!("\\x{cp:02x}")),
            // DEL + C1 controls (U+007F..U+009F): not printable YAML at
            // all; U+0085 (NEL) inside that range is additionally a
            // line-fold hazard (see doc comment above) — `\xNN` handles
            // both reasons identically and correctly.
            _ if (0x7F..=0x9F).contains(&cp) => out.push_str(&format!("\\x{cp:02x}")),
            // U+2028/U+2029: the same line-fold hazard as NEL, one BMP
            // plane over.
            '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{cp:04x}")),
            // Unicode noncharacters: last two code points of every plane
            // (`cp & 0xFFFE == 0xFFFE` matches U+_FFFE/U+_FFFF for every
            // plane prefix, including plane 0), plus the reserved
            // U+FDD0..=U+FDEF block.
            _ if (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE => {
                if cp <= 0xFFFF {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else {
                    out.push_str(&format!("\\U{cp:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
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

/// The single implementation of [`AddVersionError::JobIdMismatch`]'s check,
/// shared by [`Job::add_version`] (for every version after the first) and by
/// [`TryFrom<JobWire> for Job`](TryFrom) (for the first version, which
/// [`Job::new`] itself does not check — see that impl's comment). Keeping
/// this in one place means both call sites enforce byte-identical behavior
/// and cannot drift.
fn check_job_id(expected: JobId, version: &JobVersion) -> Result<(), AddVersionError> {
    if version.job_id() != expected {
        return Err(AddVersionError::JobIdMismatch {
            expected,
            actual: version.job_id(),
        });
    }
    Ok(())
}

/// A job, identified by `id`, retaining every version it has ever had.
/// `versions` is private and append-only (via [`Job::add_version`]) and can
/// never be empty: [`Job::new`] requires a first version, so the
/// no-versions state this type could otherwise represent simply doesn't
/// exist, and [`Job::latest`] never needs to panic to account for it.
///
/// Deserialized via `#[serde(try_from = "JobWire")]` rather than a plain
/// derive (Task 29): a derived `Deserialize` would build this struct
/// directly, bypassing both invariants below for wire/storage-sourced data
/// even though hand-written code can never violate them. `TryFrom<JobWire>
/// for Job` closes that gap by re-running the *same* validation — it builds
/// the `Job` through [`Job::new`] and [`Job::add_version`] rather than
/// re-implementing their checks, so there is exactly one implementation of
/// each invariant and the wire path cannot silently drift from the
/// hand-written path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "JobWire")]
pub struct Job {
    id: JobId,
    /// Every prior version is retained; nothing here is ever mutated in
    /// place — see the module docs. Always non-empty; see the type docs.
    versions: Vec<JobVersion>,
}

/// A plain-field mirror of [`Job`]'s wire shape, with no invariants of its
/// own — its only purpose is to be the `Deserialize` target that
/// `TryFrom<JobWire> for Job` then validates. Its field names and types
/// match `Job`'s exactly, so the serialized shape is unaffected (see
/// `tests/job.rs`'s round-trip regression test, which pins this).
#[derive(Debug, Deserialize)]
struct JobWire {
    id: JobId,
    versions: Vec<JobVersion>,
}

/// Why a deserialized [`JobWire`] could not be converted into a valid
/// [`Job`]: either it had zero versions (unrepresentable via [`Job::new`],
/// which requires a first version) or one of its versions failed the same
/// check [`Job::add_version`] applies to hand-written code.
#[derive(Debug, Error, Clone, PartialEq)]
pub enum JobFromWireError {
    #[error("a Job must have at least one version; found zero")]
    NoVersions,
    #[error(transparent)]
    InvalidVersion(#[from] AddVersionError),
}

impl TryFrom<JobWire> for Job {
    type Error = JobFromWireError;

    /// Builds the `Job` through its real constructors — [`Job::new`] for
    /// the first version, then [`Job::add_version`] for every version after
    /// it, in order — instead of re-implementing their validation. `Job::new`
    /// itself never checks that its first version's `job_id` matches the
    /// job's own id (hand-written callers pass both from the same value, so
    /// hand-written code can never violate it), so that one check is made
    /// explicit here via the same [`check_job_id`] helper `add_version`
    /// uses, rather than skipped.
    fn try_from(wire: JobWire) -> Result<Self, Self::Error> {
        let mut versions = wire.versions.into_iter();
        let first = versions.next().ok_or(JobFromWireError::NoVersions)?;
        check_job_id(wire.id, &first)?;
        let mut job = Job::new(wire.id, first);
        for version in versions {
            job.add_version(version)?;
        }
        Ok(job)
    }
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
        check_job_id(self.id, &version)?;
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
/// is also required: struct fields (`SessionTemplate`, `Body`) always
/// serialize in their declared order via `#[derive(Serialize)]`, and
/// `InputSchema`'s embedded JSON Schema — an arbitrary, user-supplied
/// `serde_json::Value` — is canonicalized by [`canonicalize_json`] before
/// hashing: every `Value::Object` it contains, at any nesting depth, has
/// its keys explicitly re-sorted (lexicographically, by `String`'s `Ord`)
/// into a fresh `Map` before serialization. The resulting byte stream
/// therefore depends only on the value's *structure*, never on the key
/// insertion order used to build it, and never on which `Map` backing
/// (a sorted `BTreeMap`, or an insertion-ordered map) `serde_json`'s
/// `preserve_order` feature happens to select for a given build — this
/// function does not rely on, or assert anything about, which of those
/// this workspace's Cargo feature unification currently chooses. Both
/// properties are enforced by tests in `tests/job.rs`, not just asserted
/// here.
pub fn content_hash(job: &JobVersion) -> String {
    let canonical_schema = canonicalize_json(&job.input_schema.0);
    let canonical = serde_json::to_vec(&(&job.template, &job.body, &canonical_schema))
        .expect("JobVersion's fields are always JSON-serializable");
    let digest = Sha256::digest(&canonical);
    format!("sha256:{digest:x}")
}

/// Return a `Value` equal to `value` but with every `Object`'s keys
/// re-inserted in sorted order, recursively, at every nesting depth
/// (including inside arrays). This makes the value's JSON *encoding*
/// canonical by construction: two structurally-equal `Value`s produce this
/// same sorted-key encoding regardless of the order their objects' keys
/// were originally inserted in, and regardless of whether the `Map`
/// `serde_json` uses under the hood is a `BTreeMap` or an insertion-ordered
/// map (i.e. regardless of the `preserve_order` feature).
///
/// `pub(crate)` rather than private (Task 18/B10, ruling P73): the workspace
/// already carries three copies of this recursive key-sort — here,
/// `roundhouse-policy`'s `approval.rs`, and `roundhouse-mcp`'s `executor.rs`,
/// the last with a written invitation to replace itself with a call to this
/// one if it were ever made public. [`crate::report`] needs the identical
/// property for [`crate::report::Report`]'s open extension fields and for the
/// carry-over seed, and a fourth copy *in the same crate as the first* would
/// be indefensible. Cross-crate deduplication is a separate move: this helper
/// would have to land in `roundhouse-core` to serve the other two, which is
/// not this task's to do.
pub(crate) fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonicalize_json(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}
