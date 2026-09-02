use roundhouse_core::JobId;
use roundhouse_flow::job::{content_hash, Body, InputSchema, Job, JobVersion, SessionTemplate};

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "anthropic".to_string(),
        model: "claude-sonnet".to_string(),
        cwd: "/repo".to_string(),
        tools: vec!["read".to_string(), "shell".to_string()],
        isolation: roundhouse_core::Tier::Worktree,
        permission_policy_ref: "pr-review-default".to_string(),
    }
}

#[test]
fn editing_a_job_produces_a_new_immutable_version_with_a_different_hash() {
    let v1 = JobVersion {
        job_id: JobId::new(),
        version: 1,
        template: template(),
        body: Body::Workflow {
            workflow_yaml: "name: pr-review\nversion: 1\n".to_string(),
        },
        input_schema: InputSchema(serde_json::json!({"type": "object"})),
    };
    let mut v2 = v1.clone();
    v2.version = 2;
    v2.body = Body::Workflow {
        workflow_yaml: "name: pr-review\nversion: 2\n".to_string(),
    };

    let hash1 = content_hash(&v1);
    let hash2 = content_hash(&v2);
    assert_ne!(hash1, hash2, "different body content must hash differently");

    let job = Job {
        id: v1.job_id,
        versions: vec![v1, v2],
    };
    assert_eq!(job.latest().version, 2);
    assert_eq!(
        job.pinned(1).unwrap().version,
        1,
        "old versions remain retrievable, never mutated"
    );
}

#[test]
fn a_prompt_job_is_sugar_for_a_single_step_workflow() {
    // §8.3: "a prompt job is defined as sugar for a single-step workflow" —
    // collapses scheduling and workflows into one execution path.
    let body = Body::Prompt {
        template: "Summarize open PRs in ${{ inputs.repo }}".to_string(),
    };
    let as_workflow_yaml = body.to_workflow_yaml("adhoc-prompt", 1);
    assert!(as_workflow_yaml.contains("steps:"));
    assert!(as_workflow_yaml.contains("agent:"));
}

#[test]
fn prompt_lowering_is_actually_consumable_by_the_task_2_workflow_parser_shape() {
    // The cross-task seam this task's dispatch flagged: `Body::Workflow`
    // carries raw YAML, `parse_workflow(yaml: &str) -> Result<WorkflowDef, ParseError>`
    // (Task 2 of this subsystem) parses raw YAML — so `Body::Prompt`'s
    // lowering must itself be a valid `&str` of YAML text carrying every
    // field `WorkflowDef` requires without a `#[serde(default)]`: `name`,
    // `version`, `permissions` (with required `default` and
    // `unattended.escalate`), and `steps`. This crate doesn't (yet) depend
    // on `serde_yaml` in `src/`, so this test parses the generated text as
    // a generic YAML document (a stand-in for Task 2's `parse_workflow`,
    // whose `WorkflowDef` is a strict superset of these keys) to prove it
    // is well-formed and carries them, rather than merely containing the
    // substrings "steps:"/"agent:".
    let body = Body::Prompt {
        template: "line one\nline two".to_string(),
    };
    let yaml_text = body.to_workflow_yaml("adhoc-prompt", 7);

    let doc: serde_yaml::Value = serde_yaml::from_str(&yaml_text)
        .expect("Body::Prompt::to_workflow_yaml must produce parseable YAML");
    let map = doc.as_mapping().expect("top level is a mapping");

    assert_eq!(
        map.get("name").and_then(|v| v.as_str()),
        Some("adhoc-prompt")
    );
    assert_eq!(map.get("version").and_then(|v| v.as_u64()), Some(7));

    let permissions = map
        .get("permissions")
        .and_then(|v| v.as_mapping())
        .expect("permissions is present and a mapping (required by WorkflowDef)");
    assert_eq!(
        permissions.get("default").and_then(|v| v.as_str()),
        Some("deny")
    );
    let unattended = permissions
        .get("unattended")
        .and_then(|v| v.as_mapping())
        .expect("permissions.unattended is present (required by UnattendedDef)");
    assert_eq!(
        unattended.get("escalate").and_then(|v| v.as_str()),
        Some("park")
    );

    let steps = map
        .get("steps")
        .and_then(|v| v.as_sequence())
        .expect("steps is present and a sequence (required by WorkflowDef)");
    assert_eq!(steps.len(), 1);
    let prompt_text = steps[0]["agent"]["prompt"]
        .as_str()
        .expect("step has an agent.prompt");
    assert_eq!(
        prompt_text.trim_end(),
        "line one\nline two",
        "the original multi-line prompt template round-trips through the YAML block literal"
    );
}

#[test]
fn content_hash_is_stable_for_a_known_input() {
    // Regression guard for hash-algorithm stability: this exact input must
    // always hash to this exact value. If this test ever needs to change,
    // that means the algorithm or the canonical encoding changed — which is
    // precisely the defect class this test exists to catch (content
    // addressing requires the same content to hash identically across
    // processes and across runs).
    let v = JobVersion {
        job_id: JobId::from_uuid(uuid::Uuid::nil()),
        version: 1,
        template: SessionTemplate {
            provider: "anthropic".to_string(),
            model: "claude-sonnet".to_string(),
            cwd: "/repo".to_string(),
            tools: vec!["read".to_string(), "shell".to_string()],
            isolation: roundhouse_core::Tier::Worktree,
            permission_policy_ref: "pr-review-default".to_string(),
        },
        body: Body::Workflow {
            workflow_yaml: "name: pr-review\nversion: 1\n".to_string(),
        },
        input_schema: InputSchema(serde_json::json!({"type": "object"})),
    };

    assert_eq!(
        content_hash(&v),
        "sha256:2831bb5c12fd9169f23f69ca40567a9c0c18c065f2c94644eb1cf1fef69d1142",
        "content_hash's algorithm/encoding must never silently drift"
    );
}

#[test]
fn equal_content_hashes_the_same_regardless_of_how_it_was_built() {
    // Field ordering / serialization must not silently change the hash:
    // two `JobVersion`s with equal content, but whose embedded JSON schema
    // was built with keys inserted in a different order, must hash
    // identically.
    let job_id = JobId::new();
    let schema_a = serde_json::json!({
        "type": "object",
        "properties": { "repo": { "type": "string" }, "max_prs": { "type": "integer" } }
    });

    let mut props_reversed = serde_json::Map::new();
    props_reversed.insert(
        "max_prs".to_string(),
        serde_json::json!({ "type": "integer" }),
    );
    props_reversed.insert("repo".to_string(), serde_json::json!({ "type": "string" }));
    let mut schema_b_map = serde_json::Map::new();
    schema_b_map.insert(
        "properties".to_string(),
        serde_json::Value::Object(props_reversed),
    );
    schema_b_map.insert("type".to_string(), serde_json::json!("object"));
    let schema_b = serde_json::Value::Object(schema_b_map);

    assert_eq!(
        schema_a, schema_b,
        "sanity check: these two Values are equal despite differing construction order"
    );

    let v_a = JobVersion {
        job_id,
        version: 1,
        template: template(),
        body: Body::Prompt {
            template: "hello".to_string(),
        },
        input_schema: InputSchema(schema_a),
    };
    let mut v_b = v_a.clone();
    v_b.input_schema = InputSchema(schema_b);

    assert_eq!(
        content_hash(&v_a),
        content_hash(&v_b),
        "equal content must hash the same no matter how it was constructed"
    );
}
