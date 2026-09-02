use roundhouse_flow::parse::types::{Effect, IsolationDef, UnattendedEscalate};
use roundhouse_flow::parse::{parse_workflow, ParseError, MAX_TOP_LEVEL_STEPS, MAX_YAML_BYTES};

const PR_REVIEW_YAML: &str = include_str!("fixtures/pr_review.yaml");

/// A minimal, otherwise-valid workflow header — every field `WorkflowDef`
/// requires without a `#[serde(default)]`, nothing more. Individual tests
/// append/mutate around this to isolate one construct at a time, rather
/// than editing copies of the full §8.9 fixture.
fn minimal_header() -> String {
    "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n"
        .to_string()
}

#[test]
fn parses_name_version_inputs_defaults_secrets_permissions() {
    let def = parse_workflow(PR_REVIEW_YAML).expect("parses");
    assert_eq!(def.name, "pr-review");
    assert_eq!(def.version, 3);
    assert_eq!(def.inputs.len(), 2);
    assert!(def.inputs["repo"].required);
    assert_eq!(def.inputs["max_prs"].default, Some(serde_json::json!(10)));
    assert_eq!(def.defaults.isolation, IsolationDef::Worktree);
    assert_eq!(def.secrets, vec!["GH_TOKEN".to_string()]);
    assert_eq!(def.permissions.default, Effect::Deny);
    assert_eq!(def.permissions.rules.len(), 3);
    assert_eq!(
        def.permissions.unattended.escalate,
        UnattendedEscalate::Park
    );
    assert!(!def.steps.is_empty());
    assert_eq!(def.catch.len(), 1);
    assert_eq!(def.finally.len(), 1);
}

#[test]
fn unknown_top_level_key_is_rejected() {
    let yaml = format!("{}nonsense_key: true\n", minimal_header());
    let err = parse_workflow(&yaml).expect_err("unknown top-level key must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn permissions_default_absent_defaults_to_deny_never_allow() {
    // Risk callout: "If `permissions.default` is absent, the safe default
    // is deny, never allow." No `default:` key at all here.
    let def = parse_workflow(&minimal_header()).expect("parses without explicit default");
    assert_eq!(def.permissions.default, Effect::Deny);
}

#[test]
fn misspelled_permission_effect_is_rejected() {
    let yaml = "name: t\nversion: 1\npermissions:\n  rules:\n    - { shell: { program: \"cargo\", args: [] }, effect: alow }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("misspelled effect value must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn misspelled_permissions_default_is_rejected() {
    let yaml = "name: t\nversion: 1\npermissions:\n  default: mayeb\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("misspelled permissions.default must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn unknown_permission_matcher_kind_is_rejected() {
    let yaml = "name: t\nversion: 1\npermissions:\n  rules:\n    - { git: { op: push }, effect: deny }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("unrecognised matcher kind must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn unknown_field_within_a_permission_matcher_is_rejected() {
    // Fix round 1 on Task 10 (finding H1): a typo'd field *inside* a
    // recognised matcher (`hostz` for `hosts`) used to be silently dropped
    // by `#[serde(flatten)]`'s leniency, turning a host-restricted allow
    // rule into an unrestricted one that still *reads* as restricted.
    let yaml = "name: t\nversion: 1\npermissions:\n  rules:\n    - { http: { methods: [GET], hostz: [\"evil.com\"] }, effect: allow }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml)
        .expect_err("an unrecognised field inside a known matcher kind must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn two_matcher_kinds_on_one_rule_is_rejected() {
    // Fix round 1 on Task 10 (finding H1): flatten only guarantees *a*
    // recognised key is present, not that exactly one is — a rule
    // carrying both `http` and `shell` used to silently keep one and drop
    // the other.
    let yaml = "name: t\nversion: 1\npermissions:\n  rules:\n    - { http: { methods: [GET] }, shell: { program: \"rm\" }, effect: allow }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err =
        parse_workflow(yaml).expect_err("a rule with more than one matcher kind must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn isolation_omitted_defaults_to_worktree_never_none() {
    // Risk callout, applied to isolation: an omitted `defaults.isolation`
    // must never silently mean unsandboxed (`Tier::None`).
    let def = parse_workflow(&minimal_header()).expect("parses without a defaults: block at all");
    assert_eq!(def.defaults.isolation, IsolationDef::Worktree);
    assert_eq!(
        def.defaults.isolation.to_core_tier(),
        roundhouse_core::Tier::Worktree
    );
}

#[test]
fn park_escalation_without_deadline_and_on_timeout_is_rejected() {
    let yaml =
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: park }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("park without deadline/on_timeout must fail closed");
    assert!(matches!(
        err,
        ParseError::ParkEscalationRequiresDeadlineAndOnTimeout
    ));
}

#[test]
fn park_escalation_with_deadline_and_on_timeout_parses() {
    let yaml = "name: t\nversion: 1\npermissions:\n  unattended: { escalate: park, deadline: 12h, on_timeout: deny }\nsteps:\n  - id: s\n";
    let def = parse_workflow(yaml).expect("park with both fields parses");
    assert_eq!(
        def.permissions.unattended.escalate,
        UnattendedEscalate::Park
    );
}

#[test]
fn oversized_yaml_is_rejected_before_parsing() {
    let yaml = format!(
        "{}\n# {}\n",
        minimal_header(),
        "x".repeat(MAX_YAML_BYTES + 1)
    );
    let err = parse_workflow(&yaml).expect_err("oversized input must be rejected");
    match err {
        ParseError::TooLarge { actual, max } => {
            assert_eq!(max, MAX_YAML_BYTES);
            assert!(actual > max);
        }
        other => panic!("expected ParseError::TooLarge, got {other:?}"),
    }
}

#[test]
fn too_many_top_level_steps_is_rejected() {
    let mut yaml =
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n".to_string();
    for i in 0..(MAX_TOP_LEVEL_STEPS + 1) {
        yaml.push_str(&format!("  - id: s{i}\n"));
    }
    let err = parse_workflow(&yaml).expect_err("too many top-level steps must be rejected");
    match err {
        ParseError::TooManySteps { actual, max } => {
            assert_eq!(max, MAX_TOP_LEVEL_STEPS);
            assert_eq!(actual, MAX_TOP_LEVEL_STEPS + 1);
        }
        other => panic!("expected ParseError::TooManySteps, got {other:?}"),
    }
}

#[test]
fn yaml_syntax_error_reports_a_line_and_column() {
    let yaml =
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("malformed YAML must fail");
    assert!(
        err.location().is_some(),
        "expected a line/column for a YAML syntax error, got {err:?}"
    );
}

#[test]
fn rejects_pathological_flow_nesting_cheaply() {
    // Fix round 1 on Task 10 (finding H2): a payload of nothing but a long
    // run of unclosed `[` characters, embedded in an otherwise-valid
    // document, was measured (through this crate's real `parse_workflow`,
    // not the library in isolation) to cost single-digit seconds at ~50 KB
    // and grow highly non-linearly from there — roughly 84s at 200 KB,
    // ~560s at 520 KB — once handed to `serde_yaml`, all comfortably under
    // `MAX_YAML_BYTES`. The pre-parse nesting scan must reject this before
    // `serde_yaml` ever sees it, and must do so fast regardless of size.
    let bomb = "[".repeat(200_000);
    let yaml = format!("{}bomb: {bomb}\n", minimal_header());
    assert!(
        yaml.len() < MAX_YAML_BYTES,
        "the payload must stay under the byte cap — the point is that size alone doesn't catch this"
    );

    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml).expect_err("pathological flow nesting must be rejected");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ParseError::TooDeeplyNested { .. }),
        "expected the pre-parse nesting bound to fire, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the nesting bound must fire in well under a second even on a 200KB payload that \
         previously cost ~84s when handed to serde_yaml directly; took {elapsed:?}"
    );
}

#[test]
fn rejects_a_billion_laughs_style_alias_bomb() {
    // Classic "billion laughs": each level re-references the previous
    // level's anchor several times, so the fully-expanded value would be
    // exponential in the nesting depth even though the source text is
    // tiny. `steps` is the one open (`serde_yaml::Value`) field available
    // in a `WorkflowDef`, so the bomb lives inside one step's opaque body.
    // `serde_yaml` 0.9's deserializer bounds total alias-jump work to
    // ~100x the document's event count (see `parse::mod`'s doc comment),
    // so this must fail fast with a parse error rather than hang or OOM —
    // proving that protection is real and reachable through this crate's
    // actual entry point, not just a property of the library in isolation.
    let yaml = "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    bomb:\n      b0: &b0 [x, x, x, x, x]\n      b1: &b1 [*b0, *b0, *b0, *b0, *b0]\n      b2: &b2 [*b1, *b1, *b1, *b1, *b1]\n      b3: &b3 [*b2, *b2, *b2, *b2, *b2]\n      b4: &b4 [*b3, *b3, *b3, *b3, *b3]\n      b5: &b5 [*b4, *b4, *b4, *b4, *b4]\n      b6: [*b5, *b5, *b5, *b5, *b5]\n";

    assert!(
        yaml.len() < MAX_YAML_BYTES,
        "the bomb's source text must stay tiny — the point is that size alone cannot catch this"
    );

    let err = parse_workflow(yaml).expect_err("an alias bomb must not parse successfully");
    assert!(
        matches!(err, ParseError::Yaml(_)),
        "expected the library's own repetition-limit guard to fire, got {err:?}"
    );
}
