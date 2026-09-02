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
fn zero_matchers_on_one_rule_is_rejected() {
    // Fix round 2 on Task 10, minor: a rule with no recognised matcher key
    // at all (just `effect:`) was already correctly rejected by the same
    // `matcher_fields.len() != 1` check that catches the two-matcher case,
    // but had no test of its own naming it.
    let yaml = "name: t\nversion: 1\npermissions:\n  rules:\n    - { effect: allow }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("a rule with zero matchers must fail closed");
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn serializing_and_reparsing_a_permission_rule_round_trips() {
    // Fix round 2 on Task 10, minor: `PermissionRuleDef`'s derived
    // `Serialize` used to emit its own struct layout
    // (`{"matcher": {"http": {...}}, "effect": "allow"}`) rather than the
    // wire shape its own `Deserialize` expects
    // (`{"http": {...}, "effect": "allow"}`), so re-parsing serialized
    // output failed. No exploitable path reaches this today, but a type
    // whose own output its own parser rejects is a trap for a future
    // normalize-persist-reparse path.
    use roundhouse_flow::parse::types::{HttpMatcher, PermissionMatcher, PermissionRuleDef};

    let rule = PermissionRuleDef {
        matcher: PermissionMatcher::Http(HttpMatcher {
            methods: vec!["GET".to_string()],
            hosts: vec!["api.github.com".to_string()],
        }),
        effect: Effect::Allow,
    };

    let serialized = serde_yaml::to_string(&rule).expect("PermissionRuleDef must serialize");
    let reparsed: PermissionRuleDef =
        serde_yaml::from_str(&serialized).expect("serialized output must re-parse");
    assert_eq!(reparsed, rule, "round trip must preserve the rule exactly");
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
fn rejects_a_bracket_bomb_hidden_behind_an_apostrophe() {
    // Fix round 2 on Task 10 (finding H2): the previous scan tracked
    // single-/double-quote state char-by-char to skip quoted content. An
    // apostrophe in perfectly ordinary YAML text (`don't` is literal text
    // here, not a scalar delimiter — YAML only treats a quote as an
    // indicator at scalar-start position) flipped that scanner into
    // "quoted" state *permanently*, since nothing ever closed it — every
    // character for the rest of the document, brackets included, was then
    // silently skipped. Measured through the real `parse_workflow`
    // (release build): this exact shape cost 2.53s at a 50 KB bomb, 38.8s
    // at 200 KB. The fix drops quote-tracking entirely, so this must be
    // rejected, and rejected fast.
    let bomb = "[".repeat(200_000);
    let yaml = format!("{}note: \"don't\"\nbomb: {bomb}\n", minimal_header());
    assert!(yaml.len() < MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml)
        .expect_err("a bracket bomb after an apostrophe must still be rejected");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ParseError::TooDeeplyNested { .. }),
        "expected the nesting bound to fire despite the preceding apostrophe, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "must reject cheaply, not fall through to serde_yaml (previously ~38.8s at this size); took {elapsed:?}"
    );
}

#[test]
fn accepts_a_bracket_heavy_block_scalar_prompt() {
    // Fix round 2 on Task 10 (finding H2): the same scan that must reject
    // a real bracket bomb must NOT reject a legitimate `prompt: |` block
    // scalar just because its literal text happens to contain many `[`
    // characters — block-scalar bodies carry zero nesting cost to YAML
    // regardless of what characters they contain. Reviewer's reproduction:
    // a 173-byte workflow whose `prompt: |` held 70 `[` characters was
    // rejected as "nests 65 deep" by the previous (non-block-scalar-aware)
    // scan, while `serde_yaml` itself accepts it without hesitation.
    let brackets: String = "[".repeat(70);
    let yaml = format!(
        "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    agent:\n      prompt: |\n        some literal brackets: {brackets}\n"
    );

    let start = std::time::Instant::now();
    let def = parse_workflow(&yaml)
        .expect("a bracket-heavy block scalar body must not trip the nesting bound");
    let elapsed = start.elapsed();

    assert_eq!(def.name, "t");
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "took {elapsed:?}"
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
