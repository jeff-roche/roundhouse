use roundhouse_flow::parse::types::{Effect, IsolationDef, UnattendedEscalate};
use roundhouse_flow::parse::{
    parse_workflow, ParseError, MAX_EXPANDED_NODES, MAX_LEADING_INDENT_CHARS, MAX_TOP_LEVEL_STEPS,
    MAX_YAML_BYTES,
};

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
fn a_syntax_error_is_reported_as_a_syntax_error_not_as_a_downstream_schema_error() {
    // Task X1. `parse_workflow` returns the metered walk's `serde_yaml`
    // error rather than continuing to the typed parse, which is what closes
    // the "errors cheaply in the meter, parses expensively for real" bypass
    // (ruling P52's second finding). Without a test that can see the
    // difference, that change would be unverified — on every *legitimate*
    // document the two paths agree, which is the whole point of the
    // over-rejection sweep above.
    //
    // Payload: the same truncated flow mapping as
    // `yaml_syntax_error_reports_a_line_and_column` — `unattended: {
    // escalate: fail` with no closing brace, so the rest of the document is
    // swallowed into the unterminated mapping.
    //
    // The typed parse blames the wrong thing: measured, it reports
    // "permissions.unattended.escalate: unknown variant `fail steps`",
    // a schema error caused by the syntax error rather than the syntax
    // error itself. The metered walk hits the truncation first and reports
    // "did not find expected ',' or '}'". So this assertion fails if the
    // walk's error is ever passed over in favour of the typed parse's.
    let yaml =
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail\nsteps:\n  - id: s\n";
    let err = parse_workflow(yaml).expect_err("malformed YAML must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("did not find expected"),
        "expected the metered walk's syntax error, got {msg:?} — if this says \
         \"unknown variant\" the walk's error is being discarded and the document is \
         reaching the typed parse anyway, which is the bypass this rejects"
    );
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
    // not the library in isolation) to cost seconds once handed to
    // `serde_yaml`, growing highly non-linearly with size. The best-effort
    // pre-parse nesting scan rejects this shape before `serde_yaml` ever
    // sees it, cheaply, whenever it understands the shape.
    //
    // P51 sweep, Task X1: this comment used to say "fix round 3 demoted
    // this scan to best-effort defence in depth — `MAX_YAML_BYTES`, now
    // 32 KiB, is the actual bound regardless of whether this scan catches a
    // given payload; see `worst_case_bracket_nesting_at_the_byte_cap_is_
    // bounded`". Three things wrong with it: the cap is 256 KiB, not 32
    // KiB; the "actual bound" claim was retracted in fix round 4; and the
    // test it named was renamed to
    // `the_retracted_cap_claim_held_only_for_the_one_shape_it_measured`.
    // The scan really is best-effort defence in depth, and the bracket-bomb
    // shape it addresses lives in the tokenizing stage, which
    // `MAX_EXPANDED_NODES` does NOT cover. Bomb size kept well under the
    // byte cap so this exercises the scan, not the cap.
    let bomb = "[".repeat(300);
    let yaml = format!("{}bomb: {bomb}\n", minimal_header());
    assert!(
        yaml.len() < MAX_YAML_BYTES,
        "the payload must stay under the byte cap — this test is about the scan, not the cap"
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
        "the nesting bound should fire fast on an obvious bomb; took {elapsed:?}"
    );
}

#[test]
fn rejects_a_bracket_bomb_hidden_behind_an_apostrophe() {
    // Fix round 2 on Task 10 (finding H2): the round-1 scan tracked
    // single-/double-quote state char-by-char to skip quoted content. An
    // apostrophe in perfectly ordinary YAML text (`don't` is literal text
    // here, not a scalar delimiter — YAML only treats a quote as an
    // indicator at scalar-start position) flipped that scanner into
    // "quoted" state *permanently*, since nothing ever closed it — every
    // character for the rest of the document, brackets included, was then
    // silently skipped. The round-2 fix dropped quote-tracking entirely, so
    // this specific shape must still be rejected (bomb size kept well
    // under `MAX_YAML_BYTES`, so this exercises the scan, not the cap).
    let bomb = "[".repeat(300);
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
        "should reject fast on an obvious bomb; took {elapsed:?}"
    );
}

#[test]
fn rejects_a_bracket_bomb_hidden_behind_a_comment_line_opener() {
    // Fix round 3 on Task 10 (finding H2): the round-2 scan detected a
    // block-scalar opener via a bare `rfind(':')` over the whole line, with
    // no check for comment context. `# x: |` is pure comment text — the
    // colon inside it used to be misread as a real mapping-value
    // indicator, opening (bogus) block-scalar mode that hid every
    // subsequent more-indented line, including a bracket bomb, from the
    // depth counter for the rest of the document. Now rejected: a line
    // starting with `#` can never be a block-scalar opener.
    let bomb = "[".repeat(300);
    let yaml = format!("{}# x: |\n    bomb: {bomb}\n", minimal_header());
    assert!(yaml.len() < MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml)
        .expect_err("a bracket bomb hidden behind a comment-line opener must be rejected");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ParseError::TooDeeplyNested { .. }),
        "expected the nesting bound to fire despite the comment-line opener, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "took {elapsed:?}"
    );
}

#[test]
fn rejects_a_bracket_bomb_hidden_behind_a_same_line_flow_context_opener() {
    // Fix round 3 on Task 10 (finding H2): the same bare-`rfind(':')`
    // opener detector also misread a colon inside an *unclosed flow
    // collection on the same line* (`items: ["note: |`) as a real
    // block-scalar opener, even though YAML has no block scalars in flow
    // context at all. Now rejected: the colon this detector keys off of
    // must sit at the line's own top level (bracket depth zero within the
    // line), not merely be the last colon found anywhere in its text.
    let bomb = "[".repeat(300);
    let yaml = format!("{}items: [\"note: |\n    bomb: {bomb}\n", minimal_header());
    assert!(yaml.len() < MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml).expect_err(
        "a bracket bomb hidden behind a same-line flow-context opener must be rejected",
    );
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ParseError::TooDeeplyNested { .. }),
        "expected the nesting bound to fire despite the flow-context opener, got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "took {elapsed:?}"
    );
}

#[test]
fn excessive_leading_indent_is_rejected() {
    // Fix round 3 on Task 10, minor: `ExcessiveIndentWidth` was reachable
    // and correctly labelled but had zero test coverage — nothing would
    // have caught a future edit that swapped the two `NestingViolation`
    // match arms back to the round-1 mislabeling bug.
    let indent = " ".repeat(MAX_LEADING_INDENT_CHARS + 1);
    let yaml = format!("{}{indent}x: 1\n", minimal_header());
    let err = parse_workflow(&yaml).expect_err("excessive leading indentation must be rejected");
    match err {
        ParseError::ExcessiveIndentWidth { width, max } => {
            assert_eq!(max, MAX_LEADING_INDENT_CHARS);
            assert_eq!(width, MAX_LEADING_INDENT_CHARS + 1);
        }
        other => panic!("expected ParseError::ExcessiveIndentWidth, got {other:?}"),
    }
}

#[test]
fn the_retracted_cap_claim_held_only_for_the_one_shape_it_measured() {
    // Fix round 3 on Task 10 claimed `MAX_YAML_BYTES` bounded worst-case
    // parse cost "regardless of payload shape". Fix round 4 retracted that.
    // This test is what survives of the old
    // `worst_case_bracket_nesting_at_the_byte_cap_is_bounded`: the *one*
    // shape round 3 actually measured — a run of unclosed `[` fed straight
    // to raw `serde_yaml::from_str`, bypassing this crate's scan on purpose
    // — really is cheap at the cap. It is roughly linear in the input, not
    // quadratic, so raising the cap 32 KiB -> 256 KiB kept it cheap.
    //
    // What it does NOT show, and what round 3 wrongly generalised from it,
    // is a bound on parse cost. The anchor/alias half of that gap is closed
    // (see `the_anchor_alias_fan_out_family_is_rejected_cheaply` below and
    // `parse/mod.rs`'s history section); this shape's cost is in the
    // *tokenizing* stage, which `MAX_EXPANDED_NODES` still does not cover,
    // which is why this test remains a characterization rather than a
    // bound.
    //
    // Fix round 5: the payload is a literal 32 KiB, deliberately NOT tied
    // to `MAX_YAML_BYTES`. Round 3's claim was made about 32 KiB, so 32 KiB
    // is what characterizing it means; and pinning the size keeps this
    // test's cost independent of a future change to the cap (round 4 raised
    // the cap 8x and this payload silently grew 8x with it, which is what
    // made the timing assertion flaky).
    const ROUND_3_CAP_BYTES: usize = 32_768;
    let bomb = "[".repeat(ROUND_3_CAP_BYTES);

    let start = std::time::Instant::now();
    let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(&bomb);
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "an unclosed bracket bomb must not parse successfully"
    );
    // A smoke test that this shape is not quadratic, not a calibration.
    // Measured here: ~80 ms release, ~500 ms debug. 60 s is ~120x the debug
    // figure, chosen so a contended CI runner cannot turn a *timing* margin
    // into a failure inside a test whose real subject is a security claim —
    // a flake here invites the next reader to "fix" it by weakening the
    // narrative. If this ever actually fires, the shape became quadratic
    // and that is a real finding, not a slow machine.
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "took {elapsed:?} for {ROUND_3_CAP_BYTES} bytes — this shape should be roughly linear"
    );
}

/// Builds the historical attack payload: one anchored leaf list of
/// `leaves` plain scalars, then `levels` levels each aliasing the previous
/// one `fan` times. Every bracket is balanced, nesting is one level deep,
/// and the alias count stays low — so none of `parse`'s *shape* checks see
/// anything unusual. `MAX_EXPANDED_NODES` catches it because it does not
/// look at shape at all: it counts the nodes the expansion actually
/// produces.
fn anchor_alias_fanout(leaves: usize, fan: usize, levels: usize) -> String {
    let mut yaml = String::from(
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    bomb:\n",
    );
    yaml.push_str("      a0: &a0 [");
    for i in 0..leaves {
        if i > 0 {
            yaml.push(',');
        }
        yaml.push('x');
    }
    yaml.push_str("]\n");
    for level in 1..=levels {
        yaml.push_str(&format!("      a{level}: &a{level} ["));
        for i in 0..fan {
            if i > 0 {
                yaml.push(',');
            }
            yaml.push_str(&format!("*a{}", level - 1));
        }
        yaml.push_str("]\n");
    }
    yaml
}

/// Same fan-out, but every anchored level carries a YAML tag, so the
/// metered walk can only reach it through `Visitor::visit_enum`.
fn tagged_anchor_alias_fanout(leaves: usize, fan: usize, levels: usize) -> String {
    anchor_alias_fanout(leaves, fan, levels).replace(": &a", ": !Thing &a")
}

/// A generous ceiling for "the rejection did not itself cost what the
/// attack used to cost". Measured through `parse_workflow`: every payload
/// below is rejected in 7.8-21.6 ms release and 123-199 ms debug (debug is
/// what `cargo test` builds), the 199 ms being the 260,364-byte member at
/// the byte cap. 10 s is ~50x the slowest debug figure — chosen so
/// a contended CI runner cannot turn a timing margin into a failure inside
/// a test whose real subject is a security property, following the
/// precedent in `the_retracted_cap_claim_held_only_for_the_one_shape_it_measured`.
/// If this ever actually fires, the bound stopped working; that is a real
/// finding, not a slow machine.
const REJECTION_MUST_BE_CHEAP: std::time::Duration = std::time::Duration::from_secs(10);

/// Rejects `yaml`, asserting it was the expansion ceiling that fired and
/// that firing was cheap. Returns the elapsed time so callers can report it.
fn assert_rejected_by_the_node_ceiling(label: &str, yaml: &str) -> std::time::Duration {
    assert!(
        yaml.len() <= MAX_YAML_BYTES,
        "{label}: payload must stay under the byte cap so this exercises the node \
         ceiling, not the cap ({} bytes)",
        yaml.len()
    );
    let start = std::time::Instant::now();
    let err = parse_workflow(yaml).expect_err("must be rejected");
    let elapsed = start.elapsed();

    match err {
        ParseError::ExpandsTooManyNodes { actual_bytes, max } => {
            assert_eq!(max, MAX_EXPANDED_NODES);
            assert_eq!(actual_bytes, yaml.len());
        }
        other => panic!("{label}: expected ParseError::ExpandsTooManyNodes, got {other:?}"),
    }
    assert!(
        elapsed < REJECTION_MUST_BE_CHEAP,
        "{label}: rejection took {elapsed:?} for {} bytes — the point of the bound is \
         that rejecting is cheap",
        yaml.len()
    );
    elapsed
}

#[test]
fn the_anchor_alias_fan_out_family_is_rejected_cheaply() {
    // Task X1. This replaces `ignored_reproduction_of_the_open_anchor_alias
    // _fanout_dos`, which asserted the parse took MORE than 250 ms and was
    // `#[ignore]`d because it burned CPU on purpose. The property is now
    // enforced on every `cargo test`.
    //
    // Payloads, not names: each row is
    // `anchor_alias_fanout(leaves, fan, levels)` — one anchored flow
    // sequence of `leaves` plain `x` scalars, then `levels` further
    // sequences each aliasing the previous one `fan` times, inside one
    // step's opaque body. Every bracket is balanced, nesting is one level
    // deep, `MAX_YAML_BYTES` is nowhere near, and one step is declared, so
    // no shape-based check in `parse` looks at any of them. The first five
    // rows are exactly the sizes in `parse/mod.rs`'s history table, whose
    // "before" costs were 123 ms, 137 ms, 2.1 s, 8.1 s and 33.9 s.
    let cases = [
        ("706 B", anchor_alias_fanout(100, 4, 12)),
        ("2,268 B", anchor_alias_fanout(1000, 4, 5)),
        ("2,332 B", anchor_alias_fanout(1000, 4, 7)),
        ("2,364 B", anchor_alias_fanout(1000, 4, 8)),
        ("4,396 B", anchor_alias_fanout(2016, 4, 8)),
        // The security review's 32 KiB payload, which it measured at
        // 287.8 s through the unfixed parser.
        ("32 KiB", anchor_alias_fanout(16200, 4, 8)),
        // Larger than anything previously measured: a member sized to sit
        // just under the byte cap, so the byte cap cannot be what rejects it.
        ("at the byte cap", anchor_alias_fanout(130_000, 4, 8)),
    ];
    for (label, yaml) in cases {
        assert_rejected_by_the_node_ceiling(label, &yaml);
    }
}

#[test]
fn the_smallest_attack_payload_is_rejected_while_the_larger_frozen_fixture_parses() {
    // The reason no byte cap could ever close this finding, made
    // executable: the review's smallest expensive payload class is SMALLER
    // than the frozen §8.9 fixture, so any threshold on `yaml.len()` that
    // rejects the first also rejects the second.
    //
    // Payloads: `anchor_alias_fanout(1075, 4, 7)` at 2,482 bytes on one
    // side (the closest constructible member to the review's 2,229 B
    // figure), and `tests/fixtures/pr_review.yaml` at 2,271 bytes on the
    // other. `MAX_EXPANDED_NODES` separates them by five orders of
    // magnitude in the *other* unit: measured, the fixture expands to 236
    // nodes and the attack passes 262,145 before the walk stops.
    let attack = anchor_alias_fanout(1075, 4, 7);
    assert_rejected_by_the_node_ceiling("2,482 B fan-out", &attack);

    let def = parse_workflow(PR_REVIEW_YAML).expect("the frozen §8.9 fixture must still parse");
    assert_eq!(def.name, "pr-review");
    assert_eq!(def.steps.len(), 2);
    assert!(
        PR_REVIEW_YAML.len() < attack.len(),
        "the point of this test is that the legitimate document is not the smaller one"
    );
}

#[test]
fn a_tag_wrapped_anchor_alias_fan_out_is_rejected() {
    // Task X1, defect 2 of the orchestrator's audit (ruling P52). The draft
    // this work inherited asserted, without testing it, that a tagged
    // node's payload "is always a newtype variant in `serde_yaml`'s
    // encoding". If that were wrong the metered walk would error at the tag
    // and — under the draft's fail-open error path — wave the document
    // through to a real parse whose `steps` field is a `serde_yaml::Value`
    // and constructs `Value::Tagged` happily.
    //
    // Payload: `anchor_alias_fanout(1000, 4, 7)` with every anchor
    // introduced as `!Thing &aN [...]` instead of `&aN [...]`, so the walk
    // reaches every level through `visit_enum` rather than `visit_seq`.
    // 2,388 bytes. Measured with no ceiling, the tagged form walks to
    // 21,932,398 nodes against the untagged form's 21,874,150 — the tags
    // are charged, not skipped.
    let yaml = tagged_anchor_alias_fanout(1000, 4, 7);
    assert!(
        yaml.contains("!Thing &a0 ["),
        "the payload must actually be tag-wrapped, or this test proves nothing: {}",
        &yaml[..yaml.len().min(400)]
    );
    assert_rejected_by_the_node_ceiling("tag-wrapped fan-out", &yaml);
}

#[test]
fn an_anchor_alias_fan_out_behind_a_cheaply_erroring_prefix_is_rejected() {
    // Task X1, the general form of defect 2: a document that errors cheaply
    // in the meter but parses expensively for real would bypass the ceiling
    // entirely under a fail-open error path. `parse_workflow` therefore
    // rejects on any `serde_yaml` error the walk reports rather than
    // continuing.
    //
    // Payload: `anchor_alias_fanout(1000, 4, 7)` with `tag: !Weird\n`
    // inserted as an earlier sibling field, so the walk meets a bare tagged
    // null before it reaches the fan-out. 2,348 bytes. Measured with no
    // ceiling, this walks to 21,874,154 nodes — four more than the
    // un-prefixed form — i.e. the tagged null does not stop the walk, and
    // the fan-out behind it is still counted.
    let yaml =
        anchor_alias_fanout(1000, 4, 7).replace("    bomb:\n", "    tag: !Weird\n    bomb:\n");
    assert!(yaml.contains("tag: !Weird"));
    assert_rejected_by_the_node_ceiling("fan-out behind a tagged null", &yaml);
}

#[test]
fn the_metered_walk_rejects_a_fan_out_without_expanding_it() {
    // Task X1. This is the regression detector for the one `serde_yaml`
    // internal the bound depends on: that alias expansion is *demand
    // driven*, so aborting the walk aborts the expansion. If a future
    // 0.9.x expanded aliases while building the event list instead, the
    // damage would be done before the first node is charged and this bound
    // would meter a walk over an already-materialised bomb.
    //
    // There is no API to assert that property directly, so it is asserted
    // by cost. Payload: `anchor_alias_fanout(1000, 4, 6)`, 2,300 bytes,
    // whose full expansion is 5,468,304 nodes — measured by walking it with
    // no ceiling, which is safe precisely because the counting visitor
    // allocates nothing. Materialising it is not safe: the real parse of
    // this document was measured at 367 ms and 555 MB resident, and the
    // 2,332-byte member one level up exhausts a 2 GiB address space.
    //
    // Rejecting it must therefore cost far less than expanding it would.
    // Measured: 7.9 ms release, 124 ms debug. The threshold is loose;
    // an eager-expansion regression would blow past it by orders of
    // magnitude, or die on memory first.
    let yaml = anchor_alias_fanout(1000, 4, 6);
    assert_eq!(
        yaml.len(),
        2_300,
        "payload size is load-bearing for the figures above"
    );
    let elapsed = assert_rejected_by_the_node_ceiling("demand-driven expansion", &yaml);
    assert!(
        elapsed < REJECTION_MUST_BE_CHEAP,
        "rejecting a 2,300-byte document whose expansion is 5.4M nodes took {elapsed:?}"
    );
}

#[test]
fn the_node_ceiling_leaves_room_for_any_alias_free_document_under_the_byte_cap() {
    // Task X1. `MAX_EXPANDED_NODES`'s derivation, pinned so that raising
    // `MAX_YAML_BYTES` without revisiting it fails here rather than
    // silently starting to reject dense legitimate documents.
    //
    // The claim: the densest alias-free YAML spends at least two source
    // bytes per node, so an alias-free document at the byte cap cannot
    // reach a ceiling set at one node per admitted byte. Nothing can
    // therefore be rejected by the node ceiling for being *large*; only for
    // expanding beyond what its own bytes could have encoded directly.
    //
    // A `const` block, not a runtime `assert!`: both constants are
    // compile-time, so this fails the build rather than a test run if a
    // future change to `MAX_YAML_BYTES` outgrows the ceiling. (Clippy's
    // `assertions_on_constants` asks for exactly this, and it is the
    // stronger form anyway.)
    const {
        assert!(
            MAX_EXPANDED_NODES >= MAX_YAML_BYTES,
            "MAX_EXPANDED_NODES must be at least MAX_YAML_BYTES, or an alias-free \
             document under the byte cap could be rejected by the node ceiling"
        );
    }

    // And executed, not just asserted arithmetically. Payload: a single
    // flow sequence of two-byte elements (`x,`) padded to 262,142 bytes —
    // one byte under the cap, no anchors, no aliases. Measured: 131,042
    // nodes, exactly 2.00x under the ceiling, walked in 15.7 ms and parsed
    // in 21.0 ms (release).
    let mut yaml = String::from(
        "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    bomb: [",
    );
    let elements = (MAX_YAML_BYTES - yaml.len() - 3) / 2;
    for i in 0..elements {
        if i > 0 {
            yaml.push(',');
        }
        yaml.push('x');
    }
    yaml.push_str("]\n");
    assert!(yaml.len() <= MAX_YAML_BYTES && yaml.len() > MAX_YAML_BYTES - 8);
    assert!(!yaml.contains('&') && !yaml.contains('*'));

    let def = parse_workflow(&yaml)
        .expect("a maximally dense alias-free document under the byte cap must still parse");
    assert_eq!(def.steps.len(), 1);
}

#[test]
fn the_metered_walk_does_not_over_reject_legitimate_yaml_shapes() {
    // Task X1. `parse_workflow` now rejects on any `serde_yaml` error the
    // metered walk reports instead of passing the document to the typed
    // parse. That closes the fail-open bypass, and its cost is
    // over-rejection: a shape the walk's `deserialize_any` chokes on that
    // the typed parse would have accepted.
    //
    // The walk accepts every YAML shape and produces no schema errors, so
    // the risk is concentrated in YAML-level constructs. These are the
    // constructs, as payloads: document markers, comments, an explicit
    // null, a bare tagged node, a tagged null in value position, a `!!`
    // standard tag, non-finite floats, a merge key, flow nesting one level
    // under `serde_yaml`'s own 128-deep recursion guard, anchor reuse
    // across steps, empty collections, both permission matcher kinds
    // (which is the `#[serde(flatten)]` path), typed `inputs`, and
    // `catch`/`finally`. Plus the frozen fixture and the alias-heavy prose
    // prompt. Measured across this set: zero over-rejections.
    let deep_but_legal = {
        let mut y = format!("{}    d: ", minimal_header());
        y.push_str(&"[".repeat(120));
        y.push_str(&"]".repeat(120));
        y.push('\n');
        y
    };
    let anchor_reuse = {
        let mut y = String::from(
            "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n",
        );
        y.push_str("  - id: s0\n    with: &common { cwd: /tmp, timeout: 30 }\n");
        for i in 1..200 {
            y.push_str(&format!("  - id: s{i}\n    with: *common\n"));
        }
        y
    };
    let cases: Vec<(&str, String)> = vec![
        ("frozen §8.9 fixture", PR_REVIEW_YAML.to_string()),
        ("leading ---", format!("---\n{}", minimal_header())),
        ("trailing ...", format!("{}...\n", minimal_header())),
        ("comments", format!("# hi\n{}# bye\n", minimal_header())),
        ("explicit null step", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - ~\n".to_string()),
        ("bare tagged step", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - !Custom { id: s }\n".to_string()),
        ("bare tagged null step", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - !Empty\n".to_string()),
        ("tagged null in value position", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - { id: s, x: !Empty }\n".to_string()),
        ("!!binary", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - { id: s, b: !!binary \"aGk=\" }\n".to_string()),
        (".nan / .inf", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - { id: s, n: .nan, m: .inf }\n".to_string()),
        ("merge key", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    a: &a { x: 1 }\n    b: { <<: *a, y: 2 }\n".to_string()),
        ("120-deep flow nesting", deep_but_legal),
        ("anchor reused across 200 steps", anchor_reuse),
        ("empty collections", "name: t\nversion: 1\ninputs: {}\nsecrets: []\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    e: []\n    f: {}\n".to_string()),
        ("both matcher kinds (flatten path)", "name: t\nversion: 1\npermissions:\n  default: deny\n  rules:\n    - { http: { methods: [GET], hosts: [a.com] }, effect: allow }\n    - { shell: { program: cargo, args: [test] }, effect: allow }\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n".to_string()),
        ("typed inputs", "name: t\nversion: 1\ninputs:\n  repo: { type: string, required: true }\n  n: { type: integer, default: 10 }\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n".to_string()),
        ("catch and finally", "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\ncatch:\n  - id: c\nfinally:\n  - id: f\n".to_string()),
    ];

    for (label, yaml) in cases {
        match parse_workflow(&yaml) {
            Ok(_) => {}
            Err(err) => panic!(
                "{label}: a legitimate YAML shape was rejected after Task X1 made the \
                 metered walk fail closed: {err:?}"
            ),
        }
    }
}

#[test]
fn an_alias_heavy_prose_prompt_parses() {
    // Fix round 5 on Task 10: fix round 4 shipped a `MAX_ALIAS_TOKENS`
    // guard rejecting more than 64 `*[A-Za-z0-9_-]` tokens. That pattern is
    // also markdown emphasis, so this document — an ordinary agent prompt
    // using `*word*` and `**bold**` in prose — was rejected outright as
    // `TooManyAliases` (measured: 140 "alias" tokens in 4,719 bytes). The
    // guard is gone; this pins that a real prompt parses, so a future
    // reader does not reintroduce the same shape of check.
    //
    // Task X1 added `MAX_EXPANDED_NODES`, which is deliberately not that
    // shape: it counts nodes the deserializer produced, and a `prompt: |`
    // block scalar is exactly one node however much markdown emphasis it
    // contains. Measured: this document walks to 20 nodes.
    let mut prose = String::new();
    for i in 0..70 {
        prose.push_str(&format!(
            "        Check the *config{i}* file and note any **bold** findings.\n"
        ));
    }
    let yaml = format!(
        "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    agent:\n      prompt: |\n{prose}"
    );
    assert!(yaml.len() < MAX_YAML_BYTES);

    let def = parse_workflow(&yaml).expect("markdown emphasis in a prompt must not be rejected");
    assert_eq!(def.name, "t");
}

#[test]
fn known_false_positive_bracket_heavy_prompt_after_an_unbalanced_bracket() {
    // Fix round 4 on Task 10: a characterization test for an over-rejection
    // fix round 3 introduced and this round documents rather than fixes
    // (see `nesting_depth_bound_violation`'s doc comment for why).
    //
    // Round 3 made the block-scalar opener detector refuse to recognise an
    // opener while the running bracket depth is non-zero. Because that
    // depth counter also counts brackets inside comments and quoted
    // scalars, ONE net-unbalanced `[` earlier in the document suppresses
    // block-scalar recognition for everything after it — so a legitimate
    // `prompt: |` body gets bracket-counted as if it were structure.
    //
    // The result is a document `serde_yaml` accepts and `parse_workflow`
    // rejects. It takes 256 net-unbalanced opening brackets to reach, which
    // no realistic workflow accumulates. If a future change fixes this,
    // this test flips to `Ok` and should be rewritten as an acceptance
    // test rather than deleted.
    let brackets = "[".repeat(300);
    let yaml = format!(
        "name: t\nversion: 1\n# allowlist hint: program args match [a-z\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    agent:\n      prompt: |\n        literal text {brackets}\n"
    );

    let raw: Result<serde_yaml::Value, _> = serde_yaml::from_str(&yaml);
    assert!(
        raw.is_ok(),
        "serde_yaml itself accepts this document, which is what makes it a false positive"
    );

    let err = parse_workflow(&yaml)
        .expect_err("documented over-rejection: the scan counts the prompt body's brackets");
    assert!(
        matches!(err, ParseError::TooDeeplyNested { .. }),
        "expected the documented TooDeeplyNested false positive, got {err:?}"
    );

    // Remove the single unbalanced bracket from the comment and the very
    // same prompt body is recognised as a block scalar and skipped.
    let repaired = yaml.replace("match [a-z", "match a-z");
    parse_workflow(&repaired)
        .expect("without the stray unbalanced bracket, the block scalar is recognised again");
}

#[test]
fn the_byte_cap_and_the_step_cap_are_coherent() {
    // Fix round 4 on Task 10: `MAX_YAML_BYTES` is not a security bound
    // (see `parse/mod.rs`'s history section); its remaining job is to
    // refuse absurdly large documents, which means it must not be so tight
    // that `MAX_TOP_LEVEL_STEPS` is unreachable for realistic steps. At
    // 32 KiB it left ~65 bytes per step at the step limit — less than an
    // empty step costs. This pins the two constants against each other.
    let bytes_per_step_at_the_step_limit = MAX_YAML_BYTES / MAX_TOP_LEVEL_STEPS;
    assert!(
        bytes_per_step_at_the_step_limit >= 512,
        "MAX_YAML_BYTES ({MAX_YAML_BYTES}) leaves only \
         {bytes_per_step_at_the_step_limit} bytes per step at MAX_TOP_LEVEL_STEPS \
         ({MAX_TOP_LEVEL_STEPS}), which is too tight for a step carrying a prompt"
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
    //
    // P51 sweep, Task X1: the guard still fires, but it now fires inside
    // the metered walk rather than inside the typed parse — measured, the
    // walk reaches `RepetitionLimitExceeded` after 40,062 nodes, well under
    // `MAX_EXPANDED_NODES`, in 1.25 ms. `parse_workflow` returns that error
    // rather than continuing, so the variant asserted below is unchanged.
    // A `serde_yaml` error found by the walk is a rejection, never a
    // "proceed anyway": see `parse/expansion.rs`'s doc comment.
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
