use roundhouse_flow::parse::types::{Effect, IsolationDef, UnattendedEscalate};
use roundhouse_flow::parse::{
    parse_workflow, ParseError, MAX_EXPANDED_WEIGHT, MAX_LEADING_INDENT_CHARS,
    MAX_PLAIN_NUMERIC_DIGIT_RUN, MAX_TOP_LEVEL_STEPS, MAX_YAML_BYTES,
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
    // `MAX_EXPANDED_WEIGHT` does NOT cover. Bomb size kept well under the
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
    // *tokenizing* stage, which `MAX_EXPANDED_WEIGHT` still does not cover,
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
/// anything unusual. `MAX_EXPANDED_WEIGHT` catches it because it does not
/// look at shape at all: it weighs what the expansion actually produces.
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
/// below is rejected in **0.6-24.5 ms release and 3.8-216.4 ms debug**
/// (debug is what `cargo test` builds), the slowest being the 260,364-byte
/// fan-out at the byte cap. Re-measured at fix round 3 over every payload
/// `parse/mod.rs`'s history tables name; the previous figures here (and the
/// two other sites quoting them) predated the ceiling tightening, which cut
/// the node budget and with it the rejection cost. 10 s is ~46x the slowest
/// debug figure — chosen so
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
        ParseError::ExpandsTooLarge { actual_bytes, max } => {
            assert_eq!(max, MAX_EXPANDED_WEIGHT);
            assert_eq!(actual_bytes, yaml.len());
        }
        other => panic!("{label}: expected ParseError::ExpandsTooLarge, got {other:?}"),
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
    // other. `MAX_EXPANDED_WEIGHT` separates them by three orders of
    // magnitude in the *other* unit: measured, the frozen fixture weighs
    // 3,299 and the attack passes 2,621,440 before the walk stops.
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
    // 2,388 bytes.
    //
    // P51 sweep, fix round 2: this comment quoted the tagged and untagged
    // NODE counts (21,932,398 vs 21,874,150) from the retired node-count
    // unit, which the round-1 sweep missed while re-measuring the same
    // construction in `expansion.rs`. Re-measured in the live unit, with no
    // ceiling: 197,449,877 weight tagged against 196,838,273 untagged, a
    // 0.3% difference — the tags are charged, not skipped.
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
    // null before it reaches the fan-out. 2,348 bytes.
    //
    // P51 sweep, fix round 2: this comment also quoted a node count
    // (21,874,154) from the retired unit. What it was evidence for is
    // unchanged and is what the assertion below tests directly: the tagged
    // null does not stop the walk, and the fan-out behind it is still
    // charged, so the document is rejected rather than waved through.
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
    // Measured: 18.6 ms release, 213 ms debug. The threshold is loose;
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

/// One anchored plain float of `digits` fractional digits, aliased `k`
/// times inside a step body (a raw `serde_yaml::Value`, so nothing is typed
/// away and the real parse would materialise all of it). `quoted` decides
/// whether the anchored scalar carries quotes, which is the only difference
/// between the two halves of the A/B below.
fn aliased_float(digits: usize, k: usize, quoted: bool) -> String {
    let num = format!("1.{}", "7".repeat(digits));
    let anchored = if quoted {
        format!("&f \"{num}\"")
    } else {
        format!("&f {num}")
    };
    let mut y = format!(
        "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    a: {anchored}\n    b: ["
    );
    for i in 0..k {
        if i > 0 {
            y.push(',');
        }
        y.push_str("*f");
    }
    y.push_str("]\n");
    y
}

#[test]
fn a_long_plain_numeric_scalar_aliased_many_times_is_rejected() {
    // Task X1 fix round 2, the Critical this round exists for, and the
    // third distinct axis this bound has had to grow to cover.
    //
    // `serde_yaml` hands the visitor a DECODED value —
    // `visit_f64(self, v: f64)` — so the expansion meter charges a numeric
    // scalar `NODE_WEIGHT_BYTES` whether its source token was 3 bytes or
    // 250,000, while `parse_f64` re-runs an O(token) `dec2flt` scan on every
    // alias expansion. No refinement of the meter's unit can see this;
    // `MAX_PLAIN_NUMERIC_DIGIT_RUN` bounds it in the source instead.
    //
    // **This test covers the PLAIN route only, and that is all the bound
    // covers.** Fix round 2's version of this comment attributed the
    // dispatch to `visit_untagged_scalar` alone, which is reached only for
    // `ScalarStyle::Plain`; `visit_scalar` has its own core-tag dispatch
    // above it (`de.rs:882-884`) with no style check, and that route is
    // still open. See
    // `the_core_tag_route_to_visit_f64_is_open_and_this_pins_which_syntaxes_reach_it`
    // and the UNBOUNDED row in `parse/mod.rs`'s axis inventory.
    //
    // Payload: `a: &f 1.777…` with 131,000 fractional digits, aliased
    // 43,648 times as `b: [*f,*f,…]` — 262,048 bytes, every bracket
    // balanced, one step, no nesting. Measured on `77d6008`: ADMITTED,
    // 838.8 ms in the metered walk plus 831.0 ms in the real parse.
    let attack = aliased_float(131_000, 43_648, false);
    assert!(
        attack.len() <= MAX_YAML_BYTES,
        "payload must stay under the byte cap: {} bytes",
        attack.len()
    );
    let start = std::time::Instant::now();
    let err = parse_workflow(&attack).expect_err("must be rejected");
    let elapsed = start.elapsed();
    assert!(
        matches!(err, ParseError::NumericTokenTooLong { .. }),
        "expected the digit-run bound to fire, got {err:?}"
    );
    assert!(
        elapsed < REJECTION_MUST_BE_CHEAP,
        "rejection took {elapsed:?}"
    );

    // The A/B that made the axis visible: the SAME document with two quote
    // characters added routes the scalar to `visit_str`, which charges its
    // length, so the expansion meter catches it. Both must be rejected —
    // before this round only the quoted one was.
    let quoted = aliased_float(131_000, 43_648, true);
    let err = parse_workflow(&quoted).expect_err("must be rejected");
    assert!(
        matches!(
            err,
            ParseError::ExpandsTooLarge { .. } | ParseError::NumericTokenTooLong { .. }
        ),
        "expected the quoted twin to be rejected too, got {err:?}"
    );

    // And the shape that made the meter's own work unbounded: one level of
    // alias nesting drives the expansion count to the weight budget while
    // 60,000 padding scalars inflate `events.len()` so `serde_yaml`'s
    // repetition guard does not bind first. Measured on `77d6008`: rejected,
    // but only after burning 8,630 ms *inside* the metered walk.
    let mut nested = format!(
        "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    f: &f 1.{}\n    p: [",
        "7".repeat(131_072)
    );
    for i in 0..60_000 {
        if i > 0 {
            nested.push(',');
        }
        nested.push('q');
    }
    nested.push_str("]\n    a: &a [");
    for i in 0..724 {
        if i > 0 {
            nested.push(',');
        }
        nested.push_str("*f");
    }
    nested.push_str("]\n    c: [");
    for i in 0..724 {
        if i > 0 {
            nested.push(',');
        }
        nested.push_str("*a");
    }
    nested.push_str("]\n");
    let start = std::time::Instant::now();
    let err = parse_workflow(&nested).expect_err("must be rejected");
    let elapsed = start.elapsed();
    assert!(
        matches!(err, ParseError::NumericTokenTooLong { .. }),
        "expected the digit-run bound to fire before the walk starts, got {err:?}"
    );
    assert!(
        elapsed < REJECTION_MUST_BE_CHEAP,
        "the walk must not run at all on this payload; took {elapsed:?}"
    );
}

#[test]
fn the_core_tag_route_to_visit_f64_is_open_and_this_pins_which_syntaxes_reach_it() {
    // Task X1 fix round 3. A CHARACTERIZATION test for an axis this crate
    // does not close, not a bound. `parse/mod.rs`'s axis inventory records
    // "non-string scalar source length / decode CPU" as UNBOUNDED; this is
    // the executable half of that row.
    //
    // Why it is open, in one sentence: `serde_yaml`'s `visit_scalar`
    // (`de.rs:858-900`) dispatches a core-tagged scalar to `parse_f64` and
    // `visit_f64` at `de.rs:882-884` with **no `ScalarStyle::Plain` check**,
    // while the equivalent check does exist one branch below at `de.rs:891`
    // for custom tags. So a double-quoted scalar whose digits are broken by
    // escaped line continuations decodes to an arbitrarily long number while
    // the source carries no long digit run, and
    // `MAX_PLAIN_NUMERIC_DIGIT_RUN` — which reads source — cannot see it.
    //
    // What this test pins is the thing a fix would have to cover: FOUR
    // distinct source syntaxes reach that branch, and none of the last three
    // contains the text `!!float`. That is why a source-level scan for
    // `!!float` was rejected as a remedy — catching all four means parsing
    // `%TAG` directives, resolving tag handles and percent-decoding tag
    // suffixes, i.e. implementing YAML tag resolution.
    //
    // Payloads are deliberately tiny (a 4-character number), so this test
    // costs microseconds and never materialises anything: it asserts which
    // ROUTE is taken, not that the route is expensive. The expense is
    // measured out-of-band and recorded in the inventory.
    let variants = [
        ("shorthand", "!!float \"1.75\""),
        ("verbatim tag", "!<tag:yaml.org,2002:float> \"1.75\""),
        ("percent-encoded suffix", "!!fl%6Fat \"1.75\""),
    ];
    for (label, tagged) in variants {
        let yaml = format!(
            "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    a: {tagged}\n"
        );
        assert!(
            !yaml.contains("!!float") || label == "shorthand",
            "{label}: only the shorthand variant may contain the literal `!!float`, \
             or this test is not demonstrating what it claims"
        );
        parse_workflow(&yaml).unwrap_or_else(|err| {
            panic!(
                "{label}: expected this to parse — it reaches `visit_f64` with a zero \
                 charge, which is the open axis. It failed with {err:?}. If `serde_yaml` \
                 has added the missing style check at de.rs:882, re-measure the decode \
                 axis and update `parse/mod.rs`'s axis inventory, which may be closable."
            )
        });
    }

    // The `%TAG` handle form needs a directive, so it is built separately.
    let with_directive = "%TAG !e! tag:yaml.org,2002:\n---\nname: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    a: !e!float \"1.75\"\n";
    assert!(!with_directive.contains("!!float"));
    parse_workflow(with_directive)
        .expect("a remapped tag handle reaches the same branch without the text `!!float`");

    // And the contrast that makes the point: the SAME value plain, and the
    // same value under a *custom* tag. The custom tag goes through
    // `visit_enum` (`parse_tag` at de.rs:1193 returns Some for `!`-tags), so
    // its payload lands on `visit_str` and is charged by length — which is
    // why custom tags were never part of this hole.
    for (label, scalar) in [("plain", "1.75"), ("custom tag", "!Thing \"1.75\"")] {
        let yaml = format!(
            "name: t\nversion: 1\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    a: {scalar}\n"
        );
        parse_workflow(&yaml).unwrap_or_else(|_| panic!("{label} must still parse"));
    }
}

#[test]
fn ordinary_numeric_content_is_not_rejected_by_the_digit_run_bound() {
    // The over-rejection direction of `MAX_PLAIN_NUMERIC_DIGIT_RUN`. The
    // scan counts digit runs anywhere in the source, including inside
    // comments, quoted scalars and block-scalar bodies that never reach a
    // numeric decoder, so its cost has to be paid in false positives and
    // measured rather than asserted away.
    //
    // Payloads: every numeric shape a real workflow plausibly carries —
    // timeouts and retry counts, a `u64`-sized literal at 20 digits, the
    // same 39-digit value as a quoted string (unquoted it is rejected by
    // `serde_yaml::Value`, which has no `u128` variant — unrelated to this
    // bound, and the quoted form is the better test here anyway because a
    // long digit run inside a string is exactly the over-rejection this
    // scan risks), a
    // float with a full 17-significant-digit mantissa and an exponent, a
    // dotted version chain, an ISO timestamp, an IPv4 address, a 64-char
    // hex digest, a base64 blob, a `# ----` comment rule 200 dashes long,
    // and 4,000 consecutive small integers in a flow sequence. None has a
    // run of 512 consecutive digits; the separators (`.`, `-`, `,`, `:`,
    // and the non-digit letters of hex and base64) break every run.
    let digest = "3b1f".repeat(16);
    let base64 = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q".repeat(20);
    let dashes = "-".repeat(200);
    let mut ints = String::new();
    for i in 0..4_000 {
        if i > 0 {
            ints.push(',');
        }
        ints.push_str(&(i % 1000).to_string());
    }
    let yaml = format!(
        "name: t\nversion: 1\n# {dashes}\npermissions:\n  unattended: {{ escalate: park, deadline: 12h, on_timeout: deny }}\nsteps:\n  - id: s\n    timeout: 30\n    retries: 3\n    big: 18446744073709551615\n    bigger_as_text: \"340282366920938463463374607431768211455\"\n    precise: 1.7976931348623157e308\n    tiny: -1.2345678901234567e-300\n    version: 1.2.3.4.5.6.7.8.9\n    when: 2026-09-03T12:34:56.789012Z\n    addr: 192.168.100.200\n    digest: {digest}\n    blob: {base64}\n    ints: [{ints}]\n"
    );
    assert!(yaml.len() < MAX_YAML_BYTES);

    let def =
        parse_workflow(&yaml).expect("ordinary numeric content must not trip the digit-run bound");
    assert_eq!(def.steps.len(), 1);

    // And the bound really is where the comment says it is: one digit more
    // than the limit, in an inert position (a comment), is rejected. This
    // is the documented over-rejection, pinned so it is visible rather than
    // discovered.
    let over = format!(
        "name: t\nversion: 1\n# {}\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n",
        "7".repeat(MAX_PLAIN_NUMERIC_DIGIT_RUN + 1)
    );
    match parse_workflow(&over).expect_err("one digit over the limit must be rejected") {
        ParseError::NumericTokenTooLong { run, max } => {
            assert_eq!(max, MAX_PLAIN_NUMERIC_DIGIT_RUN);
            assert_eq!(run, MAX_PLAIN_NUMERIC_DIGIT_RUN + 1);
        }
        other => panic!("expected NumericTokenTooLong, got {other:?}"),
    }
    // Exactly at the limit still parses, so the boundary is where it says.
    let at = format!(
        "name: t\nversion: 1\n# {}\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n",
        "7".repeat(MAX_PLAIN_NUMERIC_DIGIT_RUN)
    );
    parse_workflow(&at).expect("exactly at the limit must still parse");
}

#[test]
fn the_densest_alias_free_documents_under_the_byte_cap_still_parse() {
    // Task X1 fix round 1. This is the behavioural half of
    // `MAX_EXPANDED_WEIGHT`'s derivation; the arithmetic half is the `const`
    // assert next to that constant in `parse/mod.rs`.
    //
    // It replaces `the_node_ceiling_leaves_room_for_any_alias_free_document
    // _under_the_byte_cap`, whose assertion was
    // `MAX_EXPANDED_NODES >= MAX_YAML_BYTES` with the former *defined* as
    // the latter — a tautology that could not fail for any value, while its
    // comment claimed it pinned the two together. That is the shape of
    // defect `MAX_ALIAS_TOKENS` had: a guard that reads as protection while
    // protecting nothing.
    //
    // The claim being guarded: no alias-free document under the byte cap
    // may be rejected by the expansion ceiling, so nothing is ever rejected
    // for being *large* — only for amplifying.
    //
    // Payloads, each padded to within a few bytes of `MAX_YAML_BYTES`, with
    // no `&` or `*` anywhere:
    //
    //   1. `b: {a,a,a,…}`  — a flow mapping with omitted values. The
    //      densest alias-free YAML there is: measured 262,070 nodes in
    //      262,144 bytes, exactly 1.00 nodes/byte. The previous round's
    //      derivation claimed the densest was `[x,x,…]` at 2.00 bytes per
    //      node, and was wrong by 2x because it never tried this shape.
    //   2. `b: [x,x,x,…]`  — 131,044 nodes, 0.50 nodes/byte.
    //   3. `b: [[],[],…]`  — 87,368 nodes.
    //   4. a block sequence of `- a` — 65,529 nodes.
    //   5. one 250,000-byte quoted scalar — 18 nodes, but the maximum
    //      possible scalar payload, which is the axis the node-count unit
    //      was blind to.
    //
    // Measured weights: 2,227,640 / 1,179,432 / 698,998 / 589,798 /
    // 250,198 against a 2,621,440 ceiling. The heaviest sits at 85.0% of
    // it — fix round 2 tightened the ceiling from 4 MiB, and fix round 3
    // re-measured what that bought against the *maximising* shape rather
    // than across two different ones: 159.1 MB at 4 MiB against 101.9 MB
    // here. The margin is correspondingly thinner on purpose. Lowering the
    // ceiling further, or raising `MAX_YAML_BYTES`, turns this test red;
    // widening the ceiling trips the upper tripwire beside the derivation.
    let hdr = "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: s\n    b: ";
    let dense = |open: &str, close: &str, unit: &str| -> String {
        let base = hdr.len() + open.len() + close.len() + 1;
        let n = (MAX_YAML_BYTES - base) / unit.len();
        let mut y = String::with_capacity(MAX_YAML_BYTES);
        y.push_str(hdr);
        y.push_str(open);
        for _ in 0..n {
            y.push_str(unit);
        }
        y.push_str(close);
        y.push('\n');
        y
    };
    let block_seq = {
        let mut y = String::from(
            "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n",
        );
        while y.len() < MAX_YAML_BYTES - 8 {
            y.push_str("- a\n");
        }
        y
    };
    let cases = [
        (
            "densest: flow map with omitted values",
            dense("{", "}", "a,"),
        ),
        ("flow sequence of 1-char scalars", dense("[", "]", "x,")),
        ("nested empty sequences", dense("[", "]", "[],")),
        ("block sequence", block_seq),
        (
            "one 250,000-byte scalar",
            format!("{hdr}\"{}\"\n", "z".repeat(250_000)),
        ),
    ];

    for (label, yaml) in cases {
        assert!(
            yaml.len() <= MAX_YAML_BYTES,
            "{label}: {} bytes exceeds the byte cap, so this would test the wrong bound",
            yaml.len()
        );
        assert!(
            !yaml.contains('&') && !yaml.contains('*'),
            "{label}: must be alias-free or it proves nothing"
        );
        // The duplicate keys in shape 1 make `serde_yaml` reject it on its
        // own terms, and shape 5 is a step body that is not a mapping — so
        // the assertion is specifically that the EXPANSION ceiling did not
        // fire, not that every shape is a valid workflow.
        if let Err(ParseError::ExpandsTooLarge { actual_bytes, max }) = parse_workflow(&yaml) {
            panic!(
                "{label}: an alias-free {actual_bytes}-byte document under the byte cap was \
                 rejected by the {max}-byte expansion ceiling. MAX_EXPANDED_WEIGHT is now too \
                 small for MAX_YAML_BYTES: legitimate documents are being rejected for being \
                 large rather than for amplifying."
            );
        }
    }
}

#[test]
fn a_large_anchored_scalar_aliased_many_times_is_rejected() {
    // Task X1 fix round 1, the Critical this round exists for. The first
    // version of `MAX_EXPANDED_WEIGHT` counted nodes and `visit_str`
    // discarded the scalar's length, so one node could carry an arbitrarily
    // large aliased payload.
    //
    // Payload: one anchored scalar of L `z` bytes, aliased K times in a
    // FLAT sequence — `secrets: &big ["zzz…"]` then `b: [*big,*big,…]`.
    // Flat matters: jumps stay proportional to events, so `serde_yaml`'s
    // `jumpcount > events.len() * 100` guard never fires, unlike the
    // fan-outs the other tests use. The source stays under the byte cap
    // because the scalar is written once and each reuse costs ~5 bytes.
    //
    // The two K/L pairs the security review measured against the
    // node-count version are first. Both were ADMITTED by it: K=40,000
    // L=60,000 (180,138 B in the review's construction) drove the real
    // parse to 4,593 MB resident, and K=43,000 L=131,072 reached allocation
    // failure past a 2 GiB address space.
    //
    // Under the byte-weight unit, row 1 — 260,110 B in this construction,
    // still under the byte cap — weighs 4,201,333 against the 2,621,440
    // ceiling and is rejected by the expansion ceiling after expanding 159
    // nodes: measured 3.2 ms release, 23.3 ms debug, process peak RSS
    // 9.3 MB, essentially the source string itself. Row 2 is 346,182 B in
    // this construction and so is rejected by `MAX_YAML_BYTES` first, which
    // is also correct but is a different bound — the match below accepts
    // either, and the precise assertion at the end of this test pins the
    // row that actually exercises the expansion ceiling.
    //
    // The remaining rows sweep the K/L trade-off so the test does not pass
    // for one accidental parameter choice: few huge scalars, many medium
    // ones, and many small ones.
    let aliased_scalar = |k: usize, l: usize| -> String {
        let mut y = format!(
            "name: t\nversion: 1\nsecrets: &big [\"{}\"]\npermissions:\n  unattended: {{ escalate: fail }}\nsteps:\n  - id: s\n    b: [",
            "z".repeat(l)
        );
        for i in 0..k {
            if i > 0 {
                y.push(',');
            }
            y.push_str("*big");
        }
        y.push_str("]\n");
        y
    };

    for (label, k, l) in [
        ("review row 1: K=40,000 L=60,000", 40_000usize, 60_000usize),
        ("review row 2: K=43,000 L=131,072", 43_000, 131_072),
        ("few huge: K=2,000 L=120,000", 2_000, 120_000),
        ("many medium: K=60,000 L=30,000", 60_000, 30_000),
        ("many small: K=80,000 L=1,000", 80_000, 1_000),
    ] {
        let yaml = aliased_scalar(k, l);
        // These payloads are deliberately allowed to exceed MAX_YAML_BYTES:
        // rows 2 and 4 do, and are then rejected by the byte cap instead,
        // which is also correct. Rows 1, 3 and 5 sit under it, so those are
        // the ones that exercise the expansion ceiling.
        let err = parse_workflow(&yaml).expect_err("must be rejected");
        match err {
            ParseError::ExpandsTooLarge { max, .. } => assert_eq!(max, MAX_EXPANDED_WEIGHT),
            ParseError::TooLarge { .. } if yaml.len() > MAX_YAML_BYTES => {}
            other => panic!(
                "{label}: a {}-byte document that materialises {} bytes of string data \
                 must be rejected, got {other:?}",
                yaml.len(),
                k.saturating_mul(l)
            ),
        }
    }

    // And the one that matters most, asserted precisely: the review's
    // 4,593 MB row sits UNDER the byte cap, so nothing but the expansion
    // ceiling can be what rejects it.
    let yaml = aliased_scalar(40_000, 60_000);
    assert!(
        yaml.len() < MAX_YAML_BYTES,
        "this row must stay under the byte cap or it does not test the expansion ceiling: {} bytes",
        yaml.len()
    );
    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml).expect_err("must be rejected");
    let elapsed = start.elapsed();
    assert!(
        matches!(err, ParseError::ExpandsTooLarge { .. }),
        "expected the expansion ceiling to fire, got {err:?}"
    );
    assert!(
        elapsed < REJECTION_MUST_BE_CHEAP,
        "rejecting 2.4 GB of would-be string data took {elapsed:?}"
    );
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
    // Task X1 added `MAX_EXPANDED_WEIGHT`, which is deliberately not that
    // shape: it weighs what the deserializer produced, and a `prompt: |`
    // block scalar is one node charged its own length once, however much
    // markdown emphasis it contains. Measured: this document weighs 4,274
    // against a 2,621,440 ceiling.
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
    // P51 sweep, Task X1 (re-measured in fix round 1 after the meter's
    // unit changed from node count to byte weight): the guard still fires,
    // and it fires inside the metered walk rather than inside the typed
    // parse. Which of the two limits stops this payload is measured, not
    // assumed — it is `serde_yaml`'s repetition guard, not
    // `MAX_EXPANDED_WEIGHT`, because five-way nesting reaches the jump
    // limit while still inside the weight budget. Measured end to end
    // through `parse_workflow`: 1.4 ms release, 18.3 ms debug.
    // `parse_workflow` returns that error rather than continuing, so the
    // variant asserted below is unchanged. A `serde_yaml` error found by
    // the walk is a rejection, never a "proceed anyway": see
    // `parse/expansion.rs`'s doc comment.
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
