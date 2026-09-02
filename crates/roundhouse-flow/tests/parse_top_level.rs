use roundhouse_flow::parse::types::{Effect, IsolationDef, UnattendedEscalate};
use roundhouse_flow::parse::{
    parse_workflow, ParseError, MAX_ALIAS_TOKENS, MAX_LEADING_INDENT_CHARS, MAX_TOP_LEVEL_STEPS,
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
    // sees it, cheaply, whenever it understands the shape (fix round 3
    // demoted this scan to best-effort defence in depth — `MAX_YAML_BYTES`,
    // now 32 KiB, is the actual bound regardless of whether this scan
    // catches a given payload; see
    // `worst_case_bracket_nesting_at_the_byte_cap_is_bounded`). Bomb size
    // kept well under the 32 KiB cap so this exercises the scan, not the
    // cap.
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
    // under the 32 KiB cap from fix round 3, so this exercises the scan,
    // not the cap).
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
    // is a bound on parse cost: see
    // `ignored_reproduction_of_the_open_anchor_alias_fanout_dos` below, and
    // the open finding in `parse/mod.rs`'s module doc comment.
    let bomb = "[".repeat(MAX_YAML_BYTES);
    assert_eq!(bomb.len(), MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let result: Result<serde_yaml::Value, _> = serde_yaml::from_str(&bomb);
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "an unclosed bracket bomb must not parse successfully"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "this one shape is cheap at the cap (measured ~650ms at 256 KiB in this environment); \
         took {elapsed:?}"
    );
}

/// Builds the open finding's attack payload: one anchored leaf list of
/// `leaves` plain scalars, then `levels` levels each aliasing the previous
/// one `fan` times. Every bracket is balanced, nesting is one level deep,
/// and the alias count stays low — so none of this module's shape checks
/// see anything unusual.
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

#[test]
#[ignore = "reproduces an OPEN, UNFIXED denial-of-service finding: burns seconds of CPU on purpose. Run with `cargo test -p roundhouse-flow --release -- --ignored`."]
fn ignored_reproduction_of_the_open_anchor_alias_fanout_dos() {
    // The executable record of the open finding in `parse/mod.rs`'s module
    // doc comment. A ~2.3 KB document — SMALLER than the frozen §8.9
    // fixture (2,271 B) — costs seconds of pinned CPU, and every bound this
    // module enforces admits it: it is well under `MAX_YAML_BYTES`, it has
    // 28 alias tokens (under `MAX_ALIAS_TOKENS`), its brackets are balanced
    // at depth 1 (under `MAX_FLOW_NESTING_DEPTH`), and it declares one step.
    //
    // Measured in this environment, release build, via `parse_workflow`:
    // 2,268 B -> 137 ms; 2,300 B -> 537 ms; 2,332 B -> 2.1 s;
    // 2,364 B -> 8.1 s; 4,396 B -> 33.9 s. Doubling the document roughly
    // quadruples the cost, which is the O(bytes^2) mechanism the module doc
    // comment explains. This test uses the 2,332 B point.
    let yaml = anchor_alias_fanout(1000, 4, 7);
    assert!(yaml.len() < 3_000, "payload must stay tiny: {}", yaml.len());
    assert!(yaml.len() < MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let _ = parse_workflow(&yaml);
    let elapsed = start.elapsed();

    assert!(
        elapsed > std::time::Duration::from_millis(250),
        "if this ever stops being expensive, the finding is fixed and this test (and the open \
         finding in parse/mod.rs) should be retired; took {elapsed:?} for {} bytes",
        yaml.len()
    );
}

#[test]
fn an_alias_dense_document_is_rejected_cheaply() {
    // Fix round 4 on Task 10: `MAX_ALIAS_TOKENS` is best-effort defence in
    // depth against alias fan-out. It catches the wide-fan variants; it
    // provably does NOT catch the narrow-fan ones (see `MAX_ALIAS_TOKENS`'s
    // own doc comment for the measured table). This pins the half it does.
    let yaml = anchor_alias_fanout(10, 16, 8);
    assert!(yaml.len() < MAX_YAML_BYTES);

    let start = std::time::Instant::now();
    let err = parse_workflow(&yaml).expect_err("an alias-dense document must be rejected");
    let elapsed = start.elapsed();

    match err {
        ParseError::TooManyAliases { actual, max } => {
            assert_eq!(max, MAX_ALIAS_TOKENS);
            assert!(actual > max, "{actual} must exceed {max}");
        }
        other => panic!("expected ParseError::TooManyAliases, got {other:?}"),
    }
    assert!(
        elapsed < std::time::Duration::from_secs(1),
        "the check must reject before paying serde_yaml's cost; took {elapsed:?}"
    );
}

#[test]
fn shell_globs_are_not_counted_as_alias_tokens() {
    // The refinement that keeps `MAX_ALIAS_TOKENS` off legitimate
    // workflows: an alias is `*` followed by an anchor-name character. The
    // frozen §8.9 fixture's only two `*` characters are shell globs, each
    // followed by `"` — so it counts zero, not two. This builds a workflow
    // with far more globs than the threshold and asserts it still parses.
    let mut yaml = String::from("name: t\nversion: 1\npermissions:\n  default: deny\n  rules:\n");
    for i in 0..(MAX_ALIAS_TOKENS * 2) {
        yaml.push_str(&format!(
            "    - {{ shell: {{ program: \"p{i}\", args: [\"run\", \"*\"] }}, effect: allow }}\n"
        ));
    }
    yaml.push_str("  unattended: { escalate: fail }\nsteps:\n  - id: s\n");

    let def = parse_workflow(&yaml).expect("shell globs must not be counted as alias tokens");
    assert_eq!(def.permissions.rules.len(), MAX_ALIAS_TOKENS * 2);
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
    // Fix round 4 on Task 10: `MAX_YAML_BYTES` is no longer a security
    // bound (see `parse/mod.rs`'s open finding); its remaining job is to
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
