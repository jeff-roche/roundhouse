use roundhouse_flow::parse::steps::{
    parse_step, topological_order, MapIsolationDef, OnItemError, StepBody, StepDef,
};
use roundhouse_flow::parse::types::OnTimeout;
use roundhouse_flow::parse::{parse_workflow, ParseError};

const PR_REVIEW_YAML: &str = include_str!("fixtures/pr_review.yaml");

fn step(yaml: &str) -> StepDef {
    parse_step(&serde_yaml::from_str(yaml).unwrap()).unwrap()
}

fn try_step(yaml: &str) -> Result<StepDef, ParseError> {
    parse_step(&serde_yaml::from_str(yaml).unwrap())
}

#[test]
fn parses_every_step_kind_in_the_fixture() {
    let def = parse_workflow(PR_REVIEW_YAML).unwrap();
    let top_steps: Vec<StepDef> = def.steps.iter().map(|v| parse_step(v).unwrap()).collect();

    assert_eq!(top_steps[0].id, "list_prs");
    assert!(matches!(top_steps[0].body, StepBody::Tool { .. }));

    assert_eq!(top_steps[1].id, "per_pr");
    let StepBody::Map {
        over,
        r#as,
        max_parallel,
        on_item_error,
        isolation,
        steps: inner,
    } = &top_steps[1].body
    else {
        panic!("expected Map step");
    };
    assert_eq!(
        over,
        "${{ slice(steps.list_prs.output, 0, inputs.max_prs) }}"
    );
    assert_eq!(r#as, "pr");
    assert_eq!(*max_parallel, 4);
    assert_eq!(*on_item_error, OnItemError::Continue);
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree {
            base_ref: Some("refs/pull/${{ pr.number }}/head".to_string())
        })
    );

    let inner_steps: Vec<StepDef> = inner.iter().map(|v| parse_step(v).unwrap()).collect();
    assert!(matches!(inner_steps[0].body, StepBody::Agent { .. }));
    assert!(matches!(inner_steps[1].body, StepBody::Tool { .. }));
    assert!(matches!(inner_steps[2].body, StepBody::Gate { .. }));
    assert_eq!(
        inner_steps[3].when.as_deref(),
        Some("${{ steps.gate.output.approve }}")
    );
    assert_eq!(
        inner_steps[3].idempotency_key.as_deref(),
        Some("pr-${{ pr.number }}-review-${{ run.id }}")
    );

    let StepBody::Gate {
        title, on_timeout, ..
    } = &inner_steps[2].body
    else {
        panic!("expected Gate step");
    };
    assert_eq!(title, "Post review on PR #${{ pr.number }}?");
    assert_eq!(*on_timeout, OnTimeout::Deny);

    let catch_step = parse_step(&def.catch[0]).unwrap();
    assert!(matches!(catch_step.body, StepBody::Emit { .. }));
    let finally_step = parse_step(&def.finally[0]).unwrap();
    assert!(matches!(finally_step.body, StepBody::Report { .. }));
}

#[test]
fn file_order_is_default_but_needs_declares_explicit_dag() {
    let a = step("id: a\ntool: shell\nwith: { cmd: [echo] }");
    let b = step("id: b\nneeds: [a]\ntool: shell\nwith: { cmd: [echo] }");
    let c = step("id: c\ntool: shell\nwith: { cmd: [echo] }");
    // Declared out of dependency order (c before b) but b needs a, which is before it.
    let steps = [c.clone(), a.clone(), b.clone()];
    let order = topological_order(&steps).unwrap();
    let pos = |id: &str| order.iter().position(|&i| steps[i].id == id).unwrap();
    assert!(
        pos("a") < pos("b"),
        "b's declared dependency on a must be honored"
    );
    // c has no dependency, so it keeps its file-order position (index 0).
    assert_eq!(order[0], 0);
}

#[test]
fn a_plain_tool_step_parses_with_default_with() {
    let s = step("id: a\ntool: shell");
    let StepBody::Tool { tool, with } = &s.body else {
        panic!("expected Tool step");
    };
    assert_eq!(tool, "shell");
    assert_eq!(with, &serde_json::json!({}));
}

#[test]
fn a_call_step_parses_workflow_and_with() {
    let s = step("id: a\ncall: other-workflow\nwith: { x: 1 }");
    let StepBody::Call { workflow, with } = &s.body else {
        panic!("expected Call step");
    };
    assert_eq!(workflow, "other-workflow");
    assert_eq!(with, &serde_json::json!({ "x": 1 }));
}

// ---------------------------------------------------------------------
// "Exactly one of tool/agent/map/gate/call/emit/report" — zero and two-key
// cases each get a distinct, actionable error (per this task's brief: "give
// zero-key and two-key cases distinct, actionable errors").
// ---------------------------------------------------------------------

#[test]
fn a_step_body_with_no_recognized_kind_is_rejected() {
    // Every field here is individually recognised by `StepDefWire` — none
    // of them is a body-kind key, so this exercises the "zero kinds found"
    // branch specifically, not `deny_unknown_fields`.
    let err = try_step("id: a\nwhen: \"${{ true }}\"").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("found none"), "message was: {msg}");
}

#[test]
fn a_step_body_with_two_recognized_kinds_is_rejected() {
    let err = try_step("id: a\ntool: shell\nagent: { prompt: hi }").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("found 2"), "message was: {msg}");
}

#[test]
fn an_orphaned_with_key_is_rejected() {
    // `with` only makes sense alongside `tool`/`call`; alone with `agent` it
    // would otherwise be silently ignored.
    let err = try_step("id: a\nagent: { prompt: hi }\nwith: { x: 1 }").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("`with`"), "message was: {msg}");
}

#[test]
fn an_orphaned_steps_key_is_rejected() {
    // `steps` only makes sense alongside `map`.
    let err = try_step("id: a\ntool: shell\nsteps: [{ id: b, tool: shell }]").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("`steps`"), "message was: {msg}");
}

#[test]
fn a_map_step_without_a_sibling_steps_list_is_rejected() {
    let err = try_step("id: a\nmap: { over: x, as: y }").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("requires a sibling `steps:`"),
        "message was: {msg}"
    );
}

// ---------------------------------------------------------------------
// Fail-closed nested shapes: `deny_unknown_fields` inside each body kind.
// ---------------------------------------------------------------------

#[test]
fn unknown_step_level_key_is_rejected() {
    let err = try_step("id: a\ntool: shell\ntoolz: 1").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn unknown_field_inside_agent_body_is_rejected() {
    let err = try_step("id: a\nagent: { promt: hi }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn unknown_field_inside_map_body_is_rejected() {
    let err = try_step(
        "id: a\nmap: { over: x, as: y, on_itme_error: continue }\nsteps: [{ id: b, tool: shell }]",
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn unknown_field_inside_gate_body_is_rejected() {
    let err =
        try_step("id: a\ngate: { title: t, timeout: 1h, on_timeout: deny, extra: 1 }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn misspelled_on_item_error_value_is_rejected() {
    let err = try_step(
        "id: a\nmap: { over: x, as: y, on_item_error: continu }\nsteps: [{ id: b, tool: shell }]",
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

#[test]
fn misspelled_gate_on_timeout_value_is_rejected() {
    let err = try_step("id: a\ngate: { title: t, timeout: 1h, on_timeout: aproove }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)));
}

// ---------------------------------------------------------------------
// Duplicate keys inside a step body. This task's brief characterized this
// as "silently last-wins today", framing typing the body as the fix.
// Measured against the pinned serde_yaml 0.9.34 before relying on that
// framing: it is not true for this library version — see
// `parse::steps`'s module doc comment for the full finding.
// `serde_yaml::Mapping::deserialize` already rejects a duplicate key when
// parsing raw YAML text, before a `Value` even exists, so `parse_step`
// (which only ever receives an already-successfully-built `Value`) can
// never actually observe one. The tests below prove that at the two places
// it's actually observable: the raw-`Value` stage directly, and this
// crate's real entry point (`parse_workflow`) end to end.
// ---------------------------------------------------------------------

#[test]
fn duplicate_step_body_key_is_rejected_at_the_raw_value_stage() {
    // This task's brief characterized duplicate keys in a step body as
    // "silently last-wins today" (true of a `serde_yaml::Value` built
    // *programmatically*, e.g. via `Mapping::insert`, which just overwrites
    // a repeated key). Measured against the pinned `serde_yaml` 0.9.34
    // rather than assumed: parsing raw YAML *text* into a plain untyped
    // `Value` already rejects a duplicate key, before this module's types
    // are involved at all (`serde_yaml::Mapping`'s own `Deserialize` impl
    // checks `mapping.entry(key)` and errors on the second occurrence).
    let raw = "id: a\ntool: shell\ntool: http\nwith: {}";
    let err = serde_yaml::from_str::<serde_yaml::Value>(raw).unwrap_err();
    assert!(
        err.to_string().contains("duplicate entry"),
        "err was: {err}"
    );
}

#[test]
fn duplicate_step_body_key_is_rejected_end_to_end_through_parse_workflow() {
    // The consequence for this task's actual entry point: a workflow whose
    // step body has a duplicate key never reaches `parse_step` with a
    // silently-merged `Value` — the whole document fails to parse first,
    // at `parse_workflow`'s `serde_yaml::from_str::<WorkflowDef>` call,
    // because building `WorkflowDef.steps: Vec<serde_yaml::Value>` already
    // goes through the same `Mapping` deserialization checked above.
    let yaml = "name: t\nversion: 1\npermissions:\n  unattended: { escalate: fail }\nsteps:\n  - id: a\n    tool: shell\n    tool: http\n    with: {}\n";
    let err = parse_workflow(yaml).unwrap_err();
    assert!(
        err.to_string().contains("duplicate entry"),
        "err was: {err}"
    );
}

#[test]
fn duplicate_step_id_key_is_rejected_at_the_raw_value_stage() {
    let raw = "id: a\nid: b\ntool: shell";
    let err = serde_yaml::from_str::<serde_yaml::Value>(raw).unwrap_err();
    assert!(
        err.to_string().contains("duplicate entry"),
        "err was: {err}"
    );
}

#[test]
fn duplicate_nested_agent_field_is_rejected_at_the_raw_value_stage() {
    let raw = "id: a\nagent: { prompt: hi, prompt: bye }";
    let err = serde_yaml::from_str::<serde_yaml::Value>(raw).unwrap_err();
    assert!(
        err.to_string().contains("duplicate entry"),
        "err was: {err}"
    );
}

// ---------------------------------------------------------------------
// Step id validation.
// ---------------------------------------------------------------------

#[test]
fn empty_step_id_is_rejected() {
    let err = try_step("id: \"\"\ntool: shell").unwrap_err();
    assert!(matches!(err, ParseError::InvalidStepId { .. }));
}

#[test]
fn a_step_id_with_illegal_characters_is_rejected() {
    let err = try_step("id: \"a b\"\ntool: shell").unwrap_err();
    assert!(matches!(err, ParseError::InvalidStepId { .. }));
}

#[test]
fn an_overlong_step_id_is_rejected() {
    let long_id = "a".repeat(roundhouse_flow::parse::steps::MAX_STEP_ID_LEN + 1);
    let yaml = format!("id: {long_id}\ntool: shell");
    let err = try_step(&yaml).unwrap_err();
    assert!(matches!(err, ParseError::InvalidStepId { .. }));
}

#[test]
fn a_step_id_at_exactly_the_length_limit_parses() {
    let id = "a".repeat(roundhouse_flow::parse::steps::MAX_STEP_ID_LEN);
    let yaml = format!("id: {id}\ntool: shell");
    let s = try_step(&yaml).unwrap();
    assert_eq!(s.id, id);
}

#[test]
fn a_wildly_overlong_step_id_does_not_get_echoed_into_the_error_in_full() {
    // Fix round 2, item 6 (M-1): pre-fix, `ParseError::InvalidStepId`'s
    // `{id:?}` echoed the whole offending id, so a 5,000-character step id
    // (well past `MAX_STEP_ID_LEN`) produced a 5,054-character error
    // message. Payload: 5,000 `'a'` bytes as the `id:` value.
    let long_id = "a".repeat(5_000);
    let yaml = format!("id: {long_id}\ntool: shell");
    let err = try_step(&yaml).unwrap_err();
    let ParseError::InvalidStepId { id, .. } = &err else {
        panic!("expected InvalidStepId, got {err:?}");
    };
    assert!(
        id.len() < 200,
        "the echoed id field must be bounded, not the full 5,000-byte input: {} bytes",
        id.len()
    );
    let rendered = err.to_string();
    assert!(
        rendered.len() < 300,
        "the whole rendered error must be bounded too: {} bytes ({rendered:?})",
        rendered.len()
    );
    assert!(
        rendered.contains("5000 bytes total") || rendered.contains("5000"),
        "the truncated message should still state the original length: {rendered:?}"
    );
}

#[test]
fn too_many_needs_entries_is_rejected() {
    let needs: Vec<String> = (0..roundhouse_flow::parse::steps::MAX_NEEDS_PER_STEP + 1)
        .map(|i| format!("s{i}"))
        .collect();
    let yaml = format!("id: a\nneeds: [{}]\ntool: shell", needs.join(", "));
    let err = try_step(&yaml).unwrap_err();
    assert!(
        matches!(err, ParseError::TooManyNeeds { .. }),
        "err was: {err:?}"
    );
}

// ---------------------------------------------------------------------
// `needs:` graph hazards: cycle, self-reference, unknown reference,
// duplicate step id — each a clean typed error, never a panic or a hang.
// ---------------------------------------------------------------------

#[test]
fn a_cycle_is_rejected() {
    let a = step("id: a\nneeds: [b]\ntool: shell");
    let b = step("id: b\nneeds: [a]\ntool: shell");
    let err = topological_order(&[a, b]).unwrap_err();
    assert!(
        matches!(err, ParseError::StepGraphCycle { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn a_longer_cycle_is_rejected() {
    let a = step("id: a\nneeds: [c]\ntool: shell");
    let b = step("id: b\nneeds: [a]\ntool: shell");
    let c = step("id: c\nneeds: [b]\ntool: shell");
    let err = topological_order(&[a, b, c]).unwrap_err();
    let ParseError::StepGraphCycle { steps: stuck } = err else {
        panic!("expected StepGraphCycle");
    };
    assert_eq!(stuck.len(), 3);
}

#[test]
fn a_self_reference_is_rejected_as_a_cycle() {
    let a = step("id: a\nneeds: [a]\ntool: shell");
    let err = topological_order(&[a]).unwrap_err();
    assert!(
        matches!(err, ParseError::StepGraphCycle { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn needs_naming_an_unknown_step_id_is_rejected() {
    let a = step("id: a\nneeds: [nonexistent]\ntool: shell");
    let err = topological_order(&[a]).unwrap_err();
    let ParseError::UnknownStepDependency { step, needs } = err else {
        panic!("expected UnknownStepDependency, got {err:?}");
    };
    assert_eq!(step, "a");
    assert_eq!(needs, "nonexistent");
}

#[test]
fn duplicate_step_ids_across_a_list_are_rejected() {
    let a1 = step("id: a\ntool: shell");
    let a2 = step("id: a\ntool: shell");
    let err = topological_order(&[a1, a2]).unwrap_err();
    let ParseError::DuplicateStepId { id } = err else {
        panic!("expected DuplicateStepId, got {err:?}");
    };
    assert_eq!(id, "a");
}

#[test]
fn a_diamond_dependency_parses_deterministically() {
    // a <- b, a <- c, b and c <- d (d needs both b and c). File order:
    // a, b, c, d. Expected order: a first (no deps), then b before c (file
    // order tie-break among two steps that both only need a), then d.
    let a = step("id: a\ntool: shell");
    let b = step("id: b\nneeds: [a]\ntool: shell");
    let c = step("id: c\nneeds: [a]\ntool: shell");
    let d = step("id: d\nneeds: [b, c]\ntool: shell");
    let steps = [a, b, c, d];
    let order = topological_order(&steps).unwrap();
    assert_eq!(order, vec![0, 1, 2, 3]);
}

// =======================================================================
// Fix round 1 (security + code review on the initial implementation).
// =======================================================================

// -- H3: validation moved from `parse_step` into `TryFrom`, so every ------
// -- deserialize entry point gets it, not just `parse_step`'s callers. ---

#[test]
fn h3_an_invalid_step_id_is_rejected_through_serde_yaml_from_value_directly() {
    // Before the fix, this exact call (bypassing `parse_step`) returned
    // `Ok` — validation lived in `parse_step`, not in `StepDef`'s own
    // `Deserialize`/`TryFrom`.
    let v: serde_yaml::Value =
        serde_yaml::from_str("id: \"../../../etc/passwd\"\ntool: shell\nwith: {}").unwrap();
    let err = serde_yaml::from_value::<StepDef>(v).unwrap_err();
    assert!(err.to_string().contains("is invalid"), "err was: {err}");
}

#[test]
fn h3_too_many_needs_is_rejected_through_serde_json_from_str_directly() {
    // The reviewer's exact second entry point: `serde_json::from_str`,
    // never touching `parse_step`, `serde_yaml`, or this crate's own
    // helpers at all.
    let needs: Vec<String> = (0..roundhouse_flow::parse::steps::MAX_NEEDS_PER_STEP + 1)
        .map(|i| format!("s{i}"))
        .collect();
    let json = serde_json::json!({
        "id": "z",
        "tool": "shell",
        "with": {},
        "needs": needs,
    });
    let err = serde_json::from_value::<StepDef>(json).unwrap_err();
    assert!(
        err.to_string().contains("exceeding the limit"),
        "err was: {err}"
    );
}

#[test]
fn h3_parse_step_still_returns_a_fully_typed_error_for_its_own_callers() {
    // The fix's other half: `parse_step`'s own direct callers must not
    // lose typed-error granularity as the price of closing the bypass.
    let err = try_step("id: \"a b\"\ntool: shell").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepId { .. }),
        "err was: {err:?}"
    );
}

// -- H1: `map.isolation` is a closed, validated type. ---------------------

#[test]
fn h1_a_misspelled_isolation_tier_is_rejected() {
    let err = try_step(
        "id: a\nmap: { over: x, as: y, isolation: { worktreee: { base_ref: r } } }\nsteps: [{ id: b, tool: shell }]",
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h1_an_unrecognised_isolation_param_is_rejected() {
    let err = try_step(
        "id: a\nmap: { over: x, as: y, isolation: { worktree: { basee_ref: r } } }\nsteps: [{ id: b, tool: shell }]",
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h1_a_numeric_isolation_value_is_rejected() {
    let err =
        try_step("id: a\nmap: { over: x, as: y, isolation: 42 }\nsteps: [{ id: b, tool: shell }]")
            .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h1_a_bare_worktree_isolation_string_parses_with_no_base_ref() {
    let s = step(
        "id: a\nmap: { over: x, as: y, isolation: worktree }\nsteps: [{ id: b, tool: shell }]",
    );
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree { base_ref: None })
    );
}

#[test]
fn h1_a_second_isolation_tier_key_is_rejected() {
    let err = try_step(
        "id: a\nmap: { over: x, as: y, isolation: { worktree: {}, sandbox: {} } }\nsteps: [{ id: b, tool: shell }]",
    )
    .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn map_isolation_none_parses_without_checking_narrowing_against_defaults() {
    // Documents, rather than fixes, the deferral in `MapIsolationDef`'s doc
    // comment: `isolation: none` under `defaults.isolation: worktree`
    // would *widen* the step's isolation (forbidden by the phase Global
    // Constraint and §8.5), but `parse_step` has no visibility into the
    // enclosing workflow's `defaults.isolation` to check that. The real
    // narrowing check is the executor's (Task 5) responsibility.
    let s =
        step("id: a\nmap: { over: x, as: y, isolation: none }\nsteps: [{ id: b, tool: shell }]");
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(isolation, &Some(MapIsolationDef::None));
}

// -- H2: `caps.max_cost_usd` rejects non-finite and negative values. ------

#[test]
fn h2_nan_max_cost_usd_is_rejected() {
    let err = try_step("id: a\ntool: shell\ncaps: { max_cost_usd: .nan }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h2_infinite_max_cost_usd_is_rejected() {
    let err = try_step("id: a\ntool: shell\ncaps: { max_cost_usd: .inf }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h2_negative_max_cost_usd_is_rejected() {
    let err = try_step("id: a\ntool: shell\ncaps: { max_cost_usd: -1.0 }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn h2_a_finite_non_negative_max_cost_usd_parses() {
    let s = step("id: a\ntool: shell\ncaps: { max_cost_usd: 0.5 }");
    assert_eq!(s.caps.unwrap().max_cost_usd, Some(0.5));
}

#[test]
fn h2_a_zero_max_cost_usd_parses() {
    // Zero is finite and non-negative — a legitimate (if unusual) "no
    // spend allowed" cap, unlike retry.rs's own "0s means unconfigured"
    // duration case (a different field with a different semantics).
    let s = step("id: a\ntool: shell\ncaps: { max_cost_usd: 0.0 }");
    assert_eq!(s.caps.unwrap().max_cost_usd, Some(0.0));
}

// -- M2: `gate.on_timeout: approve` parses; its §8.11 precondition is a ---
// -- documented, tested deferral to the executor. -------------------------

#[test]
fn gate_on_timeout_approve_parses_without_checking_its_run_time_precondition() {
    // §8.11: "approve is permitted only when the run's policy is narrower
    // than the job default." This parser has no access to "the run's
    // policy" (a run-time, bound fact) from one step's YAML alone, unlike
    // Task 2's Park-escalation check (fully expressible from sibling
    // fields in the same static document). Deferred to the executor.
    let s = step("id: a\ngate: { title: t, timeout: 1h, on_timeout: approve }");
    let StepBody::Gate { on_timeout, .. } = &s.body else {
        panic!("expected Gate step");
    };
    assert_eq!(*on_timeout, OnTimeout::Approve);
}

// -- M3: `map.as` gets the same charset/length rule as a step id, plus ---
// -- a reserved-expression-root check. ------------------------------------

#[test]
fn m3_an_empty_map_as_is_rejected() {
    let err =
        try_step("id: a\nmap: { over: x, as: \"\" }\nsteps: [{ id: b, tool: shell }]").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn m3_a_map_as_with_illegal_characters_is_rejected() {
    let err = try_step("id: a\nmap: { over: x, as: \"a b\" }\nsteps: [{ id: b, tool: shell }]")
        .unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

#[test]
fn m3_map_as_shadowing_a_reserved_expression_root_is_rejected() {
    for reserved in ["secrets", "steps", "inputs", "run", "vars", "env"] {
        let yaml =
            format!("id: a\nmap: {{ over: x, as: {reserved} }}\nsteps: [{{ id: b, tool: shell }}]");
        let err = try_step(&yaml).unwrap_err();
        assert!(
            matches!(err, ParseError::Yaml(_)),
            "expected rejection for as: {reserved}, err was: {err:?}"
        );
    }
}

#[test]
fn m3_an_ordinary_map_as_parses() {
    let s = step("id: a\nmap: { over: x, as: pr }\nsteps: [{ id: b, tool: shell }]");
    let StepBody::Map { r#as, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(r#as, "pr");
}

// -- L2: `env` is a typed string-to-string map with a POSIX name check. --

#[test]
fn l2_env_accepts_ordinary_names() {
    let s = step("id: a\ntool: shell\nenv: { GH_TOKEN: secret, PATH_2: x }");
    let env = s.env.unwrap();
    assert_eq!(env.get("GH_TOKEN"), Some(&"secret".to_string()));
    assert_eq!(env.get("PATH_2"), Some(&"x".to_string()));
}

#[test]
fn l2_an_env_name_containing_equals_is_rejected() {
    let err = try_step("id: a\ntool: shell\nenv: { \"A=B\": x }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn l2_an_env_name_containing_a_newline_is_rejected() {
    let err = try_step("id: a\ntool: shell\nenv: { \"A\\nLD_PRELOAD\": x }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn l2_an_env_name_starting_with_a_digit_is_rejected() {
    let err = try_step("id: a\ntool: shell\nenv: { \"2X\": x }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn l2_a_non_string_env_value_is_rejected() {
    // Values are typed `String` now too, not arbitrary JSON — an array or
    // nested object is a parse error, not silently accepted.
    let err = try_step("id: a\ntool: shell\nenv: { X: [1, 2] }").unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
}

// =======================================================================
// Fix round 2 (security + code review on fix round 1).
// =======================================================================

// -- Minor 1: env *values* are validated too, not just names. -----------

#[test]
fn minor1_an_env_value_containing_a_newline_is_rejected() {
    let err =
        try_step("id: a\ntool: shell\nenv: { A: \"safe\\nLD_PRELOAD=/tmp/evil.so\" }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn minor1_an_env_value_containing_a_carriage_return_is_rejected() {
    let err = try_step("id: a\ntool: shell\nenv: { A: \"x\\ry\" }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn minor1_an_env_value_containing_a_nul_byte_is_rejected() {
    let err = try_step("id: a\ntool: shell\nenv: { A: \"x\\0y\" }").unwrap_err();
    assert!(
        matches!(err, ParseError::InvalidStepBody { .. }),
        "err was: {err:?}"
    );
}

#[test]
fn minor1_an_ordinary_env_value_with_an_expression_parses() {
    let s = step("id: a\ntool: shell\nenv: { GH_TOKEN: \"${{ secrets.GH_TOKEN }}\" }");
    assert_eq!(
        s.env.unwrap().get("GH_TOKEN"),
        Some(&"${{ secrets.GH_TOKEN }}".to_string())
    );
}

// -- Minor 2: `worktree.base_ref` gets a git-ref-shaped charset check, ---
// -- with a narrow exemption (space/$/{/}) for expression syntax, -------
// -- applied everywhere, not skipped outright when `${{` is present. ----

/// Builds a `map` step whose `worktree.base_ref` is `base_ref`. `{base_ref:?}`
/// emits a Rust-escaped double-quoted string, which is also valid YAML
/// double-quoted scalar syntax for the escapes these tests use (`\n`, `\0`,
/// `\"`, `\\`).
fn base_ref_step_yaml(base_ref: &str) -> String {
    format!(
        "id: a\nmap: {{ over: x, as: y, isolation: {{ worktree: {{ base_ref: {base_ref:?} }} }} }}\nsteps: [{{ id: b, tool: shell }}]"
    )
}

/// Asserts `base_ref` is rejected and returns the rendered error message, so
/// each caller can pin *why* it was rejected.
///
/// Fix round 4: every test in this section previously asserted only
/// `matches!(err, ParseError::Yaml(_))`, which any YAML-level error
/// satisfies — a test named for a specific bypass would have stayed green if
/// the payload were rejected for an unrelated reason (a YAML syntax
/// accident, a `deny_unknown_fields` hit, a different rule firing first).
/// The message substring each caller asserts is what actually pins the
/// property the test's name claims.
fn base_ref_rejection_message(base_ref: &str) -> String {
    let err = try_step(&base_ref_step_yaml(base_ref)).unwrap_err();
    assert!(matches!(err, ParseError::Yaml(_)), "err was: {err:?}");
    err.to_string()
}

#[test]
fn minor2_a_base_ref_starting_with_a_dash_is_rejected() {
    let msg = base_ref_rejection_message("--upload-pack=/tmp/x");
    assert!(msg.contains("must not start with `-`"), "msg was: {msg}");
}

#[test]
fn minor2_a_base_ref_containing_shell_metacharacters_is_rejected() {
    let msg = base_ref_rejection_message("$(id)");
    assert!(msg.contains("must not contain '$'"), "msg was: {msg}");
}

#[test]
fn minor2_an_ordinary_literal_base_ref_parses() {
    let s = step(
        "id: a\nmap: { over: x, as: y, isolation: { worktree: { base_ref: \"refs/heads/main\" } } }\nsteps: [{ id: b, tool: shell }]",
    );
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree {
            base_ref: Some("refs/heads/main".to_string())
        })
    );
}

#[test]
fn minor2_a_templated_base_ref_with_a_narrow_exemption_still_parses() {
    // The frozen §8.9 fixture's own shape: an expression placeholder
    // legitimately contains a space and `$`/`{`/`}` — exempted from the
    // charset check specifically, everywhere in the string, not by
    // skipping validation for the whole value. This is also this test's
    // regression coverage for the fixture test itself, from the other
    // direction.
    let s = step(
        "id: a\nmap: { over: x, as: y, isolation: { worktree: { base_ref: \"refs/pull/${{ pr.number }}/head\" } } }\nsteps: [{ id: b, tool: shell }]",
    );
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree {
            base_ref: Some("refs/pull/${{ pr.number }}/head".to_string())
        })
    );
}

#[test]
fn minor2_an_overlong_base_ref_is_rejected() {
    let max = roundhouse_flow::parse::steps::MAX_GIT_REF_LEN;
    let msg = base_ref_rejection_message(&"a".repeat(max + 1));
    assert!(
        msg.contains(&format!("exceeds the {max}-byte limit")),
        "msg was: {msg}"
    );
}

// -- Fix round 3's own defining regression cases: every payload the ------
// -- Minor-2 fix was written to reject, with `${{` appended, must still --
// -- be rejected — the earlier `${{`-exemption made all five pass. -------

#[test]
fn fix_round_3_leading_dash_plus_expression_suffix_is_still_rejected() {
    let msg = base_ref_rejection_message("--upload-pack=/tmp/x${{");
    assert!(msg.contains("must not start with `-`"), "msg was: {msg}");
}

#[test]
fn fix_round_3_command_substitution_plus_expression_suffix_is_still_rejected() {
    let msg = base_ref_rejection_message("$(id)${{");
    assert!(msg.contains("must not contain '$'"), "msg was: {msg}");
}

#[test]
fn fix_round_3_shell_command_plus_expression_suffix_is_still_rejected() {
    let msg = base_ref_rejection_message("; rm -rf / #${{");
    assert!(msg.contains("must not contain ';'"), "msg was: {msg}");
}

#[test]
fn fix_round_3_embedded_newline_plus_expression_suffix_is_still_rejected() {
    let msg = base_ref_rejection_message("refs/heads/main\n--exec=evil${{");
    assert!(msg.contains("must not contain '\\n'"), "msg was: {msg}");
}

#[test]
fn fix_round_3_embedded_nul_plus_expression_suffix_is_still_rejected() {
    let msg = base_ref_rejection_message("refs/heads/x\0${{");
    assert!(msg.contains("must not contain '\\0'"), "msg was: {msg}");
}

// =======================================================================
// Fix round 4 (security review on fix round 3).
//
// Fix round 3 replaced a whole-value `${{`-skip with a uniform
// four-character exemption (space, `$`, `{`, `}`) on the charset scan
// only. The rules *above* that scan are position-anchored (leading `-`,
// leading/trailing `/`, trailing `.lock`), so a uniform space exemption
// let one leading space — or one interior space — move a payload out from
// under every anchored rule. These are the seven payloads the review
// measured as newly accepted, plus the further variants of the same class
// found while fixing them.
// =======================================================================

// -- The review's own seven payloads. ------------------------------------

#[test]
fn fix_round_4_a_leading_space_does_not_evade_the_leading_dash_rule() {
    let msg = base_ref_rejection_message(" --upload-pack=/tmp/evil");
    assert!(
        msg.contains("must not begin or end with whitespace"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_trailing_flag_segment_is_rejected() {
    let msg = base_ref_rejection_message("refs/heads/main --upload-pack=/tmp/evil");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_trailing_force_flag_segment_is_rejected() {
    let msg = base_ref_rejection_message("HEAD --force");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_leading_space_does_not_evade_the_leading_slash_rule() {
    let msg = base_ref_rejection_message(" /etc/passwd");
    assert!(
        msg.contains("must not begin or end with whitespace"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_trailing_space_does_not_evade_the_dot_lock_rule() {
    let msg = base_ref_rejection_message("refs/heads/x.lock ");
    assert!(
        msg.contains("must not begin or end with whitespace"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_shell_variable_reference_is_rejected() {
    let msg = base_ref_rejection_message("refs/heads/main $HOME");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    // The `$` itself is independently pinned by
    // `fix_round_4_an_ifs_expansion_needs_no_literal_space_to_split_a_word`
    // and `fix_round_4_a_dollar_inside_a_template_placeholder_is_still_rejected`.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_an_ifs_expansion_is_rejected() {
    let msg = base_ref_rejection_message("refs/heads/main ${IFS}");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

// -- Further variants of the same class, found while fixing the seven. ---

#[test]
fn fix_round_4_an_ifs_expansion_needs_no_literal_space_to_split_a_word() {
    // The sharper form of the same class: `${IFS}` expands to whitespace in
    // a shell string, so it re-creates the word split the seven payloads
    // above use a literal space for — from a value with no literal
    // whitespace at all, and therefore exactly one whitespace-separated
    // segment for the segment rules to look at.
    let msg = base_ref_rejection_message("refs/heads/main${IFS}--upload-pack=/tmp/evil");
    assert!(msg.contains("must not contain '$'"), "msg was: {msg}");
}

#[test]
fn fix_round_4_a_brace_expansion_is_rejected() {
    // `{`/`}` were named in fix round 3's exemption but were never in
    // `FORBIDDEN_GIT_REF_CHARS` to begin with, so exempting them was a
    // no-op and bash brace expansion was accepted unconditionally. Fix
    // round 4 adds them to the set and exempts them only where they form a
    // literal `${{` / `}}` delimiter.
    let msg = base_ref_rejection_message("refs/heads/{main,--upload-pack=/tmp/evil}");
    assert!(msg.contains("must not contain '{'"), "msg was: {msg}");
}

#[test]
fn fix_round_4_a_dollar_inside_a_template_placeholder_is_still_rejected() {
    // The exemption is positional, not "anywhere once a `${{` appears": a
    // second `$` that is not itself the start of a `${{` is rejected even
    // though the value opens with a well-formed placeholder.
    let msg = base_ref_rejection_message("${{ x }}$HOME");
    assert!(msg.contains("must not contain '$'"), "msg was: {msg}");
}

#[test]
fn fix_round_4_a_second_absolute_path_segment_is_rejected() {
    let msg = base_ref_rejection_message("refs/heads/main /etc/passwd");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_dot_lock_suffix_on_an_earlier_segment_is_rejected() {
    // Deliberately not the last segment: `value.ends_with(".lock")` alone
    // already catches a trailing one, so a `.lock` segment followed by
    // another segment is what actually pins the per-segment rule.
    let msg = base_ref_rejection_message("refs/heads/x.lock refs/heads/main");
    // Fix round 5 note: this payload is now rejected one rule earlier, by
    // the tightened space rule, rather than by the per-segment rule it was
    // written against — a non-delimiter-adjacent space is itself forbidden
    // now. The payload is kept as regression coverage; the per-segment rules
    // are pinned separately by the `fix_round_5_*_inside_a_placeholder_*`
    // tests, where a space is legitimately exempt.
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_4_a_tab_separated_flag_segment_is_rejected() {
    // A tab is not the exempt character (only a plain space is), so this is
    // caught by the charset scan rather than the segment rules — pinned so
    // the two mechanisms don't silently swap roles.
    let msg = base_ref_rejection_message("refs/heads/main\t--force");
    assert!(msg.contains("must not contain '\\t'"), "msg was: {msg}");
}

// =======================================================================
// Fix round 5 (security review on fix round 4).
//
// Fix round 4 exempted a plain space everywhere and documented the
// resulting extra-plain-segment acceptance as un-closable "without
// modelling where a placeholder begins and ends". That was wrong: a local
// adjacency test closes it. A space is now exempt only when it touches a
// delimiter — after the `{` of a `${{`, or before the `}` of a `}}`.
// =======================================================================

#[test]
fn fix_round_5_an_extra_plain_segment_is_now_rejected() {
    // Fix round 4 accepted this and called it an un-closable residual.
    let msg = base_ref_rejection_message("refs/heads/main HEAD");
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_5_a_space_after_a_closing_delimiter_is_rejected() {
    // The space touches a `}` — but the *following* byte, not the one it
    // precedes. Exemption is directional: after a `{`, or before a `}`.
    let msg = base_ref_rejection_message("${{ x }} HEAD");
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_5_a_multi_word_placeholder_is_rejected() {
    // The stated cost of the adjacency rule, pinned rather than assumed:
    // the space between `a` and `b` touches no delimiter.
    let msg = base_ref_rejection_message("${{ a b }}");
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_5_a_comment_introducer_is_rejected() {
    // `git check-ref-format 'refs/heads/a#b'` succeeds, so this is a
    // deliberate deviation from git's own charset: in a shell string `#`
    // does not add an argument, it deletes the rest of the command line —
    // a trailing `--` separator, a redirect, or an `&&` clause. No space is
    // needed to reach it, so the space rule cannot be what makes this pass.
    let msg = base_ref_rejection_message("refs/heads/main#--extra");
    assert!(msg.contains("must not contain '#'"), "msg was: {msg}");
}

#[test]
fn fix_round_5_the_spaced_comment_payload_is_rejected_by_the_space_rule() {
    // The review's own measured payload. It is rejected one rule earlier
    // than the `#`, by the space; the `#` itself is pinned above.
    let msg = base_ref_rejection_message("refs/heads/main #");
    assert!(
        msg.contains("must not contain a space outside"),
        "msg was: {msg}"
    );
}

// -- The per-segment rules stay reachable: a space inside a placeholder --
// -- is still exempt, so its contents still go through them. -------------

#[test]
fn fix_round_5_a_flag_inside_a_placeholder_is_rejected_by_the_segment_rule() {
    let msg = base_ref_rejection_message("${{ --force }}");
    assert!(msg.contains("must not start with `-`"), "msg was: {msg}");
}

#[test]
fn fix_round_5_an_absolute_path_inside_a_placeholder_is_rejected_by_the_segment_rule() {
    let msg = base_ref_rejection_message("${{ /etc/passwd }}");
    assert!(
        msg.contains("must not start or end with `/`"),
        "msg was: {msg}"
    );
}

#[test]
fn fix_round_5_a_dot_lock_inside_a_placeholder_is_rejected_by_the_segment_rule() {
    let msg = base_ref_rejection_message("${{ x.lock }}");
    assert!(msg.contains("must not end with `.lock`"), "msg was: {msg}");
}

// -- Two acceptances deliberately left in place, pinned so a future -----
// -- change to either is a decision rather than a side effect. -----------

#[test]
fn fix_round_5_a_function_call_placeholder_is_rejected_a_stated_trade() {
    // `${{ default(inputs.base, 'refs/heads/main') }}` is the canonical
    // idiom for exactly this field, and it does not parse: `(`, `)` and `'`
    // are all forbidden. Pinned so the trade is visible in the suite rather
    // than only in a doc comment — it fails closed and loud at parse time,
    // naming the offending character.
    let msg = base_ref_rejection_message("${{ default(inputs.base, 'refs/heads/main') }}");
    assert!(msg.contains("must not contain '('"), "msg was: {msg}");
}

#[test]
fn fix_round_5_a_closer_run_without_an_opener_is_accepted() {
    // `expression_delimiter_positions` never pairs an opener with a closer,
    // so a bare `}}` run marks itself and passes. Deliberate: `}` is inert
    // outside command position, and the alternative is the span reasoning
    // this function refuses. Pinned so it stays a choice.
    let s = step(&base_ref_step_yaml("refs/heads/}}main"));
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree {
            base_ref: Some("refs/heads/}}main".to_string())
        })
    );
}

// -- What the fix must NOT break. ----------------------------------------

#[test]
fn fix_round_4_the_frozen_fixtures_templated_base_ref_still_parses() {
    // Same value as `minor2_a_templated_base_ref_with_a_narrow_exemption_still_parses`,
    // restated here as this round's own regression anchor: it has no
    // leading/trailing whitespace, no segment starting with `-` or `/`, and
    // its `$`/`{`/`}` are all part of a literal `${{` or `}}`.
    let s = step(&base_ref_step_yaml("refs/pull/${{ pr.number }}/head"));
    let StepBody::Map { isolation, .. } = &s.body else {
        panic!("expected Map step");
    };
    assert_eq!(
        isolation,
        &Some(MapIsolationDef::Worktree {
            base_ref: Some("refs/pull/${{ pr.number }}/head".to_string())
        })
    );
}
