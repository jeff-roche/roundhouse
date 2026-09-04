//! Task 19 (B11): composition primitives — the `call:` budget transfer, the
//! recursion-depth bound, and workflow-as-tool registration.
//!
//! These test the primitives only. Nothing here drives a run: Task 20 (B12)
//! owns composition's run loop and is the caller that will wire all three.

use roundhouse_core::JobId;
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::compose::{
    child_call_depth, draw_child_budget, refund_child_budget, register_as_tool, CallDepthError,
    MAX_CALL_DEPTH,
};
use roundhouse_flow::job::{Body, InputSchema, JobVersion, SessionTemplate};
use roundhouse_flow::parse::parse_workflow;
use std::time::Duration;

fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "anthropic".to_string(),
        model: "claude-sonnet".to_string(),
        cwd: "/repo".to_string(),
        tools: vec![],
        isolation: roundhouse_core::Tier::Worktree,
        permission_policy_ref: "default".to_string(),
    }
}

/// A workflow body that really parses: `WorkflowDef` requires `permissions`
/// (with `unattended.escalate`, plus `deadline`/`on_timeout` for `park`) and
/// `steps`, and is `deny_unknown_fields`. A fixture missing any of them makes
/// `parse_workflow` fail, which is the whole point of
/// `a_workflow_whose_body_does_not_parse_is_refused_rather_than_named_unknown`
/// below.
const PR_REVIEW_YAML: &str = r#"
name: pr-review
version: 3
inputs:
  repo:    { type: string, required: true }
  branch:  { type: string, required: true }
  max_prs: { type: integer, default: 10 }
  dry_run: { type: boolean }
permissions:
  default: deny
  unattended:
    escalate: park
    deadline: 24h
    on_timeout: deny
steps:
  - id: run
    emit:
      done: true
"#;

fn workflow_job(yaml: &str) -> JobVersion {
    JobVersion::new(
        JobId::new(),
        3,
        template(),
        Body::Workflow {
            workflow_yaml: yaml.to_string(),
        },
        // Deliberately *not* the tool schema: §8.9's "the `inputs:` schema
        // becomes the JSON tool schema" names `WorkflowDef.inputs`, a
        // different object from `JobVersion::input_schema`. If
        // `register_as_tool` ever reached for this instead, the assertions
        // below would see `{"never": "this one"}`.
        InputSchema(serde_json::json!({"never": "this one"})),
    )
}

/// Half of every default, so a draw of the full default is a draw of exactly
/// what remains — the clamp is visible in the numbers rather than inferred.
fn half_of_default() -> ResourceCaps {
    ResourceCaps {
        run_wall_timeout: Duration::from_secs(300),
        run_active_timeout: Duration::from_secs(240),
        step_timeout: Duration::from_secs(60),
        max_tokens: 1_000_000,
        max_cost_usd: 5.0,
        max_tasks: 2_500,
        max_tool_calls: 1_000,
        max_subagents: 10,
        max_bytes_written: 50_000_000,
        max_escalations: 25,
    }
}

// ---------------------------------------------------------------------------
// Budget: draw is a real transfer, refund returns only what went unspent
// ---------------------------------------------------------------------------

#[test]
fn drawing_a_child_budget_is_a_real_transfer_and_refund_returns_only_the_unspent_part() {
    let mut parent = ResourceCaps {
        max_cost_usd: 10.0,
        max_tokens: 1_000_000,
        max_tool_calls: 100,
        ..ResourceCaps::default()
    };
    let requested = ResourceCaps {
        max_cost_usd: 4.0,
        max_tokens: 400_000,
        max_tool_calls: 40,
        ..ResourceCaps::default()
    };

    let drawn = draw_child_budget(&mut parent, &requested);

    assert_eq!(drawn.caps().max_cost_usd, 4.0);
    assert_eq!(drawn.caps().max_tokens, 400_000);
    assert_eq!(drawn.caps().max_tool_calls, 40);
    assert_eq!(
        parent.max_cost_usd, 6.0,
        "drawing decrements the parent's pool — a transfer, not a display rollup"
    );
    assert_eq!(parent.max_tokens, 600_000);
    assert_eq!(parent.max_tool_calls, 60);

    // The child spent 2.5 / 250_000 / 25 of its 4.0 / 400_000 / 40.
    let spent = ResourceCaps {
        max_cost_usd: 2.5,
        max_tokens: 250_000,
        max_tool_calls: 25,
        ..ResourceCaps::default()
    };
    refund_child_budget(&mut parent, drawn, &spent);

    assert_eq!(parent.max_cost_usd, 7.5);
    assert_eq!(parent.max_tokens, 750_000);
    assert_eq!(parent.max_tool_calls, 75);
}

#[test]
fn every_countable_field_is_drawn_and_decremented_not_passed_through() {
    // Ruling P75 §C: the plan drew three of ten fields and passed the other
    // seven through `..requested.clone()`. This pins all seven countables.
    let mut parent = half_of_default();
    let requested = ResourceCaps::default(); // asks for the full default of everything

    let drawn = draw_child_budget(&mut parent, &requested);
    let child = drawn.caps();

    assert_eq!(child.max_cost_usd, 5.0);
    assert_eq!(child.max_tokens, 1_000_000);
    assert_eq!(child.max_tasks, 2_500);
    assert_eq!(child.max_tool_calls, 1_000);
    assert_eq!(child.max_subagents, 10);
    assert_eq!(child.max_bytes_written, 50_000_000);
    assert_eq!(child.max_escalations, 25);

    assert_eq!(parent.max_cost_usd, 0.0);
    assert_eq!(parent.max_tokens, 0);
    assert_eq!(parent.max_tasks, 0);
    assert_eq!(parent.max_tool_calls, 0);
    assert_eq!(parent.max_subagents, 0);
    assert_eq!(parent.max_bytes_written, 0);
    assert_eq!(parent.max_escalations, 0);
}

#[test]
fn the_three_durations_are_clamped_to_the_parents_window_and_never_decremented() {
    // Ruling P75 §C's concrete example: a child asking for a 24 h wall
    // timeout from a parent with five minutes left.
    let mut parent = half_of_default();
    let before = parent.clone();
    let requested = ResourceCaps::default(); // 24 h / 4 h / 30 min

    let drawn = draw_child_budget(&mut parent, &requested);

    assert_eq!(drawn.caps().run_wall_timeout, Duration::from_secs(300));
    assert_eq!(drawn.caps().run_active_timeout, Duration::from_secs(240));
    assert_eq!(drawn.caps().step_timeout, Duration::from_secs(60));

    assert_eq!(
        (
            parent.run_wall_timeout,
            parent.run_active_timeout,
            parent.step_timeout
        ),
        (
            before.run_wall_timeout,
            before.run_active_timeout,
            before.step_timeout
        ),
        "wall-clock windows are clamped, not withdrawn: the parent's clock does \
         not stop running because a child is running inside it"
    );
}

#[test]
fn a_shorter_requested_timeout_is_honoured_rather_than_widened_to_the_parents() {
    let mut parent = ResourceCaps::default();
    let requested = ResourceCaps {
        run_wall_timeout: Duration::from_secs(30),
        run_active_timeout: Duration::from_secs(20),
        step_timeout: Duration::from_secs(10),
        ..ResourceCaps::default()
    };

    let drawn = draw_child_budget(&mut parent, &requested);

    assert_eq!(drawn.caps().run_wall_timeout, Duration::from_secs(30));
    assert_eq!(drawn.caps().run_active_timeout, Duration::from_secs(20));
    assert_eq!(drawn.caps().step_timeout, Duration::from_secs(10));
}

#[test]
fn a_subtree_can_never_spend_more_than_its_root_was_given() {
    // §8.12's invariant, stated over every countable field rather than three.
    let mut parent = ResourceCaps {
        max_cost_usd: 5.0,
        max_tokens: 100,
        max_tasks: 3,
        max_tool_calls: 7,
        max_subagents: 1,
        max_bytes_written: 900,
        max_escalations: 2,
        ..ResourceCaps::default()
    };

    let greedy = ResourceCaps {
        max_cost_usd: 20.0,
        max_tokens: 9_999_999,
        max_tasks: 9_999,
        max_tool_calls: 9_999,
        max_subagents: 9_999,
        max_bytes_written: 9_999_999_999,
        max_escalations: 9_999,
        ..ResourceCaps::default()
    };

    let first = draw_child_budget(&mut parent, &greedy);
    assert_eq!(first.caps().max_cost_usd, 5.0, "clamped to what remains");
    assert_eq!(first.caps().max_tokens, 100);
    assert_eq!(first.caps().max_tasks, 3);
    assert_eq!(first.caps().max_tool_calls, 7);
    assert_eq!(first.caps().max_subagents, 1);
    assert_eq!(first.caps().max_bytes_written, 900);
    assert_eq!(first.caps().max_escalations, 2);

    // A second sibling call, from a pool the first drained, gets nothing —
    // not a second full grant. This is the property that makes the invariant
    // hold across siblings, not just across one call.
    let second = draw_child_budget(&mut parent, &greedy);
    assert_eq!(second.caps().max_cost_usd, 0.0);
    assert_eq!(second.caps().max_tokens, 0);
    assert_eq!(second.caps().max_tasks, 0);
    assert_eq!(second.caps().max_tool_calls, 0);
    assert_eq!(second.caps().max_subagents, 0);
    assert_eq!(second.caps().max_bytes_written, 0);
    assert_eq!(second.caps().max_escalations, 0);
}

#[test]
fn a_refund_can_never_return_more_than_was_drawn() {
    // The refund is computed from the grant the draw handed back, so there is
    // no caller-supplied "unspent" figure that could exceed it — the tightest
    // case is a child that spent nothing, which lands the parent exactly back
    // where it started and never above.
    let before = half_of_default();
    let mut parent = before.clone();
    let drawn = draw_child_budget(
        &mut parent,
        &ResourceCaps {
            max_cost_usd: 4.0,
            max_tokens: 400,
            max_tasks: 4,
            max_tool_calls: 40,
            max_subagents: 4,
            max_bytes_written: 4_000,
            max_escalations: 4,
            ..ResourceCaps::default()
        },
    );
    assert_eq!(parent.max_cost_usd, 1.0);
    assert_eq!(parent.max_tokens, 999_600);

    let spent_nothing = ResourceCaps {
        max_cost_usd: 0.0,
        max_tokens: 0,
        max_tasks: 0,
        max_tool_calls: 0,
        max_subagents: 0,
        max_bytes_written: 0,
        max_escalations: 0,
        ..ResourceCaps::default()
    };
    refund_child_budget(&mut parent, drawn, &spent_nothing);

    assert_eq!(
        parent, before,
        "a full refund restores the parent exactly, and cannot overshoot it"
    );
}

#[test]
fn a_child_that_reports_spending_more_than_its_grant_refunds_nothing() {
    let mut parent = ResourceCaps {
        max_cost_usd: 10.0,
        max_tokens: 1_000,
        ..ResourceCaps::default()
    };
    let drawn = draw_child_budget(
        &mut parent,
        &ResourceCaps {
            max_cost_usd: 4.0,
            max_tokens: 400,
            ..ResourceCaps::default()
        },
    );

    let overspent = ResourceCaps {
        max_cost_usd: 40.0,
        max_tokens: 4_000,
        ..ResourceCaps::default()
    };
    refund_child_budget(&mut parent, drawn, &overspent);

    assert_eq!(
        parent.max_cost_usd, 6.0,
        "no refund, and no negative refund"
    );
    assert_eq!(parent.max_tokens, 600);
}

#[test]
fn a_nan_or_negative_requested_cost_draws_nothing_rather_than_minting_budget() {
    // `max_cost_usd` is `f64` (see `caps.rs`'s recorded deviation from
    // §8.4's `Decimal`) and reaches this function from YAML `caps:`, where
    // `.nan` and `-1e18` are both authorable scalars. Unguarded,
    // `parent -= requested.min(parent)` with a negative request *raises* the
    // parent's remaining budget.
    for hostile in [f64::NAN, -1.0e18, f64::NEG_INFINITY, f64::INFINITY] {
        let mut parent = ResourceCaps {
            max_cost_usd: 10.0,
            ..ResourceCaps::default()
        };
        let drawn = draw_child_budget(
            &mut parent,
            &ResourceCaps {
                max_cost_usd: hostile,
                ..ResourceCaps::default()
            },
        );
        assert_eq!(
            drawn.caps().max_cost_usd,
            0.0,
            "a {hostile} request must draw nothing"
        );
        assert_eq!(
            parent.max_cost_usd, 10.0,
            "a {hostile} request must not change the parent's pool"
        );
        assert!(drawn.caps().max_cost_usd.is_finite());
    }
}

#[test]
fn an_unusable_reported_spend_refunds_nothing() {
    // NaN, infinite and negative reported spends all mean the caller's ledger
    // is broken. Refusing to refund is the direction that cannot inflate the
    // parent's pool above what the root granted.
    for hostile in [f64::NAN, f64::NEG_INFINITY, f64::INFINITY, -5.0] {
        let mut parent = ResourceCaps {
            max_cost_usd: 10.0,
            ..ResourceCaps::default()
        };
        let drawn = draw_child_budget(
            &mut parent,
            &ResourceCaps {
                max_cost_usd: 4.0,
                ..ResourceCaps::default()
            },
        );
        refund_child_budget(
            &mut parent,
            drawn,
            &ResourceCaps {
                max_cost_usd: hostile,
                ..ResourceCaps::default()
            },
        );
        assert_eq!(
            parent.max_cost_usd, 6.0,
            "an unusable reported spend of {hostile} refunds nothing"
        );
        assert!(parent.max_cost_usd.is_finite());
    }
}

// ---------------------------------------------------------------------------
// The recursion bound (ruling P75 §B)
// ---------------------------------------------------------------------------

#[test]
fn call_depth_is_bounded_and_the_bound_fails_closed() {
    assert_eq!(MAX_CALL_DEPTH, 4);

    // The root run is depth 0; each `call:` adds one.
    assert_eq!(child_call_depth(0), Ok(1));
    assert_eq!(child_call_depth(1), Ok(2));
    assert_eq!(child_call_depth(2), Ok(3));
    assert_eq!(child_call_depth(3), Ok(4));

    // The fifth nested call is refused, which is what makes `call: self`
    // terminate rather than recurse forever.
    assert_eq!(
        child_call_depth(4),
        Err(CallDepthError::TooDeep {
            parent_depth: 4,
            attempted: 5,
            max: MAX_CALL_DEPTH
        })
    );
    assert_eq!(
        child_call_depth(9),
        Err(CallDepthError::TooDeep {
            parent_depth: 9,
            attempted: 10,
            max: MAX_CALL_DEPTH
        })
    );
}

#[test]
fn a_parent_depth_at_the_integer_ceiling_is_refused_rather_than_wrapping_to_zero() {
    // Saturating, not wrapping: `u32::MAX + 1` must not become 0 and hand
    // back a fresh depth budget.
    assert_eq!(
        child_call_depth(u32::MAX),
        Err(CallDepthError::TooDeep {
            parent_depth: u32::MAX,
            attempted: u32::MAX,
            max: MAX_CALL_DEPTH
        })
    );
}

#[test]
fn a_self_calling_workflow_terminates_after_max_call_depth_calls() {
    // The `call: self` shape ruling P75 §B names, driven to exhaustion: a
    // workflow that calls itself unconditionally gets exactly
    // `MAX_CALL_DEPTH` child runs and then a refusal, instead of recursing
    // until the process dies.
    let mut depth = 0u32;
    let mut children = 0u32;
    while let Ok(next) = child_call_depth(depth) {
        children += 1;
        depth = next;
        assert!(
            children <= MAX_CALL_DEPTH,
            "the loop must terminate at the bound, not run away"
        );
    }
    assert_eq!(children, MAX_CALL_DEPTH);
    assert_eq!(depth, MAX_CALL_DEPTH);
    // And the refusal that ended it is the depth bound, not some other error.
    assert!(matches!(
        child_call_depth(depth),
        Err(CallDepthError::TooDeep { .. })
    ));
}

// ---------------------------------------------------------------------------
// Workflow-as-tool registration
// ---------------------------------------------------------------------------

#[test]
fn a_workflow_registers_as_workflow_name_with_its_inputs_block_as_the_tool_schema() {
    let job = workflow_job(PR_REVIEW_YAML);
    let reg = register_as_tool(&job, "ignored-for-a-workflow-body").expect("fixture parses");

    assert_eq!(reg.name, "workflow:pr-review");

    // Ruling P29: assert on the parsed structure, never on serialized text.
    assert_eq!(reg.input_schema["type"], serde_json::json!("object"));
    assert_eq!(
        reg.input_schema["properties"]["repo"],
        serde_json::json!({"type": "string"})
    );
    assert_eq!(
        reg.input_schema["properties"]["max_prs"],
        serde_json::json!({"type": "integer", "default": 10})
    );
    assert_eq!(
        reg.input_schema["properties"]["dry_run"],
        serde_json::json!({"type": "boolean"})
    );
    assert_eq!(
        reg.input_schema["required"],
        serde_json::json!(["branch", "repo"]),
        "required names are sorted, so the schema does not change shape \
         between processes with `inputs` being a HashMap"
    );

    // The `JobVersion::input_schema` decoy is not what got used.
    assert!(reg.input_schema.get("never").is_none());
}

#[test]
fn required_input_names_are_emitted_in_a_deterministic_sorted_order() {
    // `WorkflowDef.inputs` is a `HashMap`, whose iteration order is randomised
    // per process. Six required names would land in sorted order by chance
    // with probability 1/720.
    let yaml = r#"
name: many-inputs
version: 1
inputs:
  zulu:    { type: string, required: true }
  yankee:  { type: string, required: true }
  xray:    { type: string, required: true }
  whiskey: { type: string, required: true }
  victor:  { type: string, required: true }
  uniform: { type: string, required: true }
permissions:
  default: deny
  unattended:
    escalate: fail
steps:
  - id: run
    emit:
      done: true
"#;
    let reg = register_as_tool(&workflow_job(yaml), "n/a").expect("fixture parses");
    assert_eq!(
        reg.input_schema["required"],
        serde_json::json!(["uniform", "victor", "whiskey", "xray", "yankee", "zulu"])
    );

    let props = reg.input_schema["properties"]
        .as_object()
        .expect("properties is an object");
    assert_eq!(
        props.keys().cloned().collect::<Vec<_>>(),
        vec!["uniform", "victor", "whiskey", "xray", "yankee", "zulu"],
        "property keys are inserted in sorted order too, so the schema is \
         byte-identical run to run once `preserve_order` is on (ruling P29)"
    );
}

#[test]
fn a_workflow_with_no_inputs_gets_an_empty_object_schema_with_no_required_key() {
    let yaml = r#"
name: no-inputs
version: 1
permissions:
  default: deny
  unattended:
    escalate: fail
steps:
  - id: run
    emit:
      done: true
"#;
    let reg = register_as_tool(&workflow_job(yaml), "n/a").expect("fixture parses");
    assert_eq!(reg.input_schema["type"], serde_json::json!("object"));
    assert_eq!(reg.input_schema["properties"], serde_json::json!({}));
    assert!(
        reg.input_schema.get("required").is_none(),
        "an empty `required` array is omitted rather than emitted empty"
    );
}

#[test]
fn a_workflow_whose_body_does_not_parse_is_refused_rather_than_named_unknown() {
    // Ruling P75 §D.3: the plan's `unwrap_or_else(|_| "unknown")` turned an
    // unparsable body into a cheerfully-registered `workflow:unknown`. This
    // fixture is the exact shape `tests/job.rs` uses for hashing — valid
    // YAML, but missing `WorkflowDef`'s required `permissions` and `steps`.
    let job = workflow_job("name: pr-review\nversion: 1\n");
    let err = register_as_tool(&job, "n/a").expect_err("missing permissions/steps must not parse");
    let rendered = err.to_string();
    assert!(!rendered.contains("workflow:unknown"), "got {rendered:?}");
    assert!(
        rendered.contains("permissions"),
        "the error should name the missing field, got {rendered:?}"
    );
}

#[test]
fn the_yaml_name_is_authoritative_for_a_workflow_body_and_the_argument_is_ignored() {
    let reg =
        register_as_tool(&workflow_job(PR_REVIEW_YAML), "some-other-name").expect("fixture parses");
    assert_eq!(reg.name, "workflow:pr-review");
}

#[test]
fn a_prompt_bodied_job_registers_under_the_name_the_caller_supplies() {
    // `Body::Prompt` synthesizes its YAML and has no `name:` of its own, so
    // the caller's job name is the only source for one (§8.3: a prompt job is
    // sugar for a single-step workflow).
    let job = JobVersion::new(
        JobId::new(),
        1,
        template(),
        Body::Prompt {
            template: "summarise the diff".to_string(),
        },
        InputSchema(serde_json::json!({"never": "this one"})),
    );
    let reg = register_as_tool(&job, "nightly-summary").expect("prompt lowering parses");
    assert_eq!(reg.name, "workflow:nightly-summary");
    assert_eq!(reg.input_schema["properties"], serde_json::json!({}));
}

#[test]
fn outputs_is_not_authorable_in_the_workflow_format_so_no_output_schema_is_registered() {
    // The named frozen-contract gap: §8.12 says "`outputs` *is* the result",
    // but `WorkflowDef` has no `outputs` field and is `deny_unknown_fields`,
    // so authoring one is a hard parse error rather than an ignored key.
    // This pins the gap as an observed fact, not a claim.
    let with_outputs = r#"
name: has-outputs
version: 1
outputs:
  verdict: { type: string }
permissions:
  default: deny
  unattended:
    escalate: fail
steps:
  - id: run
    emit:
      done: true
"#;
    let err = parse_workflow(with_outputs).expect_err("`outputs:` must not parse today");
    assert!(
        err.to_string().contains("outputs"),
        "the parse error should name the rejected key, got {:?}",
        err.to_string()
    );

    // And so the registration carries no output schema at all, rather than a
    // fabricated `{"type": "object"}`.
    let reg = register_as_tool(&workflow_job(PR_REVIEW_YAML), "n/a").expect("fixture parses");
    assert_eq!(reg.output_schema, None);
}
