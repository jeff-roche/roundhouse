//! Tests for Task 14/B6 (`map` step fan-out) — see
//! `crates/roundhouse-flow/src/exec/map_step.rs`'s own module doc comment
//! for the design this exercises and, in particular, "Deviations from the
//! plan text" for why these payloads differ from the brief's own illustrative
//! test code (`OnItemError` instead of `&str`; a compiling budget-exhaustion
//! probe instead of the brief's — the brief's own `budget_has_room` stub
//! always returns `true`, which cannot produce a skip at all, and its call
//! site borrows the same `budget` both as `&mut` into `run_map` and
//! immutably inside the closure, which does not borrow-check).
//!
//! # Fix round 1 sweep: three of these tests drove `run_map` directly, not `dispatch_map_step`
//!
//! `run_budget_exhaustion_is_cooperative_and_skips_are_recorded_not_dropped`,
//! `on_item_error_collect_gathers_failures_onto_the_maps_own_output_while_continue_does_not`,
//! and `fail_fast_stops_dispatching_after_the_first_failure_and_records_the_rest_as_skipped`
//! all construct a synthetic `run_item` closure and call [`run_map`]
//! directly — none goes through `Executor`/`dispatch_map_step`. That is
//! exactly the shape fix round 1's security lens identified as the reason
//! the fail-open `on_item_error` defect (item 4) shipped undetected: these
//! tests validate `run_map`'s own loop logic (`should_stop`/
//! `collected_errors`), which was and is correct, in isolation from the code
//! that actually *populates* an `ItemOutcome` from a real item's inner
//! steps. They remain valid coverage of `run_map` itself and are kept
//! un-migrated (`run_map`'s loop-level contract is still worth testing
//! directly) — but the two new tests below,
//! `on_item_error_collect_through_dispatch_map_step_gathers_a_non_final_inner_step_failure`
//! and
//! `on_item_error_fail_fast_through_dispatch_map_step_stops_at_a_non_final_inner_step_failure`,
//! are the ones that actually pin the fixed behavior, because only they
//! exercise the real caller.
//!
//! # `isolation: worktree` in these YAML fixtures is not exercised here (fix round 1, "also record"; updated for Task 34)
//!
//! Every workflow YAML below declares `defaults: { isolation: worktree }`
//! because `parse_workflow` requires *some* isolation default — none of
//! these fixtures set an explicit **map-level** `isolation:` field, so none
//! of them materializes a worktree: `Defaults.isolation` is never read as
//! an implicit demand for one (see
//! `crate::exec::map_step::Executor::dispatch_map_step`'s own doc comment,
//! "Task 34"). Worktree materialization itself — real `git worktree add`/
//! `remove`, the fail-closed missing-provider path, the
//! `${{ worktree.path }}` binding, and cleanup on both the success and
//! failure paths — is exercised in `tests/map_step_worktree.rs`, not here.
//! This note exists so a green run of *this* file is never mistaken for
//! evidence that isolation materialization is exercised by it.

use roundhouse_core::TaskKind;
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::exec::map_step::{
    run_map, split_budget, ItemOutcome, MapBudget, MAX_MAP_ITEMS,
};
use roundhouse_flow::exec::{Executor, RunContext, StepStatus, TaskSink};
use roundhouse_flow::expr::EnvAllowlist;
use roundhouse_flow::parse::parse_workflow;
use roundhouse_flow::parse::steps::OnItemError;
use std::collections::HashMap;

fn caps(max_cost_usd: f64) -> ResourceCaps {
    ResourceCaps {
        max_cost_usd,
        max_tool_calls: 100,
        ..Default::default()
    }
}

// Each integration-test binary (`tests/*.rs`) is its own separate crate, so
// `RecordingSink`/`RecordedEvent` cannot be imported from
// `tests/exec_sequencing.rs` — this is the same struct/impl, declared again
// here.
#[derive(Debug, Clone)]
struct RecordedEvent {
    #[allow(dead_code)]
    parent: Option<roundhouse_core::TaskId>,
    kind: TaskKind,
    payload_json: serde_json::Value,
}

struct RecordingSink(Vec<RecordedEvent>);
impl TaskSink for RecordingSink {
    fn emit(
        &mut self,
        _task_id: roundhouse_core::TaskId,
        parent: Option<roundhouse_core::TaskId>,
        kind: TaskKind,
        payload: roundhouse_core::EventPayload,
    ) {
        let payload_json = serde_json::to_value(&payload).unwrap_or(serde_json::Value::Null);
        self.0.push(RecordedEvent {
            parent,
            kind,
            payload_json,
        });
    }
}

fn run_ctx(inputs: serde_json::Value) -> RunContext {
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets: HashMap::new(),
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    }
}

fn secret_run_ctx(inputs: serde_json::Value, key: &str, value: &str) -> RunContext {
    let mut secrets = HashMap::new();
    secrets.insert(key.to_string(), value.to_string());
    RunContext {
        inputs,
        vars: serde_json::json!({}),
        secrets,
        run_id: roundhouse_flow::exec::RunId::new(),
        previous_report: None,
        env_allowlist: EnvAllowlist::deny_all(),
        worktree_provider: None,
    }
}

// ---------------------------------------------------------------------
// `split_budget` / `run_map` — pure unit tests, no `Executor` involved.
// ---------------------------------------------------------------------

#[test]
fn unset_item_caps_default_to_an_even_split_of_remaining_budget() {
    let total = caps(4.0);
    let per_item = split_budget(&total, 4);
    assert_eq!(per_item.max_cost_usd, 1.0);
}

#[test]
fn run_budget_exhaustion_is_cooperative_and_skips_are_recorded_not_dropped() {
    // `run_map` itself has no live cost signal — Task 8's admission ledger is
    // what will report real consumption (see `run_map`'s own doc comment).
    // This test's closure stands in for that ledger with its own counter,
    // entirely separate from the `budget: &mut MapBudget` argument `run_map`
    // requires structurally (to compute the even split handed to each item).
    let items: Vec<serde_json::Value> = (0..5).map(|i| serde_json::json!({"n": i})).collect();
    let mut budget = MapBudget {
        total_remaining: caps(2.0),
    };
    let remaining = std::cell::Cell::new(2.0_f64);
    let result = run_map(
        items,
        1,
        OnItemError::Continue,
        &mut budget,
        |_item, _item_caps| {
            if remaining.get() >= 1.0 {
                remaining.set(remaining.get() - 1.0);
                ItemOutcome::Completed(serde_json::json!({"ok": true}))
            } else {
                ItemOutcome::Skipped {
                    reason: "run_budget_exhausted".to_string(),
                }
            }
        },
    );
    let completed = result
        .outcomes
        .iter()
        .filter(|o| matches!(o, ItemOutcome::Completed(_)))
        .count();
    let skipped = result
        .outcomes
        .iter()
        .filter(|o| matches!(o, ItemOutcome::Skipped { .. }))
        .count();
    assert_eq!(result.outcomes.len(), 5, "no item is ever silently dropped");
    assert_eq!(
        completed, 2,
        "only 2 of 5 items fit in a 2.0 budget at 1.0/item"
    );
    assert_eq!(skipped, 3);
}

#[test]
fn on_item_error_collect_gathers_failures_onto_the_maps_own_output_while_continue_does_not() {
    // Finding 10: `on_item_error: collect` previously behaved identically to
    // `continue` — both simply proceeded past a failed item with no
    // distinguishing effect anywhere. `collect`'s point is to *gather* the
    // errors onto the map step's own output; `continue` proceeds silently.
    let items: Vec<serde_json::Value> = (0..3).map(|i| serde_json::json!({"n": i})).collect();
    let run_item = |item: &serde_json::Value, _caps: ResourceCaps| {
        if item["n"] == serde_json::json!(1) {
            ItemOutcome::Failed("item 1 exploded".to_string())
        } else {
            ItemOutcome::Completed(serde_json::json!({"ok": true}))
        }
    };

    let mut collect_budget = MapBudget {
        total_remaining: caps(10.0),
    };
    let collected = run_map(
        items.clone(),
        1,
        OnItemError::Collect,
        &mut collect_budget,
        run_item,
    );
    assert_eq!(
        collected.outcomes.len(),
        3,
        "collect still proceeds past the error, same control flow as continue"
    );
    assert_eq!(
        collected.collected_errors,
        vec!["item 1 exploded".to_string()],
        "collect gathers the failure for the map step's own output"
    );

    let mut continue_budget = MapBudget {
        total_remaining: caps(10.0),
    };
    let continued = run_map(
        items,
        1,
        OnItemError::Continue,
        &mut continue_budget,
        run_item,
    );
    assert_eq!(continued.outcomes.len(), 3);
    assert!(
        continued.collected_errors.is_empty(),
        "continue proceeds past the error but never collects it anywhere — \
         that's the entire distinction from collect"
    );
}

#[test]
fn fail_fast_stops_dispatching_after_the_first_failure_and_records_the_rest_as_skipped() {
    let items: Vec<serde_json::Value> = (0..4).map(|i| serde_json::json!({"n": i})).collect();
    let mut budget = MapBudget {
        total_remaining: caps(10.0),
    };
    let result = run_map(
        items,
        1,
        OnItemError::FailFast,
        &mut budget,
        |item, _item_caps| {
            if item["n"] == serde_json::json!(1) {
                ItemOutcome::Failed("item 1 exploded".to_string())
            } else {
                ItemOutcome::Completed(serde_json::json!({"ok": true}))
            }
        },
    );
    assert_eq!(result.outcomes.len(), 4, "no item is ever silently dropped");
    assert!(matches!(result.outcomes[0], ItemOutcome::Completed(_)));
    assert!(matches!(result.outcomes[1], ItemOutcome::Failed(_)));
    assert!(
        matches!(result.outcomes[2], ItemOutcome::Skipped { .. }),
        "fail_fast stops dispatching after the first failure"
    );
    assert!(matches!(result.outcomes[3], ItemOutcome::Skipped { .. }));
    assert!(
        result.collected_errors.is_empty(),
        "fail_fast does not collect — only `collect` does"
    );
}

// ---------------------------------------------------------------------
// `Executor::dispatch_map_step` — end-to-end integration tests.
// ---------------------------------------------------------------------

#[test]
fn map_item_variable_is_bound_for_real_inside_the_inner_steps() {
    // Finding 8's headline assertion: `${{ pr.number }}` inside a `map` over
    // PRs must resolve to a real per-item value, never `Null` — this is the
    // item-variable-binding gap the audit named explicitly.
    let yaml = r#"
name: pr-numbers
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: per_pr
    map:
      over: "${{ inputs.prs }}"
      as: pr
      max_parallel: 1
      on_item_error: continue
    steps:
      - id: echo_number
        tool: shell
        with: { cmd: ["echo", "${{ pr.number }}"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"prs": [{"number": 41}, {"number": 42}]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    exec.run_to_completion().unwrap();

    let shell_events: Vec<_> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Shell))
        .collect();
    assert_eq!(shell_events.len(), 2, "one shell task per PR item");
    let cmds: Vec<_> = shell_events
        .iter()
        .map(|e| {
            e.payload_json["TaskCreated"]["input"]["Json"]["cmd"][1]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        cmds,
        vec!["41".to_string(), "42".to_string()],
        "${{ pr.number }} resolved to the real per-item value, not Null, for each iteration"
    );
}

#[test]
fn map_over_that_does_not_evaluate_to_an_array_fails_the_step_closed() {
    let yaml = r#"
name: bad-over
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: bad
    map:
      over: "${{ 'not an array' }}"
      as: item
      on_item_error: continue
    steps:
      - id: noop
        emit: { v: 1 }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut exec = Executor::new(&def, &mut sink, run_ctx(serde_json::json!({}))).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert!(message.contains("must evaluate to an array"));
            assert!(message.contains("a string"));
        }
        other => panic!("expected the map step to fail closed, got {other:?}"),
    }
    assert!(
        sink.0.is_empty(),
        "no inner step ever dispatched — the type check runs before any item"
    );
}

#[test]
fn an_unterminated_quote_can_merge_map_over_into_a_string_but_the_array_type_check_fails_it_closed()
{
    // ROUND 2 carry-forward item 3: `expr.rs`'s quote-scanning residual
    // (documented on `find_closing_delimiter`) can absorb a second,
    // well-formed `${{ }}` block into an unterminated string literal,
    // producing a `Value::String` with no error at all — measured against
    // `interpolate` directly in
    // `tests/expr.rs::an_open_quote_can_still_silently_absorb_a_later_block_when_the_forgery_looks_syntactically_valid`.
    // This payload is the same shape, applied to a single `map.over` field
    // (which must be exactly one `${{ }}` block, nothing trailing): the
    // opening block's own string literal never closes before its intended
    // `}}`; the *next* `'` in the text is placed right before the field's
    // own trailing `}}`, which is exactly the shape
    // `looks_like_a_real_string_close` accepts as a plausible string close.
    let yaml = r#"
name: map-over-quote-merge
version: 1
inputs: { prs: { type: array, required: false } }
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: merged
    map:
      over: "${{ 'oops }} filler ${{ inputs.prs }} trailing' }}"
      as: item
      on_item_error: continue
    steps:
      - id: noop
        emit: { v: 1 }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    // `inputs.prs` sits inside the swallowed span and must never be read —
    // give it a real array so a failure to swallow (i.e. a regression that
    // makes this field parse as two blocks and actually iterate `inputs.prs`)
    // would be observable as dispatched `noop` tasks instead of a failure.
    let ctx = run_ctx(serde_json::json!({"prs": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            // The merge produced a `Value::String` (the swallowed literal
            // text), not the intended array — this crate's own explicit
            // type check on `over_evaluated.value` is what turns that into a
            // closed failure rather than a silent zero-iteration or
            // one-character-iteration map. Unlike a `when:` gate (protected
            // by its own `Value::Bool(true)`-only acceptance), nothing in
            // the grammar itself protects `map.over` — this assertion is
            // exactly the property the carry-forward asked to be measured,
            // not assumed.
            assert!(
                message.contains("must evaluate to an array") && message.contains("a string"),
                "got: {message}"
            );
        }
        other => panic!(
            "expected the merge to still fail closed via the array-type check, got {other:?}"
        ),
    }
    assert!(
        sink.0.is_empty(),
        "`inputs.prs` was swallowed into the merged string and never reached as a real \
         collection to iterate — no inner `noop` step ever dispatched"
    );
}

#[test]
fn a_secret_derived_maps_as_name_does_not_poison_a_later_clean_maps_use_of_the_same_as_name() {
    // R-2b: provenance is monotone per root NAME and irreversible for the
    // life of an `ExprContext`. Two separate `map` steps in one workflow,
    // both `as: item` — the first over a secret-derived collection, the
    // second over a genuinely clean one. If `dispatch_map_step` rebound
    // `self.ctx`'s "item" root in place (instead of forking a fresh
    // `ExprContext` per item from the pre-map context), the first map's
    // secret-derived binding would permanently mark the shared root "item"
    // secret for the rest of the run, and the second map's clean items
    // would log as `***` too — costing the second map's own log
    // readability for a taint that has nothing to do with it.
    let yaml = r#"
name: two-maps-same-as-name
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: first
    map:
      over: "${{ json(secrets.K).items }}"
      as: item
      on_item_error: continue
    steps:
      - id: echo_item
        emit: { v: "${{ item }}" }
  - id: second
    needs: [first]
    map:
      over: "${{ inputs.clean }}"
      as: item
      on_item_error: continue
    steps:
      - id: echo_item2
        emit: { v: "${{ item }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut ctx = secret_run_ctx(serde_json::json!({}), "K", r#"{"items":["s1"]}"#);
    ctx.inputs = serde_json::json!({"clean": ["a", "b"]});
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(outcomes
        .iter()
        .all(|o| matches!(o.status, StepStatus::Completed)));

    let flow_created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(
        flow_created.len(),
        3,
        "1 item from `first` + 2 items from `second`"
    );
    assert_eq!(
        flow_created[0]["v"],
        serde_json::json!("***"),
        "first map's item is genuinely secret-derived"
    );
    assert_eq!(
        flow_created[1]["v"],
        serde_json::json!("a"),
        "second map's item logs in cleartext — the shared `as: item` root was not poisoned \
         by `first`'s secret-derived collection"
    );
    assert_eq!(flow_created[2]["v"], serde_json::json!("b"));
}

#[test]
fn map_output_taint_survives_the_step_boundary_so_a_downstream_step_reading_it_is_redacted() {
    // Fix-round-3-style step-boundary taint (see
    // `Executor::run_to_completion`'s own `secret_derived_steps` comment),
    // applied at the `map` step's own aggregate output: if a `map` step's
    // per-item work reads secret material, a *dependent* step reading
    // `${{ steps.<map_id>.output }}` must be tainted too, not just the
    // per-item substitutions inside the map's own inner steps.
    let yaml = r#"
name: map-output-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ json(secrets.K).items }}"
      as: item
      on_item_error: continue
    steps:
      - id: echo_item
        emit: { v: "${{ item }}" }
  - id: downstream
    needs: [fan_out]
    emit: { echoed: "${{ steps.fan_out.output }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({}), "K", r#"{"items":["s1"]}"#);
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(outcomes
        .iter()
        .all(|o| matches!(o.status, StepStatus::Completed)));
    assert!(
        outcomes[0].output_is_secret_derived,
        "the map step's own output carries secret-derived material"
    );

    let flow_created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    // flow_created[0] is `echo_item` (inside the map, item = "s1"),
    // flow_created[1] is `downstream`.
    assert_eq!(flow_created.len(), 2);
    assert_eq!(
        flow_created[1]["echoed"],
        serde_json::json!("***"),
        "a dependent step reading `${{{{ steps.fan_out.output }}}}` is redacted in the log"
    );
    // The real, unredacted value still reaches dispatch — this is not a
    // corrupted value, only a redacted *logged rendering*.
    let real_echoed = outcomes[1].output["echoed"]
        .as_str()
        .expect("downstream's real output is a string");
    assert!(
        real_echoed.contains("s1"),
        "the real value handed to the dispatched task must still contain the item content: \
         {real_echoed}"
    );
}

// ---------------------------------------------------------------------
// Fix round 1 tests.
// ---------------------------------------------------------------------

#[test]
fn a_map_over_exceeding_max_map_items_fails_closed_before_dispatching_any_item() {
    // Fix round 1, item 3: attacker-/data-controlled `over:` fan-out was
    // unbounded. Payload: MAX_MAP_ITEMS + 1 items, each a trivial number, no
    // secret material — purely a count check.
    let yaml = r#"
name: too-many-items
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: noop
        emit: { v: 1 }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let items: Vec<serde_json::Value> = (0..(MAX_MAP_ITEMS + 1))
        .map(|i| serde_json::json!(i))
        .collect();
    let ctx = run_ctx(serde_json::json!({"items": items}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    match &outcomes[0].status {
        StepStatus::Failed { message } => {
            assert!(
                message.contains("exceeding") && message.contains(&MAX_MAP_ITEMS.to_string()),
                "got: {message}"
            );
        }
        other => panic!("expected the map step to fail closed above MAX_MAP_ITEMS, got {other:?}"),
    }
    assert!(
        sink.0.is_empty(),
        "no item is ever dispatched once the cap is exceeded — the check runs before the loop"
    );
}

#[test]
fn on_item_error_collect_through_dispatch_map_step_gathers_a_non_final_inner_step_failure() {
    // Fix round 1, item 4 (the real defect): `last` used to be
    // unconditionally overwritten by every inner step dispatched for an
    // item, so a failure in a NON-FINAL inner step was silently erased by
    // whichever inner step ran after it. This test drives the real
    // `Executor`/`dispatch_map_step` path — not `run_map` directly with a
    // synthetic closure — which is the point (see this file's own module
    // doc comment: the three tests that drive `run_map` directly could not
    // have caught this).
    //
    // Payload: 3 items, 2 inner steps each. The FIRST inner step
    // (`doomed`) always fails (an undefined function reference —
    // deterministic, independent of any future task landing). The SECOND
    // inner step (`after`) would trivially succeed if ever reached.
    let yaml = r#"
name: fail-not-final-collect
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: collect
    steps:
      - id: doomed
        emit: { v: "${{ nope_this_function_does_not_exist(1) }}" }
      - id: after
        emit: { v: "should never run" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let output = &outcomes[0].output;
    let items = output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(items.len(), 3);
    for (i, item) in items.iter().enumerate() {
        assert_eq!(
            item["status"],
            serde_json::json!("failed"),
            "item {i}'s first inner step must fail the item, not be erased: {item:?}"
        );
    }
    let collected = output["collected_errors"]
        .as_array()
        .expect("map output has a `collected_errors` array");
    assert_eq!(
        collected.len(),
        3,
        "collect gathers every item's failure onto the map step's own output, \
         even though the failure is in the first of two inner steps"
    );
    assert!(
        sink.0.is_empty(),
        "`doomed` fails before ever calling sink.emit, and `after` must never dispatch for \
         any item — the inner loop breaks at the first failing inner step"
    );
}

#[test]
fn on_item_error_fail_fast_through_dispatch_map_step_stops_at_a_non_final_inner_step_failure() {
    // Same payload shape as the `collect` test above, `on_item_error:
    // fail_fast` instead. Before the fix: `fail_fast` never stopped
    // dispatching further items, because every item's `doomed` failure was
    // erased by `after`'s success, so `run_map` never saw an
    // `ItemOutcome::Failed` to act on at all.
    let yaml = r#"
name: fail-not-final-fail-fast
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: fail_fast
    steps:
      - id: doomed
        emit: { v: "${{ nope_this_function_does_not_exist(1) }}" }
      - id: after
        emit: { v: "should never run" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let output = &outcomes[0].output;
    let items = output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(
        items.len(),
        3,
        "every item still gets an entry, even though only the first ever ran"
    );
    assert_eq!(
        items[0]["status"],
        serde_json::json!("failed"),
        "item 0's first inner step fails the item"
    );
    assert_eq!(
        items[1]["status"],
        serde_json::json!("skipped"),
        "fail_fast stops dispatching after item 0's failure — item 1 is recorded skipped, \
         not dropped"
    );
    assert_eq!(items[2]["status"], serde_json::json!("skipped"));
    let collected = output["collected_errors"]
        .as_array()
        .expect("map output has a `collected_errors` array");
    assert!(
        collected.is_empty(),
        "fail_fast never collects — only `collect` does"
    );
    assert!(
        sink.0.is_empty(),
        "no event is ever emitted: item 0's `doomed` fails before emitting, `after` never runs, \
         and items 1-2 never dispatch at all"
    );
}

// ---------------------------------------------------------------------
// Fix round 2 tests.
// ---------------------------------------------------------------------

#[test]
fn a_when_false_inner_step_gate_is_evaluated_and_skips_the_dispatch() {
    // Fix round 2, item 1 (the working exploit this round exists to close):
    // before the fix, `dispatch_map_step` never evaluated an inner step's
    // `when:` at all, so a guarded destructive step dispatched anyway once
    // per item. Payload: `inputs.approved = false`, a guarded `tool: shell`
    // step whose `cmd` would be `["rm","-rf","/"]` if ever dispatched.
    //
    // Assert **zero sink events, counted** — not merely "the item's status
    // isn't completed". Round 1's own shipped `fail_fast` test could not
    // tell "the fan-out stopped" apart from "the failing step happened to
    // emit nothing", because its failing step emitted nothing either way; a
    // `tool: shell` step that actually dispatches is exactly what an event
    // count catches and a bare status check would not.
    let yaml = r#"
name: map-inner-when-false
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: guarded
        when: "${{ inputs.approved }}"
        tool: shell
        with: { cmd: ["rm", "-rf", "/"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"approved": false, "items": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let items = outcomes[0].output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(items.len(), 3);
    for (i, item) in items.iter().enumerate() {
        assert_eq!(
            item["status"],
            serde_json::json!("skipped"),
            "item {i}: the guarded step's `when:` evaluated false, so the item is skipped, \
             not completed: {item:?}"
        );
    }
    assert_eq!(
        sink.0.len(),
        0,
        "the guarded `rm -rf /` step must never dispatch for any item — zero sink events, \
         counted, not just \"the map didn't report success\""
    );
}

#[test]
fn a_when_that_fails_to_evaluate_on_an_inner_step_fails_closed_and_never_dispatches() {
    // Fix round 2, item 1, the "worse half": a gate that FAILS TO EVALUATE
    // must fail closed inside a `map` exactly as it does at top level — not
    // dispatch the guarded step. Payload: `when: "${{ no_such_fn(1) }}"`,
    // an undefined-function reference (deterministic, unrelated to any
    // future task's changes elsewhere), guarding the same destructive
    // `tool: shell` step.
    let yaml = r#"
name: map-inner-when-error
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: guarded
        when: "${{ no_such_fn(1) }}"
        tool: shell
        with: { cmd: ["rm", "-rf", "/"] }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"items": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let items = outcomes[0].output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(items.len(), 3);
    for (i, item) in items.iter().enumerate() {
        assert_eq!(
            item["status"],
            serde_json::json!("failed"),
            "item {i}: an un-evaluable `when:` must fail the item closed, not dispatch: {item:?}"
        );
        let error = item["error"]
            .as_str()
            .expect("a failed item carries an error string");
        assert!(
            error.contains("when:"),
            "the error should name the `when:` evaluation as the cause: {error}"
        );
    }
    assert_eq!(
        sink.0.len(),
        0,
        "the guarded `rm -rf /` step must never dispatch for any item when its gate fails to \
         evaluate — zero sink events, counted"
    );
}

#[test]
fn a_skipped_inner_step_does_not_abort_the_item_and_later_inner_steps_still_run() {
    // Fix round 2, item 1's own consequence: before the fix, `Skipped` was
    // unreachable through `dispatch_map_step`'s inner loop (the only
    // producer of `Skipped` is `when:`, and nothing reached it). Now that it
    // is reachable, `Skipped` must behave like `run_to_completion`'s own
    // top-level semantics — unlike `Failed`, a `Skipped` inner step must NOT
    // abort the rest of that item's inner steps.
    let yaml = r#"
name: map-inner-skipped-continues
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: guarded
        when: "${{ inputs.approved }}"
        emit: { v: "should be skipped" }
      - id: after
        emit: { v: "should still run" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = run_ctx(serde_json::json!({"approved": false, "items": [1, 2, 3]}));
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let items = outcomes[0].output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(items.len(), 3);
    for (i, item) in items.iter().enumerate() {
        assert_eq!(
            item["status"],
            serde_json::json!("completed"),
            "item {i}: `guarded` is skipped but `after` still runs and completes the item: \
             {item:?}"
        );
    }
    let flow_created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(
        flow_created.len(),
        3,
        "exactly one dispatched event per item (`after`) — `guarded` never dispatches"
    );
    for created in &flow_created {
        assert_eq!(created["v"], serde_json::json!("should still run"));
    }
}

#[test]
fn a_nested_maps_secret_derived_as_name_does_not_poison_the_outer_maps_use_of_the_same_as_name() {
    // Fix round 2, items 2/3: the case the atomicity safety argument has to
    // survive — a NESTED `map` reusing its parent's `as:` name, with the
    // nested collection secret-derived and the outer's genuinely clean.
    //
    // Payload: outer `map` over one clean item ("OUTER-CLEAN-1"), `as: item`.
    // Its inner steps: emit `item` (should log clean), a NESTED `map` also
    // `as: item` over a secret-derived one-item collection whose own inner
    // step emits `item` (should log `***`), then emit `item` again (should
    // log clean again — proving the nested map's secret binding did not
    // survive past its own restore).
    let yaml = r#"
name: nested-maps-same-name
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: outer
    map:
      over: "${{ inputs.outer_items }}"
      as: item
      on_item_error: continue
    steps:
      - id: echo_outer_before
        emit: { v: "${{ item }}" }
      - id: inner_map
        map:
          over: "${{ json(secrets.K).items }}"
          as: item
          on_item_error: continue
        steps:
          - id: echo_inner
            emit: { v: "${{ item }}" }
      - id: echo_outer_after
        emit: { v: "${{ item }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let mut ctx = secret_run_ctx(serde_json::json!({}), "K", r#"{"items":["s1"]}"#);
    ctx.inputs = serde_json::json!({"outer_items": ["OUTER-CLEAN-1"]});
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();
    assert!(matches!(outcomes[0].status, StepStatus::Completed));

    let flow_created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(
        flow_created.len(),
        3,
        "echo_outer_before, echo_inner (nested map's one item), echo_outer_after"
    );
    assert_eq!(
        flow_created[0]["v"],
        serde_json::json!("OUTER-CLEAN-1"),
        "before the nested map runs, the outer's own clean binding logs in cleartext"
    );
    assert_eq!(
        flow_created[1]["v"],
        serde_json::json!("***"),
        "inside the nested map, the secret-derived binding logs redacted"
    );
    assert_eq!(
        flow_created[2]["v"],
        serde_json::json!("OUTER-CLEAN-1"),
        "after the nested map returns and restores its snapshot, the outer's own clean \
         binding logs in cleartext again — the nested secret did not survive past its own \
         restore"
    );
}

// ---------------------------------------------------------------------
// Fix round 3 tests.
// ---------------------------------------------------------------------

#[test]
fn an_inner_steps_secret_derived_gate_taints_the_maps_own_output_even_when_the_items_output_does_not(
) {
    // Fix round 3, item 1 (the working gap this round exists to close): an
    // inner step's `when:` gate WAS evaluated correctly (fix round 2 closed
    // the fail-open dispatch bug) but the resulting
    // `gate_condition_was_secret_derived` flag was computed and thrown away
    // — lost at the `ItemOutcome` boundary on every arm, and hard-coded
    // `false` on the map's own returned `StepOutcome`. So a downstream step
    // reading `${{ steps.<map_id>.output }}` had no idea the map's dispatch
    // decisions were secret-derived, even though the crate's own
    // `when:`-gate doc comment (`evaluate_when_gate`, `crate::exec::mod`)
    // states that which branch a gate takes is itself a one-bit function of
    // the secret.
    //
    // Payload: `guarded`'s own `when: "${{ secrets.K == 'yesyesyesyes' }}"`
    // reads a secret; `K = "yesyesyesyes"` makes the gate TRUE, so the step
    // dispatches. Its own emitted value ("clean-value-not-derived-from-K")
    // is a fixed literal, NOT built from `secrets.*` — deliberately, to
    // isolate this test to the *gate's* taint rather than the item's
    // *output* taint (which `map_output_taint_survives_the_step_boundary_...`
    // above already covers). A downstream step reads
    // `${{ steps.fan_out.output }}`.
    let yaml = r#"
name: map-inner-gate-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: guarded
        when: "${{ secrets.K == 'yesyesyesyes' }}"
        emit: { v: "clean-value-not-derived-from-K" }
  - id: downstream
    needs: [fan_out]
    emit: { echoed: "${{ steps.fan_out.output }}" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(serde_json::json!({"items": [1]}), "K", "yesyesyesyes");
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let fan_out = outcomes.iter().find(|o| o.step_id == "fan_out").unwrap();
    assert!(
        matches!(fan_out.status, StepStatus::Completed),
        "the gate is true, so the guarded step dispatches and the item completes"
    );
    let items = fan_out.output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(
        items[0]["output"]["v"],
        serde_json::json!("clean-value-not-derived-from-K"),
        "the item's own OUTPUT is not secret-derived — isolating this test to the gate"
    );
    assert!(
        fan_out.output_is_secret_derived,
        "the guarded step's `when:` read `secrets.K`, so the map's own aggregate output \
         must be recorded as secret-derived even though no item's OUTPUT was — before this \
         round's fix, `dispatch_map_step` folded only `output_is_secret_derived` into its \
         aggregate, never `gate_condition_was_secret_derived`, so this flag stayed false"
    );

    let flow_created: Vec<&serde_json::Value> = sink
        .0
        .iter()
        .filter(|e| matches!(e.kind, TaskKind::Flow) && e.payload_json.get("TaskCreated").is_some())
        .map(|e| &e.payload_json["TaskCreated"]["input"]["Json"])
        .collect();
    assert_eq!(
        flow_created.len(),
        2,
        "`guarded`'s one item, then `downstream`"
    );
    assert_eq!(
        flow_created[1]["echoed"],
        serde_json::json!("***"),
        "the map's aggregate taint survives the step boundary, so `downstream` reading \
         `${{{{ steps.fan_out.output }}}}` is redacted in the log, exactly as \
         `map_output_taint_survives_the_step_boundary_so_a_downstream_step_reading_it_is_redacted` \
         already establishes for item-output taint"
    );
}

#[test]
fn an_inner_gate_that_fails_to_evaluate_because_of_a_secret_taints_the_maps_own_output() {
    // Fix round 3, item 1, the fail-closed arm this crate's posture depends
    // on (fix round 5, item 1 — `evaluate_when_gate`'s `Err` arm deliberately
    // FORCES `gate_condition_was_secret_derived = true`, because an
    // evaluation failure's taint is unknown and ruling P35 says treat
    // unknown as secret-derived). Before this round's fix, that forced
    // `true` was thrown away identically to the `Decided`/`true`-condition
    // case above.
    //
    // Payload, identical in shape to
    // `tests/exec_sequencing.rs`'s
    // `a_when_that_fails_to_evaluate_because_of_the_secrets_content_records_the_gate_as_secret_derived`,
    // nested under a `map` instead of at top level:
    // `when: "${{ inputs.arr[json(secrets.K).idx] }}"`, `inputs.arr = [true,
    // false]`, `K = {"idx":"not-a-number"}` — the subscript fails to
    // evaluate only because of what the secret said.
    let yaml = r#"
name: map-inner-gate-eval-failure-taint
version: 1
inputs: {}
defaults: { isolation: worktree }
permissions: { default: deny, unattended: { escalate: fail } }
steps:
  - id: fan_out
    map:
      over: "${{ inputs.items }}"
      as: item
      on_item_error: continue
    steps:
      - id: guarded
        when: "${{ inputs.arr[json(secrets.K).idx] }}"
        emit: { v: "clean-value-not-derived-from-K" }
"#;
    let def = parse_workflow(yaml).unwrap();
    let mut sink = RecordingSink(Vec::new());
    let ctx = secret_run_ctx(
        serde_json::json!({"items": [1], "arr": [true, false]}),
        "K",
        r#"{"idx":"not-a-number"}"#,
    );
    let mut exec = Executor::new(&def, &mut sink, ctx).unwrap();
    let outcomes = exec.run_to_completion().unwrap();

    let fan_out = outcomes.iter().find(|o| o.step_id == "fan_out").unwrap();
    let items = fan_out.output["items"]
        .as_array()
        .expect("map output has an `items` array");
    assert_eq!(
        items[0]["status"],
        serde_json::json!("failed"),
        "the un-evaluable subscript fails the item closed: {:?}",
        items[0]
    );
    assert!(
        fan_out.output_is_secret_derived,
        "an inner gate that fails to evaluate because of the secret's content forces \
         `gate_condition_was_secret_derived = true` (fix round 5, item 1); that must fold \
         into the map's own aggregate too, not just the true-condition dispatch case above"
    );
    assert!(
        sink.0.is_empty(),
        "the guarded step never dispatches — its own gate never evaluated to true"
    );
}
