//! Tests for Task 14/B6 (`map` step fan-out) — see
//! `crates/roundhouse-flow/src/exec/map_step.rs`'s own module doc comment
//! for the design this exercises and, in particular, "Deviations from the
//! plan text" for why these payloads differ from the brief's own illustrative
//! test code (`OnItemError` instead of `&str`; a compiling budget-exhaustion
//! probe instead of the brief's — the brief's own `budget_has_room` stub
//! always returns `true`, which cannot produce a skip at all, and its call
//! site borrows the same `budget` both as `&mut` into `run_map` and
//! immutably inside the closure, which does not borrow-check).

use roundhouse_core::TaskKind;
use roundhouse_flow::caps::ResourceCaps;
use roundhouse_flow::exec::map_step::{run_map, split_budget, ItemOutcome, MapBudget};
use roundhouse_flow::exec::{Executor, RunContext, StepStatus, TaskSink};
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
