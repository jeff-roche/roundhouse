//! Task 16 (B8) — the durable state machine behind §8.10's
//! "checkpoint-and-re-drive beats replay whenever control flow is data
//! rather than code".

use roundhouse_core::{BindingId, JobId, SessionId, Timestamp};
use roundhouse_flow::durability::{
    checkpoint_step, derive_disposition, on_crash_policy, open_test_db, previous_run_for_binding,
    recover_run, CrashPolicy, DurabilityError, RunState, StepDisposition, StepOutput, StepRunState,
    WorkflowRun, WorkflowStepRun,
};
use roundhouse_flow::durability::{insert_workflow_run, TOP_LEVEL_ITEM_INDEX};
use roundhouse_flow::exec::{Provenance, RunId, StepOutcome, StepStatus};
use roundhouse_flow::parse::steps::parse_step;

fn step(yaml: &str) -> roundhouse_flow::parse::steps::StepDef {
    parse_step(&serde_yaml::from_str(yaml).expect("fixture parses as YAML"))
        .expect("fixture parses as a step")
}

fn a_run(id: RunId, binding_id: Option<BindingId>, started_at: i64) -> WorkflowRun {
    WorkflowRun {
        id,
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:a".into(),
        session_id: SessionId::new(),
        binding_id,
        trigger_event_id: None,
        state: RunState::Running,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: Timestamp::from_unix_nanos(started_at),
        ended_at: None,
    }
}

fn a_step_run(run_id: RunId, step_id: &str, disposition: StepDisposition) -> WorkflowStepRun {
    WorkflowStepRun {
        run_id,
        step_id: step_id.to_string(),
        attempt: 1,
        item_index: None,
        disposition,
        state: StepRunState::Running,
        first_task_seq: Some(10),
        last_task_seq: Some(12),
        output: None,
        error: None,
    }
}

#[test]
fn disposition_is_derived_from_the_real_step_kind_not_hand_picked() {
    let post = step("id: post\ntool: shell\nwith: { cmd: [gh, pr, comment] }");
    assert_eq!(
        derive_disposition(&post),
        StepDisposition::Effectful,
        "shell is side-effecting by default"
    );

    let list_prs =
        step("id: list_prs\ntool: http\nwith: { method: GET, url: 'https://api.github.com' }");
    assert_eq!(
        derive_disposition(&list_prs),
        StepDisposition::Pure,
        "a GET is safe to re-run blindly"
    );

    let post_http =
        step("id: p\ntool: http\nwith: { method: POST, url: 'https://api.github.com' }");
    assert_eq!(derive_disposition(&post_http), StepDisposition::Effectful);

    let read = step("id: r\ntool: read\nwith: { path: 'x.txt' }");
    assert_eq!(derive_disposition(&read), StepDisposition::Pure);

    let post_with_key = step(
        "id: post\ntool: shell\nidempotency_key: 'pr-1-review'\nwith: { cmd: [gh, pr, comment] }",
    );
    assert_eq!(
        derive_disposition(&post_with_key),
        StepDisposition::Idempotent,
        "an explicit idempotency_key overrides the tool-kind default"
    );
}

/// A `method:` this crate cannot read as a literal `GET`/`HEAD` — because it
/// is still an uninterpolated `${{ }}` template, or spelled in lowercase —
/// falls to `Effectful`, the fail-safe side. Pinned so the fallback is a
/// decision rather than an accident.
#[test]
fn an_http_method_this_crate_cannot_read_as_a_literal_get_is_effectful_not_pure() {
    let templated =
        step("id: t\ntool: http\nwith: { method: '${{ inputs.m }}', url: 'https://x' }");
    assert_eq!(derive_disposition(&templated), StepDisposition::Effectful);

    let lowercase = step("id: l\ntool: http\nwith: { method: get, url: 'https://x' }");
    assert_eq!(derive_disposition(&lowercase), StepDisposition::Effectful);
}

#[test]
fn effectful_step_found_running_after_crash_is_marked_indeterminate_not_completed() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let post = step("id: post\ntool: shell\nwith: { cmd: [gh, pr, comment] }");
    let step_run = a_step_run(run_id, &post.id, derive_disposition(&post));
    checkpoint_step(&mut conn, &step_run).unwrap();

    // Simulate a crash: recover without any further writes.
    let recovered = recover_run(&conn, run_id).unwrap();
    let post_row = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "post")
        .expect("the checkpointed step is recovered");
    assert_eq!(
        post_row.state,
        StepRunState::Indeterminate,
        "a Running Effectful step is NOT known to have completed"
    );

    // A Pure step in the same position stays Running — §8.10 tier 2 marks
    // only Effectful steps Indeterminate.
    let read = step("id: r\ntool: read\nwith: { path: 'x.txt' }");
    let read_run = a_step_run(run_id, &read.id, derive_disposition(&read));
    checkpoint_step(&mut conn, &read_run).unwrap();
    let recovered = recover_run(&conn, run_id).unwrap();
    let read_row = recovered.steps.iter().find(|s| s.step_id == "r").unwrap();
    assert_eq!(read_row.state, StepRunState::Running);
    assert_eq!(on_crash_policy(read_row.disposition), CrashPolicy::Rerun);
}

#[test]
fn pure_and_idempotent_steps_rerun_on_crash_effectful_defaults_to_ask() {
    assert_eq!(on_crash_policy(StepDisposition::Pure), CrashPolicy::Rerun);
    assert_eq!(
        on_crash_policy(StepDisposition::Idempotent),
        CrashPolicy::Rerun
    );
    assert_eq!(
        on_crash_policy(StepDisposition::Effectful),
        CrashPolicy::Ask
    );
}

#[test]
fn previous_run_for_binding_finds_the_most_recent_prior_run_excluding_itself() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();
    let older = a_run(RunId::new(), Some(binding_id), 1_000);
    let newer = a_run(RunId::new(), Some(binding_id), 2_000);
    let other_binding = a_run(RunId::new(), Some(BindingId::new()), 3_000);
    let manual = a_run(RunId::new(), None, 4_000);

    insert_workflow_run(&mut conn, &older).unwrap();
    insert_workflow_run(&mut conn, &newer).unwrap();
    insert_workflow_run(&mut conn, &other_binding).unwrap();
    insert_workflow_run(&mut conn, &manual).unwrap();

    let previous = previous_run_for_binding(&conn, binding_id, newer.id).unwrap();
    assert_eq!(
        previous.expect("the older run of the same binding").id,
        older.id,
        "the previous run is the most recent run of this binding before the asking run"
    );

    let none_for_first_run = previous_run_for_binding(&conn, binding_id, older.id).unwrap();
    assert!(
        none_for_first_run.is_none(),
        "a binding's very first run has no previous run, even though a later run exists — \
         `previous` means strictly earlier, not merely `some other run`"
    );

    // The `carry_over` case: the daemon asks before the new run's row exists,
    // and gets the binding's most recent run.
    let not_yet_inserted = RunId::new();
    let previous = previous_run_for_binding(&conn, binding_id, not_yet_inserted).unwrap();
    assert_eq!(
        previous.expect("a run of this binding").id,
        newer.id,
        "a run whose row does not exist yet still gets the binding's latest run to seed from"
    );
}

/// B-2. `Provenance` is `(run_id, step_id, attempt, item_index)`, so the
/// `workflow_step_run` primary key must be too — otherwise two items of one
/// `map` step collide and the second silently overwrites the first.
#[test]
fn two_map_items_of_the_same_step_and_attempt_are_distinct_rows_not_one_overwritten_row() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    for item_index in [0u32, 1u32] {
        let provenance = Provenance {
            run_id,
            step_id: "review".into(),
            attempt: 1,
            item_index: Some(item_index),
        };
        let mut row = a_step_run(run_id, &provenance.step_id, StepDisposition::Effectful);
        row.attempt = provenance.attempt;
        row.item_index = provenance.item_index;
        row.state = StepRunState::Completed;
        row.first_task_seq = Some(u64::from(item_index) + 100);
        row.last_task_seq = Some(u64::from(item_index) + 200);
        checkpoint_step(&mut conn, &row).unwrap();
    }

    let recovered = recover_run(&conn, run_id).unwrap();
    let mut items: Vec<Option<u32>> = recovered
        .steps
        .iter()
        .filter(|s| s.step_id == "review")
        .map(|s| s.item_index)
        .collect();
    items.sort();
    assert_eq!(
        items,
        vec![Some(0), Some(1)],
        "each map item keeps its own row"
    );

    let seqs: Vec<(Option<u64>, Option<u64>)> = {
        let mut v: Vec<_> = recovered
            .steps
            .iter()
            .filter(|s| s.step_id == "review")
            .map(|s| (s.first_task_seq, s.last_task_seq))
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        seqs,
        vec![(Some(100), Some(200)), (Some(101), Some(201))],
        "neither item's log join range was overwritten by the other's"
    );
}

/// The other half of B-2: a *top-level* step has no item index, and two
/// checkpoints of it must still be one row. `item_index` is stored with a
/// sentinel rather than NULL because these are `STRICT` tables, where every
/// `PRIMARY KEY` column is implicitly `NOT NULL` and a NULL therefore cannot
/// be stored at all. (The "NULLs compare distinct in a PRIMARY KEY" behaviour
/// is real, but it belongs to an ordinary rowid table; under `STRICT` the
/// same mistake is an insert-time error instead of silent duplicate rows.)
/// Either way the sentinel is required — this pins the one-row result.
#[test]
fn a_top_level_step_checkpointed_twice_is_one_row_not_two() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let mut row = a_step_run(run_id, "build", StepDisposition::Effectful);
    assert_eq!(row.item_index, None);
    checkpoint_step(&mut conn, &row).unwrap();
    row.state = StepRunState::Completed;
    row.last_task_seq = Some(99);
    checkpoint_step(&mut conn, &row).unwrap();

    let recovered = recover_run(&conn, run_id).unwrap();
    let build: Vec<_> = recovered
        .steps
        .iter()
        .filter(|s| s.step_id == "build")
        .collect();
    assert_eq!(build.len(), 1, "the second checkpoint updated one row");
    assert_eq!(build[0].state, StepRunState::Completed);
    assert_eq!(build[0].item_index, None);
    assert_eq!(
        build[0].last_task_seq,
        Some(99),
        "the later checkpoint's state is what survives"
    );
    assert_eq!(
        build[0].first_task_seq,
        Some(10),
        "`first` means first: a later checkpoint never moves it"
    );
    // The sentinel is outside `u32`, so `map` item 0 of the same step is a
    // different row rather than an overwrite of the top-level one.
    assert!(u32::try_from(TOP_LEVEL_ITEM_INDEX).is_err());
    let mut item_zero = a_step_run(run_id, "build", StepDisposition::Effectful);
    item_zero.item_index = Some(0);
    item_zero.state = StepRunState::Failed;
    checkpoint_step(&mut conn, &item_zero).unwrap();

    let recovered = recover_run(&conn, run_id).unwrap();
    let mut build: Vec<(Option<u32>, StepRunState)> = recovered
        .steps
        .iter()
        .filter(|s| s.step_id == "build")
        .map(|s| (s.item_index, s.state))
        .collect();
    build.sort_by_key(|(i, _)| *i);
    assert_eq!(
        build,
        vec![
            (None, StepRunState::Completed),
            (Some(0), StepRunState::Failed)
        ],
        "item 0 and the top-level row coexist"
    );
}

/// B-3. `checkpoint_step` persists the step's output **and** the
/// `output_is_secret_derived` flag the executor already computed. Both
/// survive the round trip, so a consumer reads the flag rather than
/// re-deriving it (`exec/mod.rs`: "a re-derivation that disagrees with this
/// one is a leak").
#[test]
fn step_output_and_its_taint_flag_round_trip_instead_of_being_re_derived() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let tainted = StepOutcome {
        step_id: "notify".into(),
        output: serde_json::json!({"body": "token sk-super-secret"}),
        status: StepStatus::Completed,
        output_is_secret_derived: true,
        gate_condition_was_secret_derived: false,
    };
    let clean = StepOutcome {
        step_id: "summary".into(),
        output: serde_json::json!({"count": 3}),
        status: StepStatus::Completed,
        output_is_secret_derived: false,
        gate_condition_was_secret_derived: false,
    };

    for outcome in [&tainted, &clean] {
        let mut row = a_step_run(run_id, &outcome.step_id, StepDisposition::Effectful);
        row.state = StepRunState::Completed;
        row.output = Some(StepOutput::from_outcome(outcome));
        checkpoint_step(&mut conn, &row).unwrap();
    }

    let recovered = recover_run(&conn, run_id).unwrap();
    let notify = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "notify")
        .unwrap();
    let notify_output = notify.output.as_ref().expect("output was persisted");
    assert_eq!(
        notify_output.value_unredacted_for_resume(),
        &serde_json::json!({"body": "token sk-super-secret"}),
        "§8.13's fork inherits the real completed step output, not a redacted stand-in"
    );
    assert!(
        notify_output.is_secret_derived(),
        "the executor's own flag is what comes back"
    );

    let summary = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "summary")
        .unwrap();
    let summary_output = summary.output.as_ref().unwrap();
    assert_eq!(
        summary_output.value_unredacted_for_resume(),
        &serde_json::json!({"count": 3})
    );
    assert!(!summary_output.is_secret_derived());

    // A step with no output at all is distinguishable from one whose output
    // is JSON `null` — the resume path must not confuse the two.
    let mut pending = a_step_run(run_id, "pending", StepDisposition::Pure);
    pending.state = StepRunState::Pending;
    pending.output = None;
    checkpoint_step(&mut conn, &pending).unwrap();
    let recovered = recover_run(&conn, run_id).unwrap();
    let pending = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "pending")
        .unwrap();
    assert!(pending.output.is_none());
}

/// A hand-written `Debug` prints the output's *shape*, never a leaf's
/// content — `StepOutput` is `pub` and reachable from any consumer's
/// `tracing::debug!`, and it deliberately holds unredacted material.
#[test]
fn step_output_debug_never_prints_a_leaf_value() {
    let outcome = StepOutcome {
        step_id: "notify".into(),
        output: serde_json::json!({"body": "sk-super-secret"}),
        status: StepStatus::Completed,
        output_is_secret_derived: true,
        gate_condition_was_secret_derived: false,
    };
    let rendered = format!("{:?}", StepOutput::from_outcome(&outcome));
    assert!(
        !rendered.contains("sk-super-secret"),
        "leaf content must not reach a Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains("body"),
        "the shape (key names) is what is printed: {rendered}"
    );
}

/// B-4. The three run-level columns Tasks 17/20 need exist and round-trip
/// now, so neither has to migrate the table later. `awaiting_until` is an
/// **absolute** instant, written by Task 17.
#[test]
fn awaiting_until_parent_run_and_forked_from_run_round_trip() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();
    let parent = a_run(RunId::new(), Some(binding_id), 1_000);
    insert_workflow_run(&mut conn, &parent).unwrap();

    let mut child = a_run(RunId::new(), Some(binding_id), 2_000);
    child.parent_run_id = Some(parent.id);
    child.forked_from_run_id = Some(parent.id);
    child.state = RunState::AwaitingHuman;
    child.awaiting_until = Some(Timestamp::from_unix_nanos(9_000_000_000));
    child.trigger_event_id = Some(42);
    child.ended_at = Some(Timestamp::from_unix_nanos(2_500));
    insert_workflow_run(&mut conn, &child).unwrap();

    let read_back = recover_run(&conn, child.id).unwrap().run;
    assert_eq!(read_back, child, "every run-level column round-trips");
    assert_eq!(
        read_back.awaiting_until,
        Some(Timestamp::from_unix_nanos(9_000_000_000))
    );
}

#[test]
fn recover_run_for_an_unknown_run_id_is_an_error_not_an_empty_step_list() {
    let mut conn = open_test_db();
    let err = recover_run(&conn, RunId::new()).unwrap_err();
    assert!(
        matches!(err, DurabilityError::RunNotFound { .. }),
        "an unknown run must not be indistinguishable from a run with no steps yet: {err:?}"
    );

    // A run that exists but has checkpointed nothing yet is a legitimate
    // state, and reads as an empty step list rather than an error.
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();
    let recovered = recover_run(&conn, run_id).unwrap();
    assert!(recovered.steps.is_empty());
    assert_eq!(recovered.run.id, run_id);
}

/// No connection in this workspace turns on `PRAGMA foreign_keys`, so a
/// declared `FOREIGN KEY` would be inert. `checkpoint_step` does the check
/// itself: without it, the step row would be written and then be permanently
/// invisible to `recover_run`, which errors on the missing run.
#[test]
fn checkpointing_a_step_of_a_run_that_was_never_inserted_is_refused_not_orphaned() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    let row = a_step_run(run_id, "build", StepDisposition::Effectful);

    let err = checkpoint_step(&mut conn, &row).unwrap_err();
    assert!(
        matches!(err, DurabilityError::RunNotFound { .. }),
        "expected RunNotFound, got {err:?}"
    );

    // And the refusal rolled back: inserting the run afterwards must not
    // reveal a step row written by the rejected call.
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();
    assert!(recover_run(&conn, run_id).unwrap().steps.is_empty());
}

/// I-2 (fix round 1). `StepOutput` now has a **safe** accessor as well as an
/// honestly-named hazardous one. `value_for_display` is the call a web
/// handler or an inbox renderer reaches for, and it performs the taint check
/// itself — so the leak shape the security lens described
/// (`json!({ "output": step.output.as_ref().map(StepOutput::value) })`) has
/// no innocent-looking spelling left.
#[test]
fn a_tainted_output_is_withheld_from_the_display_accessor_but_not_from_resume() {
    let tainted = StepOutput::from_outcome(&StepOutcome {
        step_id: "notify".into(),
        output: serde_json::json!({"body": "sk-super-secret"}),
        status: StepStatus::Completed,
        output_is_secret_derived: true,
        gate_condition_was_secret_derived: false,
    });
    assert_eq!(
        tainted.value_for_display(),
        None,
        "a secret-derived output is not renderable"
    );
    assert_eq!(
        tainted.value_unredacted_for_resume(),
        &serde_json::json!({"body": "sk-super-secret"}),
        "resume and §8.13's fork still need the real value"
    );

    let clean = StepOutput::from_outcome(&StepOutcome {
        step_id: "summary".into(),
        output: serde_json::json!({"count": 3}),
        status: StepStatus::Completed,
        output_is_secret_derived: false,
        gate_condition_was_secret_derived: false,
    });
    assert_eq!(
        clean.value_for_display(),
        Some(&serde_json::json!({"count": 3})),
        "an untainted output renders normally"
    );
}

/// C-1 (fix round 1). A `when:`-skipped step is **finished**: on re-drive the
/// run loop must not re-evaluate its `when:`, and downstream steps read
/// `${{ steps.<id>.status }}`. `exec::StepStatus::Skipped` already exists, so
/// migration 0007's CHECK and `StepRunState` carry `skipped` from the start
/// rather than making Task 20 rebuild a table SQLite cannot alter in place.
/// Nothing in this task writes it; this pins that it *can* be written.
#[test]
fn a_skipped_step_state_round_trips_through_the_schema() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let mut skipped = a_step_run(run_id, "deploy", StepDisposition::Effectful);
    skipped.state = StepRunState::Skipped;
    skipped.error = Some("when: evaluated false".into());
    checkpoint_step(&mut conn, &skipped).unwrap();

    let recovered = recover_run(&conn, run_id).unwrap();
    let deploy = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "deploy")
        .expect("the skipped step was checkpointed");
    assert_eq!(
        deploy.state,
        StepRunState::Skipped,
        "skipped is a storable, recoverable state — not re-derived by re-evaluating `when:`"
    );
    assert_eq!(
        deploy.error.as_deref(),
        Some("when: evaluated false"),
        "the skip reason survives the process that produced it"
    );
    assert_ne!(
        deploy.state,
        StepRunState::Indeterminate,
        "an Effectful step that was skipped was never Running, so recovery must not mark it \
         indeterminate"
    );
}

/// C-3 (fix round 1). A failure message is persisted for the same reason the
/// output is: it cannot be recomputed once the process that produced it is
/// gone, and Task 20's `catch:` and the web Runs inbox both need it.
#[test]
fn a_failure_message_survives_the_checkpoint_instead_of_being_dropped() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let mut failed = a_step_run(run_id, "build", StepDisposition::Effectful);
    failed.state = StepRunState::Failed;
    failed.error = Some("cargo build exited 101".into());
    checkpoint_step(&mut conn, &failed).unwrap();

    let build = recover_run(&conn, run_id).unwrap().steps.remove(0);
    assert_eq!(build.state, StepRunState::Failed);
    assert_eq!(build.error.as_deref(), Some("cargo build exited 101"));

    // And a step that has not failed carries no error, rather than an empty
    // string standing in for one.
    let ok = a_step_run(run_id, "aaa_ok", StepDisposition::Pure);
    checkpoint_step(&mut conn, &ok).unwrap();
    let recovered = recover_run(&conn, run_id).unwrap();
    let ok = recovered
        .steps
        .iter()
        .find(|s| s.step_id == "aaa_ok")
        .unwrap();
    assert_eq!(ok.error, None);
}

/// `checkpoint_step`'s upsert makes `output` last-write-wins rather than
/// `COALESCE`ing it, so a checkpoint carrying no output **clears** a stored
/// one. That is deliberate on both counts: it keeps `output` and its taint
/// flag moving together (a `COALESCE`d value beside a fresh `0` flag would be
/// a leak), and it is the only mechanism by which a stored output can ever be
/// erased — the erasure whose *caller* is a residual owned by Task 20. Pinned
/// here so it is a decision rather than something rediscovered as a bug.
#[test]
fn a_checkpoint_with_no_output_clears_a_previously_stored_one() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();

    let mut row = a_step_run(run_id, "notify", StepDisposition::Effectful);
    row.state = StepRunState::Completed;
    row.output = Some(StepOutput::from_outcome(&StepOutcome {
        step_id: "notify".into(),
        output: serde_json::json!({"body": "sk-super-secret"}),
        status: StepStatus::Completed,
        output_is_secret_derived: true,
        gate_condition_was_secret_derived: false,
    }));
    checkpoint_step(&mut conn, &row).unwrap();
    assert!(recover_run(&conn, run_id).unwrap().steps[0]
        .output
        .is_some());

    row.output = None;
    checkpoint_step(&mut conn, &row).unwrap();
    let recovered = recover_run(&conn, run_id).unwrap();
    assert_eq!(recovered.steps.len(), 1, "still one row, not two");
    assert!(
        recovered.steps[0].output.is_none(),
        "the stored output was cleared, and with it the taint flag"
    );
}

/// C-2 (fix round 1). `item_index` is bounded at both ends. The lower bound
/// keeps the `-1` sentinel the only negative value; the upper bound matters
/// because `item_index` is a `u32` in Rust, so an out-of-domain stored value
/// would otherwise read back through the same "not a u32" path as the
/// sentinel — aliasing two rows with different states onto one identity.
/// Insert-time rejection and read-back rejection are both pinned; the
/// read-back leg is reached by suspending CHECK enforcement, which is the
/// closest a test can get to a hand-edited or pre-CHECK row.
#[test]
fn an_out_of_domain_item_index_is_refused_on_write_and_on_read_never_aliased() {
    let mut conn = open_test_db();
    let run_id = RunId::new();
    insert_workflow_run(&mut conn, &a_run(run_id, None, 1_000)).unwrap();
    let run_text = run_id.to_string();

    let insert = "INSERT INTO workflow_step_run \
         (run_id, step_id, attempt, item_index, disposition, state, output_is_secret_derived) \
         VALUES (?1, ?2, 1, ?3, 'effectful', 'running', 0)";

    let too_big = conn.execute(insert, rusqlite::params![run_text, "m", 4_294_967_296i64]);
    assert!(
        too_big.is_err(),
        "an item_index above u32::MAX must violate the CHECK constraint"
    );
    let too_small = conn.execute(insert, rusqlite::params![run_text, "m", -2i64]);
    assert!(
        too_small.is_err(),
        "-1 is the only negative item_index the CHECK admits"
    );

    // A row that got in anyway: read-back must reject it rather than hand it
    // back as the top-level sentinel, which is what `u32::try_from(..).ok()`
    // used to do.
    conn.pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    conn.execute(insert, rusqlite::params![run_text, "m", 4_294_967_296i64])
        .expect("CHECK enforcement is suspended for this one insert");
    conn.pragma_update(None, "ignore_check_constraints", false)
        .unwrap();

    let err = recover_run(&conn, run_id).unwrap_err();
    assert!(
        matches!(
            err,
            DurabilityError::ItemIndexOutOfRange {
                stored: 4_294_967_296
            }
        ),
        "expected ItemIndexOutOfRange, got {err:?}"
    );
}
