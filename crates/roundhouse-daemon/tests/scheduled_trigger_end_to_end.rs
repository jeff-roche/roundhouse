//! Phase 8, L3, Task 9's own exit criterion (Phase 8 exit criterion 4): a
//! `sched` binding fires, starts a `flow` run through a production
//! `WorkflowHost`, and the run is queryable as a `workflow_run` row joined
//! by `binding_id` — proven end to end, through the REAL production
//! composition path, in one process.
//!
//! # Why in-process, not a real subprocess
//!
//! `real_boot_smoke.rs` proves its own exit criterion by spawning a real
//! `round-daemon-internal` subprocess. This test deliberately does not:
//! `scheduler_driver.rs`'s scheduled-run `SessionSpec` hardcodes
//! `on_degrade: OnDegrade::Refuse` unconditionally — unlike the socket path,
//! there is no CLI flag that relaxes this for a scheduled run, so a real
//! daemon subprocess would perform a genuine, un-fakeable host isolation
//! probe at boot and only pass on a machine with real `bwrap` installed at
//! the hardcoded production path, which `real_boot_smoke.rs`'s own comment
//! already documents this project's CI as lacking. Every existing
//! daemon-crate test that touches scheduled-run session construction
//! already uses an in-process, fake-probed isolate
//! (`tests/common::available_isolate`) instead — the established, portable
//! convention this test follows.
//!
//! This test drives the real production composition path in-process: a real
//! `BackgroundServices { scheduler: Some(...) }` (spelled exactly the way
//! `main.rs`'s own `background_services()` constructs it), started via its
//! real, public `.start(store, sessions, resources)` entrypoint — the
//! identical call `main.rs` makes.
//!
//! # Why this test genuinely waits on real wall-clock time
//!
//! `scheduler_driver::run` hardcodes `SystemClock` and a real
//! `tokio::time::interval` heartbeat — it cannot be driven by an injected
//! fake clock, because that is a property of the real background service
//! this test exists to prove, not something to work around. This is not the
//! banned "sleep(N); assert!(...)" pattern: nothing here asserts based on a
//! specific elapsed duration. Instead, exactly like `real_boot_smoke.rs`'s
//! own socket-existence poll loop, this test repeatedly checks the actual
//! condition (a `trigger_delivery` row reaching `Delivered`) on a short
//! interval inside a generous overall `tokio::time::timeout`, and fails only
//! if the condition never becomes true. A slow host makes this test take
//! longer, not wrong.
//!
//! `TriggerSpec::Interval` (not `Cron`) is used for the seeded binding: a
//! cron binding only fires at literal minute boundaries, which would make a
//! test started at `:59.9` wait up to a real 60 seconds depending on
//! wall-clock alignment at run time — a real, unnecessary slowness/flakiness
//! risk `Interval` avoids entirely by design.

use std::sync::Arc;
use std::time::Duration;

use roundhouse_core::Tier;
use roundhouse_daemon::scheduler_driver;
use roundhouse_daemon::session_bootstrap::{policy_rules_from_files, BackgroundServices};
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_flow::durability::recover_run;
use roundhouse_flow::exec::RunId;
use roundhouse_flow::job::SessionTemplate;
use roundhouse_flow::job_store::register_workflow_file;
use roundhouse_policy::config::compile_policy_layers;
use roundhouse_policy::trust::{record_explicit_trust, TrustStore};
use roundhouse_sched::delivery::DeliveryState;
use roundhouse_sched::store::list_deliveries_in_states;

mod common;

/// The `BackgroundService` value `main.rs` installs for the scheduler,
/// spelled the same way (`scheduler_driver_service.rs`'s own
/// `scheduler_service` helper).
fn scheduler_service() -> roundhouse_daemon::session_bootstrap::BackgroundService {
    Arc::new(|context| Box::pin(scheduler_driver::run(context)))
}

/// The `SessionTemplate` every scheduled run in this test is registered
/// with — modelled on `scheduler_driver.rs`'s own `#[cfg(test)] mod
/// delivery_tests::template`, the authoritative shape for a job version
/// this crate's `register_workflow_file` accepts.
fn template() -> SessionTemplate {
    SessionTemplate {
        provider: "test".into(),
        model: "test-model".into(),
        cwd: "/tmp".into(),
        tools: vec![],
        isolation: Tier::Sandbox,
        permission_policy_ref: "default".into(),
    }
}

/// A workflow whose single step completes with no dispatch of any kind —
/// `scheduler_driver.rs`'s own `#[cfg(test)] mod
/// delivery_tests::completing_workflow` fixture, reused verbatim. `emit:` at
/// the top level satisfies §8.6/ruling P112's "exactly one report per
/// terminal run" with the least machinery that can reach `Completed`.
fn completing_workflow() -> String {
    "name: scheduled\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
     escalate: fail\nsteps:\n  - id: result\n    emit: { value: ready }\n"
        .to_string()
}

/// Seeds one enabled `trigger_binding` row directly via SQL, modelled on
/// `scheduler_driver.rs`'s own `#[cfg(test)] mod tests::seed_binding` (the
/// authoritative column list and JSON encoding for this table — that helper
/// is private to a different crate, so this inlines the identical shape
/// rather than guessing it from the migration alone). `TriggerSpec::Interval`
/// with a short period, `align: false`, `anchor: None`, per this file's own
/// module doc on why `Interval` (not `Cron`) is required here.
async fn seed_enabled_interval_binding(
    store: &roundhouse_store::StorePool,
    binding_id: &str,
    workspace_id: &str,
    job_id: &str,
) {
    let conn = store.pool.get().await.unwrap();
    let binding_id = binding_id.to_string();
    let workspace_id = workspace_id.to_string();
    let job_id = job_id.to_string();
    conn.interact(move |connection| {
        connection
            .execute(
                "INSERT INTO trigger_binding
                    (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 0)",
                rusqlite::params![
                    binding_id,
                    workspace_id,
                    job_id,
                    r#"{"Interval":{"every":{"secs":1,"nanos":0},"align":false,"anchor":null}}"#,
                    r#""Skip""#,
                ],
            )
            .unwrap();
    })
    .await
    .unwrap();
}

/// Phase 8 exit criterion 4, proven end to end: a real `Scheduler` (driven
/// by `scheduler_driver::run`'s real heartbeat) fires a seeded `Interval`
/// binding, `accept_occurrence` durably admits it, the driver claims the
/// resulting `ready` delivery and drives a real `SqliteWorkflowHost` run
/// through a real headless session, and the whole chain becomes queryable:
/// a `trigger_delivery` reaching `Delivered`, the `workflow_run` it names
/// carrying this binding's id and a real `trigger_event_id`, and a terminal
/// `Report`-kind task recorded against that run's session.
#[tokio::test]
async fn a_scheduled_binding_fires_through_the_real_scheduler_and_completes_a_real_workflow_run() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;
    let sessions = Arc::new(SessionRegistry::new());

    // `real_resources` already registered a real "default" workspace at
    // `dir` — resolve its canonical root/id rather than reconstructing one,
    // exactly as `scheduler_driver.rs`'s own `harness_with_overlap` does
    // after registering its own workspace.
    let workspace = resources
        .workspace_registry
        .as_ref()
        .expect("real_resources wires a real WorkspaceRegistry")
        .resolve("default")
        .expect("real_resources registers a \"default\" workspace");

    // Register a minimal, real, completing workflow in that workspace, and
    // resolve its real JobId — this crate's production job store, not a
    // fabricated id.
    let source = workspace.root.join("workflow.yaml");
    std::fs::write(&source, completing_workflow()).unwrap();
    let job_id = {
        let conn = resources.store.pool.get().await.unwrap();
        let root = workspace.root.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let binding_id = uuid::Uuid::new_v4().to_string();
    seed_enabled_interval_binding(
        &resources.store,
        &binding_id,
        &workspace.id.to_string(),
        &job_id.to_string(),
    )
    .await;

    // The real production composition path: exactly what `main.rs`'s own
    // `background_services()` constructs, started through its real, public
    // entrypoint.
    let services = BackgroundServices {
        scheduler: Some(scheduler_service()),
        ..Default::default()
    };
    let running = services
        .start(resources.store.clone(), sessions, Arc::clone(&resources))
        .await
        .expect("the scheduler driver must signal readiness so daemon boot proceeds");

    // Bounded poll for the real heartbeat's real work — see this file's own
    // module doc for why this is not the banned real-clock-timing pattern.
    // 45s is generous: the seeded binding is due after one real second, the
    // heartbeat ticks once a second, and real headless session construction
    // (a real, if fake-probed, isolate `prepare`) is on the path.
    let delivered = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let conn = resources.store.pool.get().await.unwrap();
            let binding_id = binding_id.clone();
            let found = conn
                .interact(move |connection| {
                    list_deliveries_in_states(connection, &[DeliveryState::Delivered])
                        .expect("querying delivered trigger_delivery rows must not fail")
                        .into_iter()
                        .find(|delivery| delivery.binding_id.to_string() == binding_id)
                })
                .await
                .unwrap();
            if let Some(delivery) = found {
                return delivery;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect(
        "a seeded, enabled Interval binding must reach a Delivered trigger_delivery within the \
         bound",
    );

    // The `workflow_run` this delivery names must carry the seeded binding's
    // id and a real trigger_event_id — the join this whole exit criterion is
    // about.
    let run_id_str = delivered
        .run_id
        .clone()
        .expect("a Delivered delivery must carry the run_id it drove");
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(&run_id_str).unwrap());
    let workflow_run = {
        let conn = resources.store.pool.get().await.unwrap();
        conn.interact(move |connection| recover_run(connection, run_id).unwrap().run)
            .await
            .unwrap()
    };
    assert_eq!(
        workflow_run.binding_id.map(|id| id.to_string()),
        Some(binding_id.clone()),
        "the workflow_run this delivery drove must be joinable back to the seeded binding"
    );
    assert!(
        workflow_run.trigger_event_id.is_some(),
        "a scheduled run's workflow_run row must carry the trigger_event_id that started it"
    );

    // And a terminal Report-kind task must exist for that run's session —
    // ruling P112's "exactly one report on every terminal path", now proven
    // through the daemon's real materialized `tasks` cache rather than a
    // test-only sink.
    let report_task_count: i64 = {
        let session_id = workflow_run.session_id;
        let conn = resources.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM tasks WHERE session_id = ?1 AND kind = 'Report' \
                     AND state = 'Completed'",
                    rusqlite::params![session_id.to_string()],
                    |row| row.get(0),
                )
                .unwrap()
        })
        .await
        .unwrap()
    };
    assert_eq!(
        report_task_count, 1,
        "the run's session must record exactly one completed Report-kind task"
    );

    running
        .shutdown()
        .await
        .expect("the scheduler driver must observe cancellation and return Ok");
}

/// A workflow whose single step is a real `tool: read` — Phase 8 Task
/// 25.3's own exit criterion: this step must suspend the run
/// (`RunOutcome::AwaitingWork`), be dispatched for real by
/// `DeliveryExecutor::execute_pending`/`dispatch_tool_for_workflow`, and
/// resume the run to completion, rather than the fixed `{}`/`Completed`
/// stub every `tool:` step produced before this task's seam existed.
fn reading_workflow() -> String {
    "name: scheduled-read\nversion: 1\npermissions:\n  default: deny\n  unattended:\n    \
     escalate: fail\nsteps:\n  - id: read_it\n    tool: read\n    with: { path: greeting.txt }\n"
        .to_string()
}

/// Phase 8 Task 25.3's exit criterion, proven end to end through the real
/// production composition path (the identical harness
/// [`a_scheduled_binding_fires_through_the_real_scheduler_and_completes_a_real_workflow_run`]
/// uses): a scheduled run's `tool: read` step actually reads a real file —
/// admitted through the real `SessionActor::admit_task` gate, executed
/// through the real `roundhouse-tools` `read_file`, and recorded as a real
/// `Read`-kind task — with the run reaching `Completed` afterward, not
/// suspended forever and not silently faked.
#[tokio::test]
async fn a_scheduled_runs_tool_read_step_executes_for_real_and_the_run_completes() {
    let dir = tempfile::tempdir().unwrap();
    let fixture_root = dir.path().canonicalize().unwrap();

    // The real file `tool: read` must actually read — proves this is not
    // the old stub, which never touched the filesystem at all.
    let fixture = fixture_root.join("greeting.txt");
    std::fs::write(&fixture, "hello from a real file").unwrap();

    // `SessionActor::admit_task` runs the real, independent
    // `roundhouse-policy` admission gate — a *different* system from this
    // workflow's own `permissions:` block (that one governs `gate:`/hitl
    // escalation inside `roundhouse-flow`, not tool admission). With no
    // rule granting it, `no_policy_rules()`'s real fail-closed default
    // requires human approval for a `read`, exactly like
    // `submit_turn_e2e.rs`'s own `the_phase_exit_criterion_...` test — so
    // this test loads one project `Allow` rule the identical way, through
    // the production `policy_rules_from_files` loader, after recording the
    // explicit out-of-repository trust a project Allow requires.
    let policy_dir = fixture_root.join(".roundhouse");
    std::fs::create_dir(&policy_dir).unwrap();
    let policy_path = policy_dir.join("policy.toml");
    let policy_text = format!(
        "[[rule]]\nid = 'fixture-read'\noutcome = 'allow'\nread = {:?}\n",
        fixture
    );
    std::fs::write(&policy_path, &policy_text).unwrap();
    let trust_state = tempfile::tempdir().unwrap();
    let rules =
        policy_rules_from_files(Some(fixture_root.clone()), trust_state.path().to_path_buf())
            .unwrap();
    let compiled = compile_policy_layers(vec![roundhouse_config::PolicyLayer {
        scope: roundhouse_config::ConfigScope::Project,
        path: policy_path,
        contents: policy_text.clone(),
        file: roundhouse_config::PolicyFile {
            rule: vec![roundhouse_config::PolicyRule {
                id: "fixture-read".to_string(),
                outcome: roundhouse_config::PolicyRuleOutcome::Allow,
                read: fixture.clone(),
            }],
        },
    }])
    .unwrap();
    record_explicit_trust(
        &fixture_root,
        &policy_text,
        &compiled,
        &TrustStore::new(trust_state.path().to_path_buf()),
    )
    .unwrap();

    let resources = common::resources_with(
        dir.path(),
        common::available_isolate(),
        Arc::new(common::NoopProvider),
        rules,
    )
    .await;
    let sessions = Arc::new(SessionRegistry::new());

    let workspace = resources
        .workspace_registry
        .as_ref()
        .expect("real_resources wires a real WorkspaceRegistry")
        .resolve("default")
        .expect("real_resources registers a \"default\" workspace");

    let source = workspace.root.join("workflow.yaml");
    std::fs::write(&source, reading_workflow()).unwrap();
    let job_id = {
        let conn = resources.store.pool.get().await.unwrap();
        let root = workspace.root.clone();
        conn.interact(move |connection| {
            register_workflow_file(connection, &root, &source, template())
                .unwrap()
                .job
                .id()
        })
        .await
        .unwrap()
    };

    let binding_id = uuid::Uuid::new_v4().to_string();
    seed_enabled_interval_binding(
        &resources.store,
        &binding_id,
        &workspace.id.to_string(),
        &job_id.to_string(),
    )
    .await;

    let services = BackgroundServices {
        scheduler: Some(scheduler_service()),
        ..Default::default()
    };
    let running = services
        .start(resources.store.clone(), sessions, Arc::clone(&resources))
        .await
        .expect("the scheduler driver must signal readiness so daemon boot proceeds");

    // Generous bound: this run suspends mid-flight (`AwaitingWork`) and
    // resumes through a second segment before it can complete, on top of
    // the same real headless-session-construction cost the sibling test
    // budgets 45s for.
    let delivered = tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let conn = resources.store.pool.get().await.unwrap();
            let binding_id = binding_id.clone();
            let found = conn
                .interact(move |connection| {
                    let all = list_deliveries_in_states(
                        connection,
                        &[
                            DeliveryState::Delivered,
                            DeliveryState::Failed,
                            DeliveryState::Running,
                            DeliveryState::Reserved,
                        ],
                    )
                    .expect("querying trigger delivery rows must not fail");
                    all.into_iter()
                        .find(|delivery| delivery.binding_id.to_string() == binding_id)
                })
                .await
                .unwrap();
            if let Some(delivery) = found {
                if delivery.state == DeliveryState::Failed {
                    let run_id_str = delivery.run_id.clone().unwrap();
                    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(&run_id_str).unwrap());
                    let conn2 = resources.store.pool.get().await.unwrap();
                    let steps = conn2
                        .interact(move |c| recover_run(c, run_id).unwrap().steps)
                        .await
                        .unwrap();
                    panic!(
                        "delivery failed: {:?}; steps: {:#?}",
                        delivery.last_error, steps
                    );
                }
                if delivery.state == DeliveryState::Delivered {
                    return delivery;
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect(
        "a scheduled run whose only step is `tool: read` must still reach a Delivered \
         trigger_delivery within the bound — a run stuck AwaitingWork forever would time out \
         here instead",
    );

    let run_id_str = delivered
        .run_id
        .clone()
        .expect("a Delivered delivery must carry the run_id it drove");
    let run_id = RunId::from_uuid(uuid::Uuid::parse_str(&run_id_str).unwrap());
    let (workflow_run, step) = {
        let conn = resources.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            let recovered = recover_run(connection, run_id).unwrap();
            let step = recovered
                .steps
                .into_iter()
                .find(|s| s.step_id == "read_it")
                .expect("the read_it step must have a durable row");
            (recovered.run, step)
        })
        .await
        .unwrap()
    };
    assert_eq!(
        workflow_run.state,
        roundhouse_flow::durability::RunState::Completed,
        "a run whose only step is a real tool: read must reach Completed, not stay stuck or fail"
    );

    // The seam's whole point: this step's row must carry a REAL task
    // identity and log range, not the `None`/`None` the fixed stub always
    // left — `WorkDone::first_task_seq`/`last_task_seq`'s own doc comment
    // calls these "the first real values ... have ever carried".
    assert!(
        step.first_task_seq.is_some() && step.last_task_seq.is_some(),
        "a dispatched-for-real tool: read step must carry a real task_seq range, got {step:?}"
    );
    let output = step
        .output
        .as_ref()
        .expect("a completed tool: read step must have a durable output")
        .value_unredacted_for_resume();
    assert_eq!(
        output.get("content").and_then(|v| v.as_str()),
        Some("hello from a real file"),
        "the step's durable output must be the real file's real content, got {output:?}"
    );

    // And a real `Read`-kind task, admitted and completed, must exist in
    // this run's own session — not folded into a chat turn (this run has
    // none) and not a fixed empty `{}` no executor ever touched.
    let read_task_count: i64 = {
        let session_id = workflow_run.session_id;
        let conn = resources.store.pool.get().await.unwrap();
        conn.interact(move |connection| {
            connection
                .query_row(
                    "SELECT COUNT(*) FROM tasks WHERE session_id = ?1 AND kind = 'Read' AND \
                     state = 'Completed'",
                    rusqlite::params![session_id.to_string()],
                    |row| row.get(0),
                )
                .unwrap()
        })
        .await
        .unwrap()
    };
    assert_eq!(
        read_task_count, 1,
        "the run's session must record exactly one completed Read-kind task"
    );

    running
        .shutdown()
        .await
        .expect("the scheduler driver must observe cancellation and return Ok");
}
