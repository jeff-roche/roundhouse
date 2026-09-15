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
use roundhouse_daemon::session_bootstrap::BackgroundServices;
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_flow::durability::recover_run;
use roundhouse_flow::exec::RunId;
use roundhouse_flow::job::SessionTemplate;
use roundhouse_flow::job_store::register_workflow_file;
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
