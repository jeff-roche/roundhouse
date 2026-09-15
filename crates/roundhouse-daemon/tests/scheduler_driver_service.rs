//! The scheduler driver as a real background service (Phase 8, L3, Task 5).
//!
//! These drive `scheduler_driver::run` through the production
//! `BackgroundServices::start` path — the same one `main.rs` uses — rather
//! than calling its pieces directly, because the two things worth proving
//! here are properties of the *contract* between the two: that the driver
//! signals readiness exactly once (so `start` returns at all), and that it
//! observes the cancellation watch and returns `Ok(())` (so `shutdown`
//! returns instead of hanging).
//!
//! Neither test waits on the driver's one-second heartbeat: the tick-to-
//! `accept_occurrence` bridge is covered by `scheduler_driver`'s own unit
//! tests, which drive it through a fixed clock. A test that slept and then
//! asserted would be asserting on the host's scheduler, not on this code.

use std::sync::Arc;

use roundhouse_daemon::session_bootstrap::{BackgroundService, BackgroundServices};
use roundhouse_daemon::session_registry::SessionRegistry;

mod common;

/// The `BackgroundService` value `main.rs` installs, spelled the same way.
fn scheduler_service() -> BackgroundService {
    Arc::new(|context| Box::pin(roundhouse_daemon::scheduler_driver::run(context)))
}

async fn seed_interval_binding(store: &roundhouse_store::StorePool, enabled: bool) {
    let conn = store.pool.get().await.unwrap();
    conn.interact(move |connection| {
        connection
            .execute(
                "INSERT INTO trigger_binding
                    (binding_id, workspace_id, job_id, spec_json, overlap_json, enabled, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                rusqlite::params![
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    // An hour apart, so this binding is never due during the
                    // test — the heartbeat's first, immediate tick must find
                    // nothing rather than racing the assertions below.
                    r#"{"Interval":{"every":{"secs":3600,"nanos":0},"align":false,"anchor":null}}"#,
                    r#""Skip""#,
                    enabled as i64,
                ],
            )
            .unwrap();
    })
    .await
    .unwrap();
}

/// `start` returning at all is the readiness proof: it waits on the
/// service's `ready` channel and fails boot if the service returns, errors,
/// or drops the sender before signalling. `shutdown` returning `Ok(())` is
/// the orderly-cancellation proof: it sets the cancel watch and then *joins*
/// the driver's task, so a driver that ignored cancellation would hang here
/// rather than fail.
#[tokio::test]
async fn the_scheduler_driver_signals_readiness_and_shuts_down_on_cancellation() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;
    seed_interval_binding(&resources.store, true).await;
    seed_interval_binding(&resources.store, false).await;

    let services = BackgroundServices {
        workflow: None,
        scheduler: Some(scheduler_service()),
        acp: None,
    };

    let running = services
        .start(
            resources.store.clone(),
            Arc::new(SessionRegistry::new()),
            Arc::clone(&resources),
        )
        .await
        .expect("the scheduler driver must signal readiness so daemon boot proceeds");

    running
        .shutdown()
        .await
        .expect("the scheduler driver must observe cancellation and return Ok");
}

/// A daemon with no persisted bindings at all must still boot: the driver's
/// load succeeds with an empty result and it signals readiness anyway. This
/// is the configuration every existing deployment is in today, so a driver
/// that treated "no bindings" as a failure would break every boot.
#[tokio::test]
async fn the_scheduler_driver_boots_with_no_bindings_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;

    let running = BackgroundServices {
        workflow: None,
        scheduler: Some(scheduler_service()),
        acp: None,
    }
    .start(
        resources.store.clone(),
        Arc::new(SessionRegistry::new()),
        Arc::clone(&resources),
    )
    .await
    .expect("an empty trigger_binding table must not fail daemon boot");

    running.shutdown().await.unwrap();
}

/// Change 1 of this task: `DaemonResources` reaches a service through the
/// context, as a `start` parameter. It cannot arrive any other way —
/// `DaemonResources` owns the `BackgroundServices` value holding these
/// closures, so no closure can capture an `Arc` of it. A *test* can build
/// resources first and capture them for comparison, which is exactly what
/// makes the identity assertion below possible.
#[tokio::test]
async fn a_service_receives_the_daemons_own_resources_through_its_context() {
    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;

    let expected = Arc::clone(&resources);
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let seen_tx = Arc::new(std::sync::Mutex::new(Some(seen_tx)));
    let probe: BackgroundService = Arc::new(move |mut context| {
        let expected = Arc::clone(&expected);
        let seen_tx = Arc::clone(&seen_tx);
        Box::pin(async move {
            let same = Arc::ptr_eq(&context.resources, &expected);
            context.signal_ready().await?;
            if let Some(tx) = seen_tx.lock().unwrap().take() {
                let _ = tx.send(same);
            }
            while !*context.cancelled.borrow() {
                if context.cancelled.changed().await.is_err() {
                    break;
                }
            }
            Ok(())
        })
    });

    let running = BackgroundServices {
        workflow: Some(probe),
        scheduler: None,
        acp: None,
    }
    .start(
        resources.store.clone(),
        Arc::new(SessionRegistry::new()),
        Arc::clone(&resources),
    )
    .await
    .unwrap();

    assert!(
        seen_rx.await.unwrap(),
        "a service must receive the daemon's own DaemonResources, not a separate value"
    );
    running.shutdown().await.unwrap();
}
