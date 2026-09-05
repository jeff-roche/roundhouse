//! Fix round 3, SHOULD 2: proves `construct_real_session_bounded`'s
//! `construction_slots` semaphore actually bounds concurrent in-flight
//! constructions, daemon-wide, across DIFFERENT peers — distinct from
//! `FailedConstructionLimiter` (per-peer, over a time window) and
//! `SessionRegistry::is_full` (bounds already-registered sessions, not
//! in-flight construction work). Without this cap, nothing bounds how many
//! real `Isolate::prepare` calls (or, when MCP servers are configured, real
//! spawned subprocesses) can be simultaneously in flight, including ones
//! whose own caller already gave up on the timeout.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use roundhouse_core::SessionSpec;
use roundhouse_daemon::socket_server::{drive_session, FailedConstructionLimiter};
use roundhouse_proto::{ClientEvent, ClientRequest};
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
};

/// An `Isolate` whose `prepare` sleeps for `delay` before failing — long
/// enough to reliably hold a `construction_slots` permit while a second,
/// concurrent attempt is made against the same (size-1) semaphore.
struct SlowThenFailsPrepare {
    delay: Duration,
    prepare_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Isolate for SlowThenFailsPrepare {
    fn declared(&self) -> roundhouse_core::Tier {
        roundhouse_core::Tier::Sandbox
    }
    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: roundhouse_core::Tier::None,
            degradations: vec!["SlowThenFailsPrepare never achieves anything".into()],
        }
    }
    async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Err(IsolationError::DegradedBelowRequested)
    }
    async fn spawn(&self, _h: &Handle, _cmd: CommandSpec) -> Result<Child, IsolationError> {
        unreachable!("prepare always fails; spawn is never reached")
    }
    fn attest(&self, _h: &Handle) -> Attestation {
        unreachable!("prepare always fails; attest is never reached")
    }
    async fn teardown(&self, _h: Handle) -> Result<(), IsolationError> {
        unreachable!("prepare always fails; teardown is never reached")
    }
}

async fn drive_one_create_session(
    registry: Arc<roundhouse_daemon::session_registry::SessionRegistry>,
    resources: Arc<roundhouse_daemon::session_bootstrap::DaemonResources>,
    peer_uid: u32,
    limiter: Arc<FailedConstructionLimiter>,
    construction_slots: Arc<tokio::sync::Semaphore>,
) {
    let (requests_tx, requests_rx) = tokio::sync::mpsc::channel::<ClientRequest>(1);
    let (events_tx, mut events_rx) = tokio::sync::mpsc::channel::<ClientEvent>(1);
    requests_tx
        .send(ClientRequest::CreateSession {
            workspace_name: "test".into(),
        })
        .await
        .unwrap();
    drop(requests_tx);
    drive_session(
        requests_rx,
        events_tx,
        registry,
        resources,
        Duration::from_secs(5),
        peer_uid,
        limiter,
        construction_slots,
    )
    .await;
    while events_rx.recv().await.is_some() {}
}

#[tokio::test]
async fn a_second_peer_is_refused_at_capacity_while_the_first_constructions_prepare_is_still_in_flight(
) {
    let dir = tempfile::tempdir().unwrap();
    let isolate = Arc::new(SlowThenFailsPrepare {
        delay: Duration::from_millis(300),
        prepare_calls: AtomicUsize::new(0),
    });
    let resources = common::resources_with_isolate(dir.path(), isolate.clone()).await;
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    // Exactly one slot: the first attempt holds it for the whole 300ms
    // `prepare` sleep; a second, concurrent attempt (different peer, so
    // `FailedConstructionLimiter` — a per-peer mechanism — cannot be what
    // refuses it) must be refused by capacity alone.
    let construction_slots = Arc::new(tokio::sync::Semaphore::new(1));

    let first = tokio::spawn(drive_one_create_session(
        registry.clone(),
        resources.clone(),
        /* peer_uid */ 1,
        Arc::new(FailedConstructionLimiter::default()),
        construction_slots.clone(),
    ));
    // Give the first attempt time to actually acquire the sole permit and
    // enter its (slow) `prepare` call before the second one starts.
    tokio::time::sleep(Duration::from_millis(50)).await;

    drive_one_create_session(
        registry.clone(),
        resources.clone(),
        /* peer_uid */ 2,
        Arc::new(FailedConstructionLimiter::default()),
        construction_slots.clone(),
    )
    .await;

    // The second attempt must have been refused at capacity — its own
    // `prepare` never ran — while the first is presumably still in flight
    // (or just finishing) its 300ms sleep.
    let calls_right_after_second = isolate.prepare_calls.load(Ordering::SeqCst);
    assert_eq!(
        calls_right_after_second, 1,
        "the second, concurrent attempt must be refused at capacity before ever calling \
         Isolate::prepare — expected exactly 1 real prepare() call (the first attempt's), \
         got {calls_right_after_second}"
    );

    first.await.unwrap();
    // Sanity: the first attempt's prepare() really did run — proving the
    // permit was genuinely held by real, in-flight work, not just an
    // artifact of the semaphore never being exercised at all.
    assert_eq!(isolate.prepare_calls.load(Ordering::SeqCst), 1);
}
