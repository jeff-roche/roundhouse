//! Fix round 2, MUST 2 (remainder): proves
//! `socket_server::FailedConstructionLimiter` is actually wired into
//! `drive_session`'s `CreateSession` branch, not just correct in isolation.
//!
//! Without this, `SessionRegistry::is_full`'s pre-check (the only
//! pre-`construct_real_session_bounded` gate that existed before this fix)
//! does nothing to bound a peer that loops `CreateSession` against a host
//! where construction always fails — every attempt still runs a real
//! `Isolate::prepare`/`probe` and appends a `Degradation` note to the
//! append-only `events` table before failing. This drives more
//! `CreateSession` attempts than the limiter's default budget through a
//! single simulated peer (one `drive_session`/`FailedConstructionLimiter`
//! pair, matching how one accepted connection is handled in production) and
//! counts real `Isolate::prepare` calls directly, so a regression that
//! drops the `failed_construction_limiter.allow(..)` check would make this
//! test's own assertion fail (more `prepare` calls than the budget allows),
//! not merely "look plausible."

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

/// An `Isolate` whose `prepare` always fails — cheaply, with no real
/// syscall — while counting every call, so this test can assert exactly how
/// many times construction actually ran a real `prepare()` rather than
/// having been refused up front by the limiter.
struct AlwaysFailsPrepare {
    prepare_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Isolate for AlwaysFailsPrepare {
    fn declared(&self) -> roundhouse_core::Tier {
        roundhouse_core::Tier::Sandbox
    }
    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: roundhouse_core::Tier::None,
            degradations: vec!["AlwaysFailsPrepare never achieves anything".into()],
        }
    }
    async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
        self.prepare_calls.fetch_add(1, Ordering::SeqCst);
        Err(IsolationError::DegradedBelowRequested)
    }
    async fn spawn(&self, _h: &Handle, _cmd: CommandSpec) -> Result<Child, IsolationError> {
        unreachable!("prepare always fails first; spawn is never reached")
    }
    fn attest(&self, _h: &Handle) -> Attestation {
        unreachable!("prepare always fails first; attest is never reached")
    }
    async fn teardown(&self, _h: Handle) -> Result<(), IsolationError> {
        unreachable!("prepare always fails first; teardown is never reached")
    }
}

#[tokio::test]
async fn a_peer_looping_create_session_against_a_failing_host_is_cut_off() {
    let dir = tempfile::tempdir().unwrap();
    let isolate = Arc::new(AlwaysFailsPrepare {
        prepare_calls: AtomicUsize::new(0),
    });
    let resources = common::resources_with_isolate(dir.path(), isolate.clone()).await;
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());

    let peer_uid = 4242;
    let limiter = Arc::new(FailedConstructionLimiter::default());
    let construction_slots = Arc::new(tokio::sync::Semaphore::new(64));

    // `FailedConstructionLimiter::default()` allows 5 failures per 10s
    // window (see its own doc comment) — drive one more attempt than that
    // through a fresh `drive_session` call each time, exactly mirroring one
    // real accepted connection per `CreateSession` attempt (a single
    // connection only ever gets one handshake request honored as
    // `CreateSession` — see `drive_session`'s own doc comment).
    let attempts = 8;
    for _ in 0..attempts {
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
            registry.clone(),
            resources.clone(),
            Duration::from_secs(5),
            peer_uid,
            limiter.clone(),
            construction_slots.clone(),
        )
        .await;
        // Every attempt here fails one way or another (real prepare()
        // failure, or the limiter's own refusal) — `drive_session` never
        // sends a reply on either path, so this channel stays empty either
        // way; draining it just avoids an unread-channel warning/leak.
        while events_rx.recv().await.is_some() {}
    }

    let prepare_calls = isolate.prepare_calls.load(Ordering::SeqCst);
    assert!(
        prepare_calls < attempts,
        "the failed-construction limiter must cut this peer off before every one of \
         {attempts} attempts reaches a real Isolate::prepare() call; got {prepare_calls} \
         real prepare() calls"
    );
    assert_eq!(
        prepare_calls, 5,
        "expected exactly the limiter's default budget (5) of real prepare() calls before \
         the 6th+ attempts are refused up front; got {prepare_calls}"
    );
}
