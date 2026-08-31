//! Phase 2, Task 25: the integration test the audit's recurring-pattern
//! warning (§5.1, "built in isolation, never wired") asks for — this drives
//! `PolicyEngine::decide_sealed`, the isolation-shortfall `Degradation`
//! recording, and the network-policy egress proxy through the real call
//! sites every task and every session actually goes through
//! (`SessionActor::admit_task` and the session-creation path that precedes
//! it), not through a unit test that calls any of those mechanisms directly
//! (Tasks 9/10/11/23/24 already cover that).

use std::sync::Arc;

use roundhouse_core::{
    EventPayload, NoteLevel, OnDegrade, Origin, SessionId, SessionSpec, SessionState, Tier,
    TaskKind,
};
use roundhouse_engine::{
    create_session_isolation, create_session_with_egress, AdmitError, SessionActor,
    TaskCreateRequest,
};
use roundhouse_net::policy::EgressPolicy;
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_policy::engine::PolicyEngine;
use roundhouse_policy::{FsOp, TaskParams};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::Isolate;
use roundhouse_store::{open, session_events, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call per-process, and every
/// test in this binary shares one process — one shared `&'static TaskRunner`
/// for all tests here, matching `cancel_admission.rs`/`finally_steps.rs`.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

/// A `BwrapLandlockIsolate` whose probe reports every mechanism `Available`
/// except Seatbelt (n/a off macOS) — achieves `Tier::Sandbox` deterministically,
/// hermetically, with no real bwrap/landlock syscalls made.
fn available_isolate() -> BwrapLandlockIsolate {
    BwrapLandlockIsolate::test_with_probe(MechanismProbeReport {
        landlock: MechanismStatus::Available,
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Available,
        seatbelt: MechanismStatus::Unavailable {
            reason: "n/a".into(),
        },
    })
}

#[tokio::test]
async fn admit_task_denies_a_sealed_write_through_the_real_admission_path() {
    // The integration check the audit's recurring-pattern note asks for:
    // this drives PolicyEngine::decide through SessionActor::admit_task —
    // the exact path a task actually goes through before
    // TaskRunner::execute — not the sealed_rules() predicate called
    // directly in a unit test (which Task 10 already covers).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let policy = Arc::new(PolicyEngine::from_rules(vec![])); // zero config rules — sealed floor is compiled in
    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let actor = SessionActor::new(
        SessionId::new(),
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        false, // unsealed
        std::path::PathBuf::new(),
        std::path::PathBuf::new(),
        isolate,
        handle,
        spec,
    );

    // sealed.rs's own home-dir helper reads $HOME directly (no `dirs` crate
    // dependency, matching `roundhouse-config/src/loader.rs`'s convention) —
    // this test does the same rather than introducing a new dependency.
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .expect("HOME must be set for this test to exercise the real sealed:ssh-write rule");
    let ssh_target = home.join(".ssh/authorized_keys");

    let write_ssh = TaskCreateRequest {
        kind: TaskKind::Write,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Fs {
            op: FsOp::Write,
            path: ssh_target.clone(),
            canonical: Ok(ssh_target),
        },
    };

    let err = actor.admit_task(&write_ssh).unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "the sealed floor must fire from the real admission path, with zero config rules involved"
    );
}

#[tokio::test]
async fn session_creation_records_a_real_degradation_when_the_sandbox_falls_short() {
    // Fixes audit finding 11's "downgrade-recording deferred to unshown
    // session-actor code" — implemented here, for real, using only the
    // frozen Isolate::probe/ProbeResult contract (no downcast from the
    // generic `dyn Isolate` the engine actually holds).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let isolate = BwrapLandlockIsolate::test_with_probe(MechanismProbeReport {
        landlock: MechanismStatus::Degraded {
            reason: "BestEffort: missing TruncateFs".into(),
        },
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Available,
        seatbelt: MechanismStatus::Unavailable {
            reason: "not macOS".into(),
        },
    });
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::AllowDownTo(Tier::Worktree));

    let _handle = create_session_isolation(&writer, &RUNNER, session_id, &isolate, &spec)
        .await
        .unwrap();

    // `writer` above only holds an mpsc::Sender into the writer task; open a
    // fresh, independent connection to the same on-disk DB to verify the
    // Note event actually landed, matching cancel_admission.rs's pattern.
    let store2 = open(&db_path).await.unwrap();
    let events = session_events(&store2, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note {
                level: NoteLevel::Degradation,
                text,
            } if text.contains("isolation shortfall")
        )),
        "a tier shortfall must be recorded on the real session-creation path even when \
         prepare() succeeds at the lower tier"
    );
}

#[tokio::test]
async fn session_creation_registers_egress_with_the_real_loopback_proxy() {
    // Regression for G1's specific complaint: "every task will attest to a
    // network property nothing ever enforces." This drives session creation
    // end to end through `create_session_with_egress` and checks that the
    // returned `ProxyHandle` really is backed by this proxy's own live,
    // `serve()`-bound listener — not a caller-fabricated address — closing
    // the "network-policy proxy built, never wired into session creation"
    // gap for real.
    //
    // Note on `Attestation.net_enforced`: per `isolate.rs::attest()` (fix-
    // round-2), `net_enforced` only flips true once a task has actually been
    // `spawn()`ed under bwrap with a confirmed namespace setup — it is
    // deliberately per-task, re-read on every `attest()` call, not a
    // property session *creation* alone can establish (`create_session_
    // with_egress`/`create_session_isolation` only ever call `prepare()`).
    // Actually spawning a task under bwrap is task-execution wiring, out of
    // this integration task's scope (session *creation*), so this test
    // verifies what session creation actually is responsible for: a real,
    // live proxy registration, not a fabricated placeholder.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let proxy = Arc::new(LoopbackProxy::new());
    let bound_addr = proxy
        .clone()
        .serve(&RUNNER, writer.clone())
        .await
        .expect("serve() must bind a real loopback listener");

    let isolate = available_isolate();
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let session_id = SessionId::new();

    let (handle, proxy_handle) = create_session_with_egress(
        &writer,
        &RUNNER,
        session_id,
        &isolate,
        &spec,
        &proxy,
        EgressPolicy {
            allowed_hosts: vec![],
        },
    )
    .await
    .unwrap();

    assert_eq!(
        proxy_handle.addr(),
        bound_addr,
        "the ProxyHandle session creation hands back must point at this proxy's own \
         serve()-bound listener, not a fabricated address"
    );

    let attestation = isolate.attest(&handle);
    assert_eq!(
        attestation.tier,
        Tier::Sandbox,
        "the isolation handle session creation produced must reflect the achieved tier"
    );
}
