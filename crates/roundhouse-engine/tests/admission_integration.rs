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
    EventPayload, NoteLevel, OnDegrade, Origin, SessionId, SessionSpec, SessionState, TaskKind,
    Tier,
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
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
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

    let err = actor.admit_task(&write_ssh).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "the sealed floor must fire from the real admission path, with zero config rules involved"
    );
}

#[tokio::test]
async fn admit_task_denies_writes_under_the_real_state_dir_and_daemon_binary() {
    // Security-review fix-round-1: `sealed_state_dir_write`/
    // `sealed_daemon_binary_write` both silently no-op when `SealedContext`'s
    // `state_dir`/`daemon_binary` are empty — a guard meant only for
    // `sealed::default_context`'s unit-test placeholder. `SessionActor::new`
    // now fail-closed asserts both are real, absolute, non-empty paths; this
    // test proves the two rules those paths exist to drive actually fire
    // through the real `admit_task` path, with real non-empty paths, not
    // `PathBuf::new()` — closing the exact regression security review
    // reproduced (an empty-context write to the daemon's own state dir was
    // silently `Ok(())` instead of `Denied(sealed:state-dir-write)`).
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let state_dir = dir.path().join("state");
    let daemon_binary = dir.path().join("bin/round-daemon-internal");

    let policy = Arc::new(PolicyEngine::from_rules(vec![]));
    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let actor = SessionActor::new(
        SessionId::new(),
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        state_dir.clone(),
        daemon_binary.clone(),
        isolate,
        handle,
        spec,
    );

    let write_state_dir = TaskCreateRequest {
        kind: TaskKind::Write,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Fs {
            op: FsOp::Write,
            path: state_dir.join("events.db"),
            canonical: Ok(state_dir.join("events.db")),
        },
    };
    let err = actor.admit_task(&write_state_dir).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "a write under the session's real state_dir must be denied by sealed:state-dir-write \
         through the real admission path — got {err:?}"
    );

    let write_daemon_binary = TaskCreateRequest {
        kind: TaskKind::Write,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Fs {
            op: FsOp::Write,
            path: daemon_binary.clone(),
            canonical: Ok(daemon_binary.clone()),
        },
    };
    let err = actor.admit_task(&write_daemon_binary).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "a write to the session's real daemon_binary must be denied by \
         sealed:daemon-binary-write through the real admission path — got {err:?}"
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

#[tokio::test]
async fn a_legitimately_downgraded_session_does_not_deny_every_subsequent_task() {
    // Security-review fix-round-1: `sealed_context()` used to compare the
    // live attestation against `session_spec.requested_tier` directly — the
    // ORIGINAL ask, which never changes even after a human explicitly
    // accepted a downgrade via `OnDegrade::AllowDownTo`. That made
    // `sealed_tier_shortfall` fire on every single task for the rest of a
    // legitimately-downgraded session's life, making `on_degrade`
    // functionally meaningless. `sealed_context()` now compares against
    // `SessionActor::effective_tier` (the tier the handle actually settled
    // at, captured once at construction) instead — this test proves an
    // ordinary, otherwise-allowed task is admitted on such a session.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    // Achieves only Worktree tier (bwrap available, landlock degraded,
    // seatbelt unavailable) — a real, human-accepted downgrade from the
    // Sandbox tier this session asks for.
    let isolate: Arc<dyn Isolate> = Arc::new(BwrapLandlockIsolate::test_with_probe(
        MechanismProbeReport {
            landlock: MechanismStatus::Degraded {
                reason: "BestEffort: missing TruncateFs".into(),
            },
            bwrap: MechanismStatus::Available,
            seccomp: MechanismStatus::Available,
            seatbelt: MechanismStatus::Unavailable {
                reason: "not macOS".into(),
            },
        },
    ));
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::AllowDownTo(Tier::Worktree));
    let handle = isolate.prepare(&spec).await.unwrap();
    assert_eq!(
        isolate.attest(&handle).tier,
        Tier::Worktree,
        "test setup bug: this isolate/spec combination must actually downgrade to Worktree"
    );

    let policy = Arc::new(roundhouse_policy::engine::PolicyEngine::from_rules(vec![
        roundhouse_policy::engine::CompiledRule::test_new(
            roundhouse_policy::engine::Scope::Builtin,
            roundhouse_policy::engine::Outcome::Allow,
            roundhouse_policy::engine::Predicate::program("true"),
        ),
    ]));

    let actor = SessionActor::new(
        SessionId::new(),
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        isolate,
        handle,
        spec,
    );

    let ordinary = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Shell(roundhouse_policy::ParsedCommand {
            program: "true".to_string(),
            argv: vec![],
        }),
    };

    // Ask twice: the fix must hold for more than just the first task on
    // this session — a stale one-time comparison would only happen to pass
    // once by accident.
    actor
        .admit_task(&ordinary)
        .await
        .expect("an otherwise-allowed task on a legitimately-downgraded session must be admitted");
    actor
        .admit_task(&ordinary)
        .await
        .expect("the fix must hold for every subsequent task, not just the first one");
}

#[tokio::test]
async fn admitting_a_task_with_the_sealed_floor_disabled_records_a_real_never_silent_note() {
    // Security-review fix-round-1: `sealed.rs`/`engine.rs` both already
    // carried a pre-existing doc-comment contract that `--unsealed` "must
    // be recorded per-task ... never silent" once Tasks 17/25 landed. Task
    // 25 landed and recorded nothing until this fix. `SessionActor` no
    // longer holds its own independent `unsealed` bool — `admit_task` reads
    // `self.policy.unsealed()`, the single source of truth — and records a
    // `Note` for every task admitted while that flag is set.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let policy = Arc::new(PolicyEngine::from_rules(vec![]).with_unsealed(true));
    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let actor = SessionActor::new(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        isolate,
        handle,
        spec,
    );

    let task = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Shell(roundhouse_policy::ParsedCommand {
            program: "whatever".to_string(),
            argv: vec![],
        }),
    };
    let _ = actor.admit_task(&task).await; // outcome doesn't matter — the Note must be recorded regardless

    let store2 = open(&db_path).await.unwrap();
    let events = session_events(&store2, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Warn, text }
                if text.contains("sealed floor") && text.contains("--unsealed")
        )),
        "admitting a task with the sealed floor disabled must durably record a Note — \
         never silent, per sealed.rs/engine.rs's own pre-existing doc contract"
    );
}

#[tokio::test]
async fn a_dead_or_unrecognized_handle_fails_closed_instead_of_permanently_disabling_the_tier_shortfall_rule(
) {
    // Security-review fix-round-2 regression test. Fix-round-1's original
    // `effective_tier = isolate.attest(&handle).tier` collapsed to
    // `Tier::None` for any handle `BwrapLandlockIsolate::attest` doesn't
    // recognize (a dead handle, a handle from a different `Isolate`
    // instance, or — the realistic future case — a session rehydrated
    // after a daemon restart, since the handle map is purely in-memory).
    // That made BOTH sides of `sealed_tier_shortfall`'s comparison collapse
    // to `Tier::None` (`attested_tier == requested_tier == None`),
    // PERMANENTLY disabling the rule instead of denying — a real fail-open,
    // in the opposite direction from the original nullity finding 6
    // reported. `effective_tier` is now derived from `on_degrade` alone,
    // never from a live `attest()` read, so a genuinely-unknown handle's
    // real `Tier::None` attestation now correctly fails CLOSED instead.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    // Deliberately never `prepare()`d on this isolate instance — an id its
    // internal handle map has never seen, so `attest()` takes its
    // `Tier::None` "no live handle" branch.
    let dead_handle = roundhouse_sandbox::Handle {
        id: "dead-handle-never-prepared".to_string(),
    };
    assert_eq!(
        isolate.attest(&dead_handle).tier,
        Tier::None,
        "test setup bug: this handle must be genuinely unrecognized by the isolate"
    );

    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::AllowDownTo(Tier::Worktree));
    let policy = Arc::new(PolicyEngine::from_rules(vec![
        roundhouse_policy::engine::CompiledRule::test_new(
            roundhouse_policy::engine::Scope::Builtin,
            roundhouse_policy::engine::Outcome::Allow,
            roundhouse_policy::engine::Predicate::program("true"),
        ),
    ]));

    let actor = SessionActor::new(
        SessionId::new(),
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        isolate,
        dead_handle,
        spec,
    );

    let task = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Shell(roundhouse_policy::ParsedCommand {
            program: "true".to_string(),
            argv: vec![],
        }),
    };

    let err = actor.admit_task(&task).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "a dead/unrecognized handle's genuinely-unknown live attestation must fail admission \
         closed via sealed:tier-shortfall, not silently allow everything forever — got {err:?}"
    );
}

#[tokio::test]
async fn unsealed_audit_note_accurately_reflects_a_denied_outcome_not_admitted() {
    // Security-review fix-round-2 regression test: reproduced with
    // fix-round-1's code, `unsealed=true` + a config rule that ends up
    // denying the task still persisted a note reading "task admitted with
    // the sealed floor DISABLED" — actively misleading, worse than no note
    // at all. The note is now recorded AFTER the decision, describing the
    // real outcome.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let policy = Arc::new(
        PolicyEngine::from_rules(vec![roundhouse_policy::engine::CompiledRule::test_new(
            roundhouse_policy::engine::Scope::Builtin,
            roundhouse_policy::engine::Outcome::Deny,
            roundhouse_policy::engine::Predicate::program("rm"),
        )])
        .with_unsealed(true),
    );
    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();

    let actor = SessionActor::new(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        policy,
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        isolate,
        handle,
        spec,
    );

    let task = TaskCreateRequest {
        kind: TaskKind::Shell,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Shell(roundhouse_policy::ParsedCommand {
            program: "rm".to_string(),
            argv: vec![],
        }),
    };
    let err = actor.admit_task(&task).await.unwrap_err();
    assert!(
        matches!(err, AdmitError::Denied(_)),
        "test setup bug: this task must actually be denied by the config rule — got {err:?}"
    );

    let store2 = open(&db_path).await.unwrap();
    let events = session_events(&store2, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Warn, text }
                if text.contains("outcome=Deny")
        )),
        "the unsealed-admission audit note for a DENIED task must say so, not claim the task \
         was admitted"
    );
    assert!(
        !events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Warn, text }
                if text.contains("admitted")
        )),
        "no unsealed-admission note may claim this denied task was 'admitted'"
    );
}
