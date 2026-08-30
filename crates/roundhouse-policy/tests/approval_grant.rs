//! Tests for Task 15: real, persisted `Suspended{AwaitingApproval}` via
//! `approval::suspend_for_approval`, and `synthesize_grant` made total over
//! every `TaskParams` kind (audit finding 5 — it previously panicked with
//! `unimplemented!()` for every kind except `Fs`, including `Shell`, the
//! dominant approval path).
//!
//! Follows the real `StorePool`/`EventWriter`/`TaskRunner` triad pattern
//! used throughout `roundhouse-store`'s and `roundhouse-daemon`'s test
//! suites (see `crates/roundhouse-store/tests/suspended.rs`), not the
//! fictional single `Store` handle the plan's original brief sketched —
//! see `.superpowers/sdd/2026-08-27-phase2-robustness/task-15-addendum.md`
//! Ruling 1.

use roundhouse_core::{
    Origin, SessionId, SuspendReason, TaskId, TaskInput, TaskKind, TaskRunner, Tier, Timestamp,
};
use roundhouse_policy::approval::{
    suspend_for_approval, synthesize_grant, GrantProvenance, GrantScope,
};
use roundhouse_policy::engine::{ArgMatcher, Predicate};
use roundhouse_policy::registry::ApprovalRegistry;
use roundhouse_policy::{FsOp, Method, ParsedCommand, ProviderId, ServerId, TaskParams};
use roundhouse_store::{open, spawn_writer, suspended_tasks};
use std::path::PathBuf;

/// `TaskRunner::bootstrap()` panics on a second call per process (S-LOG-1) —
/// this file has multiple `#[tokio::test]` functions, so a shared
/// `once_cell::sync::Lazy` static is required, same pattern as
/// `roundhouse-store/tests/suspended.rs`.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// "Suspended" must be a real persisted event, not an in-memory-only future
/// (§1.1 bug #2) — a fresh `suspended_tasks` read against a freshly reopened
/// pool (simulating what a restarted daemon would see) must show the same
/// thing. Ruling 4: there is no `TaskStatus`/`store.fold_task(...).status`
/// in this codebase, so this asserts via the real `suspended_tasks` API —
/// literally the same function boot-time re-arm calls.
#[tokio::test]
async fn ask_decision_persists_as_suspended_awaiting_approval_and_survives_a_fresh_read() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let registry = ApprovalRegistry::new();

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/x"),
        canonical: Ok(PathBuf::from("/workspace/x")),
    };

    // A task must already exist (a real `TaskCreated` event) before it can be
    // suspended — `suspend_for_approval` only mints the `TaskSuspended`
    // transition, same as every other `record_task_*` call in this codebase
    // (see e.g. `roundhouse-store/tests/suspended.rs`).
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Write,
            None,
            Origin::Model,
            TaskInput::Text("write /workspace/x".into()),
            1,
        ))
        .await
        .unwrap();

    suspend_for_approval(
        &writer, &RUNNER, &registry, session_id, task_id, None, &params,
    )
    .await
    .unwrap();

    // ...it must also be live-queryable through the registry immediately,
    // not only after the next daemon restart (that path is boot.rs's job).
    let pending = registry.list();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].task_id, task_id);

    // Fresh pool over the same file — simulates the restart-survival check
    // a real daemon boot performs.
    let query_store = open(&db_path).await.unwrap();
    let suspended = suspended_tasks(&query_store).await.unwrap();
    assert_eq!(suspended.len(), 1);
    assert_eq!(suspended[0].task_id, task_id);
    assert_eq!(suspended[0].session_id, session_id);
    assert!(
        matches!(suspended[0].reason, SuspendReason::AwaitingApproval { .. }),
        "expected AwaitingApproval, got {:?}",
        suspended[0].reason
    );
}

#[test]
fn grant_is_generalised_downward_never_broader_than_the_originating_task() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/exact-file.txt"),
        canonical: Ok(PathBuf::from("/workspace/exact-file.txt")),
    };
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/workspace"),
        },
        provenance,
    );

    // Directory scope must not broaden to the filesystem root or beyond
    // /workspace — the synthesized rule's predicate must still be anchored
    // under the granted directory.
    assert!(grant.rule_covers_path(&PathBuf::from("/workspace/exact-file.txt")));
    assert!(!grant.rule_covers_path(&PathBuf::from("/etc/passwd")));
}

#[test]
fn shell_grant_generalizes_to_the_matched_argv_never_a_wildcard() {
    // Regression for audit finding 5: this used to hit unimplemented!() —
    // Shell is the dominant approval path, so this was the single
    // most-exercised panic in the plan.
    let params = TaskParams::Shell(ParsedCommand {
        program: "cargo".into(),
        argv: vec!["test".into(), "--lib".into()],
    });
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };
    let grant = synthesize_grant(&params, GrantScope::Session, provenance);
    match grant.rule.predicate {
        Predicate::Shell {
            program,
            matcher: ArgMatcher::Exact(argv),
            ..
        } => {
            assert_eq!(program, "cargo");
            assert_eq!(argv, vec!["test".to_string(), "--lib".to_string()]);
        }
        other => panic!(
            "Shell grant must synthesize a Shell predicate bound to the exact observed argv, \
             never a wildcard; got {other:?}"
        ),
    }
}

#[test]
fn http_mcp_git_agent_grants_all_synthesize_without_panicking() {
    let provenance = || GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };

    let http = synthesize_grant(
        &TaskParams::Http {
            method: Method::Get,
            url: "https://crates.io/x".into(),
            body_len: 0,
        },
        GrantScope::Once,
        provenance(),
    );
    assert!(matches!(http.rule.predicate, Predicate::Http { .. }));

    let mcp = synthesize_grant(
        &TaskParams::Mcp {
            server: ServerId("fs".into()),
            tool: "read_file".into(),
            args: serde_json::json!({}),
        },
        GrantScope::Once,
        provenance(),
    );
    assert!(matches!(mcp.rule.predicate, Predicate::Mcp { .. }));

    let git = synthesize_grant(
        &TaskParams::Git {
            subcommand: "status".into(),
            argv: vec![],
            remote: None,
        },
        GrantScope::Once,
        provenance(),
    );
    assert!(matches!(git.rule.predicate, Predicate::Git { .. }));

    let agent = synthesize_grant(
        &TaskParams::Agent {
            provider: ProviderId("anthropic".into()),
            model: "claude".into(),
            tier_request: Tier::Sandbox,
        },
        GrantScope::Once,
        provenance(),
    );
    assert!(matches!(agent.rule.predicate, Predicate::Agent { .. }));
}
