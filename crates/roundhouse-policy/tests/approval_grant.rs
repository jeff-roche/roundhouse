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
use roundhouse_policy::engine::{ArgMatcher, Outcome, Predicate};
use roundhouse_policy::registry::ApprovalRegistry;
use roundhouse_policy::{
    FsOp, Method, ParsedCommand, PolicyEngine, ProviderId, ServerId, TaskParams,
};
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
    assert!(grant.rule_covers_path(FsOp::Write, &PathBuf::from("/workspace/exact-file.txt")));
    assert!(!grant.rule_covers_path(FsOp::Write, &PathBuf::from("/etc/passwd")));

    // Security fix round 1, finding 4: rule_covers_path must also gate on op
    // — a Write-scoped grant must not report covering a Read of the same path.
    assert!(!grant.rule_covers_path(FsOp::Read, &PathBuf::from("/workspace/exact-file.txt")));
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

// ---------------------------------------------------------------------
// Security fix round 1 regressions — adversarial reproduction style,
// mirroring the security auditor's harness: synthesize a grant for one
// exact human-approved action, install its rule into a real PolicyEngine,
// then feed adjacent-but-different params through PolicyEngine::decide and
// assert they are NOT silently Allow.
// ---------------------------------------------------------------------

/// Finding 1: a human approving `https://api.example.com/v1/status` exactly
/// once must not also grant a query-string-appended or path-traversal
/// variant of that same URL. Before the fix, `Predicate::Http` matched via
/// `starts_with`, so all three adversarial variants below were wrongly
/// `Allow`.
#[test]
fn http_grant_never_widens_past_the_exact_approved_url() {
    let approved_url = "https://api.example.com/v1/status";
    let params = TaskParams::Http {
        method: Method::Get,
        url: approved_url.into(),
        body_len: 0,
    };
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };
    let grant = synthesize_grant(&params, GrantScope::Once, provenance);
    let engine = PolicyEngine::from_rules(vec![grant.rule.clone()]);

    // The exact approved call is still Allow.
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);

    // Adversarial widenings must NOT be Allow.
    for adversarial_url in [
        "https://api.example.com/v1/status/../../admin/keys",
        "https://api.example.com/v1/status?exfil=/etc/passwd",
        "https://api.example.com/v1/statusSECRET",
    ] {
        let adversarial = TaskParams::Http {
            method: Method::Get,
            url: adversarial_url.into(),
            body_len: 0,
        };
        assert_ne!(
            engine.decide(&adversarial).outcome,
            Outcome::Allow,
            "approving {approved_url:?} must not also grant {adversarial_url:?}"
        );
    }

    // An unrelated sibling path is correctly not granted either.
    let unrelated = TaskParams::Http {
        method: Method::Get,
        url: "https://api.example.com/v1/other".into(),
        body_len: 0,
    };
    assert_ne!(engine.decide(&unrelated).outcome, Outcome::Allow);
}

/// Finding 2: a human approving `git push origin main` exactly once must
/// not also grant the same invocation with extra appended args (e.g.
/// `--force`, or a force-push refspec). Before the fix, `Predicate::Git`
/// matched via `argv.starts_with(argv_prefix)`, so appended-args variants
/// were wrongly `Allow`.
#[test]
fn git_grant_never_widens_past_the_exact_approved_argv() {
    let params = TaskParams::Git {
        subcommand: "push".into(),
        argv: vec!["origin".into(), "main".into()],
        remote: Some("origin".into()),
    };
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };
    let grant = synthesize_grant(&params, GrantScope::Once, provenance);
    let engine = PolicyEngine::from_rules(vec![grant.rule.clone()]);

    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);

    let force_push = TaskParams::Git {
        subcommand: "push".into(),
        argv: vec!["origin".into(), "main".into(), "--force".into()],
        remote: Some("origin".into()),
    };
    assert_ne!(
        engine.decide(&force_push).outcome,
        Outcome::Allow,
        "approving `git push origin main` must not also grant `--force` appended"
    );

    let force_refspec = TaskParams::Git {
        subcommand: "push".into(),
        argv: vec![
            "origin".into(),
            "main".into(),
            "+refs/heads/x:refs/heads/prod".into(),
        ],
        remote: Some("origin".into()),
    };
    assert_ne!(engine.decide(&force_refspec).outcome, Outcome::Allow);
}

/// Finding 2's degenerate case: the task's own test previously synthesized
/// `argv_prefix: vec![]` for a bare `git status` (empty argv), which under
/// `starts_with` matched literally any invocation of `git status` with any
/// args at all. With `exact: true`, a `git status` grant with empty argv
/// must only match `git status` with no args.
#[test]
fn git_grant_for_bare_subcommand_does_not_degenerate_to_matching_any_argv() {
    let params = TaskParams::Git {
        subcommand: "status".into(),
        argv: vec![],
        remote: None,
    };
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };
    let grant = synthesize_grant(&params, GrantScope::Once, provenance);
    let engine = PolicyEngine::from_rules(vec![grant.rule.clone()]);

    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);

    let with_args = TaskParams::Git {
        subcommand: "status".into(),
        argv: vec!["--porcelain".into()],
        remote: None,
    };
    assert_ne!(
        engine.decide(&with_args).outcome,
        Outcome::Allow,
        "an empty-argv git status grant must not match git status with any args appended"
    );
}

/// Finding 3: a `GrantScope::Directory` whose `path` is not an ancestor of
/// the originating task's own canonical path (e.g. root-directory scope
/// requested for a task that only touched one file under `/workspace`) must
/// not produce a filesystem-wide grant. Before the fix, `path` was trusted
/// verbatim with no ancestor check.
#[test]
fn directory_grant_with_unrelated_or_root_path_does_not_widen_to_filesystem_wide() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/notes.txt"),
        canonical: Ok(PathBuf::from("/workspace/notes.txt")),
    };
    let provenance = GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };

    // A caller (bug, or compromised/buggy UI layer) requests a root-directory
    // scope for a task that only ever touched one file under /workspace.
    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/"),
        },
        provenance,
    );
    let engine = PolicyEngine::from_rules(vec![grant.rule.clone()]);

    // The originating task's own write is still Allow (never broader than
    // what was actually approved means never *narrower* than the task
    // itself, either).
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);

    // But nothing outside /workspace is granted, despite the root-directory
    // scope request — this is the actual security property under test.
    for unrelated_path in ["/etc/shadow", "/root/.ssh/authorized_keys", "/etc/passwd"] {
        let unrelated = TaskParams::Fs {
            op: FsOp::Write,
            path: PathBuf::from(unrelated_path),
            canonical: Ok(PathBuf::from(unrelated_path)),
        };
        assert_ne!(
            engine.decide(&unrelated).outcome,
            Outcome::Allow,
            "a mismatched Directory{{path: \"/\"}} grant scope must not produce a \
             filesystem-wide Allow for {unrelated_path}"
        );
    }

    // A sibling file under /workspace that was NOT the requested directory
    // ancestor either (the mismatch means it downgrades to FsExact on the
    // task's own path, not FsPrefix on /workspace) is also not covered.
    let sibling = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/other.txt"),
        canonical: Ok(PathBuf::from("/workspace/other.txt")),
    };
    assert_ne!(engine.decide(&sibling).outcome, Outcome::Allow);
}

/// Finding 3, positive case: a `GrantScope::Directory` whose `path` IS a
/// real ancestor of the task's canonical path still produces the intended
/// prefix grant (this is not a regression of legitimate directory grants).
#[test]
fn directory_grant_with_a_real_ancestor_path_still_covers_the_directory() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/sub/notes.txt"),
        canonical: Ok(PathBuf::from("/workspace/sub/notes.txt")),
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
    let engine = PolicyEngine::from_rules(vec![grant.rule.clone()]);

    let sibling = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/other.txt"),
        canonical: Ok(PathBuf::from("/workspace/other.txt")),
    };
    assert_eq!(engine.decide(&sibling).outcome, Outcome::Allow);

    let outside = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/etc/shadow"),
        canonical: Ok(PathBuf::from("/etc/shadow")),
    };
    assert_ne!(engine.decide(&outside).outcome, Outcome::Allow);
}

/// Finding 5: `Grant::into_rule_for_installation` must refuse to hand back a
/// rule for scopes with no real lifetime enforcement (`Once`/`Session`/
/// `ExactArgv`), so a future caller reaching for the obvious install path
/// can't silently turn a one-time approval into a permanent standing rule.
/// `Directory`/`Always` — which ARE meant to be standing rules — pass
/// through.
#[test]
fn into_rule_for_installation_refuses_unenforced_scopes_and_allows_standing_ones() {
    let params = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/x"),
        canonical: Ok(PathBuf::from("/workspace/x")),
    };
    let provenance = || GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    };

    assert!(
        synthesize_grant(&params, GrantScope::Once, provenance())
            .into_rule_for_installation()
            .is_err(),
        "Once has no real lifetime enforcement yet and must refuse installation"
    );
    assert!(
        synthesize_grant(&params, GrantScope::Session, provenance())
            .into_rule_for_installation()
            .is_err(),
        "Session has no real lifetime enforcement yet and must refuse installation"
    );
    assert!(
        synthesize_grant(
            &params,
            GrantScope::ExactArgv { hash: [0u8; 32] },
            provenance()
        )
        .into_rule_for_installation()
        .is_err(),
        "ExactArgv has no real lifetime enforcement yet and must refuse installation"
    );
    assert!(
        synthesize_grant(&params, GrantScope::Always, provenance())
            .into_rule_for_installation()
            .is_ok(),
        "Always is meant to be a standing rule and must be installable"
    );
    assert!(
        synthesize_grant(
            &params,
            GrantScope::Directory {
                path: PathBuf::from("/workspace")
            },
            provenance()
        )
        .into_rule_for_installation()
        .is_ok(),
        "Directory is meant to be a standing rule and must be installable"
    );
}
