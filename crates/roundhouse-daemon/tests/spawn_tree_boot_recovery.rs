//! The daemon-level seam for the spawn tree's boot recovery
//! (`roundhouse_daemon::boot::reconcile_spawn_tree_at_boot`): a real store on
//! disk, opened the way `main.rs` opens it, read back through the real pool.
//!
//! The scan's own behaviour — both child kinds, the terminal filter, the
//! documented sub-agent gap — is covered where it lives, in
//! `roundhouse-daemon`'s `workflow_host` and `sub_agent_host` unit tests. This
//! file proves only that the boot seam wires it to the daemon's one shared
//! tree and reports what it restored.

use std::sync::Arc;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{SessionId, SessionOutcome, SessionSpec, TaskRunner, Timestamp};
use roundhouse_daemon::boot::reconcile_spawn_tree_at_boot;
use roundhouse_store::{open, spawn_writer};

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// `TaskRunner::bootstrap()` panics on a second call per process and each
/// integration-test binary is its own process, so this file holds exactly one
/// test — the same posture as `tests/boot.rs`.
#[tokio::test]
async fn boot_recovery_rebuilds_the_daemons_spawn_tree_from_the_store() {
    let runner = TaskRunner::bootstrap();

    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store.clone()).await;

    let parent = SessionId::new();
    let live_child = SessionId::new();
    let ended_child = SessionId::new();

    for child in [live_child, ended_child] {
        let mut spec = SessionSpec::test_default();
        spec.parent = Some(parent);
        writer
            .append(runner.record_session_created(child, 0, now_ts(), Box::new(spec), 1))
            .await
            .unwrap();
    }
    writer
        .append(runner.record_session_closed(
            ended_child,
            0,
            now_ts(),
            SessionOutcome::Completed,
            1,
        ))
        .await
        .unwrap();

    // The restart: the tree a new daemon process starts with is empty.
    let tree = Arc::new(SpawnTree::new());
    let restored = reconcile_spawn_tree_at_boot(&store, &tree).await.unwrap();

    assert_eq!(restored, 1, "one edge restored, and it is reported");
    assert_eq!(
        tree.descendants(parent),
        vec![live_child],
        "the live child is back under its parent; the closed one is not"
    );
    assert_eq!(tree.direct_children(parent), 1);
}
