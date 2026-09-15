//! The daemon's boot sequence (Task 2): runs once, between opening the event
//! store and starting anything else, to reclassify tasks a previous daemon
//! process left mid-flight when it crashed and to surface tasks that are
//! still waiting on external action across the restart.

use std::sync::Arc;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{SuspendReason, TaskId};
use roundhouse_policy::registry::{ApprovalRegistry, PendingApproval};
use roundhouse_store::{EventWriter, StoreError, StorePool, SuspendedTask};

use crate::workflow_host::{reconcile_spawn_tree, ReconcileSpawnTreeError};

/// The result of one daemon boot's recovery pass.
///
/// `interrupted` — tasks reclassified from `Created`/`Decided`/`Running` to
/// `Interrupted` because the previous daemon process died mid-run (S-SESS-4).
///
/// `suspended` — tasks already `Suspended` (e.g. `AwaitingApproval`) that
/// survived the restart untouched, with their real `SuspendReason`. As of
/// Task 15, every `AwaitingApproval` entry among these has also been
/// re-registered live in the `ApprovalRegistry` passed to
/// `run_boot_sequence` — a restarted daemon's registry is no longer empty
/// even though the approvals were always correctly sitting in the database
/// (§1.1 bug #2 / audit finding 6).
pub struct BootReport {
    pub interrupted: Vec<TaskId>,
    pub suspended: Vec<SuspendedTask>,
}

/// Runs crash recovery (`roundhouse_store::recover_interrupted_tasks`), then
/// enumerates tasks left `Suspended` (`roundhouse_store::suspended_tasks`),
/// against the same store — the two halves of "what did the previous daemon
/// process leave behind" that this daemon's startup needs to know about
/// before it does anything else.
///
/// Every enumerated `Suspended` task whose reason is `AwaitingApproval` is
/// then re-armed into `registry` (a live index for the currently running
/// process — see `roundhouse_policy::registry::ApprovalRegistry`'s doc
/// comment) so an attaching client sees it immediately, without polling.
/// Other `SuspendReason` kinds (`AwaitingElicitation`/`AwaitingReply`/
/// `AwaitingPeer`/`WorkflowGate`) re-arm through their own subsystems, not
/// this registry, and are intentionally skipped here.
pub async fn run_boot_sequence(
    store: &StorePool,
    writer: &EventWriter,
    runner: &roundhouse_core::TaskRunner,
    registry: &ApprovalRegistry,
) -> Result<BootReport, StoreError> {
    let interrupted = roundhouse_store::recover_interrupted_tasks(store, writer, runner).await?;
    let suspended = roundhouse_store::suspended_tasks(store).await?;

    let boot_ts = {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_nanos() as i64;
        roundhouse_core::Timestamp::from_unix_nanos(nanos)
    };

    for task in &suspended {
        if let SuspendReason::AwaitingApproval {
            rule: _,
            params_digest,
        } = &task.reason
        {
            // `SuspendReason::AwaitingApproval`'s `rule` is the frozen
            // `roundhouse_core::RuleId(u64)` — a lossy, one-way hash of the
            // policy engine's human-readable `RuleId` string (see
            // `approval::core_rule_id_from_policy_rule_id`'s doc comment).
            // There is no way back to the string form from persisted state,
            // so the re-armed `PendingApproval.rule` is `None` here rather
            // than fabricating a value; the digest and task/session
            // identity are what the registry actually needs to be useful.
            //
            // `since`: neither `SuspendedTask` nor the `tasks` cache table
            // carries the original suspend timestamp (Ruling 1 confirms
            // there is no `events_for_task` to walk the log for it, and
            // hand-rolling one is explicitly out of scope for this task) —
            // `since` is set to boot time as a documented approximation, not
            // the true original suspend time. A later task that wants the
            // real timestamp needs to add it to the `tasks` cache row or
            // `SuspendedTask` itself.
            registry.register(PendingApproval {
                session_id: task.session_id,
                task_id: task.task_id,
                rule: None,
                params_digest: *params_digest,
                since: boot_ts,
            });
        }
    }

    Ok(BootReport {
        interrupted,
        suspended,
    })
}

/// Why the spawn tree's boot recovery could not run to completion.
#[derive(Debug, thiserror::Error)]
pub enum SpawnTreeRecoveryError {
    /// The connection could not be checked out, or the blocking closure could
    /// not be run on it.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The durable rows were read but could not be turned into edges.
    #[error(transparent)]
    Reconcile(#[from] ReconcileSpawnTreeError),
}

/// The spawn tree's half of boot recovery: rebuilds `tree` — a fresh, empty,
/// in-memory structure at every process start — from the durable record of the
/// children a previous daemon process spawned, and reports how many edges came
/// back.
///
/// Runs once, at boot, **before** anything that admits a new child against the
/// same tree (the scheduler driver's `DeliveryExecutor`, and any session an
/// accepted client creates), so no consumer ever sees a half-reconstructed
/// tree. The scan itself, including what a restart still cannot know about a
/// sub-agent child, is [`reconcile_spawn_tree`].
///
/// Separate from [`run_boot_sequence`] rather than folded into it: that pass
/// belongs to the task log and needs an [`EventWriter`] to append its
/// reclassifications, while this one is read-only and writes only to memory.
///
/// **A single unreadable lifecycle row is skipped, loudly, rather than
/// refusing the boot.** [`reconcile_spawn_tree`] logs a `tracing::error!` for
/// each lifecycle event whose payload will not deserialize or whose
/// `events.session_id` is not a uuid, and one summary `error!` naming how many
/// it skipped; the scan then completes and this function returns `Ok` with the
/// edges it *could* rebuild.
///
/// This used to propagate instead, on the reasoning that a store the daemon
/// cannot fully read is one it should not start against. That reasoning does
/// not survive contact with S-LOG-2: the `events` table physically rejects
/// `DELETE`, and `main.rs` propagates this error with `?`, so one bad row
/// anywhere in the log means the daemon **never boots again** and the row can
/// never be removed. Both outcomes are wrong, but only one is bounded —
/// skipping under-counts one parent's fan-out by one child against a ceiling
/// of eight (permissive by one), which is the same bounded-permissive tradeoff
/// [`reconcile_spawn_tree`]'s own KNOWN GAP section already accepts for a
/// sub-agent child with no durable terminal signal.
///
/// The tolerance is scoped to that one case. A genuinely unrecoverable problem
/// — the connection cannot be checked out, the blocking closure cannot run,
/// the query itself fails, a `workflow_run.session_id` is not a uuid — still
/// returns `Err` and still refuses the boot.
pub async fn reconcile_spawn_tree_at_boot(
    store: &StorePool,
    tree: &Arc<SpawnTree>,
) -> Result<usize, SpawnTreeRecoveryError> {
    let tree = Arc::clone(tree);
    // `StoreError::Pool` for the checkout and `StoreError::Interact` only for
    // the blocking closure, per that enum's own documented convention.
    let conn = store.pool.get().await.map_err(StoreError::Pool)?;
    Ok(conn
        .interact(move |conn| reconcile_spawn_tree(conn, &tree))
        .await
        .map_err(|error| StoreError::Interact(error.to_string()))??)
}
