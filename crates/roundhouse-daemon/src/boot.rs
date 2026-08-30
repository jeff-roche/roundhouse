//! The daemon's boot sequence (Task 2): runs once, between opening the event
//! store and starting anything else, to reclassify tasks a previous daemon
//! process left mid-flight when it crashed and to surface tasks that are
//! still waiting on external action across the restart.

use roundhouse_core::{SuspendReason, TaskId};
use roundhouse_policy::registry::{ApprovalRegistry, PendingApproval};
use roundhouse_store::{EventWriter, StoreError, StorePool, SuspendedTask};

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
