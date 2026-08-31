//! The live, in-memory "approval-broadcast registry" (§6.4 / Task 15): what a
//! *currently running* daemon consults to answer "what's pending right now"
//! without polling the store, and to push live updates to every attached
//! client. `roundhouse_store::suspended_tasks` (the `tasks` table's
//! `suspend_reason_json` column) remains the source of truth across restarts
//! — this registry is a live index over it, rebuilt at boot
//! (`roundhouse_daemon::boot::run_boot_sequence`) and kept current by
//! `approval::suspend_for_approval` for the remainder of the process's life.
//!
//! Before this task, nothing in the codebase ever constructed this type —
//! §1.1 bug #2 and audit finding 6 both describe the resulting gap: a
//! `Suspended` task was correctly persisted but nothing live ever pointed at
//! it, so a running daemon (and any attached client) had no way to discover
//! it short of restarting and re-scanning the whole `tasks` table.

use crate::engine::RuleId;
use dashmap::DashMap;
use roundhouse_core::{SessionId, TaskId, Timestamp};
use tokio::sync::broadcast;

/// One task currently suspended awaiting human approval, as tracked live by
/// a running daemon process. `rule` is the policy-engine's human-readable
/// `RuleId` (the `String` one, `crate::engine::RuleId`) — the identifier a
/// UI would actually want to display — not the persisted `core::RuleId(u64)`
/// digest (see `approval.rs`'s `core_rule_id_from_policy_rule_id` for the
/// one-way conversion used only when minting the persisted event).
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub rule: Option<RuleId>,
    pub params_digest: [u8; 32],
    pub since: Timestamp,
}

#[derive(Debug, Clone)]
pub enum ApprovalEvent {
    Registered(TaskId),
    Resolved(TaskId),
}

/// The in-memory approval-broadcast registry. Persistence (the SQLite row,
/// via `roundhouse_store::suspended_tasks`) is the source of truth across
/// restarts; this registry is what makes a *currently running* daemon able
/// to answer "what's pending right now" and push live updates to every
/// attached client without polling the store (§6.4: "Approvals broadcast to
/// every attached client; first responder wins").
pub struct ApprovalRegistry {
    pending: DashMap<TaskId, PendingApproval>,
    events: broadcast::Sender<ApprovalEvent>,
}

impl ApprovalRegistry {
    pub fn new() -> Self {
        let (events, _rx) = broadcast::channel(256);
        Self {
            pending: DashMap::new(),
            events,
        }
    }

    pub fn register(&self, approval: PendingApproval) {
        let task_id = approval.task_id;
        self.pending.insert(task_id, approval);
        // No receivers yet (nobody attached) is not an error — broadcast::Sender::send
        // only errors when there are zero receivers, which is the common case at boot.
        let _ = self.events.send(ApprovalEvent::Registered(task_id));
    }

    /// Called once a human (or a matching grant) resolves the approval;
    /// removes it from the live set. The caller is still responsible for
    /// appending the resolving event to the store — this only clears the
    /// in-memory broadcast state.
    pub fn resolve(&self, task_id: TaskId) -> Option<PendingApproval> {
        let removed = self.pending.remove(&task_id).map(|(_, v)| v);
        if removed.is_some() {
            let _ = self.events.send(ApprovalEvent::Resolved(task_id));
        }
        removed
    }

    pub fn list(&self) -> Vec<PendingApproval> {
        self.pending
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ApprovalEvent> {
        self.events.subscribe()
    }
}

impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self::new()
    }
}
