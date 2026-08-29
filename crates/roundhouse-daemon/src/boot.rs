//! The daemon's boot sequence (Task 2): runs once, between opening the event
//! store and starting anything else, to reclassify tasks a previous daemon
//! process left mid-flight when it crashed and to surface tasks that are
//! still waiting on external action across the restart.

use roundhouse_core::TaskId;
use roundhouse_store::{EventWriter, StoreError, StorePool, SuspendedTask};

/// The result of one daemon boot's recovery pass.
///
/// `interrupted` — tasks reclassified from `Created`/`Decided`/`Running` to
/// `Interrupted` because the previous daemon process died mid-run (S-SESS-4).
///
/// `suspended` — tasks already `Suspended` (e.g. `AwaitingApproval`) that
/// survived the restart untouched, with their real `SuspendReason`.
///
/// **This struct only makes `suspended` tasks *enumerable* again after a
/// restart.** It does NOT wire them into a live, broadcastable
/// `ApprovalRegistry` — that type doesn't exist yet; building the mechanism
/// that actually re-arms these for live approval/resolution is Task 15's
/// job. A caller of `run_boot_sequence` today gets a list it can log or
/// inspect, not a channel anything can act on yet.
pub struct BootReport {
    pub interrupted: Vec<TaskId>,
    pub suspended: Vec<SuspendedTask>,
}

/// Runs crash recovery (`roundhouse_store::recover_interrupted_tasks`), then
/// enumerates tasks left `Suspended` (`roundhouse_store::suspended_tasks`),
/// against the same store — the two halves of "what did the previous daemon
/// process leave behind" that this daemon's startup needs to know about
/// before it does anything else.
pub async fn run_boot_sequence(
    store: &StorePool,
    writer: &EventWriter,
    runner: &roundhouse_core::TaskRunner,
) -> Result<BootReport, StoreError> {
    let interrupted = roundhouse_store::recover_interrupted_tasks(store, writer, runner).await?;
    let suspended = roundhouse_store::suspended_tasks(store).await?;
    Ok(BootReport {
        interrupted,
        suspended,
    })
}
