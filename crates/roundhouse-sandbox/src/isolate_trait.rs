use crate::types::{Attestation, Child, CommandSpec, Handle, IsolationError, ProbeResult};
use roundhouse_core::{SessionSpec, Tier};

/// §6.5 — tiers compose (`IsolationStack` pairs a `WorkspaceLayer` with a
/// `Vec<Box<dyn Enforcer>>`), but every tier, however composed, presents
/// this one trait to the rest of the system. `async_trait` is acceptable
/// here (unlike `Provider`, §9.4) because `Isolate` implementations are not
/// stored in a hot registry keyed by a hash map the way providers are —
/// object safety via boxed futures is not required for this trait's usage
/// pattern (one `Arc<dyn Isolate>` per session, not per-request dispatch).
#[async_trait::async_trait]
pub trait Isolate: Send + Sync {
    fn declared(&self) -> Tier;

    /// Real syscalls, at startup. §6.5 rule 1: fail-open is made
    /// structurally impossible by actually exercising each mechanism.
    async fn probe(&self) -> ProbeResult;

    /// §6.5 rule 2: errors if `achieved < requested`. Does not warn.
    async fn prepare(&self, spec: &SessionSpec) -> Result<Handle, IsolationError>;

    async fn spawn(&self, h: &Handle, cmd: CommandSpec) -> Result<Child, IsolationError>;

    /// §6.5 rule 4: written on every task row, not once per session.
    fn attest(&self, h: &Handle) -> Attestation;

    async fn teardown(&self, h: Handle) -> Result<(), IsolationError>;
}
