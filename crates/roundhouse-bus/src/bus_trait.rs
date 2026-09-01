use crate::mailbox::MailboxKind;
use crate::types::{Address, BusError, Envelope};
use async_trait::async_trait;
use roundhouse_core::{SessionId, WorkspaceId};

/// §7.8: "Bus is a trait and the only thing session runtimes touch, so a RemoteBus
/// framing Envelope as CBOR over a worker's control channel drops in unchanged." Two
/// rules this trait's shape must honour: Envelope is self-contained/serializable
/// (Task 1), and `to` is always resolved to a SessionId before send (Task 2) — address
/// expansion stays daemon-side, workers never resolve.
#[async_trait]
pub trait Bus: Send + Sync {
    async fn send(&self, envelope: Envelope) -> Result<(), BusError>;
    async fn poll(&self, session: SessionId) -> Result<Option<Envelope>, BusError>;
    async fn register_mailbox(&self, session: SessionId, kind: MailboxKind)
        -> Result<(), BusError>;
    async fn deregister_mailbox(&self, session: SessionId) -> Result<(), BusError>;
    async fn register_wait(&self, waiter: SessionId, target: SessionId) -> Result<(), BusError>;
    async fn clear_wait(&self, waiter: SessionId) -> Result<(), BusError>;
    async fn resolve_address(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<SessionId, BusError>;
    /// The fan-out counterpart to `resolve_address` (Task 2's `HandleRegistry`
    /// explicitly refuses `Address::Team`/`Address::Role`, deferring "local_bus
    /// expands these" — this is that expansion). `Session`/`Handle`/`Human` still
    /// resolve to exactly one recipient; `Team` expands to the whole live roster,
    /// `Role` filters the roster by role (§7.2, §7.5).
    async fn resolve_recipients(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<Vec<SessionId>, BusError>;
    /// Re-queue an envelope that was popped from a mailbox but not consumed
    /// (e.g. a non-matching reply during a quorum wait). Bypasses idempotency,
    /// ttl_hops, rate cap, and repetition damper — pushes directly to the mailbox.
    async fn requeue(&self, envelope: Envelope) -> Result<(), BusError>;
}
