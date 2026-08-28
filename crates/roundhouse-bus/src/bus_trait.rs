use crate::types::BusError;
use roundhouse_core::{Address, Envelope, SessionId};

/// §7.8 — "`Bus` is a trait and the only thing session runtimes touch, so a
/// `RemoteBus` framing `Envelope` as CBOR over a worker's control channel
/// drops in unchanged." The spec's prose gives no explicit Rust signature
/// for this trait (unlike `Provider` and `Isolate`); this shape is inferred
/// from §7.1-§7.4's described primitives (directed send, request/reply via
/// `wait`, address resolution as a daemon-side-only operation) and is
/// flagged for review alongside the rest of Phase 0's tagged types.
#[async_trait::async_trait]
pub trait Bus: Send + Sync {
    /// A session must register before it can send or receive.
    async fn register(&self, session: SessionId) -> Result<(), BusError>;

    /// Directed send (§7.3). Fire-and-forget from the caller's perspective;
    /// `expect_reply` on the `Envelope` governs whether the sender later
    /// parks in `wait`.
    async fn send(&self, envelope: Envelope) -> Result<(), BusError>;

    /// Park for the next inbound envelope addressed to `session` (§7.3's
    /// `wait` primitive; §7.7's wait-graph cycle detection wraps this).
    async fn wait(&self, session: SessionId) -> Result<Envelope, BusError>;

    /// §7.2 — "the resolved `to` is always a `SessionId` — address
    /// expansion stays daemon-side, workers never resolve." Broadcast and
    /// pub/sub are address expansion against a roster, not a separate
    /// subsystem, so this one method covers `Session`, `Handle`, `Team`,
    /// `Role`, and `Human` addressing.
    async fn resolve(&self, address: &Address) -> Result<Vec<SessionId>, BusError>;
}
