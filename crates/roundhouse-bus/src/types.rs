/// §7.4 — "Ended → `Undeliverable::Ended` synchronously, never a silent
/// drop." Phase 0 ships the one variant §7.4 names explicitly by name;
/// later phases add `MailboxFull`, `MemberNotFound`, etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Undeliverable {
    Ended,
}

#[derive(Debug, thiserror::Error)]
pub enum BusError {
    #[error("undeliverable: {0:?}")]
    Undeliverable(Undeliverable),
    #[error("wait timed out")]
    Timeout,
    #[error("would deadlock: waiting on this address would create a wait-for cycle")]
    WouldDeadlock,
}
