use crate::types::{BusError, Envelope};
use roundhouse_core::SessionId;
use std::collections::VecDeque;

/// §7.4: "bounded mailbox (default 64)." `Unbounded` is available for any ordinary
/// (non-Human) session that needs it; `Address::Human` recipients don't use a `Mailbox`
/// at all — see `LocalBus::register_human`/the `HumanNotificationRegistry` (Task 6),
/// which is §7.2's real "UI surfacing/notification, not land-in-a-mailbox" mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailboxKind {
    Bounded(usize),
    Unbounded,
}

pub const DEFAULT_MAILBOX_CAPACITY: usize = 64;

pub struct Mailbox {
    kind: MailboxKind,
    queue: VecDeque<Envelope>,
}

impl Mailbox {
    pub fn new(kind: MailboxKind) -> Self {
        Self {
            queue: VecDeque::new(),
            kind,
        }
    }

    /// §7.4: "On overflow reject the send — never drop the oldest."
    pub fn push(&mut self, session: SessionId, envelope: Envelope) -> Result<(), BusError> {
        if let MailboxKind::Bounded(capacity) = self.kind {
            if self.queue.len() >= capacity {
                return Err(BusError::MailboxFull { session, capacity });
            }
        }
        self.queue.push_back(envelope);
        Ok(())
    }

    pub fn push_front(&mut self, session: SessionId, envelope: Envelope) -> Result<(), BusError> {
        if let MailboxKind::Bounded(capacity) = self.kind {
            if self.queue.len() >= capacity {
                return Err(BusError::MailboxFull { session, capacity });
            }
        }
        self.queue.push_front(envelope);
        Ok(())
    }

    pub fn pop_front(&mut self) -> Option<Envelope> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}
