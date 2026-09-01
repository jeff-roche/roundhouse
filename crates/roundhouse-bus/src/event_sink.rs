use crate::types::MessageId;
use roundhouse_core::SessionId;
use std::collections::HashSet;
use std::sync::Mutex;

/// The append-only write path §7.1 requires: "delivery appends [a `message` task] to
/// the recipient's log." `roundhouse-bus` depends on `roundhouse-store` (§5.2) for the
/// real implementation; this trait is the seam that keeps `roundhouse-bus` testable
/// without a real SQLite file, mirroring §9.10's `HttpTransport` seam pattern.
pub trait EventSink: Send + Sync {
    /// Returns `true` if this is the first time `(session, msg_id)` has been recorded —
    /// i.e. the UNIQUE(session_id, inbound_msg_id) constraint from §7.4 would have
    /// accepted the insert. Returns `false` on a duplicate.
    fn record_inbound(&self, session: SessionId, msg_id: MessageId) -> bool;
}

/// Test double. A real `SqliteEventSink` (roundhouse-store, `INSERT ... ON CONFLICT
/// (session_id, inbound_msg_id) DO NOTHING` under `BEGIN IMMEDIATE`) is wired at the
/// daemon-assembly layer, not in this crate.
pub struct InMemoryEventSink {
    seen: Mutex<HashSet<(SessionId, MessageId)>>,
}

impl InMemoryEventSink {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    #[cfg(test)]
    pub fn inbound_count(&self, session: SessionId, msg_id: uuid::Uuid) -> usize {
        self.seen
            .lock()
            .unwrap()
            .contains(&(session, MessageId(msg_id))) as usize
    }
}

impl Default for InMemoryEventSink {
    fn default() -> Self {
        Self::new()
    }
}

impl EventSink for InMemoryEventSink {
    fn record_inbound(&self, session: SessionId, msg_id: MessageId) -> bool {
        self.seen.lock().unwrap().insert((session, msg_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_bus::LocalBus;
    use crate::mailbox::MailboxKind;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use std::sync::Arc;
    use uuid::Uuid;

    fn envelope(id: Uuid, from: SessionId, to: SessionId) -> Envelope {
        Envelope {
            id: MessageId(id),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: "s".into(),
            body: "hello".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to: None,
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[tokio::test]
    async fn redelivery_of_the_same_message_id_is_idempotent() {
        let sink = Arc::new(InMemoryEventSink::new());
        let bus = LocalBus::new().with_sink(sink.clone());
        let a = SessionId::new();
        let b = SessionId::new();
        bus.register_mailbox(a, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(b, MailboxKind::Bounded(64))
            .await
            .unwrap();

        let msg_id = Uuid::new_v4();
        // Simulate an at-least-once redelivery: same envelope sent twice (e.g. after
        // a crash before the sender's ack was durable).
        bus.send(envelope(msg_id, a, b)).await.unwrap();
        bus.send(envelope(msg_id, a, b)).await.unwrap();

        // §7.4: "the recipient's log has UNIQUE(session_id, inbound_msg_id), so
        // redelivery is idempotent." The mailbox may see it twice; the persisted,
        // observable inbound event count must be exactly one.
        assert_eq!(sink.inbound_count(b, msg_id), 1);
    }
}
