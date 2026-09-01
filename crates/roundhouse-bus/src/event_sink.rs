use crate::types::MessageId;
use roundhouse_core::SessionId;
use std::collections::HashSet;
use std::sync::Mutex;

/// The append-only write path §7.1 requires: "delivery appends [a `message` task] to
/// the recipient's log." The real implementation lives in `roundhouse-store` (§5.2)
/// and is wired at the daemon-assembly layer; this trait is the seam that keeps
/// `roundhouse-bus` testable without a real SQLite file, mirroring §9.10's
/// `HttpTransport` seam pattern.
///
/// §7.4's idempotency contract is split into two operations deliberately:
/// [`is_duplicate`](Self::is_duplicate) is a pure read used to short-circuit a
/// redelivery *before* it is enqueued, while [`record_inbound`](Self::record_inbound)
/// must be called only *after* the message is actually enqueued — so a failed push
/// (e.g. `MailboxFull`) never burns the idempotency key and a later retry isn't
/// false-acked.
pub trait EventSink: Send + Sync {
    /// Returns `true` if `(session, msg_id)` has already been recorded — i.e. the
    /// UNIQUE(session_id, inbound_msg_id) constraint from §7.4 would reject the insert.
    /// Pure read; does not mutate.
    fn is_duplicate(&self, session: SessionId, msg_id: MessageId) -> bool;

    /// Records `(session, msg_id)` as delivered. Callers must only invoke this after the
    /// message has actually been enqueued, so a bounce leaves the key unrecorded and a
    /// subsequent redelivery is still accepted.
    fn record_inbound(&self, session: SessionId, msg_id: MessageId);

    /// §7.1: "delivery appends [a `message` task] to the recipient's log." This records
    /// the outbound side of that append — the sender's event-sourced record that a
    /// message task was created. Called by `message_send` after each successful
    /// `bus.send`, so the outbound task is durably recorded rather than living only in
    /// the mailbox.
    fn record_outbound(&self, session: SessionId, msg_id: MessageId);
}

/// Test double. A real `SqliteEventSink` (roundhouse-store, `INSERT ... ON CONFLICT
/// (session_id, inbound_msg_id) DO NOTHING` under `BEGIN IMMEDIATE`) is wired at the
/// daemon-assembly layer, not in this crate.
pub struct InMemoryEventSink {
    seen: Mutex<HashSet<(SessionId, MessageId)>>,
    outbound: Mutex<HashSet<(SessionId, MessageId)>>,
}

impl InMemoryEventSink {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
            outbound: Mutex::new(HashSet::new()),
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
    fn is_duplicate(&self, session: SessionId, msg_id: MessageId) -> bool {
        self.seen.lock().unwrap().contains(&(session, msg_id))
    }

    fn record_inbound(&self, session: SessionId, msg_id: MessageId) {
        self.seen.lock().unwrap().insert((session, msg_id));
    }

    fn record_outbound(&self, session: SessionId, msg_id: MessageId) {
        self.outbound.lock().unwrap().insert((session, msg_id));
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
        // redelivery is idempotent." The duplicate is short-circuited *before* the
        // mailbox push (the `is_duplicate` read), so it is never enqueued twice and
        // the persisted, observable inbound event count is exactly one.
        assert_eq!(sink.inbound_count(b, msg_id), 1);
    }

    #[tokio::test]
    async fn mailbox_full_bounce_does_not_burn_the_idempotency_key() {
        let sink = Arc::new(InMemoryEventSink::new());
        let bus = LocalBus::new().with_sink(sink.clone());
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(1))
            .await
            .unwrap();

        // Fill the single-slot mailbox so the next push bounces.
        bus.send(envelope(Uuid::new_v4(), from, to)).await.unwrap();

        // One fixed id for the message we'll bounce and then retry.
        let msg_id = Uuid::new_v4();
        let bounced = envelope(msg_id, from, to);

        // Mailbox is full: push fails, and the idempotency key must NOT be recorded —
        // otherwise a retry of this same id would be false-acked as a duplicate.
        let err = bus.send(bounced.clone()).await.unwrap_err();
        assert!(matches!(err, crate::types::BusError::MailboxFull { .. }));
        assert_eq!(sink.inbound_count(to, msg_id), 0);

        // Drain the slot, then the same id must deliver — proving the key was never burned.
        assert!(bus.poll(to).await.unwrap().is_some());
        bus.send(bounced).await.unwrap();
        assert_eq!(sink.inbound_count(to, msg_id), 1);
    }
}
