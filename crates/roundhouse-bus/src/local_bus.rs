use crate::event_sink::{EventSink, InMemoryEventSink};
use crate::handle_registry::HandleRegistry;
use crate::mailbox::{Mailbox, MailboxKind};
use crate::types::{BusError, Envelope, Undeliverable};
use crate::wait_graph::WaitGraph;
use dashmap::DashMap;
use roundhouse_core::SessionId;
use std::sync::{Arc, Mutex};

/// §7.8: "A routed mpsc registry (LocalBus with DashMap of mailboxes, handles, teams,
/// plus the wait graph and the shared DB writer)."
pub struct LocalBus {
    pub(crate) mailboxes: DashMap<SessionId, Mutex<Mailbox>>,
    // Consumed by later bus tasks (handle resolution, wait-graph cycle detection);
    // held now so `LocalBus` has its final §7.8 shape from the start.
    #[allow(dead_code)]
    pub(crate) handles: HandleRegistry,
    #[allow(dead_code)]
    pub(crate) wait_graph: Mutex<WaitGraph>,
    pub(crate) sink: Arc<dyn EventSink>,
}

impl LocalBus {
    pub fn new() -> Self {
        Self {
            mailboxes: DashMap::new(),
            handles: HandleRegistry::new(),
            wait_graph: Mutex::new(WaitGraph::new()),
            sink: Arc::new(InMemoryEventSink::new()),
        }
    }

    pub fn with_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.sink = sink;
        self
    }

    pub async fn register_mailbox(
        &self,
        session: SessionId,
        kind: MailboxKind,
    ) -> Result<(), BusError> {
        self.mailboxes
            .entry(session)
            .or_insert_with(|| Mutex::new(Mailbox::new(kind)));
        Ok(())
    }

    pub async fn deregister_mailbox(&self, session: SessionId) -> Result<(), BusError> {
        self.mailboxes.remove(&session);
        Ok(())
    }

    pub fn has_mailbox(&self, session: SessionId) -> bool {
        self.mailboxes.contains_key(&session)
    }

    /// §7.4: "FIFO per (sender, recipient) pair." A per-recipient VecDeque already
    /// gives FIFO for everything landing in that mailbox; because sends from a given
    /// sender are pushed in the order `send` is awaited (single mailbox lock per push),
    /// each (sender, recipient) sub-sequence within that queue is preserved without
    /// needing a separate index.
    pub async fn send(&self, envelope: Envelope) -> Result<(), BusError> {
        let to = envelope.to;
        let mailbox =
            self.mailboxes
                .get(&to)
                .ok_or(BusError::Undeliverable(Undeliverable::Ended {
                    session: to,
                }))?;

        // Idempotency check happens before the mailbox push: a duplicate redelivery is
        // recorded as a no-op observation, not a second queued item.
        if !self.sink.record_inbound(to, envelope.id) {
            tracing::debug!(?to, msg_id = ?envelope.id, "duplicate inbound message, dropped as idempotent redelivery");
            return Ok(());
        }

        let mut guard = mailbox.lock().expect("mailbox mutex poisoned");
        guard.push(to, envelope)
    }

    pub async fn poll(&self, session: SessionId) -> Result<Option<Envelope>, BusError> {
        let mailbox = self
            .mailboxes
            .get(&session)
            .ok_or(BusError::Undeliverable(Undeliverable::Ended { session }))?;
        let mut guard = mailbox.lock().expect("mailbox mutex poisoned");
        Ok(guard.pop_front())
    }
}

impl Default for LocalBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use roundhouse_core::SessionId;

    #[tokio::test]
    async fn registering_a_mailbox_twice_is_idempotent() {
        let bus = LocalBus::new();
        let sid = SessionId::new();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        assert!(bus.has_mailbox(sid));
    }

    #[tokio::test]
    async fn deregistering_removes_the_mailbox() {
        let bus = LocalBus::new();
        let sid = SessionId::new();
        bus.register_mailbox(sid, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.deregister_mailbox(sid).await.unwrap();
        assert!(!bus.has_mailbox(sid));
    }
}

#[cfg(test)]
mod send_tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId, seq: u8) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: "s".into(),
            body: format!("msg-{seq}"),
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
    async fn fifo_ordering_is_per_sender_recipient_pair_not_global() {
        let bus = LocalBus::new();
        let a = SessionId::new();
        let b = SessionId::new();
        bus.register_mailbox(a, MailboxKind::Bounded(64))
            .await
            .unwrap();
        bus.register_mailbox(b, MailboxKind::Bounded(64))
            .await
            .unwrap();

        // Interleave two independent pairs: A->B and B->A.
        bus.send(envelope(a, b, 1)).await.unwrap();
        bus.send(envelope(b, a, 1)).await.unwrap();
        bus.send(envelope(a, b, 2)).await.unwrap();
        bus.send(envelope(b, a, 2)).await.unwrap();

        let b1 = bus.poll(b).await.unwrap().unwrap();
        let b2 = bus.poll(b).await.unwrap().unwrap();
        assert_eq!(b1.body, "msg-1");
        assert_eq!(b2.body, "msg-2");

        let a1 = bus.poll(a).await.unwrap().unwrap();
        let a2 = bus.poll(a).await.unwrap().unwrap();
        assert_eq!(a1.body, "msg-1");
        assert_eq!(a2.body, "msg-2");
    }

    #[tokio::test]
    async fn send_to_ended_session_is_synchronously_undeliverable() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let ended = SessionId::new(); // never registered = tombstoned/ended
        let err = bus.send(envelope(from, ended, 1)).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::Undeliverable(crate::types::Undeliverable::Ended { .. })
        ));
    }
}
