use crate::event_sink::{EventSink, InMemoryEventSink};
use crate::handle_registry::HandleRegistry;
use crate::human_notifications::{HumanNotification, HumanNotificationRegistry};
use crate::mailbox::{Mailbox, MailboxKind};
use crate::types::{BusError, Envelope, Undeliverable};
use crate::wait_graph::WaitGraph;
use dashmap::{DashMap, DashSet};
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
    pub(crate) human_sessions: DashSet<SessionId>,
    pub(crate) human_notifications: HumanNotificationRegistry,
}

impl LocalBus {
    pub fn new() -> Self {
        Self {
            mailboxes: DashMap::new(),
            handles: HandleRegistry::new(),
            wait_graph: Mutex::new(WaitGraph::new()),
            sink: Arc::new(InMemoryEventSink::new()),
            human_sessions: DashSet::new(),
            human_notifications: HumanNotificationRegistry::new(),
        }
    }

    /// Marks `session` as a human recipient: it never gets a `Mailbox` — `send`
    /// (below) routes anything addressed to it into `human_notifications` instead.
    /// Distinct from `register_mailbox` on purpose (§7.2's split delivery mechanism).
    pub fn register_human(&self, session: SessionId) {
        self.human_sessions.insert(session);
    }

    pub fn list_human_notifications(&self, session: SessionId) -> Vec<HumanNotification> {
        self.human_notifications.list(session)
    }

    pub fn drain_human_notifications(&self, session: SessionId) -> Vec<HumanNotification> {
        self.human_notifications.drain(session)
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

        // §7.2: human recipients bypass the ordinary mailbox path entirely — no
        // capacity check, no idempotency/redelivery bookkeeping (a UI notification
        // feed has no "effectively-once observation" contract the way a Task-injected
        // reply does), just a durable, listable/drainable notification.
        if self.human_sessions.contains(&to) {
            self.human_notifications.push(
                to,
                HumanNotification {
                    from: envelope.from,
                    envelope,
                    ts_unix_ms: current_unix_millis(),
                },
            );
            return Ok(());
        }

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

fn current_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

#[cfg(test)]
mod backpressure_tests {
    use super::*;
    use crate::mailbox::MailboxKind;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId, subject: &str) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Session { id: to },
            subject: subject.into(),
            body: "x".into(),
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
    async fn overflow_rejects_the_send_and_never_drops_the_oldest() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let to = SessionId::new();
        bus.register_mailbox(to, MailboxKind::Bounded(2))
            .await
            .unwrap();

        bus.send(envelope(from, to, "s")).await.unwrap();
        bus.send(envelope(from, to, "s")).await.unwrap();
        let err = bus.send(envelope(from, to, "s")).await.unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::MailboxFull { capacity: 2, .. }
        ));

        // The two original messages are both still there — nothing was evicted.
        assert!(bus.poll(to).await.unwrap().is_some());
        assert!(bus.poll(to).await.unwrap().is_some());
        assert!(bus.poll(to).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn human_recipients_never_get_an_ordinary_mailbox_or_a_capacity_limit() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let human = SessionId::new();
        bus.register_human(human);

        // A distinct subject per iteration: this test is only about the human path
        // itself, so it deliberately avoids tripping the repetition damper Task 12
        // later wires into `send` for real (keyed on `(to, subject)`, §7.7).
        for i in 0..(crate::mailbox::DEFAULT_MAILBOX_CAPACITY * 4) {
            bus.send(envelope(from, human, &format!("s{i}")))
                .await
                .unwrap();
        }

        // §7.2: "never blocked by policy" — there is no capacity concept to violate
        // because a human recipient never gets an ordinary `Mailbox` in the first
        // place, not because its `Mailbox` happens to be `Unbounded`.
        assert!(!bus.has_mailbox(human));
        assert_eq!(
            bus.list_human_notifications(human).len(),
            crate::mailbox::DEFAULT_MAILBOX_CAPACITY * 4
        );
    }

    #[tokio::test]
    async fn draining_human_notifications_removes_them() {
        let bus = LocalBus::new();
        let from = SessionId::new();
        let human = SessionId::new();
        bus.register_human(human);
        bus.send(envelope(from, human, "heads up")).await.unwrap();

        let drained = bus.drain_human_notifications(human);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].from, from);
        assert!(bus.list_human_notifications(human).is_empty());
    }
}
