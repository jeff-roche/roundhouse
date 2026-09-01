use crate::handle_registry::HandleRegistry;
use crate::mailbox::{Mailbox, MailboxKind};
use crate::types::BusError;
use crate::wait_graph::WaitGraph;
use dashmap::DashMap;
use roundhouse_core::SessionId;
use std::sync::Mutex;

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
}

impl LocalBus {
    pub fn new() -> Self {
        Self {
            mailboxes: DashMap::new(),
            handles: HandleRegistry::new(),
            wait_graph: Mutex::new(WaitGraph::new()),
        }
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
