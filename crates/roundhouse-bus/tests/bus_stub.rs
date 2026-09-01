use roundhouse_bus::mailbox::MailboxKind;
use roundhouse_bus::{
    Address, Bus, BusError, Envelope, MessageId, Provenance, Trust, Undeliverable,
};
use roundhouse_core::{Origin, SessionId, WorkspaceId};
use std::sync::Arc;
use uuid::Uuid;

struct NoopBus;

#[async_trait::async_trait]
impl Bus for NoopBus {
    async fn send(&self, _envelope: Envelope) -> Result<(), BusError> {
        Err(BusError::Undeliverable(Undeliverable::Ended {
            session: SessionId::new(),
        }))
    }

    async fn poll(&self, _session: SessionId) -> Result<Option<Envelope>, BusError> {
        Ok(None)
    }

    async fn register_mailbox(
        &self,
        _session: SessionId,
        _kind: MailboxKind,
    ) -> Result<(), BusError> {
        Ok(())
    }

    async fn deregister_mailbox(&self, _session: SessionId) -> Result<(), BusError> {
        Ok(())
    }

    async fn register_wait(&self, _waiter: SessionId, _target: SessionId) -> Result<(), BusError> {
        Ok(())
    }

    async fn clear_wait(&self, _waiter: SessionId) -> Result<(), BusError> {
        Ok(())
    }

    async fn resolve_address(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<SessionId, BusError> {
        match addr {
            Address::Session { id } => Ok(*id),
            _ => Err(BusError::UnknownHandle {
                workspace,
                name: "<unresolved>".into(),
            }),
        }
    }

    async fn resolve_recipients(
        &self,
        workspace: WorkspaceId,
        addr: &Address,
    ) -> Result<Vec<SessionId>, BusError> {
        Ok(vec![self.resolve_address(workspace, addr).await?])
    }

    async fn requeue(&self, _envelope: Envelope) -> Result<(), BusError> {
        Ok(())
    }
}

#[tokio::test]
async fn bus_trait_is_object_safe_and_resolves_a_direct_session_address() {
    let bus: Arc<dyn Bus> = Arc::new(NoopBus);
    let session = SessionId::new();
    let resolved = bus
        .resolve_address(WorkspaceId::new(), &Address::Session { id: session })
        .await
        .unwrap();
    assert_eq!(resolved, session);
}

#[tokio::test]
async fn send_to_an_ended_session_returns_undeliverable_never_a_silent_drop() {
    let bus: Arc<dyn Bus> = Arc::new(NoopBus);
    let to = SessionId::new();
    let envelope = Envelope {
        id: MessageId(Uuid::new_v4()),
        from: SessionId::new(),
        to,
        to_requested: Address::Session { id: to },
        subject: "s".into(),
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
    };
    let result = bus.send(envelope).await;
    assert!(matches!(
        result,
        Err(BusError::Undeliverable(Undeliverable::Ended { .. }))
    ));
}
