use roundhouse_bus::{Bus, BusError, Undeliverable};
use roundhouse_core::{Address, Envelope, SessionId};
use std::sync::Arc;

struct NoopBus;

#[async_trait::async_trait]
impl Bus for NoopBus {
    async fn register(&self, _session: SessionId) -> Result<(), BusError> {
        Ok(())
    }

    async fn send(&self, _envelope: Envelope) -> Result<(), BusError> {
        Err(BusError::Undeliverable(Undeliverable::Ended))
    }

    async fn wait(&self, _session: SessionId) -> Result<Envelope, BusError> {
        Err(BusError::Timeout)
    }

    async fn resolve(&self, address: &Address) -> Result<Vec<SessionId>, BusError> {
        match address {
            Address::Session { id } => Ok(vec![*id]),
            _ => Ok(vec![]),
        }
    }
}

#[tokio::test]
async fn bus_trait_is_object_safe_and_resolves_a_direct_session_address() {
    let bus: Arc<dyn Bus> = Arc::new(NoopBus);
    let session = SessionId::new();
    let resolved = bus.resolve(&Address::Session { id: session }).await.unwrap();
    assert_eq!(resolved, vec![session]);
}

#[tokio::test]
async fn send_to_an_ended_session_returns_undeliverable_never_a_silent_drop() {
    let bus: Arc<dyn Bus> = Arc::new(NoopBus);
    let envelope = Envelope::default_for_test();
    let result = bus.send(envelope).await;
    assert!(matches!(result, Err(BusError::Undeliverable(Undeliverable::Ended))));
}
