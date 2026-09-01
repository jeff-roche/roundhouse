//! A4/G7, made real: the `Message` trigger binds on a real `Address::Handle`
//! (§7.2), resolved daemon-side exactly like any other bus address, never on
//! a topic/subject string (§7.3 deliberately cut topic pub/sub). See
//! `crate::trigger::TriggerSpec::Message`'s doc comment for the full
//! rationale.
use crate::trigger::{Binding, TriggerSpec};
use roundhouse_bus::mailbox::MailboxKind;
use roundhouse_bus::Bus;
use roundhouse_core::{Address, WorkspaceId};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageTriggerError {
    #[error("binding {0} is not a Message trigger, or its address is not a Handle")]
    NotAMessageHandleTrigger(String),
    #[error(transparent)]
    Bus(#[from] roundhouse_bus::BusError),
}

fn handle_parts(binding: &Binding) -> Result<(WorkspaceId, &str), MessageTriggerError> {
    match &binding.spec {
        TriggerSpec::Message {
            address: Address::Handle { workspace, name },
            ..
        } => Ok((*workspace, name.as_str())),
        _ => Err(MessageTriggerError::NotAMessageHandleTrigger(
            binding.id.to_string(),
        )),
    }
}

/// Binding a `Message` trigger creates the durable `Address::Handle {
/// workspace, name }` §8.2 requires, mapped onto the binding's own
/// `trigger_session_id()` (Task 1) — "the binding *is* the addressable
/// recipient." Call once, at binding-creation time and again at daemon
/// startup for every enabled `Message` binding (registration is
/// re-derivable from `Binding` alone, so it never needs its own
/// persistence).
pub async fn bind_message_trigger(
    bus: &dyn Bus,
    binding: &Binding,
) -> Result<(), MessageTriggerError> {
    let (workspace, name) = handle_parts(binding)?;
    let session = binding.trigger_session_id();
    bus.register_mailbox(session, MailboxKind::Bounded(64))
        .await?;
    bus.register_handle(workspace, name.to_string(), session)
        .await?;
    Ok(())
}

pub async fn unbind_message_trigger(
    bus: &dyn Bus,
    binding: &Binding,
) -> Result<(), MessageTriggerError> {
    let (workspace, name) = handle_parts(binding)?;
    bus.unregister_handle(workspace, name).await?;
    bus.deregister_mailbox(binding.trigger_session_id()).await?;
    Ok(())
}

/// §8.2: "a `message_send` to that handle is what fires the trigger,
/// resolved daemon-side exactly like any other address — never a subject
/// match." The real `Bus::poll` is non-blocking (Phase 4 delivered no
/// blocking `wait` on the trait), so the daemon's trigger-listener loop
/// (outside this crate — an integration point, same class as this plan's
/// other daemon-owned wiring) calls this on an interval; `None` means
/// nothing has arrived since the last poll.
///
/// Deviation from the plan text: the plan's declared return type was
/// `Result<Option<roundhouse_core::Envelope>, MessageTriggerError>`. The
/// real `Bus::poll` (`roundhouse_bus::bus_trait::Bus`) yields
/// `Option<roundhouse_bus::types::Envelope>` — a structurally different,
/// richer type (`to: SessionId` already resolved, `body: String`,
/// `expect_reply: Option<ExpectReply>`, plus `id`/`subject`/`attachments`/
/// `in_reply_to`/`ttl_hops`/`provenance`) than `roundhouse_core::Envelope`,
/// which the bus only ever converts *into* one-way via
/// `Envelope::to_core_envelope()`. This function returns the real bus type.
pub async fn poll_message_trigger(
    bus: &dyn Bus,
    binding: &Binding,
) -> Result<Option<roundhouse_bus::types::Envelope>, MessageTriggerError> {
    handle_parts(binding)?; // validates shape; the session id is what actually matters below
    Ok(bus.poll(binding.trigger_session_id()).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trigger::TriggerSpec;
    use roundhouse_bus::local_bus::LocalBus;
    use roundhouse_core::{JobId, SessionId};

    fn message_binding(name: &str) -> (Binding, WorkspaceId, Address) {
        let workspace = WorkspaceId::new();
        let address = Address::Handle {
            workspace,
            name: name.to_string(),
        };
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: address.clone(),
                filter: None,
            },
        );
        (binding, workspace, address)
    }

    #[tokio::test]
    async fn bind_registers_both_the_mailbox_and_the_handle() {
        let bus = LocalBus::new();
        let (binding, workspace, address) = message_binding("listener");

        bind_message_trigger(&bus, &binding).await.unwrap();

        assert!(bus.has_mailbox(binding.trigger_session_id()));
        let resolved = bus.resolve_address(workspace, &address).await.unwrap();
        assert_eq!(resolved, binding.trigger_session_id());
    }

    #[tokio::test]
    async fn unbind_removes_both_the_handle_and_the_mailbox() {
        let bus = LocalBus::new();
        let (binding, workspace, address) = message_binding("listener");
        bind_message_trigger(&bus, &binding).await.unwrap();

        unbind_message_trigger(&bus, &binding).await.unwrap();

        assert!(!bus.has_mailbox(binding.trigger_session_id()));
        assert!(bus.resolve_address(workspace, &address).await.is_err());
    }

    #[tokio::test]
    async fn binding_on_a_non_message_spec_is_refused() {
        let bus = LocalBus::new();
        let binding = Binding::new(JobId::new(), TriggerSpec::Manual);

        let err = bind_message_trigger(&bus, &binding).await.unwrap_err();
        assert!(matches!(
            err,
            MessageTriggerError::NotAMessageHandleTrigger(_)
        ));
    }

    #[tokio::test]
    async fn binding_a_message_trigger_whose_address_is_not_a_handle_is_refused() {
        let bus = LocalBus::new();
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: Address::Session {
                    id: SessionId::new(),
                },
                filter: None,
            },
        );

        let err = bind_message_trigger(&bus, &binding).await.unwrap_err();
        assert!(matches!(
            err,
            MessageTriggerError::NotAMessageHandleTrigger(_)
        ));
    }

    #[tokio::test]
    async fn poll_with_nothing_sent_yet_returns_none() {
        let bus = LocalBus::new();
        let (binding, _workspace, _address) = message_binding("listener");
        bind_message_trigger(&bus, &binding).await.unwrap();

        let received = poll_message_trigger(&bus, &binding).await.unwrap();
        assert!(received.is_none());
    }
}
