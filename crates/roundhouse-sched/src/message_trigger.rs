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
    /// H1(a): a `Binding`'s `TriggerSpec::Message` address names its own
    /// `workspace` — that field is the *spec's claim*, not proof of
    /// ownership. `Binding` carries no owning workspace of its own to check
    /// it against, so the caller (whoever creates the binding from a job in
    /// a specific workspace) must supply the true owning workspace, and this
    /// error is what a spec naming a *different* workspace produces —
    /// otherwise a binding authored in workspace A could register a handle
    /// in workspace B.
    #[error(
        "Message binding {binding} names workspace {spec_workspace:?}, but is owned by workspace {owning_workspace:?}"
    )]
    WorkspaceMismatch {
        binding: String,
        spec_workspace: WorkspaceId,
        owning_workspace: WorkspaceId,
    },
    /// M4: `filter` narrows which messages reaching the bound handle
    /// actually fire the trigger, but evaluating it needs `roundhouse-flow`'s
    /// `${{ }}` expression engine, which this crate cannot depend on (the
    /// edge points the other way). Every envelope arriving at a `Message`
    /// trigger's handle is `Trust::Untrusted`/`Origin::Peer` by construction
    /// (§6.8), and `filter` is the only narrowing between an untrusted
    /// peer's message and starting a job — so a binding carrying `Some(_)`
    /// is refused outright (fail-closed) rather than silently firing on any
    /// message that reaches the handle (fail-open).
    #[error(
        "Message binding {0} carries a filter, but filter evaluation is not yet wired — refusing to fire unfiltered"
    )]
    FilterNotYetSupported(String),
    #[error(transparent)]
    Bus(#[from] roundhouse_bus::BusError),
}

/// Extracts `(workspace, name, filter)` from a `Message` binding whose
/// address is a `Handle`, and validates that the spec's claimed workspace
/// matches `owning_workspace` (H1(a) — `Binding` itself carries no owning
/// workspace, so the caller must supply the true one; the spec's own field
/// is a claim to check, never an instruction to act on).
fn handle_parts(
    binding: &Binding,
    owning_workspace: WorkspaceId,
) -> Result<(WorkspaceId, &str, &Option<String>), MessageTriggerError> {
    match &binding.spec {
        TriggerSpec::Message {
            address: Address::Handle { workspace, name },
            filter,
        } => {
            if *workspace != owning_workspace {
                return Err(MessageTriggerError::WorkspaceMismatch {
                    binding: binding.id.to_string(),
                    spec_workspace: *workspace,
                    owning_workspace,
                });
            }
            Ok((*workspace, name.as_str(), filter))
        }
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
///
/// `owning_workspace` is the workspace the binding's own job actually
/// belongs to (H1(a)) — the caller's trusted context, not the address's own
/// embedded field, which is only validated against it.
///
/// M4: refuses with `MessageTriggerError::FilterNotYetSupported` when the
/// binding carries `Some(filter)` — filter evaluation is not wired yet, and
/// binding anyway would let *any* message reaching the handle fire the
/// trigger unfiltered, which is worse than refusing to bind at all.
pub async fn bind_message_trigger(
    bus: &dyn Bus,
    owning_workspace: WorkspaceId,
    binding: &Binding,
) -> Result<(), MessageTriggerError> {
    let (workspace, name, filter) = handle_parts(binding, owning_workspace)?;
    if filter.is_some() {
        return Err(MessageTriggerError::FilterNotYetSupported(
            binding.id.to_string(),
        ));
    }
    let session = binding.trigger_session_id();
    bus.register_mailbox(session, MailboxKind::Bounded(64))
        .await?;
    bus.register_handle(workspace, name.to_string(), session)
        .await?;
    Ok(())
}

/// Reverses `bind_message_trigger`. Unlike bind/poll, this is NOT refused
/// for a binding carrying `Some(filter)` — tearing down a registration must
/// always be possible regardless of whether the trigger it belonged to was
/// ever actually bindable.
pub async fn unbind_message_trigger(
    bus: &dyn Bus,
    owning_workspace: WorkspaceId,
    binding: &Binding,
) -> Result<(), MessageTriggerError> {
    let (workspace, name, _filter) = handle_parts(binding, owning_workspace)?;
    let session = binding.trigger_session_id();
    bus.unregister_handle(workspace, name, session).await?;
    bus.deregister_mailbox(session).await?;
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
/// `bus.poll` *removes* the returned envelope from the mailbox. Whoever
/// eventually evaluates `filter` after polling (once M4's gap is closed and
/// filter evaluation actually exists) MUST call `Bus::requeue` on a
/// non-match — `poll_message_trigger` itself never does, since it always
/// refuses bindings that carry a filter (M4) rather than returning an
/// envelope that still needs filtering.
///
/// M4: refuses with `MessageTriggerError::FilterNotYetSupported` when the
/// binding carries `Some(filter)`, for the same fail-closed reason as
/// `bind_message_trigger` — a binding that could never legally be bound
/// must never be polled either.
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
    owning_workspace: WorkspaceId,
    binding: &Binding,
) -> Result<Option<roundhouse_bus::types::Envelope>, MessageTriggerError> {
    let (_workspace, _name, filter) = handle_parts(binding, owning_workspace)?;
    if filter.is_some() {
        return Err(MessageTriggerError::FilterNotYetSupported(
            binding.id.to_string(),
        ));
    }
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

        bind_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap();

        assert!(bus.has_mailbox(binding.trigger_session_id()));
        let resolved = bus.resolve_address(workspace, &address).await.unwrap();
        assert_eq!(resolved, binding.trigger_session_id());
    }

    #[tokio::test]
    async fn unbind_removes_both_the_handle_and_the_mailbox() {
        let bus = LocalBus::new();
        let (binding, workspace, address) = message_binding("listener");
        bind_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap();

        unbind_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap();

        assert!(!bus.has_mailbox(binding.trigger_session_id()));
        assert!(bus.resolve_address(workspace, &address).await.is_err());
    }

    #[tokio::test]
    async fn binding_on_a_non_message_spec_is_refused() {
        let bus = LocalBus::new();
        let binding = Binding::new(JobId::new(), TriggerSpec::Manual);

        let err = bind_message_trigger(&bus, WorkspaceId::new(), &binding)
            .await
            .unwrap_err();
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

        let err = bind_message_trigger(&bus, WorkspaceId::new(), &binding)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MessageTriggerError::NotAMessageHandleTrigger(_)
        ));
    }

    /// H1(a): a spec naming a workspace different from the binding's real
    /// owning workspace must be refused, not silently registered under
    /// whichever workspace the spec happens to claim.
    #[tokio::test]
    async fn binding_whose_spec_workspace_does_not_match_the_owning_workspace_is_refused() {
        let bus = LocalBus::new();
        let spec_workspace = WorkspaceId::new();
        let owning_workspace = WorkspaceId::new();
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: Address::Handle {
                    workspace: spec_workspace,
                    name: "listener".to_string(),
                },
                filter: None,
            },
        );

        let err = bind_message_trigger(&bus, owning_workspace, &binding)
            .await
            .unwrap_err();
        assert!(matches!(err, MessageTriggerError::WorkspaceMismatch { .. }));
        // Nothing must have been registered on the bus as a side effect of
        // the refused attempt.
        assert!(!bus.has_mailbox(binding.trigger_session_id()));
    }

    #[tokio::test]
    async fn poll_with_nothing_sent_yet_returns_none() {
        let bus = LocalBus::new();
        let (binding, workspace, _address) = message_binding("listener");
        bind_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap();

        let received = poll_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap();
        assert!(received.is_none());
    }

    /// M4: a binding carrying a filter must never bind, and must never
    /// poll — fail-closed, since filter evaluation does not exist yet and
    /// every envelope reaching the handle is untrusted peer input.
    #[tokio::test]
    async fn a_binding_with_a_filter_is_refused_at_bind_time() {
        let bus = LocalBus::new();
        let workspace = WorkspaceId::new();
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: Address::Handle {
                    workspace,
                    name: "listener".to_string(),
                },
                filter: Some("payload.outcome == 'ok'".to_string()),
            },
        );

        let err = bind_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap_err();
        assert!(matches!(err, MessageTriggerError::FilterNotYetSupported(_)));
        assert!(!bus.has_mailbox(binding.trigger_session_id()));
    }

    #[tokio::test]
    async fn a_binding_with_a_filter_is_refused_at_poll_time_even_if_somehow_bound() {
        let bus = LocalBus::new();
        let workspace = WorkspaceId::new();
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: Address::Handle {
                    workspace,
                    name: "listener".to_string(),
                },
                filter: Some("payload.outcome == 'ok'".to_string()),
            },
        );

        let err = poll_message_trigger(&bus, workspace, &binding)
            .await
            .unwrap_err();
        assert!(matches!(err, MessageTriggerError::FilterNotYetSupported(_)));
    }

    #[tokio::test]
    async fn unbind_is_allowed_even_for_a_binding_carrying_a_filter() {
        // Unbind must always be possible for cleanup, regardless of whether
        // the trigger it belonged to was ever bindable in the first place.
        let bus = LocalBus::new();
        let workspace = WorkspaceId::new();
        let binding = Binding::new(
            JobId::new(),
            TriggerSpec::Message {
                address: Address::Handle {
                    workspace,
                    name: "listener".to_string(),
                },
                filter: Some("payload.outcome == 'ok'".to_string()),
            },
        );

        unbind_message_trigger(&bus, workspace, &binding)
            .await
            .expect("unbind is never refused for filter presence");
    }
}
