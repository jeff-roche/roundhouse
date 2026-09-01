//! Unsolicited inbound-message rendering (Task 14).

use roundhouse_bus::types::{Envelope, MessageId, Trust};

#[derive(Debug)]
pub enum RenderedInbound {
    /// §7.6: "A reply arriving while the agent is parked in message_wait renders as
    /// the tool_result of that pending call."
    ToolResult {
        pending_call: MessageId,
        body: String,
    },
    /// §7.6: "An unsolicited message ... renders as a system-level/injected context
    /// note — never a synthetic user turn ... every peer message is Trust::Untrusted
    /// regardless of how it's phrased in context."
    SystemInjection {
        from_subject: String,
        body: String,
        trust: Trust,
    },
}

/// `pending_wait` is `Some(id)` iff the recipient session currently has an outstanding
/// `message_wait` on message `id`. This mirrors §7.6's rule exactly: only an envelope
/// whose `in_reply_to` matches the one specific pending call renders as its tool
/// result; everything else — including an unrelated reply — is unsolicited from this
/// turn's point of view.
pub fn render_inbound(envelope: &Envelope, pending_wait: Option<MessageId>) -> RenderedInbound {
    match (envelope.in_reply_to, pending_wait) {
        (Some(reply_to), Some(pending)) if reply_to == pending => RenderedInbound::ToolResult {
            pending_call: pending,
            body: envelope.body.clone(),
        },
        _ => RenderedInbound::SystemInjection {
            from_subject: envelope.subject.clone(),
            body: envelope.body.clone(),
            // §6.8: exactly two trust levels; peer messages are always Untrusted here,
            // independent of whatever the envelope's own provenance.trust says, so a
            // future bug in provenance construction can't silently upgrade trust.
            trust: Trust::Untrusted,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(in_reply_to: Option<MessageId>) -> Envelope {
        let to = SessionId::new();
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from: SessionId::new(),
            to,
            to_requested: Address::Session { id: to },
            subject: "s".into(),
            body: "hello".into(),
            attachments: vec![],
            expect_reply: None,
            in_reply_to,
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        }
    }

    #[test]
    fn a_reply_to_a_pending_wait_renders_as_a_tool_result() {
        let pending = MessageId(Uuid::new_v4());
        let env = envelope(Some(pending));
        let rendered = render_inbound(&env, Some(pending));
        assert!(matches!(rendered, RenderedInbound::ToolResult { .. }));
    }

    #[test]
    fn an_unsolicited_message_renders_as_system_framed_injection_never_a_user_turn() {
        let env = envelope(None);
        let rendered = render_inbound(&env, None);
        match rendered {
            RenderedInbound::SystemInjection { trust, .. } => assert_eq!(trust, Trust::Untrusted),
            other => panic!("expected SystemInjection, got {other:?}"),
        }
    }

    #[test]
    fn a_reply_that_does_not_match_the_pending_wait_id_still_renders_as_injection() {
        let pending = MessageId(Uuid::new_v4());
        let other_reply_to = Some(MessageId(Uuid::new_v4()));
        let env = envelope(other_reply_to);
        // §7.3: extra replies beyond the one that resolved the wait "arrive as
        // ordinary inbound message tasks at their own next turn boundary."
        let rendered = render_inbound(&env, Some(pending));
        assert!(matches!(rendered, RenderedInbound::SystemInjection { .. }));
    }
}
