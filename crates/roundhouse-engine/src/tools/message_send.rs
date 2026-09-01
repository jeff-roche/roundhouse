//! `message_send` tool executor (Task 13).

use roundhouse_bus::types::{
    Address, ArtifactRef, BusError, Envelope, ExpectReply, MessageId, Provenance, Trust,
};
use roundhouse_bus::Bus;
use roundhouse_core::{Origin, SessionId, WorkspaceId};
use uuid::Uuid;

/// What `message_send` hands back: every recipient this send actually resolved to (one
/// for point-to-point, N for a `Team`/`Role` fan-out, §7.5) and the `MessageId` minted
/// for each. §7.1's "no envelope fan-out shortcut" means a fan-out send is N distinct
/// outbound `message` tasks, not one envelope multicast, so there is no single
/// `MessageId` to hand back once `to` can resolve to a roster instead of one session.
pub struct SendOutcome {
    pub message_ids: Vec<MessageId>,
    pub recipients: Vec<SessionId>,
}

/// The `message_send` tool executor (§7.6). Resolves `to` daemon-side (§7.2) via
/// `Bus::resolve_recipients` (Task 12) — expanding to every current team member for
/// `Address::Team` and every matching-role member for `Address::Role` (§7.5's fan-out)
/// rather than refusing them, per §7.1: "messages are Tasks on both sides," so a
/// fan-out send appends one outbound `message` task per resolved recipient, never a
/// single multicast envelope. Stamps `Trust::Untrusted` provenance for the
/// *recipient's* view unconditionally (§6.8) — the sender's own outbound copy carries
/// its own session's normal provenance; it is the inbound envelope on the other end
/// that always reads as Untrusted regardless of phrasing. `ttl_hops`
/// decrementing/validation and the rate cap/repetition damper are enforced by the
/// `Bus` itself (`LocalBus::send`, Task 12), not duplicated here.
pub async fn message_send(
    bus: &dyn Bus,
    workspace: WorkspaceId,
    from: SessionId,
    to: Address,
    subject: String,
    body: String,
    attachments: Vec<ArtifactRef>,
    expect_reply: Option<ExpectReply>,
    ttl_hops: u8,
) -> Result<SendOutcome, BusError> {
    let recipients = bus.resolve_recipients(workspace, &to).await?;
    let mut message_ids = Vec::with_capacity(recipients.len());

    for &resolved_to in &recipients {
        let id = MessageId(Uuid::new_v4());
        let envelope = Envelope {
            id,
            from,
            to: resolved_to,
            to_requested: to.clone(),
            subject: subject.clone(),
            body: body.clone(),
            attachments: attachments.clone(),
            expect_reply: expect_reply.clone(),
            in_reply_to: None,
            ttl_hops,
            // §6.8: "every peer message is Trust::Untrusted regardless of how it's
            // phrased" — this is the provenance the *recipient* will see on the
            // inbound copy.
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        };
        bus.send(envelope).await?;
        message_ids.push(id);
    }

    Ok(SendOutcome {
        message_ids,
        recipients,
    })
}
