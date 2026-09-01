use crate::types::Envelope;
use roundhouse_core::SessionId;
use std::collections::HashMap;
use std::sync::Mutex;

/// §7.2/§7.7: `Address::Human`'s real delivery mechanism — "UI surfacing/notification,
/// not land-in-a-mailbox ... a human has no next turn." Never injected as a `message`
/// task the way a peer-to-peer reply is; it sits here until a UI client (a later
/// phase's TUI/web layer) polls or subscribes to it — this crate builds the mechanism,
/// not the rendering.
#[derive(Clone, Debug)]
pub struct HumanNotification {
    pub from: SessionId,
    pub envelope: Envelope,
    pub ts_unix_ms: i64,
}

/// Deliberately distinct from `Mailbox`/`MailboxKind` — human recipients never get a
/// `Mailbox` at all (`LocalBus::register_human`), so there is no capacity/backpressure
/// concept to apply here: §7.4's "Human mailboxes are unbounded" becomes, once a human
/// isn't a mailbox at all, simply "nothing here ever rejects for capacity."
pub struct HumanNotificationRegistry {
    by_session: Mutex<HashMap<SessionId, Vec<HumanNotification>>>,
}

impl HumanNotificationRegistry {
    pub fn new() -> Self {
        Self {
            by_session: Mutex::new(HashMap::new()),
        }
    }

    pub fn push(&self, session: SessionId, note: HumanNotification) {
        self.by_session
            .lock()
            .expect("human notification registry mutex poisoned")
            .entry(session)
            .or_default()
            .push(note);
    }

    /// Non-destructive read — a UI can poll repeatedly without losing history.
    pub fn list(&self, session: SessionId) -> Vec<HumanNotification> {
        self.by_session
            .lock()
            .expect("human notification registry mutex poisoned")
            .get(&session)
            .cloned()
            .unwrap_or_default()
    }

    /// Destructive read, for a UI that wants to mark everything pending as seen.
    pub fn drain(&self, session: SessionId) -> Vec<HumanNotification> {
        self.by_session
            .lock()
            .expect("human notification registry mutex poisoned")
            .remove(&session)
            .unwrap_or_default()
    }
}

impl Default for HumanNotificationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Address, Envelope, MessageId, Provenance, Trust};
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    fn envelope(from: SessionId, to: SessionId) -> Envelope {
        Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to,
            to_requested: Address::Human { session: to },
            subject: "heads up".into(),
            body: "the migration finished".into(),
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

    #[test]
    fn pushing_a_notification_makes_it_visible_via_list_without_removing_it() {
        let registry = HumanNotificationRegistry::new();
        let human = SessionId::new();
        let from = SessionId::new();
        registry.push(
            human,
            HumanNotification {
                from,
                envelope: envelope(from, human),
                ts_unix_ms: 0,
            },
        );

        assert_eq!(registry.list(human).len(), 1);
        assert_eq!(registry.list(human).len(), 1); // still there — list doesn't drain
    }

    #[test]
    fn draining_removes_everything_pending_for_that_session_only() {
        let registry = HumanNotificationRegistry::new();
        let human_a = SessionId::new();
        let human_b = SessionId::new();
        let from = SessionId::new();
        registry.push(
            human_a,
            HumanNotification {
                from,
                envelope: envelope(from, human_a),
                ts_unix_ms: 0,
            },
        );
        registry.push(
            human_b,
            HumanNotification {
                from,
                envelope: envelope(from, human_b),
                ts_unix_ms: 0,
            },
        );

        let drained = registry.drain(human_a);
        assert_eq!(drained.len(), 1);
        assert!(registry.list(human_a).is_empty());
        assert_eq!(registry.list(human_b).len(), 1); // untouched
    }
}
