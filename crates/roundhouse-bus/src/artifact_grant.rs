use crate::types::ArtifactRef;
use dashmap::DashSet;
use roundhouse_core::SessionId;

/// §7.4: attachment-is-grant. Tracks, per recipient session, exactly which
/// `ArtifactRef`s it has been handed via a message attachment and may therefore
/// dereference — nothing else, regardless of what it could otherwise guess the id of.
pub struct AttachmentGrants {
    grants: DashSet<(SessionId, ArtifactRef)>,
}

impl AttachmentGrants {
    pub fn new() -> Self {
        Self {
            grants: DashSet::new(),
        }
    }

    pub fn grant_from_envelope(&self, recipient: SessionId, attachments: &[ArtifactRef]) {
        for artifact in attachments {
            self.grants.insert((recipient, artifact.clone()));
        }
    }

    pub fn is_dereferenceable(&self, session: SessionId, artifact: &ArtifactRef) -> bool {
        self.grants.contains(&(session, artifact.clone()))
    }
}

impl Default for AttachmentGrants {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ArtifactRef;
    use roundhouse_core::{SessionId, TaskId};

    #[test]
    fn attaching_a_task_ref_grants_the_recipient_dereference_rights() {
        let grants = AttachmentGrants::new();
        let recipient = SessionId::new();
        let artifact = ArtifactRef::Task {
            session: SessionId::new(),
            task: TaskId::new(),
        };

        grants.grant_from_envelope(recipient, std::slice::from_ref(&artifact));

        assert!(grants.is_dereferenceable(recipient, &artifact));
    }

    #[test]
    fn a_session_cannot_dereference_an_artifact_never_attached_to_it() {
        let grants = AttachmentGrants::new();
        let recipient = SessionId::new();
        let never_attached = ArtifactRef::Task {
            session: SessionId::new(),
            task: TaskId::new(),
        };

        // §7.4: "Dereferencing a peer's ArtifactRef::Task is permitted because the peer
        // attached it — the attachment is the capability grant. Without that rule,
        // messaging is a hole straight through session isolation."
        assert!(!grants.is_dereferenceable(recipient, &never_attached));
    }
}
