use roundhouse_core::{SessionId, TaskId, TeamId, WorkspaceId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use roundhouse_core::Address;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Trust {
    Trusted,
    Untrusted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provenance {
    pub origin: roundhouse_core::Origin,
    pub trust: Trust,
    pub task: Option<TaskId>,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum ArtifactRef {
    Task {
        session: SessionId,
        task: TaskId,
    },
    File {
        workspace: WorkspaceId,
        path: std::path::PathBuf,
    },
    Blob {
        hash: [u8; 32],
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Quorum {
    Any,
    All,
    AtLeast(u32),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpectReply {
    pub quorum: Quorum,
    pub deadline: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub id: MessageId,
    pub from: SessionId,
    pub to: SessionId,
    pub to_requested: Address,
    pub subject: String,
    pub body: String,
    pub attachments: Vec<ArtifactRef>,
    pub expect_reply: Option<ExpectReply>,
    pub in_reply_to: Option<MessageId>,
    pub ttl_hops: u8,
    pub provenance: Provenance,
}

impl Envelope {
    pub fn to_core_envelope(&self) -> roundhouse_core::Envelope {
        roundhouse_core::Envelope {
            from: Address::Session { id: self.from },
            to: self.to_requested.clone(),
            body: roundhouse_core::TaskInput::Text(self.body.clone()),
            expect_reply: self.expect_reply.is_some(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Undeliverable {
    Ended { session: SessionId },
}

#[derive(thiserror::Error, Debug)]
pub enum BusError {
    #[error("undeliverable: {0:?}")]
    Undeliverable(Undeliverable),
    #[error("mailbox for {session:?} is full (capacity {capacity})")]
    MailboxFull { session: SessionId, capacity: usize },
    #[error("waiting on {blocked_on:?} would deadlock: cycle {cycle:?}")]
    WaitWouldDeadlock {
        waiter: SessionId,
        blocked_on: SessionId,
        cycle: Vec<SessionId>,
    },
    #[error("rate limited, retry after {retry_after_ms}ms")]
    RateLimited {
        session: SessionId,
        retry_after_ms: u64,
    },
    #[error("repeated send to {to:?} with subject {subject:?} refused (livelock damper)")]
    Repetitive { to: SessionId, subject: String },
    #[error("message ttl_hops expired")]
    TtlExpired,
    #[error("no handle {name:?} registered in workspace {workspace:?}")]
    UnknownHandle {
        workspace: WorkspaceId,
        name: String,
    },
    /// H2: `register_handle` refuses to silently steal a name a *different*
    /// session already holds — without this, whichever binding registers
    /// second would silently take over the name and receive the first
    /// binding's payloads, with no error and no log.
    #[error(
        "handle {name:?} in workspace {workspace:?} is already registered to a different session"
    )]
    HandleAlreadyRegistered {
        workspace: WorkspaceId,
        name: String,
    },
    /// H2: `unregister_handle` is a compare-and-remove against the caller's
    /// own session, not a bare remove-by-name — without this, unbinding your
    /// own trigger could delete a mapping a different session owns.
    #[error("caller does not own handle {name:?} in workspace {workspace:?}; unregister refused")]
    NotAuthorizedForHandle {
        workspace: WorkspaceId,
        name: String,
    },
    #[error("depth limit exceeded: {depth} > {max}")]
    DepthLimitExceeded { depth: u8, max: u8 },
    #[error("fan-out limit exceeded: {count} > {max}")]
    FanOutLimitExceeded { count: u32, max: u32 },
    #[error("team size limit exceeded: {count} > {max}")]
    TeamSizeLimitExceeded { count: u32, max: u32 },
    #[error("team {team:?} is draining and refuses new members/sends")]
    TeamDraining { team: TeamId },
    #[error("session {caller:?} is not authorized to close team {team:?}")]
    NotAuthorized { team: TeamId, caller: SessionId },
    #[error("session {session:?} is a human and can never join a team roster (§7.2)")]
    HumanCannotJoinTeam { session: SessionId },
    /// A `Team`/`Role` address resolved to zero live recipients (every member has
    /// ended, or none holds the requested role). Returning `Ok(vec![])` here instead
    /// would let `message_send` "succeed" with nothing sent, and a caller doing
    /// `message_wait(Quorum::All)` on that empty send registers no wait-graph edges
    /// and has no deadlock detector to ever catch the resulting hang.
    #[error("address for team {team:?} (role {role:?}) resolved to zero live recipients")]
    NoLiveRecipients { team: TeamId, role: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{Origin, SessionId};
    use uuid::Uuid;

    #[test]
    fn envelope_records_resolved_recipient_not_the_requested_address() {
        let from = SessionId::new();
        let resolved_to = SessionId::new();
        let requested = Address::Handle {
            workspace: roundhouse_core::WorkspaceId::new(),
            name: "reviewer".into(),
        };

        let env = Envelope {
            id: MessageId(Uuid::new_v4()),
            from,
            to: resolved_to,
            to_requested: requested,
            subject: "review-request".into(),
            body: "please review PR 42".into(),
            attachments: vec![],
            expect_reply: Some(ExpectReply {
                quorum: Quorum::Any,
                deadline: None,
            }),
            in_reply_to: None,
            ttl_hops: 8,
            provenance: Provenance {
                origin: Origin::Peer,
                trust: Trust::Untrusted,
                task: None,
            },
        };

        assert_eq!(env.to, resolved_to);
        assert_eq!(env.provenance.trust, Trust::Untrusted);
    }
}
