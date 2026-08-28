use crate::ids::{SessionId, TeamId, WorkspaceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// §7.2 — the one routing primitive. Ids are truth, handles are UX:
/// `(workspace, name) -> SessionId` is resolved daemon-side at send time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum Address {
    Session { id: SessionId },
    Handle { workspace: WorkspaceId, name: String },
    Team { team: TeamId },
    Role { team: TeamId, role: String },
    /// Never blocked by policy — see §7.2: the human is never a `Team` roster member.
    Human { session: SessionId },
}
