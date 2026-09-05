use crate::ids::{TeamId, WorkspaceId};
use serde::{Deserialize, Serialize};

/// §15.1 — the three memory scopes the system recognizes, and no others.
/// This is a closed set by design: `User` (private to one user, no sharing),
/// `Project` (shared within one workspace), and `Team` (shared across a
/// team's sessions, gated by team membership — see
/// `roundhouse_policy::TeamMembership`). Exactly three variants, no fourth —
/// do not add a catch-all or a fourth scope without revisiting §15.1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryScope {
    User,
    Project { workspace: WorkspaceId },
    Team { team: TeamId },
}
