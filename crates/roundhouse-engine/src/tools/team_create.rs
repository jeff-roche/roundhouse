//! `team_create`/`team_close` tool executors (Task 15).

use roundhouse_bus::teams::TeamRegistry;
use roundhouse_bus::types::BusError;
use roundhouse_core::{SessionId, TeamId, WorkspaceId};

/// The `team_create` tool (§7.6). The creator is auto-joined with the role it names
/// (defaulting to "lead" is a UX convention, not a spec requirement — §7.5 only fixes
/// the *auto-join-as-worker* rule for `agent_spawn`, not team_create's creator role).
pub fn team_create(
    registry: &TeamRegistry,
    workspace: WorkspaceId,
    name: String,
    charter: String,
    creator: SessionId,
    creator_role: Option<String>,
) -> Result<TeamId, BusError> {
    registry.create_team(
        workspace,
        name,
        charter,
        creator,
        creator_role.unwrap_or_else(|| "lead".into()),
    )
}

/// The `team_close` tool. Only begins draining — §7.5's "Draining (no new sends,
/// pending replies land) -> Closed" teardown is completed by the reaper once every
/// member has ended, not by this call directly.
///
/// Authorization: the caller must be the team's creator or hold the "lead" role on the
/// roster. Any other session gets `NotAuthorized`, and a missing team is reported as
/// `UnknownHandle` (no `TeamNotFound`).
pub fn team_close(
    registry: &TeamRegistry,
    team: TeamId,
    caller: SessionId,
) -> Result<(), BusError> {
    let team_record = registry.team(team).ok_or_else(|| BusError::UnknownHandle {
        workspace: WorkspaceId::new(),
        name: "<unknown team>".into(),
    })?;

    let authorized = team_record.created_by == caller
        || registry
            .roster(team)
            .map(|roster| {
                roster
                    .iter()
                    .any(|m| m.session == caller && m.role == "lead")
            })
            .unwrap_or(false);

    if !authorized {
        return Err(BusError::NotAuthorized { team, caller });
    }

    registry.begin_draining(team)
}
