//! `team_close` tool executor (Task 15).
//!
//! Re-exported from `team_create.rs` to keep the create/close pair colocated with the
//! `TeamRegistry` calls they wrap; this file hosts the close-path-specific test only.

pub use crate::tools::team_create::team_close;

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::teams::{TeamRegistry, TeamState};
    use roundhouse_core::{SessionId, TeamId, WorkspaceId};

    #[test]
    fn team_close_begins_draining_not_immediate_close() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        team_close(&registry, team_id, creator).unwrap();
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Draining);
    }

    #[test]
    fn lead_who_is_not_creator_can_close() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let other_lead = SessionId::new();
        registry
            .join(team_id, other_lead, Some("lead".into()))
            .unwrap();

        team_close(&registry, team_id, other_lead).unwrap();
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Draining);
    }

    #[test]
    fn non_lead_member_cannot_close() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let worker = SessionId::new();
        registry.join(team_id, worker, None).unwrap();

        let err = team_close(&registry, team_id, worker).unwrap_err();
        assert!(matches!(
            err,
            roundhouse_bus::types::BusError::NotAuthorized { team, caller }
                if team == team_id && caller == worker
        ));
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Active);
    }

    #[test]
    fn closing_unknown_team_returns_unknown_handle() {
        let registry = TeamRegistry::new();
        let caller = SessionId::new();

        let err = team_close(&registry, TeamId::new(), caller).unwrap_err();
        assert!(matches!(
            err,
            roundhouse_bus::types::BusError::UnknownHandle { .. }
        ));
    }
}
