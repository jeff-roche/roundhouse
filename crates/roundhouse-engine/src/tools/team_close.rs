//! `team_close` tool executor (Task 15).
//!
//! Re-exported from `team_create.rs` to keep the create/close pair colocated with the
//! `TeamRegistry` calls they wrap; this file hosts the close-path-specific test only.

pub use crate::tools::team_create::team_close;

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::teams::{TeamRegistry, TeamState};
    use roundhouse_core::{SessionId, WorkspaceId};

    #[test]
    fn team_close_begins_draining_not_immediate_close() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        team_close(&registry, team_id).unwrap();
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Draining);
    }
}
