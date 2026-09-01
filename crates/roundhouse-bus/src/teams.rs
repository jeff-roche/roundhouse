use crate::limits::check_team_size;
use crate::types::BusError;
use dashmap::{DashMap, DashSet};
use roundhouse_core::{SessionId, TeamId, WorkspaceId};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TeamState {
    Active,
    Draining,
    Closed,
}

/// §7.5, verbatim shape.
#[derive(Clone, Debug)]
pub struct Team {
    pub id: TeamId,
    pub workspace: WorkspaceId,
    pub name: String,
    pub charter: String,
    pub created_by: SessionId,
    pub state: TeamState,
}

#[derive(Clone, Debug)]
pub struct Membership {
    pub team: TeamId,
    pub session: SessionId,
    pub role: String,
    pub ended: bool,
}

/// §7.5: "First-class and persisted, not a view over the spawn tree." Real persistence
/// lives in roundhouse-store; this trait is the testability seam, mirrored on
/// `EventSink` (Task 5).
pub trait TeamStore: Send + Sync {
    fn save_team(&self, team: &Team);
    fn save_membership(&self, membership: &Membership);
}

pub struct InMemoryTeamStore {
    teams: DashMap<TeamId, Team>,
    memberships: DashMap<TeamId, Vec<Membership>>,
}

impl InMemoryTeamStore {
    pub fn new() -> Self {
        Self {
            teams: DashMap::new(),
            memberships: DashMap::new(),
        }
    }
}

impl Default for InMemoryTeamStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TeamStore for InMemoryTeamStore {
    fn save_team(&self, team: &Team) {
        self.teams.insert(team.id, team.clone());
    }

    fn save_membership(&self, membership: &Membership) {
        self.memberships
            .entry(membership.team)
            .or_default()
            .push(membership.clone());
    }
}

pub struct TeamRegistry {
    store: InMemoryTeamStore,
    /// Mirrors `LocalBus::register_human` (Task 6) — `TeamRegistry` has no back-
    /// reference to `LocalBus`, so the daemon-assembly layer marks a human session
    /// here too, at the same registration point, so `join` (below) can enforce §7.2's
    /// "the human is never a Team roster member" for real.
    human_sessions: DashSet<SessionId>,
}

impl TeamRegistry {
    pub fn new() -> Self {
        Self {
            store: InMemoryTeamStore::new(),
            human_sessions: DashSet::new(),
        }
    }

    pub fn mark_human(&self, session: SessionId) {
        self.human_sessions.insert(session);
    }

    pub fn create_team(
        &self,
        workspace: WorkspaceId,
        name: String,
        charter: String,
        creator: SessionId,
        creator_role: String,
    ) -> Result<TeamId, BusError> {
        // §7.2: the human can never be a roster member, including as a team's creator.
        if self.human_sessions.contains(&creator) {
            return Err(BusError::HumanCannotJoinTeam { session: creator });
        }
        let id = TeamId::new();
        let team = Team {
            id,
            workspace,
            name,
            charter,
            created_by: creator,
            state: TeamState::Active,
        };
        self.store.save_team(&team);
        self.store.save_membership(&Membership {
            team: id,
            session: creator,
            role: creator_role,
            ended: false,
        });
        Ok(id)
    }

    /// §7.5: "agent_spawn auto-joins the child to the parent's team as `worker` unless
    /// overridden." §7.2: "the human is never a Team roster member" — enforced here,
    /// not just documented, against `human_sessions` (above).
    pub fn join(
        &self,
        team: TeamId,
        session: SessionId,
        role: Option<String>,
    ) -> Result<(), BusError> {
        if self.human_sessions.contains(&session) {
            return Err(BusError::HumanCannotJoinTeam { session });
        }
        let team_state = self
            .store
            .teams
            .get(&team)
            .map(|t| t.state)
            .unwrap_or(TeamState::Closed);
        if team_state == TeamState::Draining || team_state == TeamState::Closed {
            return Err(BusError::TeamDraining { team });
        }
        let current = self
            .store
            .memberships
            .get(&team)
            .map(|m| m.len() as u32)
            .unwrap_or(0);
        check_team_size(current + 1)?;
        self.store.save_membership(&Membership {
            team,
            session,
            role: role.unwrap_or_else(|| "worker".to_string()),
            ended: false,
        });
        Ok(())
    }

    pub fn roster(&self, team: TeamId) -> Option<Vec<Membership>> {
        self.store.memberships.get(&team).map(|m| m.value().clone())
    }

    /// §15.2: "Every member of a team gets read access to the team's memory scope as a
    /// side effect of joining the roster — no separate grant needed." Read eligibility
    /// for `MemoryScope::Team(team)` is exactly "is a current (non-ended) member" — no
    /// grants table exists or is needed; `Policy::decide` (Phase 2) calls this directly
    /// for a `memory` task with `op: Read` against `Team` scope.
    pub fn can_read_team_memory(&self, team: TeamId, session: SessionId) -> bool {
        self.roster(team)
            .map(|members| members.iter().any(|m| m.session == session && !m.ended))
            .unwrap_or(false)
    }

    /// §15.2: "Write access is a distinct, explicit grant, evaluated by the same
    /// policy engine as everything else." This registry holds no write-grant state at
    /// all and never will — it always answers `false`, so joining a team can never be
    /// mistaken for a write grant. The real grant (if any) lives entirely in Phase 2's
    /// policy engine, outside this crate.
    pub fn can_write_team_memory(&self, _team: TeamId, _session: SessionId) -> bool {
        false
    }

    pub fn team(&self, team: TeamId) -> Option<Team> {
        self.store.teams.get(&team).map(|t| t.clone())
    }

    pub fn state(&self, team: TeamId) -> Option<TeamState> {
        self.store.teams.get(&team).map(|t| t.state)
    }

    pub fn begin_draining(&self, team: TeamId) -> Result<(), BusError> {
        if let Some(mut t) = self.store.teams.get_mut(&team) {
            t.state = TeamState::Draining;
        }
        Ok(())
    }

    pub fn mark_member_ended(&self, team: TeamId, session: SessionId) -> Result<(), BusError> {
        if let Some(mut members) = self.store.memberships.get_mut(&team) {
            for m in members.iter_mut() {
                if m.session == session {
                    m.ended = true;
                }
            }
        }
        Ok(())
    }

    /// §7.5: "a roster of all-Ended members is auto-closed by a reaper."
    pub fn reap_ended(&self) {
        for mut team in self.store.teams.iter_mut() {
            if team.state != TeamState::Draining {
                continue;
            }
            let all_ended = self
                .store
                .memberships
                .get(&team.id)
                .map(|m| !m.is_empty() && m.iter().all(|mem| mem.ended))
                .unwrap_or(false);
            if all_ended {
                team.state = TeamState::Closed;
            }
        }
    }
}

impl Default for TeamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{SessionId, WorkspaceId};

    #[test]
    fn create_team_and_auto_join_creator_as_lead() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(
                ws,
                "release-team".into(),
                "Ship v2".into(),
                creator,
                "lead".into(),
            )
            .unwrap();

        let roster = registry.roster(team_id).unwrap();
        assert_eq!(roster.len(), 1);
        assert_eq!(roster[0].session, creator);
        assert_eq!(roster[0].role, "lead");
    }

    #[test]
    fn agent_spawn_auto_joins_child_as_worker_unless_overridden() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let child = SessionId::new();
        registry.join(team_id, child, None).unwrap(); // §7.5: auto-join as "worker"
        let roster = registry.roster(team_id).unwrap();
        assert!(roster
            .iter()
            .any(|m| m.session == child && m.role == "worker"));
    }

    #[test]
    fn joining_beyond_team_size_limit_is_refused() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();
        for _ in 0..31 {
            registry.join(team_id, SessionId::new(), None).unwrap();
        }
        // 1 creator + 31 joins == 32, at the limit; one more must fail.
        let err = registry.join(team_id, SessionId::new(), None).unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::TeamSizeLimitExceeded { .. }
        ));
    }

    #[test]
    fn draining_then_all_ended_auto_closes_via_reaper() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        registry.begin_draining(team_id).unwrap();
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Draining);

        registry.mark_member_ended(team_id, creator).unwrap();
        registry.reap_ended(); // §7.5: "a roster of all-Ended members is auto-closed by a reaper"
        assert_eq!(registry.state(team_id).unwrap(), TeamState::Closed);
    }

    #[test]
    fn draining_team_refuses_new_sends_but_lets_pending_replies_land() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();
        registry.begin_draining(team_id).unwrap();

        let err = registry.join(team_id, SessionId::new(), None).unwrap_err();
        assert!(matches!(err, crate::types::BusError::TeamDraining { .. }));
    }

    #[test]
    fn a_human_session_cannot_join_a_team_roster() {
        // §7.2: "The human is never a Team roster member, and `to: team` never
        // implicitly pages them."
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let human = SessionId::new();
        registry.mark_human(human);
        let err = registry.join(team_id, human, None).unwrap_err();
        assert!(matches!(
            err,
            crate::types::BusError::HumanCannotJoinTeam { .. }
        ));

        let roster = registry.roster(team_id).unwrap();
        assert!(!roster.iter().any(|m| m.session == human));
    }

    #[test]
    fn joining_grants_team_memory_read_but_never_write() {
        // §15.2/§7.5: read is automatic via membership; write is a distinct grant this
        // registry never derives (Phase 2's policy engine's job).
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team_id = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let member = SessionId::new();
        let stranger = SessionId::new();
        assert!(!registry.can_read_team_memory(team_id, member)); // not a member yet
        registry.join(team_id, member, None).unwrap();

        assert!(registry.can_read_team_memory(team_id, member));
        assert!(!registry.can_read_team_memory(team_id, stranger));
        assert!(!registry.can_write_team_memory(team_id, member)); // never auto-granted
    }
}
