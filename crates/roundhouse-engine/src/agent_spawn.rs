use roundhouse_bus::limits::{check_depth, check_fan_out};
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_bus::types::BusError;
use roundhouse_core::{OnDegrade, SessionId, SessionSpec, TeamId, Tier, WorkspaceId};

/// §7.7: "Budget inheritance is a transfer, not a grant." Not a Phase 0 core type
/// (Phase 0 ships no `Budget` at all) — this plan's own, local to its only consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub remaining_tokens: u64,
}

/// §6.8's actual taint type is `roundhouse_policy::Taint { Trusted, Tainted }` — a
/// two-value enum, not a set. This is the union-on-return wrapper §6.8 needs ("union
/// of Taint over everything since the session's last human turn"), built over the real
/// `roundhouse_policy::Taint`. Lives here rather than in `roundhouse-bus::types`
/// (alongside `Trust`/`Provenance`) because `roundhouse-bus` may only depend on
/// `core, store` per §5.2's crate table — no `roundhouse-policy` edge — and
/// `roundhouse-engine` is allowed to depend on `roundhouse-policy`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaintSet {
    pub tainted: bool,
}

impl TaintSet {
    pub fn from_taint(t: roundhouse_policy::Taint) -> Self {
        TaintSet {
            tainted: matches!(t, roundhouse_policy::Taint::Tainted),
        }
    }

    pub fn union(self, other: TaintSet) -> TaintSet {
        TaintSet {
            tainted: self.tainted || other.tainted,
        }
    }
}

/// `AgentSpawnInput` (below) is this executor's own flat, Phase-4-local spawn-request
/// shape — see the `SpawnRequest` example in the "Phase 4-local types" section at the
/// top of this plan for the canonical wrap-not-extend pattern this follows: it never
/// assumes Phase 0's real, minimal `SessionSpec { workspace, name }` grows a `parent`/
/// `depth`/`provider`/`taint`/`team`/`budget_tokens` field, it just carries them
/// alongside a `SessionSpec` this executor builds separately when it constructs the
/// child (`SessionSpec { workspace: input.workspace, name: Some(handle.clone()) }`,
/// below).
///
/// §6.1's spawn-boundary rule, applied to credentials specifically (§9.9): "a child
/// resolves its own [credentials], and only for a provider it was explicitly
/// authorized to use ... evaluated by the parent's own policy scope before the child
/// is created." This trait is the seam `roundhouse-policy` implements in the daemon;
/// kept minimal here so this crate's tests don't need a real policy engine.
pub trait SpawnPolicyScope {
    fn authorizes_provider(&self, provider: &str) -> bool;
}

#[derive(Debug)]
pub struct AgentSpawnInput {
    pub workspace: WorkspaceId,
    pub parent: SessionId,
    pub parent_depth: u8,
    pub parent_direct_children: u32,
    pub team: Option<TeamId>,
    pub role: Option<String>,
    pub provider: String,
    pub budget_tokens: u64,
    pub parent_taint: TaintSet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildSpecSummary {
    pub taint: TaintSet,
    pub depth: u8,
}

#[derive(Debug)]
pub struct AgentSpawnOutput {
    pub session_id: SessionId,
    pub handle: String,
    pub child_budget: Budget,
    pub child_spec: ChildSpecSummary,
    /// The real `SessionSpec` for the child, built here rather than assumed to
    /// already carry `parent`/`depth`/`taint`/etc. (those stay on
    /// `AgentSpawnInput`/`ChildSpecSummary`, this executor's own types).
    pub session_spec: SessionSpec,
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error("provider {provider:?} not authorized by parent's policy scope")]
    ProviderNotAuthorized { provider: String },
    #[error("insufficient parent budget: requested {requested}, remaining {remaining}")]
    InsufficientBudget { requested: u64, remaining: u64 },
    #[error(transparent)]
    Bus(#[from] BusError),
}

/// The `agent` task executor (§4.2 table row, §7.2, §7.5, §6.1's spawn-boundary rule).
/// Order matters: every refusal below happens *before* the budget transfer or team
/// join, so a rejected spawn leaves the parent's budget and team roster untouched —
/// exactly what the "refused before any transfer" test asserts.
pub fn agent_spawn(
    teams: &TeamRegistry,
    policy: &dyn SpawnPolicyScope,
    parent_budget: &mut Budget,
    input: AgentSpawnInput,
) -> Result<AgentSpawnOutput, SpawnError> {
    // §9.9: credentials are a capability — "never automatic," gated by the parent's
    // own policy scope, evaluated before the child is created.
    if !policy.authorizes_provider(&input.provider) {
        return Err(SpawnError::ProviderNotAuthorized {
            provider: input.provider,
        });
    }

    // §7.7 depth/fan-out limits, evaluated before any side effect. `checked_add`
    // (not `+`) so a maxed-out parent depth/fan-out can't wrap around in a release
    // build and silently grant the child a smaller, "valid-looking" value.
    let child_depth = input.parent_depth.checked_add(1).ok_or({
        SpawnError::Bus(BusError::DepthLimitExceeded {
            depth: 255,
            max: roundhouse_bus::limits::MAX_DEPTH,
        })
    })?;
    check_depth(child_depth)?;
    let child_fan_out = input.parent_direct_children.checked_add(1).ok_or({
        SpawnError::Bus(BusError::FanOutLimitExceeded {
            count: u32::MAX,
            max: roundhouse_bus::limits::MAX_FAN_OUT,
        })
    })?;
    check_fan_out(child_fan_out)?;

    // §7.5: "agent_spawn auto-joins the child to the parent's team as `worker`
    // unless overridden." Two fences run before any budget transfer or roster
    // mutation, in this order:
    //
    //   1. Membership — the parent must already be a current (non-ended) member of
    //      the team the child is asked to join, so a child can't reach a team its
    //      parent couldn't.
    //   2. Role clamping — requesting "lead" requires the parent to be the team's
    //      creator or to already hold "lead", so a worker parent can't mint a child
    //      with team-close authority the parent itself never had.
    if let Some(team) = input.team {
        let parent_is_member = teams
            .roster(team)
            .map(|roster| roster.iter().any(|m| m.session == input.parent && !m.ended))
            .unwrap_or(false);
        if !parent_is_member {
            return Err(SpawnError::Bus(BusError::NotAuthorized {
                team,
                caller: input.parent,
            }));
        }

        if let Some(ref requested_role) = input.role {
            if requested_role == "lead" {
                let parent_is_lead = teams
                    .team(team)
                    .map(|t| t.created_by == input.parent)
                    .unwrap_or(false)
                    || teams
                        .roster(team)
                        .map(|roster| {
                            roster
                                .iter()
                                .any(|m| m.session == input.parent && m.role == "lead")
                        })
                        .unwrap_or(false);
                if !parent_is_lead {
                    return Err(SpawnError::Bus(BusError::NotAuthorized {
                        team,
                        caller: input.parent,
                    }));
                }
            }
        }
    }

    // §7.7: "Budget inheritance is a transfer, not a grant ... moves tokens from the
    // parent's remaining budget into the child's."
    if input.budget_tokens > parent_budget.remaining_tokens {
        return Err(SpawnError::InsufficientBudget {
            requested: input.budget_tokens,
            remaining: parent_budget.remaining_tokens,
        });
    }
    parent_budget.remaining_tokens -= input.budget_tokens;
    let child_budget = Budget {
        remaining_tokens: input.budget_tokens,
    };

    let session_id = SessionId::new();
    // `SessionId` implements `Display` (writes the underlying UUID) — `.to_string()`,
    // never `.0` field access, which doesn't compile from outside `roundhouse-core`
    // (the field is private).
    let handle = format!("agent-{}", &session_id.to_string()[..8]);
    // The child's `SessionSpec`. Phase 2 grew `SessionSpec` beyond the plan's assumed
    // `{ workspace, name }` to add `requested_tier`/`on_degrade` (§6.5) — this
    // executor fills those with the fail-closed defaults: the child asks for the most
    // restrictive real tier (`Sandbox`) and refuses to run weaker (`Refuse`), never
    // inheriting the parent's (possibly higher) tier automatically — the same "never
    // exceed the parent's grant" half of §6.1's spawn-boundary rule, applied to
    // isolation rather than credentials/budget.
    let session_spec = SessionSpec {
        workspace: input.workspace,
        name: Some(handle.clone()),
        requested_tier: Tier::Sandbox,
        on_degrade: OnDegrade::Refuse,
    };

    // §7.5: "agent_spawn auto-joins the child to the parent's team as `worker` unless
    // overridden." A refused join (team draining/full) rolls back the budget transfer
    // so the spawn as a whole is atomic from the caller's point of view.
    if let Some(team) = input.team {
        if let Err(e) = teams.join(team, session_id, input.role.clone()) {
            parent_budget.remaining_tokens += input.budget_tokens; // rollback
            return Err(SpawnError::Bus(e));
        }
    }

    // §6.8: "A child session's taint is seeded from its parent's current TaintSet at
    // spawn time" — capabilities never flow automatically (credentials, above); this
    // is the mirror-image "restrictions flow automatically and only tighten" half of
    // the same §6.1 rule, applied to taint instead of spend/mutate/escalate.
    let child_spec = ChildSpecSummary {
        taint: input.parent_taint,
        depth: child_depth,
    };

    Ok(AgentSpawnOutput {
        session_id,
        handle,
        child_budget,
        child_spec,
        session_spec,
    })
}

/// §6.8: "On return, the parent's TaintSet becomes the union of its own and the
/// child's." Called by the `agent` task's completion handler when the child session
/// ends (or reports back for a non-detached spawn), independent of `agent_spawn`
/// itself since it happens at a different point in the task lifecycle.
pub fn merge_taint_on_child_return(parent_taint: TaintSet, child_taint: TaintSet) -> TaintSet {
    parent_taint.union(child_taint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::teams::TeamRegistry;
    use roundhouse_core::{SessionId, WorkspaceId};

    struct AllowAnthropicOnly;
    impl SpawnPolicyScope for AllowAnthropicOnly {
        fn authorizes_provider(&self, provider: &str) -> bool {
            provider == "anthropic"
        }
    }

    #[test]
    fn spawn_transfers_budget_never_exceeding_parent_remaining() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();

        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };
        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 300,
            parent_taint: TaintSet { tainted: false },
        };

        let out = agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap();

        assert_eq!(out.child_budget.remaining_tokens, 300);
        assert_eq!(parent_budget.remaining_tokens, 700); // moved, not copied
    }

    #[test]
    fn spawn_requesting_more_than_parent_remaining_is_refused() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 100,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 300,
            parent_taint: TaintSet { tainted: false },
        };

        assert!(agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).is_err());
        assert_eq!(parent_budget.remaining_tokens, 100); // untouched on refusal
    }

    #[test]
    fn child_taint_is_seeded_from_parents_current_taint_never_laundered_clean() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 100,
            parent_taint: TaintSet { tainted: true }, // parent already tainted
        };

        let out = agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap();
        assert!(out.child_spec.taint.tainted); // §6.8: taint crosses the boundary, tightens only
    }

    #[test]
    fn spawn_against_an_unauthorized_provider_is_refused_by_parents_own_policy_scope() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "openrouter".to_string(), // not authorized per §9.9's example
            budget_tokens: 100,
            parent_taint: TaintSet { tainted: false },
        };

        let err =
            agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap_err();
        assert!(matches!(err, SpawnError::ProviderNotAuthorized { .. }));
        assert_eq!(parent_budget.remaining_tokens, 1000); // refused before any transfer
    }

    #[test]
    fn spawn_auto_joins_parents_team_as_worker_unless_role_overridden() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 100,
            parent_taint: TaintSet { tainted: false },
        };

        let out = agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap();
        let roster = registry.roster(team).unwrap();
        assert!(roster
            .iter()
            .any(|m| m.session == out.session_id && m.role == "worker"));
    }

    #[test]
    fn spawn_beyond_depth_limit_is_refused() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 4, // child would be depth 5 > MAX_DEPTH(4)
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 10,
            parent_taint: TaintSet { tainted: false },
        };

        let err =
            agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap_err();
        assert!(matches!(
            err,
            SpawnError::Bus(roundhouse_bus::types::BusError::DepthLimitExceeded { .. })
        ));
    }

    #[test]
    fn spawn_beyond_fan_out_limit_is_refused() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let parent_session = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), parent_session, "lead".into())
            .unwrap();
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };

        let input = AgentSpawnInput {
            workspace: ws,
            parent: parent_session,
            parent_depth: 0,
            parent_direct_children: 8, // would become 9 > MAX_FAN_OUT(8)
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 10,
            parent_taint: TaintSet { tainted: false },
        };

        let err =
            agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap_err();
        assert!(matches!(
            err,
            SpawnError::Bus(roundhouse_bus::types::BusError::FanOutLimitExceeded { .. })
        ));
        assert_eq!(parent_budget.remaining_tokens, 1000); // refused before any transfer
    }

    #[test]
    fn worker_parent_cannot_spawn_a_lead_child() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let worker = SessionId::new();
        registry.join(team, worker, None).unwrap(); // auto-joins as "worker"

        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };
        let input = AgentSpawnInput {
            workspace: ws,
            parent: worker,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: Some("lead".to_string()), // escalation: worker can't mint a lead child
            provider: "anthropic".to_string(),
            budget_tokens: 10,
            parent_taint: TaintSet { tainted: false },
        };

        let err =
            agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap_err();
        assert!(matches!(
            err,
            SpawnError::Bus(roundhouse_bus::types::BusError::NotAuthorized { .. })
        ));
        assert_eq!(parent_budget.remaining_tokens, 1000); // refused before any transfer
    }

    #[test]
    fn non_member_parent_cannot_spawn_into_a_team() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let creator = SessionId::new();
        let team = registry
            .create_team(ws, "t".into(), "c".into(), creator, "lead".into())
            .unwrap();

        let stranger = SessionId::new(); // not on the roster
        let mut parent_budget = Budget {
            remaining_tokens: 1000,
        };
        let input = AgentSpawnInput {
            workspace: ws,
            parent: stranger,
            parent_depth: 0,
            parent_direct_children: 0,
            team: Some(team),
            role: None,
            provider: "anthropic".to_string(),
            budget_tokens: 10,
            parent_taint: TaintSet { tainted: false },
        };

        let err =
            agent_spawn(&registry, &AllowAnthropicOnly, &mut parent_budget, input).unwrap_err();
        assert!(matches!(
            err,
            SpawnError::Bus(roundhouse_bus::types::BusError::NotAuthorized { .. })
        ));
        assert_eq!(parent_budget.remaining_tokens, 1000); // refused before any transfer
    }
}
