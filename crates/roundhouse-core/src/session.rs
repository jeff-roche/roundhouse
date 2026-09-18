use crate::event::EventPayload;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Phase 0 gave this a minimal shape — just enough for `EventPayload` to
/// compile, with real fields expected to land in downstream crates later
/// without changing `EventPayload`'s variant shapes. Phase 2 instead grew
/// `SessionSpec` itself, directly in `roundhouse-core`: `requested_tier`
/// and `on_degrade` below are real isolation-tier fields the frozen spec
/// (§6.5/§6.9) calls for on the spec itself, not something a downstream
/// crate layered on top.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionSpec {
    pub workspace: crate::ids::WorkspaceId,
    pub name: Option<String>,
    /// §6.9 — the isolation tier a session asks for at creation time. The
    /// *achieved* tier (which may differ, per `on_degrade` below) is
    /// recorded separately, per task, as `IsolationAttestation`.
    pub requested_tier: crate::tier::Tier,
    /// §6.5 — what to do if `requested_tier` can't be honored.
    pub on_degrade: OnDegrade,
    /// Durable spawn-tree edge: the parent session that created this one, if
    /// any. `None` for a root session (socket-attached or scheduler-driven).
    /// Set by both code paths that create a child session: workflow `call:`
    /// (`WorkflowSessionTree::persist_child_session` in `roundhouse-daemon`)
    /// and the sub-agent `agent` tool
    /// (`roundhouse_engine::tools::agent_spawn_tool`, whose child is created
    /// and persisted by `roundhouse-daemon`'s `DaemonSubAgentHost`).
    /// `#[serde(default)]`
    /// so `SessionCreated` events serialized before this field existed still
    /// deserialize, defaulting to `None` rather than failing to parse.
    #[serde(default)]
    pub parent: Option<crate::ids::SessionId>,
}

impl SessionSpec {
    /// Test-only placeholder `SessionSpec`, for tests that need *a*
    /// `SessionSpec` but don't care about its exact contents.
    #[doc(hidden)]
    pub fn test_default() -> Self {
        SessionSpec {
            workspace: crate::ids::WorkspaceId::new(),
            name: None,
            requested_tier: crate::tier::Tier::Sandbox,
            on_degrade: OnDegrade::Refuse,
            parent: None,
        }
    }

    /// Test-only helper for tests that care specifically about
    /// `requested_tier`/`on_degrade`, filling `workspace`/`name` with
    /// sensible placeholders.
    #[doc(hidden)]
    pub fn test_requesting(tier: crate::tier::Tier, on_degrade: OnDegrade) -> Self {
        SessionSpec {
            workspace: crate::ids::WorkspaceId::new(),
            name: None,
            requested_tier: tier,
            on_degrade,
            parent: None,
        }
    }
}

/// §6.5 — what a session's spec asks the engine to do if `requested_tier`
/// isn't achievable in the current environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum OnDegrade {
    /// Refuse to start rather than run at a weaker isolation tier than
    /// requested. Conceptually the spec's default (§6.5).
    Refuse,
    /// Accept any tier at or above the given floor.
    AllowDownTo(crate::tier::Tier),
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionPatch {
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SessionState {
    Created,
    Running,
    Suspended,
    /// §8's cooperative-cancellation model: a cancellation has been
    /// requested but the session hasn't yet wound down to `Closed`.
    Cancelling,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SessionOutcome {
    Completed,
    Cancelled,
    Failed { reason: String },
}

/// The session-level counterpart to `fold_task_state`: given every
/// `EventPayload` bearing one `session_id`, in log order, derive the
/// current `SessionState`. Only the three session-lifecycle variants ever
/// change the fold — `SessionCreated` to `Created`, `SessionStateChanged`
/// to its carried `state`, `SessionClosed` to `Closed` — every other
/// variant (task-lifecycle, `SessionConfigured`, and the cross-cutting
/// `Message`/`Note`/`Loss` payloads) leaves the running state unchanged.
/// `Closed` is a terminal fold value: once reached, every later event is
/// absorbed and the result stays `Closed`, matching the store's append
/// tail-guard that rejects writes past `SessionClosed`. Returns `None` if
/// the slice carries no session-lifecycle event at all.
pub fn fold_session_state(events: &[EventPayload]) -> Option<SessionState> {
    let mut state = None;
    for payload in events {
        if matches!(state, Some(SessionState::Closed)) {
            break;
        }
        state = match payload {
            EventPayload::SessionCreated { .. } => Some(SessionState::Created),
            EventPayload::SessionStateChanged { state, .. } => Some(state.clone()),
            EventPayload::SessionClosed { .. } => Some(SessionState::Closed),
            _ => state,
        };
    }
    state
}
