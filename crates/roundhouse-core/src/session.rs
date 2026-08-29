use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Minimal Phase 0 shape — enough for `EventPayload` to compile and for
/// `roundhouse-engine`/`roundhouse-sandbox` to grow real fields later
/// without changing `EventPayload`'s variant shapes.
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
