use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Minimal Phase 0 shape — enough for `EventPayload` to compile and for
/// `roundhouse-engine`/`roundhouse-sandbox` to grow real fields later
/// without changing `EventPayload`'s variant shapes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionSpec {
    pub workspace: crate::ids::WorkspaceId,
    pub name: Option<String>,
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
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SessionOutcome {
    Completed,
    Cancelled,
    Failed { reason: String },
}
