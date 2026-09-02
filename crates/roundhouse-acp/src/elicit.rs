use roundhouse_core::{SuspendReason, TaskKind};
use serde_json::Value;

/// §10.2: "Two elicitation shapes are unavoidable. ACP forked MCP's
/// elicitation and then kept `elicitationId` + `elicitation/complete`, which
/// MCP has since removed (correlation moved into `requestState`). Our
/// `elicit` task normalises both."
///
/// This module normalises both wire shapes into one local `ElicitRequest`
/// and binds that request to the two real frozen `roundhouse-core` types an
/// `elicit` task actually needs: `TaskKind::Elicit` (`task_kind` below) and
/// `SuspendReason::AwaitingElicitation { schema }` (`suspend_reason` below).
///
/// One seam this module deliberately does NOT cross: `roundhouse-acp` may
/// not depend on `roundhouse-mcp`, so it cannot name
/// `roundhouse_mcp::executor::TaskInput::Elicit` directly, even though that
/// is where an MCP-sourced elicitation's `TaskInput` ultimately lives
/// (`crates/roundhouse-mcp/src/executor.rs:50,67`). The far side of that
/// daemon-owned seam, precisely:
/// - `ElicitationSource::Mcp::request_state` is the string form of
///   `roundhouse_mcp::wire::RequestState(pub String)`
///   (`crates/roundhouse-mcp/src/wire.rs:22`), a typed newtype that already
///   exists on the MCP side — this module keeps it as a bare `String`
///   because it cannot name that newtype's crate.
/// - `ElicitRequest.prompt` maps to
///   `roundhouse_mcp::executor::TaskInput::Elicit.question: Option<String>`
///   as `Some(prompt)` when the daemon constructs that `TaskInput`.
#[derive(Debug, Clone, PartialEq)]
pub enum ElicitationSource {
    Acp { elicitation_id: String },
    Mcp { request_state: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ElicitRequest {
    pub source: ElicitationSource,
    pub schema: Value,
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ElicitResponse {
    pub value: Value,
}

pub fn normalize_acp_elicitation(
    elicitation_id: &str,
    schema: &Value,
    prompt: &str,
) -> ElicitRequest {
    ElicitRequest {
        source: ElicitationSource::Acp {
            elicitation_id: elicitation_id.to_string(),
        },
        schema: schema.clone(),
        prompt: prompt.to_string(),
    }
}

pub fn normalize_mcp_elicitation(
    request_state: &str,
    schema: &Value,
    prompt: &str,
) -> ElicitRequest {
    ElicitRequest {
        source: ElicitationSource::Mcp {
            request_state: request_state.to_string(),
        },
        schema: schema.clone(),
        prompt: prompt.to_string(),
    }
}

/// Returns the ACP `elicitationId` to pass to `elicitation/complete`, or
/// `None` if this request originated from MCP (in which case `complete_mcp`
/// is the correct completion path instead).
pub fn complete_acp(req: &ElicitRequest, _resp: &ElicitResponse) -> Option<String> {
    match &req.source {
        ElicitationSource::Acp { elicitation_id } => Some(elicitation_id.clone()),
        ElicitationSource::Mcp { .. } => None,
    }
}

/// Returns the opaque `requestState` to echo back on the retried
/// `tools/call`/`prompts/get`/`resources/read`, or `None` if this request
/// originated from ACP.
pub fn complete_mcp(req: &ElicitRequest, _resp: &ElicitResponse) -> Option<String> {
    match &req.source {
        ElicitationSource::Mcp { request_state } => Some(request_state.clone()),
        ElicitationSource::Acp { .. } => None,
    }
}

/// Every normalized elicitation, ACP- or MCP-sourced alike, is recorded as
/// an `elicit` task (§4.2's frozen `TaskKind::Elicit`).
pub fn task_kind() -> TaskKind {
    TaskKind::Elicit
}

/// §8 — an `elicit` task suspends awaiting the user's answer, carrying the
/// request's JSON schema per `SuspendReason::AwaitingElicitation { schema }`
/// (`roundhouse_core::task_meta`).
pub fn suspend_reason(req: &ElicitRequest) -> SuspendReason {
    SuspendReason::AwaitingElicitation {
        schema: req.schema.clone(),
    }
}
