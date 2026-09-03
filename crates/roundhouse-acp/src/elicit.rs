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

/// Carries the same [`ElicitationSource`] identity as the [`ElicitRequest`]
/// it answers. Without this, `complete_acp`/`complete_mcp` would have no
/// way to check that a response actually answers the request it's paired
/// with at the call site — a response for one elicitation could be routed
/// to complete a different, unrelated one that happens to share a
/// protocol. `for_request` is the recommended constructor: it copies the
/// source off the request being answered, so a caller has to go out of its
/// way to construct a mismatched pairing rather than doing so by accident.
///
/// Replay/dedup (the same `elicitation_id`/`request_state` answered twice)
/// is caller state this module does not track — it is out of scope here,
/// not silently assumed to be handled.
#[derive(Debug, Clone, PartialEq)]
pub struct ElicitResponse {
    pub source: ElicitationSource,
    pub value: Value,
}

impl ElicitResponse {
    /// Builds a response bound to `req`'s source, so the pairing check in
    /// `complete_acp`/`complete_mcp` succeeds by construction.
    pub fn for_request(req: &ElicitRequest, value: Value) -> Self {
        ElicitResponse {
            source: req.source.clone(),
            value,
        }
    }
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
/// `None` if either this request didn't originate from ACP (in which case
/// `complete_mcp` is the correct completion path instead) or `resp` doesn't
/// answer `req` — its `source` must carry the *same* `elicitation_id`, not
/// merely be `Acp { .. }`, otherwise one elicitation's answer could
/// complete a different one.
pub fn complete_acp(req: &ElicitRequest, resp: &ElicitResponse) -> Option<String> {
    match (&req.source, &resp.source) {
        (
            ElicitationSource::Acp {
                elicitation_id: req_id,
            },
            ElicitationSource::Acp {
                elicitation_id: resp_id,
            },
        ) if req_id == resp_id => Some(req_id.clone()),
        _ => None,
    }
}

/// Returns the opaque `requestState` to echo back on the retried
/// `tools/call`/`prompts/get`/`resources/read`, or `None` if either this
/// request didn't originate from MCP (in which case `complete_acp` is the
/// correct completion path instead) or `resp` doesn't answer `req` — its
/// `source` must carry the *same* `request_state`, not merely be
/// `Mcp { .. }`.
pub fn complete_mcp(req: &ElicitRequest, resp: &ElicitResponse) -> Option<String> {
    match (&req.source, &resp.source) {
        (
            ElicitationSource::Mcp {
                request_state: req_state,
            },
            ElicitationSource::Mcp {
                request_state: resp_state,
            },
        ) if req_state == resp_state => Some(req_state.clone()),
        _ => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_for_request_completes_the_request_it_was_built_from() {
        let req = normalize_acp_elicitation("elicit-1", &json!({"type": "boolean"}), "Approve?");
        let resp = ElicitResponse::for_request(&req, json!(true));
        assert_eq!(complete_acp(&req, &resp), Some("elicit-1".to_string()));
    }

    #[test]
    fn response_with_a_different_acp_elicitation_id_does_not_complete() {
        let req = normalize_acp_elicitation("elicit-1", &json!({"type": "boolean"}), "Approve?");
        let resp = ElicitResponse {
            source: ElicitationSource::Acp {
                elicitation_id: "elicit-2".to_string(),
            },
            value: json!(true),
        };
        assert_eq!(complete_acp(&req, &resp), None);
    }

    #[test]
    fn response_with_a_different_mcp_request_state_does_not_complete() {
        let req = normalize_mcp_elicitation("state-1", &json!({"type": "boolean"}), "Approve?");
        let resp = ElicitResponse {
            source: ElicitationSource::Mcp {
                request_state: "state-2".to_string(),
            },
            value: json!(true),
        };
        assert_eq!(complete_mcp(&req, &resp), None);
    }
}
