use crate::server::PolicyOutcome;
use roundhouse_core::PolicyDecision;
use serde::Serialize;

/// §8.5 point 3: the exact shape a denied tool call must carry back into
/// model context — legible, not a hang. This is the one internal shape both
/// crossing directions (MCP `tools/call` we approve outward as ACP
/// `session/request_permission`, and an ACP permission request we receive as
/// client) get adapted into and out of (§10.2: "One internal Decision type,
/// adapters at both edges") — built from `PolicyOutcome`'s `rule`/`hint`,
/// never from a second decision enum.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct StructuredToolError {
    pub error: &'static str,
    pub rule: String,
    pub hint: String,
}

pub fn deny_and_continue_error(rule: &str, hint: &str) -> StructuredToolError {
    StructuredToolError {
        error: "permission_denied",
        rule: rule.to_string(),
        hint: hint.to_string(),
    }
}

/// An MCP `tools/call` denial becomes a structured tool result fed back into
/// the model's context rather than a bare protocol error — this is the
/// direction "an MCP tools/call we want approved becomes an ACP
/// session/request_permission upward" resolves to when the answer is no.
/// `outcome.rule`/`outcome.hint` (both threaded alongside the real
/// `PolicyDecision`, per `crate::server::PolicyOutcome`) supply the
/// structured error's fields.
pub fn decision_to_mcp_tool_result(outcome: &PolicyOutcome) -> Option<StructuredToolError> {
    match outcome.decision {
        PolicyDecision::Allow => None,
        PolicyDecision::Deny => Some(deny_and_continue_error(
            outcome.rule.as_deref().unwrap_or("unspecified-rule"),
            outcome.hint.as_deref().unwrap_or(""),
        )),
        PolicyDecision::Ask => None, // Ask suspends for a real approval (§6.4); it is not itself a deny, so no structured error is emitted here
    }
}

/// The reverse crossing: an ACP permission request we receive as *client*
/// (from an external agent we're driving) is normalised into our own
/// `PolicyOutcome` and fed to **our** engine first (§10.2), rather than
/// trusting whatever the remote agent claims about its own tool call.
///
/// **RULING C-P6:** this is deliberately a conservative stub. It always
/// returns `PolicyOutcome { decision: PolicyDecision::Ask, .. }` — a
/// fail-closed default that suspends for a human rather than granting
/// anything — and `default_decision_is_ask_never_an_allow` below pins that
/// default down with a test, so a future change that quietly flips it to an
/// allow is caught immediately rather than discovered later as a security
/// regression.
///
/// The real wiring is daemon-owned integration work that does not exist yet
/// in this crate (`roundhouse-acp` may not depend on `roundhouse-policy` —
/// see this dispatch's standing rules): the not-yet-built ACP-client
/// `session/request_permission` request handler must call
/// `roundhouse_policy::PolicyEngine::decide` (via this crate's
/// `crate::server::PolicyEngineLike::decide(remote_declared_tool, &args)`
/// seam) with the request's *declared* tool name and arguments, and use
/// *that* result — never this stub's hardcoded `Ask` — before it ever
/// builds a wire outcome through `crate::server::handle_request_permission`.
/// Until that call site exists, this function's `Ask` is the only value
/// deployable code may see.
pub fn acp_permission_request_to_our_decision(remote_declared_tool: &str) -> PolicyOutcome {
    // Critical per §6.4: such tasks record enforced_by = RemoteAgentClaim —
    // the external agent's declared tool call is unverified metadata, so this
    // function's caller (the real client loop) must route the *declared*
    // tool name through our policy engine exactly as if we made the call
    // ourselves, never trusting the remote agent's own claimed decision.
    let _ = remote_declared_tool;
    // Conservative default until wired to the real PolicyEngine; the real
    // call site never bypasses `decide()`.
    PolicyOutcome {
        decision: PolicyDecision::Ask,
        rule: None,
        hint: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_and_continue_produces_the_exact_structured_error_shape() {
        let err = deny_and_continue_error("no-git-push", "write a patch file instead");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["error"], "permission_denied");
        assert_eq!(json["rule"], "no-git-push");
        assert_eq!(json["hint"], "write a patch file instead");
    }

    #[test]
    fn an_agent_told_it_may_not_git_push_gets_legible_context_not_a_hang() {
        // §8.5 point 3: "An agent told it may not `git push` will write a
        // patch file instead; an agent that hangs does nothing." Deny must
        // always produce a tool result the model can read, never a silent
        // drop.
        let outcome = PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: Some("no-git-push".to_string()),
            hint: Some("write a patch file instead".to_string()),
        };
        let result = decision_to_mcp_tool_result(&outcome);
        assert!(result.is_some());
        assert_eq!(result.unwrap().error, "permission_denied");
    }

    #[test]
    fn allow_produces_no_tool_error_at_all() {
        let outcome = PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        };
        assert!(decision_to_mcp_tool_result(&outcome).is_none());
    }

    #[test]
    fn ask_produces_no_tool_error_either_it_suspends_instead() {
        let outcome = PolicyOutcome {
            decision: PolicyDecision::Ask,
            rule: None,
            hint: None,
        };
        assert!(decision_to_mcp_tool_result(&outcome).is_none());
    }

    #[test]
    fn default_decision_is_ask_never_an_allow() {
        // RULING C-P6: this stub must stay fail-closed. A future change that
        // makes it return Allow (or anything else) without real PolicyEngine
        // wiring would be a silent fail-open regression; this test exists
        // specifically to catch that.
        let outcome = acp_permission_request_to_our_decision("shell");
        assert_eq!(outcome.decision, PolicyDecision::Ask);
        assert_eq!(outcome.rule, None);
        assert_eq!(outcome.hint, None);
    }

    #[test]
    fn default_decision_ignores_which_tool_was_declared_until_wired_to_the_real_engine() {
        // Also fail-closed regardless of the declared tool name — the stub
        // must not special-case any particular tool into an allow.
        assert_eq!(
            acp_permission_request_to_our_decision("rm -rf /").decision,
            PolicyDecision::Ask
        );
    }
}
