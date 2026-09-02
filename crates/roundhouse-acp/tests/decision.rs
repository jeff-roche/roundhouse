use roundhouse_acp::decision::{
    acp_permission_request_to_our_decision, decision_to_mcp_tool_result, deny_and_continue_error,
};
use roundhouse_acp::server::PolicyOutcome;
use roundhouse_core::PolicyDecision;

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
    // §8.5 point 3: "An agent told it may not `git push` will write a patch
    // file instead; an agent that hangs does nothing." Deny must always
    // produce a tool result the model can read, never a silent drop.
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
fn ask_produces_no_tool_error_either_it_suspends_for_a_human_instead() {
    let outcome = PolicyOutcome {
        decision: PolicyDecision::Ask,
        rule: None,
        hint: None,
    };
    assert!(decision_to_mcp_tool_result(&outcome).is_none());
}

#[test]
fn acp_permission_request_to_our_decision_defaults_to_ask_never_an_allow() {
    // RULING C-P6: an untested function that always returns one value is
    // how a fail-open bug hides later. This pins the conservative
    // fail-closed default so a future change to it is caught here first.
    let outcome = acp_permission_request_to_our_decision("shell");
    assert_eq!(outcome.decision, PolicyDecision::Ask);
    assert_eq!(outcome.rule, None);
    assert_eq!(outcome.hint, None);
}
