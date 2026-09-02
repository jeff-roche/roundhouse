use roundhouse_acp::decision::{
    acp_permission_request_to_our_decision, decision_to_mcp_tool_result, deny_and_continue_error,
    McpCallDisposition, DEFAULT_DENY_HINT,
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
    match decision_to_mcp_tool_result(&outcome) {
        McpCallDisposition::Denied(err) => assert_eq!(err.error, "permission_denied"),
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn deny_with_no_rule_or_hint_still_produces_legible_context_not_empty_strings() {
    // SEC-5 (round-2 review): a missing hint must not collapse to "".
    let outcome = PolicyOutcome {
        decision: PolicyDecision::Deny,
        rule: None,
        hint: None,
    };
    match decision_to_mcp_tool_result(&outcome) {
        McpCallDisposition::Denied(err) => {
            assert_eq!(err.rule, "unspecified-rule");
            assert_eq!(err.hint, DEFAULT_DENY_HINT);
            assert!(!err.hint.is_empty());
        }
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn allow_proceeds() {
    let outcome = PolicyOutcome {
        decision: PolicyDecision::Allow,
        rule: None,
        hint: None,
    };
    assert_eq!(
        decision_to_mcp_tool_result(&outcome),
        McpCallDisposition::Proceed
    );
}

#[test]
fn ask_suspends_it_is_not_a_proceed_and_not_a_denial() {
    // SEC-3 (round-2 review): under the old Option<StructuredToolError>
    // return type, Allow and Ask were both `None`, so a caller doing
    // `if let Some(err) = ... { deny } else { execute }` would execute a
    // tool call while a human decision was still pending. Proceed/Suspend
    // must be distinct dispositions.
    let outcome = PolicyOutcome {
        decision: PolicyDecision::Ask,
        rule: None,
        hint: None,
    };
    let disposition = decision_to_mcp_tool_result(&outcome);
    assert_eq!(disposition, McpCallDisposition::Suspend);
    assert_ne!(disposition, McpCallDisposition::Proceed);
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
