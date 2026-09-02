//! `session/request_permission` handling for Roundhouse acting on the
//! permission-request path of the Agent Client Protocol.
//!
//! **RULING C-P5 (binding over the original task brief):** the brief's
//! `AcpPermissionResponse { AllowOnce, AllowAlways, Reject }` does not exist
//! on the real ACP wire and cannot be serialized into a real response at
//! all. Verified against `agent-client-protocol-schema` 1.5.0's
//! `v1/client.rs`: every allow or deny is expressed by **selecting one of
//! the options the peer itself offered**, by `option_id`
//! (`RequestPermissionRequest.options: Vec<PermissionOption>`), never by a
//! free-standing verdict enum. This module selects from those offered
//! options instead of fabricating a verdict type.
use agent_client_protocol::schema::v1::{
    PermissionOption, PermissionOptionKind, RequestPermissionOutcome, SelectedPermissionOutcome,
};
use roundhouse_core::PolicyDecision;
use serde_json::Value;
use thiserror::Error;

/// The one real decision type is Phase 0's payload-free `PolicyDecision`
/// (`{ Allow, Ask, Deny }`) — this struct threads it alongside the extra
/// data this crate's callers need (the matched rule's name, a human-legible
/// hint), never replacing it with a second, incompatible enum.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    pub rule: Option<String>,
    pub hint: Option<String>,
}

/// Thin seam over Phase 2's real `PolicyEngine` so this crate's server logic
/// is unit-testable without linking roundhouse-policy's full rule evaluator.
pub trait PolicyEngineLike {
    fn decide(&self, tool: &str, args: &Value) -> PolicyOutcome;
}

pub struct AcpServer<'a> {
    pub policy: &'a dyn PolicyEngineLike,
}

/// This must fail closed: nothing converts `NoMatchingOption` into an allow
/// anywhere in this module. It carries the tool name, the decision that
/// drove the search, and every kind the peer actually offered, so a caller
/// can log what happened without re-deriving it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PermissionError {
    #[error(
        "no PermissionOption of a kind required by {decision:?} was offered for tool {tool:?}; offered kinds: {offered_kinds:?}"
    )]
    NoMatchingOption {
        tool: String,
        decision: PolicyDecision,
        offered_kinds: Vec<PermissionOptionKind>,
    },
}

fn find_option(
    options: &[PermissionOption],
    kind: PermissionOptionKind,
) -> Option<&PermissionOption> {
    options.iter().find(|opt| opt.kind == kind)
}

/// Selects a wire-level `RequestPermissionOutcome` from the options the peer
/// offered, per our engine's `PolicyDecision` for `tool`/`args`. Security
/// rules, in force regardless of how the peer phrased its options:
///
/// - `Allow` selects the offered `AllowOnce` option — **never `AllowAlways`**,
///   since selecting that would persist a grant on the peer's side that our
///   engine never made.
/// - `Deny` selects `RejectOnce`, falling back to `RejectAlways` only if no
///   `RejectOnce` was offered.
/// - `Ask` **also** selects a reject option (same `RejectOnce`-then-
///   `RejectAlways` search as `Deny`). `Ask` means a human decision is
///   pending, so nothing may be granted while it is; this function does not
///   block waiting for that decision. The caller is responsible for
///   re-entering this function (or the underlying `session/request_permission`
///   exchange) once the real approval flow (Phase 2's persisted
///   `Suspended{AwaitingApproval}`, §6.4) resolves the human's answer into a
///   fresh `Allow`/`Deny` from the policy engine.
/// - If no option of the required kind was offered at all, this returns
///   `Err(PermissionError::NoMatchingOption)`. **This must fail closed**:
///   no code path turns that error into an allow.
///
/// `PermissionOptionKind` and `RequestPermissionOutcome` are both
/// `#[non_exhaustive]` in the SDK; this function never exhaustively matches
/// on `PermissionOptionKind` (it searches by equality instead), so an
/// unknown future kind is simply never selected — it can't be mistaken for
/// an allow.
pub fn handle_request_permission(
    server: &AcpServer,
    tool: &str,
    args: &Value,
    options: &[PermissionOption],
) -> Result<RequestPermissionOutcome, PermissionError> {
    let outcome = server.policy.decide(tool, args);
    let selected = match outcome.decision {
        PolicyDecision::Allow => find_option(options, PermissionOptionKind::AllowOnce),
        PolicyDecision::Deny | PolicyDecision::Ask => {
            find_option(options, PermissionOptionKind::RejectOnce)
                .or_else(|| find_option(options, PermissionOptionKind::RejectAlways))
        }
    };

    match selected {
        Some(opt) => Ok(RequestPermissionOutcome::Selected(
            SelectedPermissionOutcome::new(opt.option_id.clone()),
        )),
        None => Err(PermissionError::NoMatchingOption {
            tool: tool.to_string(),
            decision: outcome.decision,
            offered_kinds: options.iter().map(|opt| opt.kind).collect(),
        }),
    }
}

/// Extracts the selected `PermissionOptionId` from a `RequestPermissionOutcome`
/// this crate did not itself construct — e.g. one read back off the wire, or
/// one built by a caller that already knows a `session/cancel` raced the
/// prompt. Returns `None` for `Cancelled` ("the client sent `session/cancel`
/// before the user responded" — never an allow, never a deny) and for any
/// future, currently-unknown outcome variant the `#[non_exhaustive]` wildcard
/// arm below catches. Consumers of a `RequestPermissionOutcome` should route
/// through this instead of assuming `Selected`.
pub fn selected_option_id(
    outcome: &RequestPermissionOutcome,
) -> Option<&agent_client_protocol::schema::v1::PermissionOptionId> {
    match outcome {
        RequestPermissionOutcome::Selected(sel) => Some(&sel.option_id),
        RequestPermissionOutcome::Cancelled => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePolicy(PolicyOutcome);
    impl PolicyEngineLike for FakePolicy {
        fn decide(&self, _tool: &str, _args: &Value) -> PolicyOutcome {
            self.0.clone()
        }
    }

    fn all_four_options() -> Vec<PermissionOption> {
        vec![
            PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
            PermissionOption::new(
                "allow-always",
                "Allow always",
                PermissionOptionKind::AllowAlways,
            ),
            PermissionOption::new(
                "reject-once",
                "Reject once",
                PermissionOptionKind::RejectOnce,
            ),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ]
    }

    #[test]
    fn allow_decision_selects_allow_once_never_allow_always() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome = handle_request_permission(
            &server,
            "shell",
            &serde_json::json!({"cmd": "ls"}),
            &all_four_options(),
        )
        .expect("AllowOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("allow-once".to_string())
        );
    }

    #[test]
    fn deny_decision_selects_reject_once_when_offered() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: Some("no-network".to_string()),
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome =
            handle_request_permission(&server, "http", &serde_json::json!({}), &all_four_options())
                .expect("RejectOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-once".to_string())
        );
    }

    #[test]
    fn deny_decision_falls_back_to_reject_always_when_reject_once_not_offered() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Deny,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let options = vec![
            PermissionOption::new("allow-once", "Allow once", PermissionOptionKind::AllowOnce),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ];
        let outcome = handle_request_permission(&server, "http", &serde_json::json!({}), &options)
            .expect("RejectAlways was offered as a fallback");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-always".to_string())
        );
    }

    #[test]
    fn ask_decision_also_selects_a_reject_option() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Ask,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let outcome = handle_request_permission(
            &server,
            "shell",
            &serde_json::json!({"cmd": "rm -rf /"}),
            &all_four_options(),
        )
        .expect("RejectOnce was offered");
        assert_eq!(
            selected_option_id(&outcome).map(|id| id.to_string()),
            Some("reject-once".to_string())
        );
    }

    #[test]
    fn missing_required_kind_fails_closed_with_no_matching_option() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        // Only reject options offered — no AllowOnce for an Allow decision to select.
        let options = vec![
            PermissionOption::new(
                "reject-once",
                "Reject once",
                PermissionOptionKind::RejectOnce,
            ),
            PermissionOption::new(
                "reject-always",
                "Reject always",
                PermissionOptionKind::RejectAlways,
            ),
        ];
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &options)
            .expect_err("no AllowOnce option was offered");
        assert_eq!(
            err,
            PermissionError::NoMatchingOption {
                tool: "shell".to_string(),
                decision: PolicyDecision::Allow,
                offered_kinds: vec![
                    PermissionOptionKind::RejectOnce,
                    PermissionOptionKind::RejectAlways
                ],
            }
        );
    }

    #[test]
    fn empty_options_never_produce_an_allow() {
        let policy = FakePolicy(PolicyOutcome {
            decision: PolicyDecision::Allow,
            rule: None,
            hint: None,
        });
        let server = AcpServer { policy: &policy };
        let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &[])
            .expect_err("no options at all were offered");
        assert!(matches!(err, PermissionError::NoMatchingOption { .. }));
    }

    #[test]
    fn cancelled_outcome_is_neither_an_allow_nor_a_deny() {
        // A session/cancel racing the prompt: the peer must respond with
        // Cancelled to a pending request rather than a Selected outcome.
        // `selected_option_id` must not treat this as any kind of selection.
        assert_eq!(
            selected_option_id(&RequestPermissionOutcome::Cancelled),
            None
        );
    }
}
