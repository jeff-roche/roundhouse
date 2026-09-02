// See RULING C-P5 in this subsystem's dispatch: the brief's own
// `AcpPermissionResponse { AllowOnce, AllowAlways, Reject }` does not exist
// on the real ACP wire. The real response is built by selecting one of the
// peer-offered `PermissionOption`s by `option_id`
// (`RequestPermissionResponse { outcome: RequestPermissionOutcome::Selected(..) }`),
// so these tests exercise that selection against the real SDK types instead
// of the brief's fabricated enum.
use agent_client_protocol::schema::v1::{
    PermissionOption, PermissionOptionKind, RequestPermissionOutcome,
};
use roundhouse_acp::server::{
    handle_request_permission, selected_option_id, AcpServer, PermissionError, PolicyEngineLike,
    PolicyOutcome,
};
use roundhouse_core::PolicyDecision;

struct FakePolicy(PolicyOutcome);
impl PolicyEngineLike for FakePolicy {
    fn decide(&self, _tool: &str, _args: &serde_json::Value) -> PolicyOutcome {
        self.0.clone()
    }
}

fn options(kinds: &[PermissionOptionKind]) -> Vec<PermissionOption> {
    kinds
        .iter()
        .map(|kind| {
            let id = format!("{kind:?}");
            PermissionOption::new(id, format!("{kind:?}"), *kind)
        })
        .collect()
}

fn selected_id_string(outcome: &RequestPermissionOutcome) -> Option<String> {
    selected_option_id(outcome).map(|id| id.to_string())
}

#[test]
fn allow_decision_selects_the_offered_allow_once_option_our_richer_grants_collapse_on_the_wire() {
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Allow,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::AllowAlways,
        PermissionOptionKind::RejectOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let outcome = handle_request_permission(
        &server,
        "shell",
        &serde_json::json!({"cmd": "ls"}),
        &offered,
    )
    .expect("AllowOnce was offered");
    assert_eq!(selected_id_string(&outcome), Some("AllowOnce".to_string()));
}

#[test]
fn allow_decision_never_selects_allow_always() {
    // Selecting AllowAlways would persist a grant on the peer's side that
    // our engine never made. Only AllowOnce is a valid selection for Allow.
    // This is also the concrete stand-in for "an unknown/non_exhaustive
    // PermissionOptionKind is never treated as an allow": the selection
    // logic in `handle_request_permission` matches by equality against the
    // one required kind rather than exhaustively matching the enum, so any
    // kind other than exactly `AllowOnce` — known (`AllowAlways`,
    // `RejectOnce`, `RejectAlways`) or a future unknown one the SDK adds —
    // is silently skipped, never selected, for an `Allow` decision.
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Allow,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowAlways,
        PermissionOptionKind::RejectOnce,
    ]);
    let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &offered)
        .expect_err(
            "no AllowOnce offered, so this must fail closed rather than settle for AllowAlways",
        );
    assert_eq!(
        err,
        PermissionError::NoMatchingOption {
            tool: "shell".to_string(),
            decision: PolicyDecision::Allow,
            offered_kinds: vec![
                PermissionOptionKind::AllowAlways,
                PermissionOptionKind::RejectOnce
            ],
        }
    );
}

#[test]
fn deny_decision_selects_reject() {
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Deny,
        rule: Some("no-network".to_string()),
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::RejectOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let outcome = handle_request_permission(&server, "http", &serde_json::json!({}), &offered)
        .expect("RejectOnce was offered");
    assert_eq!(selected_id_string(&outcome), Some("RejectOnce".to_string()));
}

#[test]
fn deny_decision_prefers_reject_once_over_reject_always_when_both_are_offered() {
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Deny,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::RejectAlways,
        PermissionOptionKind::RejectOnce,
    ]);
    let outcome = handle_request_permission(&server, "http", &serde_json::json!({}), &offered)
        .expect("both reject kinds offered");
    assert_eq!(
        selected_id_string(&outcome),
        Some("RejectOnce".to_string()),
        "RejectOnce must be preferred over RejectAlways whenever both are offered"
    );
}

#[test]
fn deny_decision_falls_back_to_reject_always_when_reject_once_is_not_offered() {
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Deny,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let outcome = handle_request_permission(&server, "http", &serde_json::json!({}), &offered)
        .expect("RejectAlways was offered as the only reject kind");
    assert_eq!(
        selected_id_string(&outcome),
        Some("RejectAlways".to_string())
    );
}

#[test]
fn ask_decision_also_selects_a_reject_option_never_an_allow() {
    // Ask means a human decision is pending; nothing may be granted while
    // it is. The caller re-enters with a resolved outcome once the real
    // approval flow (Phase 2's Suspended{AwaitingApproval}) answers it.
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Ask,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::AllowAlways,
        PermissionOptionKind::RejectOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let outcome = handle_request_permission(
        &server,
        "shell",
        &serde_json::json!({"cmd": "rm -rf /"}),
        &offered,
    )
    .expect("RejectOnce was offered");
    assert_eq!(selected_id_string(&outcome), Some("RejectOnce".to_string()));
}

#[test]
fn missing_required_option_kind_fails_closed_with_an_error_not_an_allow() {
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Allow,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    // Only reject kinds offered: nothing an Allow decision may select.
    let offered = options(&[
        PermissionOptionKind::RejectOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &offered)
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
fn cancelled_outcome_is_never_treated_as_a_selection() {
    // A session/cancel racing the prompt: the peer responds Cancelled to a
    // pending request instead of Selected. This is neither an allow nor a
    // deny, and must never be read as either.
    assert_eq!(
        selected_option_id(&RequestPermissionOutcome::Cancelled),
        None
    );
}
