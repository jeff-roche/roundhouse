// See RULING C-P5 in this subsystem's dispatch: the brief's own
// `AcpPermissionResponse { AllowOnce, AllowAlways, Reject }` does not exist
// on the real ACP wire. The real response is built by selecting one of the
// peer-offered `PermissionOption`s by `option_id`
// (`RequestPermissionResponse { outcome: RequestPermissionOutcome::Selected(..) }`),
// so these tests exercise that selection against the real SDK types instead
// of the brief's fabricated enum.
use agent_client_protocol::schema::v1::{
    PermissionOption, PermissionOptionKind, RequestPermissionOutcome, SelectedPermissionOutcome,
};
use roundhouse_acp::server::{
    handle_request_permission, resolve_selection, selected_option_id, AcpServer, PermissionError,
    PolicyEngineLike, PolicyOutcome, SelectionResolution,
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
    //
    // Note on scope (reworded per round-2 review): this does NOT test an
    // unknown/non_exhaustive `PermissionOptionKind` — that's untestable from
    // outside the SDK crate, since there is no way to construct a variant
    // the SDK hasn't defined. The real defense against an unrecognized kind
    // is deserialization strictness: `PermissionOptionKind` has no
    // `#[serde(other)]` and `options: Vec<PermissionOption>` has no
    // lenient/skip-invalid deserialization, so an option with an
    // unrecognized kind fails the whole request to deserialize rather than
    // silently becoming some default. What this test actually proves is
    // narrower but still real: the selection logic matches by equality
    // against exactly the required kind, so being offered any kind other
    // than `AllowOnce` for an `Allow` decision — known, like `AllowAlways`
    // here, or hypothetically unknown — is never selected.
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
fn ask_decision_selects_a_reject_once_option_never_an_allow() {
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
fn ask_decision_never_falls_back_to_reject_always() {
    // SEC-4 (round-2 review): unlike Deny, Ask must not fall back to
    // RejectAlways when RejectOnce isn't offered — RejectAlways tells a
    // conforming peer to permanently remember the rejection, which would
    // make a later human Allow unreachable (a session/request_permission is
    // answered once). This must fail closed with a distinct error, never
    // silently settle for RejectAlways.
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Ask,
        rule: None,
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::RejectAlways,
    ]);
    let err = handle_request_permission(&server, "shell", &serde_json::json!({}), &offered)
        .expect_err("RejectOnce was not offered; Ask must not settle for RejectAlways");
    assert_eq!(
        err,
        PermissionError::AskCannotFallBackToRejectAlways {
            tool: "shell".to_string(),
            offered_kinds: vec![
                PermissionOptionKind::AllowOnce,
                PermissionOptionKind::RejectAlways
            ],
        }
    );
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

#[test]
fn a_peer_cannot_launder_a_deny_into_an_allow_via_a_shared_option_id() {
    // SEC-1 (round-2 review): the exact attack described in that finding. A
    // peer offers the same option_id under two conflicting kinds:
    //   [{option_id: "go", kind: RejectOnce}, {option_id: "go", kind: AllowOnce}]
    // If selection were trusted without validating ids, our Deny decision
    // would select the RejectOnce entry and emit Selected{option_id: "go"} —
    // but a consumer resolving "go" back to a kind by first match, or the
    // peer itself, could read that as AllowOnce. This must be refused
    // outright rather than "selected correctly" by luck.
    let policy = FakePolicy(PolicyOutcome {
        decision: PolicyDecision::Deny,
        rule: Some("no-network".to_string()),
        hint: None,
    });
    let server = AcpServer { policy: &policy };
    let offered = vec![
        PermissionOption::new("go", "Reject", PermissionOptionKind::RejectOnce),
        PermissionOption::new("go", "Allow", PermissionOptionKind::AllowOnce),
    ];
    let err = handle_request_permission(&server, "http", &serde_json::json!({}), &offered)
        .expect_err("a shared option_id across conflicting kinds must be refused, not resolved");
    assert!(matches!(err, PermissionError::AmbiguousOptions { .. }));
}

#[test]
fn resolve_selection_round_trips_a_valid_choice() {
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::RejectOnce,
    ]);
    let outcome = RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("RejectOnce"));
    assert_eq!(
        resolve_selection(&offered, &outcome),
        SelectionResolution::Resolved(PermissionOptionKind::RejectOnce)
    );
}

#[test]
fn resolve_selection_refuses_to_resolve_against_an_ambiguous_options_list() {
    let offered = vec![
        PermissionOption::new("go", "Reject", PermissionOptionKind::RejectOnce),
        PermissionOption::new("go", "Allow", PermissionOptionKind::AllowOnce),
    ];
    let outcome = RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("go"));
    assert_eq!(
        resolve_selection(&offered, &outcome),
        SelectionResolution::AmbiguousOptions
    );
}

#[test]
fn resolve_selection_distinguishes_cancelled_unknown_id_and_ambiguous_options() {
    // FIX-B (round-3 review): these three outcomes used to collapse into
    // one `None`. An investigation needs to tell "the user cancelled" apart
    // from "the peer sent an id it was never offered" (a protocol
    // violation) apart from "the options list is attacker-shaped."
    let offered = options(&[
        PermissionOptionKind::AllowOnce,
        PermissionOptionKind::RejectOnce,
    ]);

    assert_eq!(
        resolve_selection(&offered, &RequestPermissionOutcome::Cancelled),
        SelectionResolution::Cancelled
    );

    let unknown_id_outcome =
        RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("never-offered"));
    assert_eq!(
        resolve_selection(&offered, &unknown_id_outcome),
        // Finding 2 (round-3 review): UnknownOptionId now carries an
        // already-escaped String (str's Debug form), never the raw
        // PermissionOptionId — see crate::peer_text::escape_and_cap_peer_str
        // (moved out of server::mod in fix round 2, Item 5).
        SelectionResolution::UnknownOptionId(format!("{:?}", "never-offered"))
    );

    let ambiguous_options = vec![
        PermissionOption::new("dup", "Allow", PermissionOptionKind::AllowOnce),
        PermissionOption::new("dup", "Reject", PermissionOptionKind::RejectOnce),
    ];
    let selected_dup = RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("dup"));
    assert_eq!(
        resolve_selection(&ambiguous_options, &selected_dup),
        SelectionResolution::AmbiguousOptions
    );

    // All three are distinct from each other and from a successful resolution.
    let resolved = resolve_selection(
        &offered,
        &RequestPermissionOutcome::Selected(SelectedPermissionOutcome::new("RejectOnce")),
    );
    assert_eq!(
        resolved,
        SelectionResolution::Resolved(PermissionOptionKind::RejectOnce)
    );
}
