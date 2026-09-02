use roundhouse_acp::elicit::{
    complete_acp, complete_mcp, normalize_acp_elicitation, normalize_mcp_elicitation,
    suspend_reason, task_kind, ElicitResponse, ElicitationSource,
};
use roundhouse_core::{SuspendReason, TaskKind};
use serde_json::json;

#[test]
fn both_shapes_normalize_into_the_same_elicit_request_type() {
    let acp_req = normalize_acp_elicitation("elicit-123", &json!({"type": "boolean"}), "Approve?");
    let mcp_req =
        normalize_mcp_elicitation("opaque-state-blob", &json!({"type": "boolean"}), "Approve?");
    assert!(matches!(acp_req.source, ElicitationSource::Acp { .. }));
    assert!(matches!(mcp_req.source, ElicitationSource::Mcp { .. }));
    assert_eq!(
        acp_req.schema, mcp_req.schema,
        "both normalize to the same schema-driven form our elicit task renders"
    );
}

#[test]
fn completion_routes_back_through_the_original_protocols_correlation_mechanism() {
    let acp_req = normalize_acp_elicitation("elicit-123", &json!({"type": "boolean"}), "Approve?");
    let acp_resp = ElicitResponse::for_request(&acp_req, json!(true));
    assert_eq!(
        complete_acp(&acp_req, &acp_resp),
        Some("elicit-123".to_string())
    );
    assert_eq!(
        complete_mcp(&acp_req, &acp_resp),
        None,
        "an ACP-sourced request never produces an MCP requestState echo"
    );

    let mcp_req =
        normalize_mcp_elicitation("opaque-state-blob", &json!({"type": "boolean"}), "Approve?");
    let mcp_resp = ElicitResponse::for_request(&mcp_req, json!(true));
    assert_eq!(
        complete_mcp(&mcp_req, &mcp_resp),
        Some("opaque-state-blob".to_string())
    );
    assert_eq!(complete_acp(&mcp_req, &mcp_resp), None);
}

#[test]
fn a_response_built_for_one_acp_request_does_not_complete_a_different_one() {
    let req_a = normalize_acp_elicitation("elicit-a", &json!({"type": "boolean"}), "Approve?");
    let req_b = normalize_acp_elicitation("elicit-b", &json!({"type": "boolean"}), "Approve?");
    let resp_for_b = ElicitResponse::for_request(&req_b, json!(true));

    assert_eq!(
        complete_acp(&req_a, &resp_for_b),
        None,
        "req_a must not be completed by a response minted for req_b"
    );
    assert_eq!(
        complete_acp(&req_b, &resp_for_b),
        Some("elicit-b".to_string())
    );
}

#[test]
fn a_response_built_for_one_mcp_request_does_not_complete_a_different_one() {
    let req_a = normalize_mcp_elicitation("state-a", &json!({"type": "boolean"}), "Approve?");
    let req_b = normalize_mcp_elicitation("state-b", &json!({"type": "boolean"}), "Approve?");
    let resp_for_b = ElicitResponse::for_request(&req_b, json!(true));

    assert_eq!(
        complete_mcp(&req_a, &resp_for_b),
        None,
        "req_a must not be completed by a response minted for req_b"
    );
    assert_eq!(
        complete_mcp(&req_b, &resp_for_b),
        Some("state-b".to_string())
    );
}

#[test]
fn task_kind_for_elicitation_is_elicit() {
    assert_eq!(task_kind(), TaskKind::Elicit);
}

#[test]
fn suspend_reason_for_elicit_request_carries_its_schema() {
    let req = normalize_acp_elicitation("elicit-123", &json!({"type": "boolean"}), "Approve?");
    assert!(matches!(
        suspend_reason(&req),
        SuspendReason::AwaitingElicitation { schema } if schema == json!({"type": "boolean"})
    ));
}
