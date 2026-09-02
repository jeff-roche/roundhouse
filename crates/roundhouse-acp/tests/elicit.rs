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
    let resp = ElicitResponse { value: json!(true) };
    assert_eq!(
        complete_acp(&acp_req, &resp),
        Some("elicit-123".to_string())
    );
    assert_eq!(
        complete_mcp(&acp_req, &resp),
        None,
        "an ACP-sourced request never produces an MCP requestState echo"
    );

    let mcp_req =
        normalize_mcp_elicitation("opaque-state-blob", &json!({"type": "boolean"}), "Approve?");
    assert_eq!(
        complete_mcp(&mcp_req, &resp),
        Some("opaque-state-blob".to_string())
    );
    assert_eq!(complete_acp(&mcp_req, &resp), None);
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
