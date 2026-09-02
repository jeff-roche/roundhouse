// SEC-2 (round-2 review on Task 24/C3): `RequestPermissionRequest.tool_call`
// is a `ToolCallUpdate`, which has no tool-name field at all. This exercises
// `normalize_tool_call_for_policy`'s fail-closed behavior against the real
// SDK type from outside the crate.
use agent_client_protocol::schema::v1::{ToolCallUpdate, ToolCallUpdateFields, ToolKind};
use roundhouse_acp::server::{normalize_tool_call_for_policy, AcpToolKindClaim, PermissionError};

#[test]
fn identifies_tool_and_args_when_kind_and_raw_input_are_both_present() {
    let update = ToolCallUpdate::new(
        "tc-1",
        ToolCallUpdateFields::new()
            .kind(ToolKind::Execute)
            .raw_input(serde_json::json!({"cmd": "ls"})),
    );
    let (tool, args) = normalize_tool_call_for_policy(&update).expect("both fields present");
    assert_eq!(tool, AcpToolKindClaim(ToolKind::Execute));
    assert_eq!(args, serde_json::json!({"cmd": "ls"}));
}

#[test]
fn the_returned_claim_requires_an_explicit_daemon_owned_mapping_to_become_a_tool_name() {
    // FIX-A (round-3 review): AcpToolKindClaim carries no From/Into/Display
    // to &str/String, so it cannot flow directly into
    // handle_request_permission's `tool: &str` parameter — a caller must
    // write out the ToolKind -> Roundhouse-tool-namespace mapping
    // explicitly, as demonstrated here.
    let update = ToolCallUpdate::new(
        "tc-6",
        ToolCallUpdateFields::new()
            .kind(ToolKind::Execute)
            .raw_input(serde_json::json!({"cmd": "ls"})),
    );
    let (claim, _args) = normalize_tool_call_for_policy(&update).expect("both fields present");
    let daemon_mapped_tool_name: &str = match claim {
        AcpToolKindClaim(ToolKind::Execute) => "shell",
        AcpToolKindClaim(ToolKind::Read) => "read",
        _ => "unmapped",
    };
    assert_eq!(daemon_mapped_tool_name, "shell");
}

#[test]
fn fails_closed_when_raw_input_is_absent_rather_than_substituting_an_empty_object() {
    // Absent rawInput must produce a distinct error, not a silent {} — that
    // substitution would be indistinguishable from a real empty-args call
    // and could bypass any policy rule that classifies on argument content.
    let update = ToolCallUpdate::new("tc-2", ToolCallUpdateFields::new().kind(ToolKind::Execute));
    let err = normalize_tool_call_for_policy(&update).expect_err("rawInput was never supplied");
    assert_eq!(
        err,
        PermissionError::MissingRawInput {
            tool_call_id: "tc-2".to_string()
        }
    );
}

#[test]
fn a_present_but_empty_raw_input_is_not_an_error() {
    // The distinction SEC-2 requires: "no arguments were supplied" (above)
    // is refused, but "the arguments are the empty object" is a legitimate,
    // distinguishable result.
    let update = ToolCallUpdate::new(
        "tc-3",
        ToolCallUpdateFields::new()
            .kind(ToolKind::Execute)
            .raw_input(serde_json::json!({})),
    );
    let (_, args) = normalize_tool_call_for_policy(&update).expect("rawInput was `{}`, not absent");
    assert_eq!(args, serde_json::json!({}));
}

#[test]
fn fails_closed_when_kind_is_absent() {
    let update = ToolCallUpdate::new(
        "tc-4",
        ToolCallUpdateFields::new().raw_input(serde_json::json!({})),
    );
    let err = normalize_tool_call_for_policy(&update).expect_err("kind was never supplied");
    assert_eq!(
        err,
        PermissionError::UnidentifiableTool {
            tool_call_id: "tc-4".to_string()
        }
    );
}

#[test]
fn fails_closed_when_kind_is_other_even_if_title_looks_informative() {
    // ToolKind::Other is both the wire default and the deserialization
    // fallback for any kind this SDK version doesn't recognize, so it must
    // not identify a specific tool. `title` is agent-authored free text and
    // is deliberately never used as a fallback identifier, even when it
    // looks descriptive — a peer could craft it to fool a naive mapping.
    let update = ToolCallUpdate::new(
        "tc-5",
        ToolCallUpdateFields::new()
            .kind(ToolKind::Other)
            .title("Running the shell tool".to_string())
            .raw_input(serde_json::json!({})),
    );
    let err = normalize_tool_call_for_policy(&update)
        .expect_err("kind was Other; title must not be used as a fallback identifier");
    assert_eq!(
        err,
        PermissionError::UnidentifiableTool {
            tool_call_id: "tc-5".to_string()
        }
    );
}
