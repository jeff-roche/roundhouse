use roundhouse_engine::assemble_context;
use roundhouse_provider::codec::anthropic_messages::encode_anthropic_messages;
use roundhouse_provider::{tool_def_from_schema, ContentBlock, Message, MessageRole as Role};

/// Test params struct for the "read" tool.
#[derive(schemars::JsonSchema)]
struct ReadParams {
    #[allow(dead_code)]
    path: String,
}

fn sample_tools() -> Vec<roundhouse_provider::ToolDef> {
    vec![tool_def_from_schema::<ReadParams>("read", "Read a file")]
}

fn sample_turn() -> Vec<Message> {
    vec![Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: "Edit main.rs".into(),
            cache: None,
            citations: vec![],
        }],
    }]
}

#[test]
fn render_order_is_system_then_tools_then_turn() {
    let req = assemble_context(
        "claude-sonnet-5",
        "You are careful.",
        &sample_tools(),
        &sample_turn(),
    );

    assert_eq!(req.system[0].text, "You are careful.");
    assert_eq!(req.tools[0].name(), "read");
    assert_eq!(req.messages[0].role, Role::User);
    assert!(
        req.system[0].cache.is_some(),
        "system layer gets the first cache breakpoint"
    );
}

#[test]
fn assembly_is_deterministic_across_repeated_calls() {
    let req_a = assemble_context(
        "claude-sonnet-5",
        "You are careful.",
        &sample_tools(),
        &sample_turn(),
    );
    let req_b = assemble_context(
        "claude-sonnet-5",
        "You are careful.",
        &sample_tools(),
        &sample_turn(),
    );

    let json_a = serde_json::to_string(&encode_anthropic_messages(&req_a)).unwrap();
    let json_b = serde_json::to_string(&encode_anthropic_messages(&req_b)).unwrap();

    assert_eq!(
        json_a, json_b,
        "identical inputs must render byte-identical requests for cache effectiveness"
    );
}
