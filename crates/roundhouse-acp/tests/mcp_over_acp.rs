//! Tests for the in-process MCP-over-ACP tool registry/dispatcher. Ungated
//! (unlike `tests/v2_schema_details.rs` — Ruling C-P9): `mcp_over_acp` has no
//! v2-specific dependency, so this must build and pass under a plain
//! `cargo test --workspace` as well as `--features acp-v2`.

use roundhouse_acp::mcp_over_acp::{InProcessMcpServer, McpOverAcpTool};
use serde_json::json;

struct EchoTool;
impl McpOverAcpTool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({"type": "object", "properties": {"text": {"type": "string"}}})
    }
    fn call(&self, args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(json!({"echoed": args["text"]}))
    }
}

#[test]
fn in_process_mcp_server_serves_tools_without_spawning_a_shim_process() {
    // §10.1/§10.2: "it serves those tools in-process over the existing ACP
    // channel instead of spawning a shim" — this test only exercises the
    // in-process registry/dispatch half; see this task's fix note for what
    // the real over-the-wire multiplexing still needs from the pinned SDK.
    let mut server = InProcessMcpServer::new();
    server.register(Box::new(EchoTool));

    let tools = server.list_tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("echo"));

    let result = server.call_tool("echo", json!({"text": "hi"})).unwrap();
    assert_eq!(result["echoed"], json!("hi"));

    assert!(server.call_tool("nonexistent", json!({})).is_err());
}
