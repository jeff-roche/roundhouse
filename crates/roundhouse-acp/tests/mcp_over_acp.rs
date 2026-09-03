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

/// A second, distinguishable tool registered under the same name as
/// [`EchoTool`] — used to prove a duplicate `register` is rejected rather
/// than silently shadowing or replacing the first (Ruling C-P55).
struct ImposterEchoTool;
impl McpOverAcpTool for ImposterEchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({"type": "object", "properties": {"totally_different": {"type": "boolean"}}})
    }
    fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(json!({"imposter": true}))
    }
}

#[test]
fn in_process_mcp_server_serves_tools_without_spawning_a_shim_process() {
    // §10.1/§10.2: "it serves those tools in-process over the existing ACP
    // channel instead of spawning a shim" — this test only exercises the
    // in-process registry/dispatch half; see this task's fix note for what
    // the real over-the-wire multiplexing still needs from the pinned SDK.
    let mut server = InProcessMcpServer::new();
    server
        .register(Box::new(EchoTool))
        .ok()
        .expect("first registration must succeed");

    let tools = server.list_tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("echo"));

    let result = server.call_tool("echo", json!({"text": "hi"})).unwrap();
    assert_eq!(result["echoed"], json!("hi"));

    assert!(server.call_tool("nonexistent", json!({})).is_err());
}

#[test]
fn register_rejects_a_duplicate_name_instead_of_silently_shadowing_it() {
    // Ruling C-P55: the old Vec-backed registry let a second `register` for
    // an already-used name shadow the first silently — `call_tool` (which
    // used `.find`) always dispatched to whichever was registered *first*,
    // while `list_tools` advertised both, with two different schemas, under
    // the same name. That confused-deputy gap is closed by making a
    // duplicate an explicit `Err` the caller must handle, rather than an
    // outcome only observable by noticing `list_tools`'s length.
    let mut server = InProcessMcpServer::new();
    server
        .register(Box::new(EchoTool))
        .ok()
        .expect("first registration must succeed");

    let rejected = server
        .register(Box::new(ImposterEchoTool))
        .expect_err("registering a second tool under the same name must be rejected");
    assert_eq!(rejected.name(), "echo");

    // The registry is unchanged: exactly one "echo" entry, still the
    // original tool's schema and behavior — not the imposter's.
    let tools = server.list_tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(
        tools[0]["inputSchema"],
        json!({"type": "object", "properties": {"text": {"type": "string"}}}),
        "the original tool's schema must survive a rejected duplicate registration"
    );
    let result = server.call_tool("echo", json!({"text": "hi"})).unwrap();
    assert_eq!(
        result,
        json!({"echoed": "hi"}),
        "call_tool must still dispatch to the original tool, not the rejected imposter"
    );
}
