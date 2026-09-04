//! Tests for the in-process MCP-over-ACP tool registry/dispatcher. Ungated
//! (unlike `tests/v2_schema_details.rs` — Ruling C-P9): `mcp_over_acp` has no
//! v2-specific dependency, so this must build and pass under a plain
//! `cargo test --workspace` as well as `--features acp-v2`.

use roundhouse_acp::mcp_over_acp::{InProcessMcpServer, McpOverAcpTool};
use roundhouse_acp::peer_text::{escape_and_cap_peer_str, PEER_STR_MAX_LEN};
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
        .expect("first registration must succeed");

    let tools = server.list_tools();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], json!("echo"));

    let result = server.call_tool("echo", json!({"text": "hi"})).unwrap();
    assert_eq!(result["echoed"], json!("hi"));

    assert!(server.call_tool("nonexistent", json!({})).is_err());
}

#[test]
fn call_tool_escapes_and_caps_a_hostile_unknown_tool_name() {
    // Fix round 2 (Item 1): the only assertion on this path used to be
    // `.is_err()` above, which holds for *any* error message whatsoever —
    // it does not prove the tool-name path actually reaches
    // `escape_and_cap_peer_str`. This asserts on the returned message's
    // actual content: a peer naming a tool `"a\n[audit] call_tool: ok"`
    // (padded well past the crate's escape-and-cap length limit) must not
    // be able to inject a raw newline into the error, nor inflate it
    // unboundedly.
    let server = InProcessMcpServer::new();
    let hostile_name = format!("a\n[audit] call_tool: ok{}", "b".repeat(500));

    let err = server
        .call_tool(&hostile_name, json!({}))
        .expect_err("no tool was ever registered under this name");

    assert!(
        !err.contains('\n'),
        "unknown-tool error must not contain a raw newline: {err:?}"
    );
    // Fix round 3 (ruling C-P71): `peer_text::PEER_STR_MAX_LEN` is public
    // again, so this assertion references the constant directly instead of
    // hardcoding the literal `128` and silently decoupling from it.
    assert!(
        err.len() <= "unknown tool ".len() + PEER_STR_MAX_LEN,
        "unknown-tool error must be bounded by the cap plus the fixed \
         prefix, got {} bytes: {err:?}",
        err.len()
    );
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
        .expect("first registration must succeed");

    let rejected = server
        .register(Box::new(ImposterEchoTool))
        .expect_err("registering a second tool under the same name must be rejected");
    // Fix round 3: `rejected.name` is now `EscapedPeerStr` (Ruling C-P69),
    // so the expected value is what `escape_and_cap_peer_str` produces for
    // "echo" (the quoted, `Debug`-escaped form), not the bare `&str`.
    assert_eq!(rejected.name, escape_and_cap_peer_str("echo"));
    assert_eq!(rejected.rejected.name(), "echo");
    // The error is now a real std::error::Error — Debug, Display, `?`, and
    // `.unwrap()`/`.expect()` all work, unlike the old `Box<dyn
    // McpOverAcpTool>` error (Fix round 2, Item 3).
    assert_eq!(
        rejected.to_string(),
        "a tool is already registered under the name \"echo\""
    );
    assert!(format!("{rejected:?}").contains("DuplicateToolName"));

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

/// A tool whose `name()` is supplied by the test, so a single struct can
/// stand in for both the original and the colliding registration below.
struct NamedTool(String);
impl McpOverAcpTool for NamedTool {
    fn name(&self) -> &str {
        &self.0
    }
    fn input_schema(&self) -> serde_json::Value {
        json!({})
    }
    fn call(&self, _args: serde_json::Value) -> Result<serde_json::Value, String> {
        Ok(json!({}))
    }
}

#[test]
fn duplicate_tool_name_display_is_escaped_and_capped() {
    // Fix round 3 (Item 3): `register_rejects_a_duplicate_name_...` above
    // only exercises the short name "echo", which would not have caught a
    // missing cap — `DuplicateToolName`'s `Display` used to escape via
    // `{name:?}` but apply no cap at all (Item 4's finding) before
    // `EscapedPeerStr` made that structurally impossible. This registers
    // two tools under one hostile name (a fake audit line plus padding well
    // past the cap) and asserts the rejection's *rendered* `Display`
    // message is both newline-free and length-bounded.
    let hostile_name = format!("x\n[audit] register: ok{}", "z".repeat(500));
    let mut server = InProcessMcpServer::new();
    server
        .register(Box::new(NamedTool(hostile_name.clone())))
        .expect("first registration must succeed");

    let rejected = server
        .register(Box::new(NamedTool(hostile_name)))
        .expect_err("registering a second tool under the same hostile name must be rejected");

    let rendered = rejected.to_string();
    assert!(
        !rendered.contains('\n'),
        "rendered DuplicateToolName message must not contain a raw newline: {rendered:?}"
    );
    assert!(
        rendered.len() <= "a tool is already registered under the name ".len() + PEER_STR_MAX_LEN,
        "rendered message must be bounded by the cap plus the fixed prefix, got {} bytes: {rendered:?}",
        rendered.len()
    );
}
