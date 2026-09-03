//! §10.1's third load-bearing v2 detail: "In v2, being an ACP client means
//! being an MCP server... it serves those tools in-process over the existing
//! ACP channel instead of spawning a shim." This trait/registry is the
//! in-process serving half — a real, unit-testable tool registry and
//! dispatcher requiring no live ACP connection.
//!
//! **Deferred, and why (Ruling C-P10):** the *transport* half — actually
//! multiplexing MCP `tools/call`-shaped requests over the same JSON-RPC
//! channel `session/update` already uses — is not built here. The pinned
//! `agent-client-protocol` 2.0.0 SDK's `unstable_mcp_over_acp` feature is a
//! real, substantial, already-shipped transport (`ConnectMcpRequest` /
//! `MessageMcpRequest` / `DisconnectMcpRequest`, `McpConnectionId`, wired
//! into the main request/notification dispatch enums) available under v1
//! *today* — it is gated completely independently of `unstable_protocol_v2`
//! and is not waiting on v2 to stabilize. The transport wiring is out of
//! scope for this task not because it is blocked on v2, but because it needs
//! a live ACP connection and daemon-owned session plumbing this crate does
//! not have (`roundhouse-acp` is frozen at deps `{core, proto}` only for this
//! subsystem; driving an actual connection is daemon integration work).
//! `InProcessMcpServer` below is written so that the day that wiring lands,
//! it plugs a fully-formed tool registry/dispatcher straight into the SDK's
//! transport loop rather than starting from nothing — the side of this that
//! doesn't depend on a live connection is built now, in full.
//!
//! Ungated (no `acp-v2` requirement): this in-process registry has no
//! v2-specific dependency of its own. It is documented as v2-only *in
//! practice* since v1 has no MCP-server-over-ACP concept at all — but
//! nothing in this file actually requires the `acp-v2` feature to compile or
//! run.

use serde_json::Value;

/// One MCP-over-ACP tool this process can serve in-process.
pub trait McpOverAcpTool: Send + Sync {
    fn name(&self) -> &str;
    fn input_schema(&self) -> Value;
    fn call(&self, args: Value) -> Result<Value, String>;
}

/// A real, testable in-process tool registry and dispatcher — the serving
/// half of §10.1's "being an ACP client means being an MCP server" model.
#[derive(Default)]
pub struct InProcessMcpServer {
    tools: Vec<Box<dyn McpOverAcpTool>>,
}

impl InProcessMcpServer {
    pub fn new() -> Self {
        Self { tools: Vec::new() }
    }

    pub fn register(&mut self, tool: Box<dyn McpOverAcpTool>) {
        self.tools.push(tool);
    }

    /// Shaped like MCP's own `tools/list` result — this is deliberate: the
    /// day the transport wiring above lands, this is the payload it hands
    /// the SDK unchanged.
    pub fn list_tools(&self) -> Vec<Value> {
        self.tools
            .iter()
            .map(|t| serde_json::json!({"name": t.name(), "inputSchema": t.input_schema()}))
            .collect()
    }

    pub fn call_tool(&self, name: &str, args: Value) -> Result<Value, String> {
        self.tools
            .iter()
            .find(|t| t.name() == name)
            .ok_or_else(|| format!("unknown tool '{name}'"))?
            .call(args)
    }
}
