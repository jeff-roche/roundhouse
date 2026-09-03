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

use crate::server::escape_and_cap_peer_str;
use serde_json::Value;
use std::collections::BTreeMap;

/// One MCP-over-ACP tool this process can serve in-process.
pub trait McpOverAcpTool: Send + Sync {
    fn name(&self) -> &str;
    fn input_schema(&self) -> Value;
    fn call(&self, args: Value) -> Result<Value, String>;
}

/// A real, testable in-process tool registry and dispatcher — the serving
/// half of §10.1's "being an ACP client means being an MCP server" model.
///
/// **Ruling C-P55 (fix round 1):** keyed on tool name (`BTreeMap`) rather
/// than a `Vec` searched with `.find(..)`. The `Vec` form let a later
/// `register` call for an already-used name silently shadow the earlier one
/// from `call_tool`'s point of view (first registration permanently wins,
/// via `.find`'s left-to-right scan) while `list_tools` still advertised
/// *both* entries with two different `inputSchema` values — a confused-
/// deputy setup: a peer sees the legitimate tool's schema in `list_tools`
/// but `call_tool` may dispatch to a different, earlier-registered
/// implementation of the same name. Keying on name and rejecting a
/// duplicate registration outright (see [`register`](Self::register)) makes
/// a name collision an explicit, observable decision instead of a silent
/// shadow.
#[derive(Default)]
pub struct InProcessMcpServer {
    tools: BTreeMap<String, Box<dyn McpOverAcpTool>>,
}

impl InProcessMcpServer {
    pub fn new() -> Self {
        Self {
            tools: BTreeMap::new(),
        }
    }

    /// Registers `tool` under its own `name()`. `name` comparison for
    /// dispatch (via the `BTreeMap` key) is exact byte equality on `&str` —
    /// no case folding, no Unicode normalization, no trimming — matching
    /// this crate's existing exact-`Arc<str>`-id-comparison convention
    /// elsewhere (`PermissionOptionId` equality in `server::mod`).
    ///
    /// Returns `Err(tool)` — handing the rejected tool back to the caller —
    /// if a tool is already registered under that name, rather than
    /// silently shadowing (first registration wins) or silently replacing
    /// (last registration wins) it. Ruling C-P55: a caller that populates
    /// this registry from more than one source of differing trust must make
    /// an explicit decision about a name collision rather than have one
    /// silently imposed on it.
    pub fn register(
        &mut self,
        tool: Box<dyn McpOverAcpTool>,
    ) -> Result<(), Box<dyn McpOverAcpTool>> {
        use std::collections::btree_map::Entry;
        match self.tools.entry(tool.name().to_string()) {
            Entry::Occupied(_) => Err(tool),
            Entry::Vacant(slot) => {
                slot.insert(tool);
                Ok(())
            }
        }
    }

    /// Shaped like MCP's own `tools/list` result — this is deliberate: the
    /// day the transport wiring above lands, this is the payload it hands
    /// the SDK unchanged.
    pub fn list_tools(&self) -> Vec<Value> {
        self.tools
            .values()
            .map(|t| serde_json::json!({"name": t.name(), "inputSchema": t.input_schema()}))
            .collect()
    }

    /// **Ruling C-P54 (fix round 1):** `name` is the peer's own tool name in
    /// this module's own MCP-`tools/call`-over-ACP wiring — untrusted input.
    /// The "unknown tool" error previously interpolated it verbatim via
    /// `Display` (`format!("unknown tool '{name}'")`), the only place in
    /// this crate that did so rather than escaping and capping peer-
    /// controlled strings first; a peer naming a tool
    /// `"\n[audit] call_tool: ok"` could forge an audit-log line, and an
    /// arbitrarily long name could inflate any log rendering this error
    /// without bound. Routed through `escape_and_cap_peer_str` — the same
    /// discipline `server::ambiguous_option_ids` and
    /// `server::resolve_selection` already apply to peer-controlled
    /// `option_id`s.
    pub fn call_tool(&self, name: &str, args: Value) -> Result<Value, String> {
        self.tools
            .get(name)
            .ok_or_else(|| format!("unknown tool {}", escape_and_cap_peer_str(name)))?
            .call(args)
    }
}
