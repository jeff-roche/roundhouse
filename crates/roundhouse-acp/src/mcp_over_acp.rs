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

use crate::peer_text::{escape_and_cap_peer_str, EscapedPeerStr};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// One MCP-over-ACP tool this process can serve in-process.
pub trait McpOverAcpTool: Send + Sync {
    fn name(&self) -> &str;
    fn input_schema(&self) -> Value;
    fn call(&self, args: Value) -> Result<Value, String>;
}

/// [`InProcessMcpServer::register`]'s error: `name` was already registered.
///
/// **Fix round 2 (Item 3):** replaces the previous
/// `Result<(), Box<dyn McpOverAcpTool>>` return type, whose error carried no
/// `Debug`, `Display`, or `std::error::Error` impl at all — unusable by any
/// idiomatic caller (`?` into `anyhow`/`color-eyre`, `.unwrap()`,
/// `.expect()` all failed to compile), which pushed a real caller toward
/// `let _ = server.register(..)`, silently discarding the collision
/// `#[must_use]` only warns about. This type keeps the rejected tool (so the
/// caller does not lose the value it passed in) while making `?`, `unwrap`,
/// and logging all work.
///
/// `Box<dyn McpOverAcpTool>` has no `Debug` impl, so this type cannot derive
/// `Debug` — see the manual impl below, which prints the escaped, capped
/// name (never the rejected tool itself, which has nothing safe to print).
///
/// **Fix round 3 (Item 1/4):** `name` is now [`EscapedPeerStr`] rather than
/// a bare `String`, fixing two defects the round-3 review found in this
/// type specifically:
///
/// - `Display` (from `#[error("... {name:?}")]`, the old format) escaped
///   via `{:?}` but applied **no cap** — unlike every other peer-controlled
///   string this crate formats. `Display` is the path a real caller
///   actually uses (`?` into `anyhow`/`color-eyre`, `%err` in `tracing`), so
///   the uncapped half of the escape-and-cap discipline never actually ran
///   for this type. Since `name` is now always the *already* escaped-and-
///   capped output of [`escape_and_cap_peer_str`], the `#[error(...)]`
///   string below interpolates it with plain `{name}`, matching
///   `PermissionError::MissingRawInput`/`UnidentifiableTool`'s convention
///   (`server::mod`) — and is capped, because the value already is.
/// - The hand-written `Debug` impl below used to call
///   `escape_and_cap_peer_str(&self.name)` on a `name: String` that was
///   *already* the tool's raw, unescaped name — so `Debug` escaped it once,
///   correctly. Once `name` itself became pre-escaped (this round), that
///   same call would have escaped it a **second** time (`debug_struct::field`
///   applies `{:?}` to whatever it's handed), producing `name:
///   "\"echo\""` instead of `name: "echo"`. The impl below now hands
///   `&self.name` straight to `.field(..)`, relying on
///   [`EscapedPeerStr`]'s own `Debug` impl (which — deliberately, for this
///   exact reason — writes its contents verbatim rather than re-escaping).
#[derive(thiserror::Error)]
#[error("a tool is already registered under the name {name}")]
pub struct DuplicateToolName {
    pub name: EscapedPeerStr,
    pub rejected: Box<dyn McpOverAcpTool>,
}

impl fmt::Debug for DuplicateToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `name` is already escaped and capped (see the struct doc above) —
        // handing it straight to `.field(..)` relies on `EscapedPeerStr`'s
        // own `Debug` impl not re-escaping it, avoiding the double-escaping
        // defect this round fixed.
        f.debug_struct("DuplicateToolName")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
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
    /// Returns `Err(DuplicateToolName { name, rejected: tool })` — handing
    /// the rejected tool back to the caller — if a tool is already
    /// registered under that name, rather than silently shadowing (first
    /// registration wins) or silently replacing (last registration wins)
    /// it. Ruling C-P55: a caller that populates this registry from more
    /// than one source of differing trust must make an explicit decision
    /// about a name collision rather than have one silently imposed on it.
    /// Fix round 2 (Item 3): `DuplicateToolName` implements
    /// `std::error::Error`, unlike the plain `Box<dyn McpOverAcpTool>` this
    /// used to return as `Err`.
    pub fn register(&mut self, tool: Box<dyn McpOverAcpTool>) -> Result<(), DuplicateToolName> {
        use std::collections::btree_map::Entry;
        let name = tool.name().to_string();
        match self.tools.entry(name.clone()) {
            Entry::Occupied(_) => Err(DuplicateToolName {
                name: escape_and_cap_peer_str(&name),
                rejected: tool,
            }),
            Entry::Vacant(slot) => {
                slot.insert(tool);
                Ok(())
            }
        }
    }

    /// Shaped like MCP's own `tools/list` result — this is deliberate: the
    /// day the transport wiring above lands, this is the payload it hands
    /// the SDK unchanged.
    ///
    /// **Fix round 2 (Item 2):** publishes the `BTreeMap` key (the name
    /// `register` actually dispatches on), not a second call to `t.name()`.
    /// `McpOverAcpTool` is `Send + Sync` with `fn name(&self) -> &str` and no
    /// determinism requirement — an implementation whose `name()` derives
    /// from mutable state could previously advertise a different name in
    /// `list_tools` than the key `call_tool` dispatches on, relocating the
    /// exact confused-deputy shape the registry keying fix (Ruling C-P55)
    /// was meant to close from the `Vec` into the trait contract. Keying the
    /// published name off the map entry makes the list/dispatch agreement
    /// structural rather than contractual.
    pub fn list_tools(&self) -> Vec<Value> {
        self.tools
            .iter()
            .map(|(name, t)| serde_json::json!({"name": name, "inputSchema": t.input_schema()}))
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
