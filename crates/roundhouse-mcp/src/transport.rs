// crates/roundhouse-mcp/src/transport.rs
use crate::wire::{DiscoverResult, McpError, McpResult, ToolCallRequest};
use async_trait::async_trait;

pub mod stdio;

/// One connection to a configured MCP server, however it is carried —
/// today over a stdio child process (`StdioMcpTransport`), always behind
/// this seam so the executor and every later task stay transport-blind.
///
/// A transport owns the connection's request plumbing: fresh JSON-RPC ids
/// per call, response matching, and a dead server surfacing as
/// `McpError::ServerExited` instead of a hang. Everything a server sends
/// back — tool names, descriptions, content — is untrusted input (§6.8);
/// callers decode and gate it. Used through `Arc<dyn McpTransport>` in
/// production and `Box<dyn McpTransport>` in tests.
#[async_trait]
pub trait McpTransport: Send + Sync {
    /// Ask the connected server what it offers: the wire protocol version
    /// it reports and its tool list. Tool descriptions are
    /// server-authored free text — untrusted, never executed (§6.8).
    async fn discover(&self) -> Result<DiscoverResult, McpError>;

    /// Invoke one tool (`tools/call`). `req` carries a fresh
    /// per-connection `jsonrpc_id` (an MRTR retry re-issues the ORIGINAL
    /// tool and args under a NEW id, with the server's opaque
    /// `request_state` echoed verbatim and the elicitation answers riding
    /// along as `input_responses`, §10.1); the wire-level id is each
    /// transport's own concern. Returns the raw wire-shaped result:
    /// `McpResultType::Ok` content, an `InputRequired` suspension point
    /// (the executor turns that into an `elicit` child task and suspends
    /// the parent), or an error.
    async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError>;

    /// End the session: close the child's stdin, stop the reader task,
    /// and CONFIRM the server process (and its whole process group, for
    /// the stdio transport) is gone before returning `Ok`.
    ///
    /// Takes `&self`, not `Box<Self>` (Phase 3 review fix, 2026-09-01):
    /// production holds transports as `Arc<dyn McpTransport>`, and
    /// `Arc<dyn Trait>` cannot be downcast to `Box<Self>` — a
    /// `self: Box<Self>` shutdown was structurally unreachable from the
    /// one place that owns live connections (`McpExecutor`), so daemon
    /// shutdown silently orphaned every MCP child process. Reaching the
    /// teardown through a shared handle requires shared-receiver dispatch;
    /// implementations must therefore be idempotent (`StdioMcpTransport`
    /// takes its child/reader/stdin out of interior state — a second call
    /// is a no-op `Ok`), and callers must not rely on a drop to shut the
    /// connection down. Explicit `shutdown()` remains the ONLY sanctioned
    /// teardown; the stdio transport's kill-on-drop is a backstop for
    /// paths that can't await, not a substitute.
    async fn shutdown(&self) -> Result<(), McpError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{JsonRpcId, McpResultType, McpToolDef};

    /// Smallest possible transport, used only to prove the trait's method
    /// signatures are actually usable through a trait object — the shape
    /// every real implementation (Task 5, Task 6) must match.
    struct NullTransport;

    #[async_trait]
    impl McpTransport for NullTransport {
        async fn discover(&self) -> Result<DiscoverResult, McpError> {
            Ok(DiscoverResult {
                protocol_version: "2026-07-28".into(),
                tools: vec![McpToolDef {
                    name: "noop".into(),
                    description: "does nothing".into(),
                    input_schema: serde_json::json!({}),
                }],
            })
        }

        async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError> {
            assert_eq!(req.jsonrpc_id, JsonRpcId(0));
            Ok(McpResult {
                result_type: McpResultType::Ok,
                content: vec![],
                is_error: false,
            })
        }

        async fn shutdown(&self) -> Result<(), McpError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn trait_object_is_dispatchable() {
        let transport: Box<dyn McpTransport> = Box::new(NullTransport);
        let discovered = transport.discover().await.unwrap();
        assert_eq!(discovered.tools.len(), 1);
        let result = transport
            .call_tool(ToolCallRequest {
                jsonrpc_id: JsonRpcId(0),
                tool: "noop".into(),
                args: serde_json::json!({}),
                request_state: None,
                input_responses: vec![],
            })
            .await
            .unwrap();
        assert!(!result.is_error);
        transport.shutdown().await.unwrap();
    }
}
