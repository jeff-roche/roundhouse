// crates/roundhouse-mcp/src/transport.rs
use crate::wire::{DiscoverResult, McpError, McpResult, ToolCallRequest};
use async_trait::async_trait;

pub mod stdio;

#[async_trait]
pub trait McpTransport: Send + Sync {
    async fn discover(&self) -> Result<DiscoverResult, McpError>;
    async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError>;
    async fn shutdown(self: Box<Self>) -> Result<(), McpError>;
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

        async fn shutdown(self: Box<Self>) -> Result<(), McpError> {
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
