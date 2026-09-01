use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Monotonic per-connection JSON-RPC id. MRTR requires a *new* id on every
/// retry (§10.1) — this type exists so "mint a new id" is one call site,
/// never ad-hoc arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct JsonRpcId(pub u64);

#[derive(Debug, Default)]
pub struct JsonRpcIdGen(std::sync::atomic::AtomicU64);

impl JsonRpcIdGen {
    pub fn next(&self) -> JsonRpcId {
        JsonRpcId(self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }
}

/// Opaque, AEAD-protected server-minted blob (§10.1). We never parse it —
/// only store and echo it verbatim on retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestState(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputRequest {
    pub id: String,
    pub prompt: String,
    pub schema: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputResponse {
    pub id: String,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct ToolCallRequest {
    pub jsonrpc_id: JsonRpcId,
    pub tool: String,
    pub args: Value,
    /// Present only on an MRTR retry.
    pub request_state: Option<RequestState>,
    pub input_responses: Vec<InputResponse>,
}

#[derive(Debug, Clone)]
pub enum McpResultType {
    Ok,
    InputRequired {
        input_requests: Vec<InputRequest>,
        request_state: RequestState,
    },
}

#[derive(Debug, Clone)]
pub struct McpResult {
    pub result_type: McpResultType,
    /// Raw `CallToolResult.content` blocks, still in MCP's wire shape —
    /// decoding into `roundhouse_provider::ContentBlock` happens in `executor.rs`.
    pub content: Vec<McpContentBlock>,
    pub is_error: bool,
}

#[derive(Debug, Clone)]
pub enum McpContentBlock {
    Text {
        text: String,
    },
    Image {
        media_type: String,
        data_base64: String,
    },
    Resource {
        uri: String,
        media_type: Option<String>,
        text: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct McpToolDef {
    pub name: String,
    /// UNTRUSTED — server-authored free text (§6.8: "MCP results *and tool
    /// descriptions*"). Never interpolated into anything executed.
    pub description: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone)]
pub struct DiscoverResult {
    pub protocol_version: String,
    pub tools: Vec<McpToolDef>,
}

#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("mcp transport io error: {0}")]
    Io(String),
    #[error("mcp server returned a protocol error: {0}")]
    Protocol(String),
    #[error("mcp server process exited before responding")]
    ServerExited,
    #[error("mcp request timed out after {after:?}")]
    Timeout { after: std::time::Duration },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_gen_never_repeats_across_a_retry_sequence() {
        let gen = JsonRpcIdGen::default();
        let first = gen.next();
        let retry = gen.next();
        assert_ne!(
            first, retry,
            "MRTR requires a NEW id on every retry (§10.1)"
        );
        assert_eq!(first.0, 0);
        assert_eq!(retry.0, 1);
    }
}
