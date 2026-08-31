// crates/roundhouse-mcp/src/testing.rs
#![cfg(test)]

use crate::transport::McpTransport;
use crate::wire::{
    DiscoverResult, InputRequest, McpContentBlock, McpError, McpResult, McpResultType, McpToolDef,
    RequestState, ToolCallRequest,
};
use async_trait::async_trait;
use std::collections::VecDeque;
use std::sync::Mutex;

pub enum ScriptedResponse {
    Ok(Vec<McpContentBlock>),
    InputRequired {
        input_requests: Vec<InputRequest>,
        request_state: RequestState,
    },
    Error(McpError),
}

pub struct FakeMcpTransport {
    tools: Vec<McpToolDef>,
    script: Mutex<VecDeque<ScriptedResponse>>,
    pub calls: Mutex<Vec<ToolCallRequest>>,
}

impl FakeMcpTransport {
    pub fn new(tools: Vec<McpToolDef>, script: Vec<ScriptedResponse>) -> Self {
        Self {
            tools,
            script: Mutex::new(script.into()),
            calls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl McpTransport for FakeMcpTransport {
    async fn discover(&self) -> Result<DiscoverResult, McpError> {
        Ok(DiscoverResult {
            protocol_version: "2026-07-28".into(),
            tools: self.tools.clone(),
        })
    }

    async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError> {
        self.calls.lock().unwrap().push(req);
        let next = self.script.lock().unwrap().pop_front();
        match next {
            None => Err(McpError::Protocol("fake transport script exhausted".into())),
            Some(ScriptedResponse::Error(e)) => Err(e),
            Some(ScriptedResponse::Ok(content)) => Ok(McpResult {
                result_type: McpResultType::Ok,
                content,
                is_error: false,
            }),
            Some(ScriptedResponse::InputRequired {
                input_requests,
                request_state,
            }) => Ok(McpResult {
                result_type: McpResultType::InputRequired {
                    input_requests,
                    request_state,
                },
                content: vec![],
                is_error: false,
            }),
        }
    }

    async fn shutdown(self: Box<Self>) -> Result<(), McpError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{JsonRpcId, McpResultType};

    #[tokio::test]
    async fn replays_scripted_responses_in_order_and_records_calls() {
        let fake = FakeMcpTransport::new(
            vec![McpToolDef {
                name: "echo".into(),
                description: "echoes".into(),
                input_schema: serde_json::json!({}),
            }],
            vec![
                ScriptedResponse::Ok(vec![McpContentBlock::Text {
                    text: "first".into(),
                }]),
                ScriptedResponse::Ok(vec![McpContentBlock::Text {
                    text: "second".into(),
                }]),
            ],
        );

        let r1 = fake
            .call_tool(ToolCallRequest {
                jsonrpc_id: JsonRpcId(0),
                tool: "echo".into(),
                args: serde_json::json!({}),
                request_state: None,
                input_responses: vec![],
            })
            .await
            .unwrap();
        matches!(r1.result_type, McpResultType::Ok);
        assert!(matches!(&r1.content[0], McpContentBlock::Text { text } if text == "first"));

        let r2 = fake
            .call_tool(ToolCallRequest {
                jsonrpc_id: JsonRpcId(1),
                tool: "echo".into(),
                args: serde_json::json!({}),
                request_state: None,
                input_responses: vec![],
            })
            .await
            .unwrap();
        assert!(matches!(&r2.content[0], McpContentBlock::Text { text } if text == "second"));

        assert_eq!(fake.calls.lock().unwrap().len(), 2);
    }
}
