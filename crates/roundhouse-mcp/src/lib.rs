#![forbid(unsafe_code)]

use roundhouse_policy::{ServerId, TaskParams};

pub fn describe_mcp_task_params(server: &str, tool: &str, args: serde_json::Value) -> TaskParams {
    TaskParams::Mcp { server: ServerId(server.to_string()), tool: tool.to_string(), args }
}
