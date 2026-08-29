//! The MCP host: connects to Model Context Protocol servers (via `rmcp`)
//! and exposes their tools to the rest of the system as ordinary
//! `TaskParams`/policy-gated actions, so an MCP tool call is subject to the
//! same permission and event-sourcing rules as any built-in executor.
//!
//! Phase 0 only proves this crate compiles against `roundhouse-policy`'s
//! stub types (`describe_mcp_task_params` below); no real MCP client exists
//! yet — that's Phase 3 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `07-protocols-acp-mcp.md`.
#![forbid(unsafe_code)]

use roundhouse_policy::{ServerId, TaskParams};

pub fn describe_mcp_task_params(server: &str, tool: &str, args: serde_json::Value) -> TaskParams {
    TaskParams::Mcp { server: ServerId(server.to_string()), tool: tool.to_string(), args }
}
