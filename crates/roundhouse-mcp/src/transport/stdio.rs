//! `StdioMcpTransport` — real child-process lifecycle over the server's
//! stdio pipes, with newline-delimited JSON-RPC framing (§7.3).
//!
//! ⚠️ Deferred reconciliation (plan finding 5 / §10.2): this hand-rolled
//! framing is deliberately kept instead of calling `rmcp` 3.1.4's client API
//! directly. The `rmcp` swap (`ServiceExt`/client-builder with
//! `ClientLifecycleMode::Auto`) is isolated to this one file — the
//! `McpTransport` trait boundary and every other task are unaffected. No
//! `initialize`/session-negotiation fallback of our own is implemented here,
//! by design; the pre-`2026-07-28` backward-compat probe rides along with
//! that same swap.

use crate::config::{McpServerConfig, McpTransportKind};
use crate::transport::McpTransport;
use crate::wire::{
    DiscoverResult, McpError, McpResult, McpResultType, McpToolDef, ToolCallRequest,
};
use async_trait::async_trait;
use process_wrap::tokio::{ChildWrapper, ProcessGroup};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Mutex};

#[derive(Debug)]
pub struct StdioMcpTransport {
    child: Box<dyn ChildWrapper>,
    stdin: Arc<Mutex<tokio::process::ChildStdin>>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>,
    reader_task: tokio::task::JoinHandle<()>,
    next_id: std::sync::atomic::AtomicU64,
}

/// Resolve `command` the way the actual spawn will: a name with a path
/// separator is used as-is, a bare name is looked up on `PATH`. Needed
/// because the hash pin must digest the bytes of the binary that would run
/// (`config.rs`: "digest of the `command` binary's bytes"), and
/// `tokio::fs::read` does no `PATH` lookup — without this, a pinned bare
/// name like `sh` would be hashed as a relative path in the daemon's cwd.
async fn resolve_command(command: &str) -> std::io::Result<PathBuf> {
    if command.contains('/') {
        return Ok(PathBuf::from(command));
    }
    let path = std::env::var_os("PATH")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "PATH not set"))?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(command);
        let is_file = tokio::fs::metadata(&candidate)
            .await
            .map(|m| m.is_file())
            .unwrap_or(false);
        if is_file {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("'{command}' not found on PATH"),
    ))
}

impl StdioMcpTransport {
    pub async fn spawn(config: &McpServerConfig) -> Result<Self, McpError> {
        let McpTransportKind::Stdio {
            command,
            args,
            env,
            pinned_binary_hash,
        } = &config.transport;

        // finding 5: §6.5 hardened profile — "MCP servers pinned by binary
        // hash." Verified BEFORE the process is ever spawned; a mismatch
        // refuses to start the server at all rather than spawning first and
        // discovering the problem later.
        if let Some(expected_hex) = pinned_binary_hash {
            let binary = resolve_command(command)
                .await
                .map_err(|e| McpError::Io(format!("hash pin: cannot read '{command}': {e}")))?;
            let bytes = tokio::fs::read(&binary)
                .await
                .map_err(|e| McpError::Io(format!("hash pin: cannot read '{command}': {e}")))?;
            let actual_hex = blake3::hash(&bytes).to_hex().to_string();
            if &actual_hex != expected_hex {
                return Err(McpError::Protocol(format!(
                    "hardened profile: binary hash mismatch for MCP server '{}' (expected {expected_hex}, got {actual_hex}) — refusing to spawn",
                    config.id.0
                )));
            }
        }

        let mut cmd = tokio::process::Command::new(command);
        cmd.args(args)
            .env_clear()
            .envs(env.iter().cloned())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit()); // stderr is daemon log, never protocol

        let mut child = process_wrap::tokio::CommandWrap::from(cmd)
            .wrap(ProcessGroup::leader())
            .spawn()
            .map_err(|e| McpError::Io(e.to_string()))?;

        let stdin = child
            .stdin()
            .take()
            .ok_or_else(|| McpError::Io("no stdin".into()))?;
        let stdout = child
            .stdout()
            .take()
            .ok_or_else(|| McpError::Io("no stdout".into()))?;

        let pending: Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_reader = pending.clone();
        let reader_task = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if let Some(id) = v.get("id").and_then(Value::as_u64) {
                        if let Some(tx) = pending_reader.lock().await.remove(&id) {
                            let _ = tx.send(v);
                        }
                    }
                }
            }
        });

        Ok(Self {
            child,
            stdin: Arc::new(Mutex::new(stdin)),
            pending,
            reader_task,
            next_id: std::sync::atomic::AtomicU64::new(0),
        })
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value, McpError> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let envelope =
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let mut line =
            serde_json::to_vec(&envelope).map_err(|e| McpError::Protocol(e.to_string()))?;
        line.push(b'\n');
        self.stdin
            .lock()
            .await
            .write_all(&line)
            .await
            .map_err(|e| McpError::Io(e.to_string()))?;

        rx.await.map_err(|_| McpError::ServerExited)
    }
}

#[async_trait]
impl McpTransport for StdioMcpTransport {
    async fn discover(&self) -> Result<DiscoverResult, McpError> {
        let resp = self
            .request(
                "server/discover",
                serde_json::json!({ "_meta": { "protocolVersion": "2026-07-28" } }),
            )
            .await?;
        let result = resp
            .get("result")
            .ok_or_else(|| McpError::Protocol("discover: missing result".into()))?;
        let tools = result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|t| McpToolDef {
                name: t
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                description: t
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                input_schema: t
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or(serde_json::json!({})),
            })
            .collect();
        Ok(DiscoverResult {
            protocol_version: result
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2026-07-28")
                .to_string(),
            tools,
        })
    }

    async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError> {
        let mut params = serde_json::json!({ "name": req.tool, "arguments": req.args });
        if let Some(state) = &req.request_state {
            params["_meta"] = serde_json::json!({ "requestState": state.0 });
            params["inputResponses"] =
                serde_json::to_value(&req.input_responses).unwrap_or(Value::Null);
        }
        let resp = self.request("tools/call", params).await?;
        let result = resp
            .get("result")
            .ok_or_else(|| McpError::Protocol("tools/call: missing result".into()))?;

        if result.get("resultType").and_then(Value::as_str) == Some("input_required") {
            let input_requests =
                serde_json::from_value(result.get("inputRequests").cloned().unwrap_or(Value::Null))
                    .map_err(|e| McpError::Protocol(format!("bad inputRequests: {e}")))?;
            let request_state = crate::wire::RequestState(
                result
                    .get("requestState")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            );
            return Ok(McpResult {
                result_type: McpResultType::InputRequired {
                    input_requests,
                    request_state,
                },
                content: vec![],
                is_error: false,
            });
        }

        let content = result
            .get("content")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|c| match c.get("type").and_then(Value::as_str) {
                Some("text") => Some(crate::wire::McpContentBlock::Text {
                    text: c
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                }),
                Some("image") => Some(crate::wire::McpContentBlock::Image {
                    media_type: c
                        .get("mimeType")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    data_base64: c
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                }),
                Some("resource") => Some(crate::wire::McpContentBlock::Resource {
                    uri: c
                        .get("uri")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    media_type: c
                        .get("mimeType")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    text: c.get("text").and_then(Value::as_str).map(str::to_string),
                }),
                _ => None,
            })
            .collect();

        Ok(McpResult {
            result_type: McpResultType::Ok,
            content,
            is_error: result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    async fn shutdown(self: Box<Self>) -> Result<(), McpError> {
        // Move out of the box so the pieces can be dropped in the order the
        // lifecycle needs: reader first, then stdin's last Arc reference —
        // dropping `ChildStdin` closes the pipe and sends EOF, so a
        // well-behaved server exits on its own instead of being SIGKILLed
        // after the timeout.
        let this = *self;
        let StdioMcpTransport {
            mut child,
            stdin,
            pending: _,
            reader_task,
            next_id: _,
        } = this;

        reader_task.abort();
        drop(stdin); // last Arc ref → ChildStdin dropped → child sees EOF
        let exited = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait()).await;
        if exited.is_err() {
            // kill() returns an unpinned `Box<dyn Future>`; into_pin makes it
            // awaitable. process-wrap kills the whole group, not just the leader pid.
            let _ = Box::into_pin(child.kill()).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn spawns_and_shuts_down_a_real_child_process() {
        // A trivial real subprocess that answers exactly one server/discover
        // call, proving spawn/pipe-wiring/shutdown against a real OS process
        // — independent of the fuller fake-mcp-stdio-server binary (Task 9),
        // which exercises the full protocol surface.
        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("echo-discover".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec![
                    "-c".into(),
                    "read line; echo '{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"protocolVersion\":\"2026-07-28\",\"tools\":[]}}'".into(),
                ],
                env: vec![],
                pinned_binary_hash: None,
            },
        };

        let transport = StdioMcpTransport::spawn(&config).await.unwrap();
        let discovered = transport.discover().await.unwrap();
        assert_eq!(discovered.protocol_version, "2026-07-28");
        assert!(discovered.tools.is_empty());

        Box::new(transport).shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn refuses_to_spawn_when_pinned_binary_hash_does_not_match() {
        // finding 5: the hardened profile's binary-hash pin must be checked
        // BEFORE the process is spawned — "sh" here stands in for a real
        // MCP server binary whose on-disk bytes don't match the pin.
        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("pinned-server".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec!["-c".into(), "true".into()],
                env: vec![],
                pinned_binary_hash: Some("0".repeat(64)), // deliberately wrong
            },
        };

        let err = StdioMcpTransport::spawn(&config).await.expect_err(
            "a mismatched binary-hash pin must refuse to spawn, not start the process anyway",
        );
        assert!(
            matches!(err, McpError::Protocol(_)),
            "expected an audited protocol-level refusal, got {err:?}"
        );
    }
}
