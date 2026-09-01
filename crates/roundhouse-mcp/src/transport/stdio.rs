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

/// In-flight JSON-RPC requests by id. `None` once the reader has seen EOF
/// or a read error: taking the map drops every pending oneshot sender —
/// in-flight receivers surface `ServerExited` instead of hanging forever —
/// and marks the connection dead so future requests fail fast.
type PendingMap = Arc<Mutex<Option<HashMap<u64, oneshot::Sender<Value>>>>>;

#[derive(Debug)]
pub struct StdioMcpTransport {
    child: Box<dyn ChildWrapper>,
    stdin: Arc<Mutex<tokio::process::ChildStdin>>,
    pending: PendingMap,
    reader_task: tokio::task::JoinHandle<()>,
    next_id: std::sync::atomic::AtomicU64,
}

/// Upper bound on a single JSON-RPC request. A wedged server must not hang
/// its caller forever; the MRTR retry policy (§10.1) lives at the layer
/// above this transport and re-issues with a fresh id on timeout.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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

/// Configure the child command. `exec` is the program to run — already
/// chosen by `spawn` (the hash-resolved binary when pinned, the configured
/// command otherwise). Explicit allowlist env only, stdio piped for the
/// protocol, stderr inherited (daemon log, never protocol).
fn build_command(
    exec: &std::ffi::OsStr,
    args: &[String],
    env: &[(String, String)],
) -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(exec);
    cmd.args(args)
        .env_clear()
        .envs(env.iter().cloned())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    cmd
}

impl StdioMcpTransport {
    pub async fn spawn(config: &McpServerConfig) -> Result<Self, McpError> {
        let McpTransportKind::Stdio {
            command,
            args,
            env,
            pinned_binary_hash,
        } = &config.transport;

        // finding 5: §6.9 hardened profile — "MCP servers pinned by binary
        // hash." Verified BEFORE the process is ever spawned; a mismatch
        // refuses to start the server at all rather than spawning first and
        // discovering the problem later. When pinned, the resolved file is
        // kept: it is both the bytes hashed here and the program spawned
        // below, so the executed binary is exactly the verified one.
        let resolved: Option<PathBuf> = match pinned_binary_hash {
            Some(expected_hex) => {
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
                Some(binary)
            }
            None => None,
        };

        // The exec target: the hash-verified file when pinned, the
        // configured command (PATH lookup at exec time) otherwise —
        // unchanged behavior for unpinned configs.
        let exec: std::ffi::OsString = match &resolved {
            Some(path) => path.as_os_str().to_os_string(),
            None => command.as_str().into(),
        };
        let cmd = build_command(&exec, args, env);

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

        let pending: PendingMap = Arc::new(Mutex::new(Some(HashMap::new())));
        let pending_reader = pending.clone();
        let reader_task = tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if let Some(id) = v.get("id").and_then(Value::as_u64) {
                        let tx = pending_reader
                            .lock()
                            .await
                            .as_mut()
                            .and_then(|map| map.remove(&id));
                        if let Some(tx) = tx {
                            let _ = tx.send(v);
                        }
                    }
                }
            }
            // EOF or read error: the server is gone. Taking the map drops
            // every pending oneshot sender — in-flight receivers surface
            // ServerExited instead of hanging — and leaves None behind so
            // future requests fail fast.
            *pending_reader.lock().await = None;
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
        self.request_with_timeout(method, params, REQUEST_TIMEOUT)
            .await
    }

    /// Insert the request, write it, and await the response under a hard
    /// deadline. Every failure path removes the pending entry so nothing
    /// leaks and no late response is routed to a dead receiver.
    async fn request_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: std::time::Duration,
    ) -> Result<Value, McpError> {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let envelope =
            serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let (tx, rx) = oneshot::channel();

        // Fail fast if the reader is already gone: a write would only pend
        // behind a response nobody can ever route.
        {
            let mut pending = self.pending.lock().await;
            let map = pending.as_mut().ok_or(McpError::ServerExited)?;
            map.insert(id, tx);
        }

        let mut line =
            serde_json::to_vec(&envelope).map_err(|e| McpError::Protocol(e.to_string()))?;
        line.push(b'\n');
        if let Err(e) = self.stdin.lock().await.write_all(&line).await {
            // The write failed — drop the entry with it so the map holds no
            // sender whose receiver is already being abandoned.
            if let Some(map) = self.pending.lock().await.as_mut() {
                map.remove(&id);
            }
            return Err(McpError::Io(e.to_string()));
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(value)) => Ok(value),
            // Sender dropped without a response: the reader saw EOF and
            // drained the map, or shutdown tore the connection down.
            Ok(Err(_)) => Err(McpError::ServerExited),
            Err(_elapsed) => {
                // Too late: remove the entry so the map doesn't leak the
                // sender and a late response has nothing to be routed to.
                if let Some(map) = self.pending.lock().await.as_mut() {
                    map.remove(&id);
                }
                Err(McpError::Timeout { after: timeout })
            }
        }
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

    #[tokio::test]
    async fn reader_eof_fails_in_flight_and_future_requests() {
        // The child reads its one request line and exits WITHOUT replying.
        // Reader EOF must take the whole pending map so the in-flight
        // request surfaces ServerExited instead of hanging forever — and
        // every later request must fail fast too.
        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("exit-without-reply".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec!["-c".into(), "read line".into()],
                env: vec![],
                pinned_binary_hash: None,
            },
        };

        let transport = StdioMcpTransport::spawn(&config).await.unwrap();

        let in_flight = transport
            .discover()
            .await
            .expect_err("an in-flight request must not hang when the server exits");
        assert!(
            matches!(in_flight, McpError::ServerExited),
            "expected ServerExited for the in-flight request, got {in_flight:?}"
        );

        let later = transport
            .discover()
            .await
            .expect_err("requests after reader EOF must fail fast, not hang");
        assert!(
            matches!(later, McpError::ServerExited),
            "expected ServerExited for a post-EOF request, got {later:?}"
        );
        assert!(
            transport.pending.lock().await.is_none(),
            "reader EOF must clear every pending sender"
        );

        Box::new(transport).shutdown().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn pinned_spawn_executes_the_exact_hashed_binary() {
        // The pin digests a PATH-resolved file, so the spawned program must
        // be that same file — never a second exec-time lookup, which could
        // land on different bytes than the ones that were verified.
        let resolved = resolve_command("sh").await.unwrap();
        let bytes = tokio::fs::read(&resolved).await.unwrap();
        let pin = blake3::hash(&bytes).to_hex().to_string();

        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("pinned-exec".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec!["-c".into(), "cat".into()], // stays alive until stdin EOF
                env: vec![],
                pinned_binary_hash: Some(pin),
            },
        };

        let transport = StdioMcpTransport::spawn(&config).await.unwrap();
        let pid = transport.child.id().expect("spawned child has a pid");
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        assert_eq!(
            exe,
            std::fs::canonicalize(&resolved).unwrap(),
            "pinned spawn must exec the exact binary whose bytes were hashed"
        );

        Box::new(transport).shutdown().await.unwrap(); // `cat` exits on stdin EOF
    }

    #[test]
    fn pinned_configs_exec_the_resolved_path_unpinned_keep_the_command() {
        // Pinned: the exec target is the resolved file — the exact bytes
        // whose digest was verified.
        let resolved = std::path::Path::new("/usr/bin/sh");
        let cmd = build_command(resolved.as_os_str(), &[], &[]);
        assert_eq!(cmd.as_std().get_program(), resolved.as_os_str());

        // Unpinned: unchanged behavior — the bare command name, resolved at
        // exec time as before.
        let cmd = build_command(std::ffi::OsStr::new("sh"), &[], &[]);
        assert_eq!(cmd.as_std().get_program(), std::ffi::OsStr::new("sh"));
    }

    #[tokio::test]
    async fn request_times_out_and_cleans_up_its_pending_entry() {
        // The child takes the request but never answers; a bounded request
        // must give up with Timeout and must not leak its pending entry.
        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("never-answers".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec!["-c".into(), "read line; sleep 0.5".into()],
                env: vec![],
                pinned_binary_hash: None,
            },
        };

        let transport = StdioMcpTransport::spawn(&config).await.unwrap();
        let err = transport
            .request_with_timeout(
                "server/discover",
                serde_json::json!({ "_meta": { "protocolVersion": "2026-07-28" } }),
                std::time::Duration::from_millis(50),
            )
            .await
            .expect_err("a wedged server must surface a timeout, not hang");
        assert!(
            matches!(err, McpError::Timeout { .. }),
            "expected Timeout for a server that never answers, got {err:?}"
        );
        {
            let pending = transport.pending.lock().await;
            assert!(
                pending.as_ref().is_some_and(|map| map.is_empty()),
                "a timed-out request must remove its pending entry"
            );
        }

        Box::new(transport).shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn write_failure_cleans_up_its_pending_entry() {
        // The child closes its own stdin before signaling readiness on
        // stdout, then stays alive briefly. Receiving the bootstrap line
        // proves the read end is already closed while the reader is still
        // running — so the request reaches write_all, which must fail with
        // a broken pipe and must not leak the pending entry it inserted.
        let config = McpServerConfig {
            id: roundhouse_policy::ServerId("closed-stdin".into()),
            transport: McpTransportKind::Stdio {
                command: "sh".into(),
                args: vec![
                    "-c".into(),
                    "exec 0<&-; echo '{\"jsonrpc\":\"2.0\",\"id\":18446744073709551615,\"result\":{}}'; exec sleep 0.2".into(),
                ],
                env: vec![],
                pinned_binary_hash: None,
            },
        };

        let transport = StdioMcpTransport::spawn(&config).await.unwrap();

        // Wait for the bootstrap response: it is emitted after the child
        // closed its own stdin, so a resolved rx proves write_all will see
        // a dead read end while the reader task is still alive.
        let (ready_tx, ready_rx) = oneshot::channel();
        transport
            .pending
            .lock()
            .await
            .as_mut()
            .expect("pending map alive before any request")
            .insert(u64::MAX, ready_tx);
        tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx)
            .await
            .expect("child signaled readiness within 2s")
            .expect("bootstrap sender alive");

        let err = transport
            .discover()
            .await
            .expect_err("writing to a child that closed its stdin must fail");
        assert!(
            matches!(err, McpError::Io(_)),
            "expected an Io error from the broken pipe, got {err:?}"
        );
        {
            let pending = transport.pending.lock().await;
            assert!(
                pending.as_ref().is_some_and(|map| map.is_empty()),
                "a failed write must remove its pending entry"
            );
        }

        Box::new(transport).shutdown().await.unwrap();
    }
}
