//! The per-session loopback egress proxy (§6.6): one accepting listener,
//! per-session token disambiguation — the parenthetical the spec explicitly
//! allows in place of one OS listener per session. Minimal HTTP CONNECT
//! support only: we match the CONNECT target and never terminate TLS,
//! matching §6.6's default (non-`intercept`) mode.

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;
use roundhouse_core::{NoteLevel, SessionId, TaskRunner, Timestamp};
use roundhouse_store::EventWriter;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::policy::{ConnectFilter, EgressDecision, EgressPolicy};

pub struct SessionEgressContext {
    pub session_id: SessionId,
    pub policy: EgressPolicy,
}

/// The per-session loopback egress proxy. Holds no store/runner state of its
/// own — those are supplied to [`LoopbackProxy::serve`] so that a single
/// process-wide `TaskRunner` (per S-LOG-1, `TaskRunner::bootstrap()` may
/// only be called once) can be shared across every proxy instance and every
/// other daemon subsystem.
pub struct LoopbackProxy {
    sessions: DashMap<String, SessionEgressContext>,
}

impl LoopbackProxy {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }

    /// Called once per session at spawn time, before the agent lane's proxy
    /// env vars (`HTTPS_PROXY`/`https_proxy`) are set in the sandboxed
    /// process's environment. Returns the session's bearer token.
    pub fn register_session(&self, session_id: SessionId, policy: EgressPolicy) -> String {
        let token = format!("rh-{}", uuid::Uuid::new_v4());
        self.sessions
            .insert(token.clone(), SessionEgressContext { session_id, policy });
        token
    }

    pub fn deregister_session(&self, token: &str) {
        self.sessions.remove(token);
    }

    /// Binds an ephemeral loopback port, serves forever in a spawned task,
    /// and returns the bound address. `runner` is the process-wide
    /// `TaskRunner` authority (per S-LOG-1, minted exactly once at daemon
    /// startup) — required `'static` because the accept loop and every
    /// per-connection handler it spawns must be able to outlive the caller's
    /// stack frame. `writer` is cheap to clone (an `mpsc::Sender`
    /// internally), so one handle is cloned per accepted connection.
    pub async fn serve(
        self: Arc<Self>,
        runner: &'static TaskRunner,
        writer: EventWriter,
    ) -> std::io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let this = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let this = this.clone();
                let writer = writer.clone();
                tokio::spawn(async move {
                    this.handle_connection(socket, runner, writer).await;
                });
            }
        });
        Ok(addr)
    }

    async fn handle_connection(
        &self,
        socket: TcpStream,
        runner: &'static TaskRunner,
        writer: EventWriter,
    ) {
        let mut reader = BufReader::new(socket);
        let Some((token, target_host)) = read_connect_request(&mut reader).await else {
            return;
        };
        let mut socket = reader.into_inner();

        // Fail-closed: an unknown/invalid bearer token is rejected with 407
        // before any allowlist evaluation happens at all — the lookup below
        // is the only gate a request has to pass before `ConnectFilter`
        // even runs.
        let Some(ctx) = self.sessions.get(&token) else {
            let _ = socket
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
            return;
        };

        match ConnectFilter::evaluate(&ctx.policy, &target_host) {
            EgressDecision::Allow => {
                drop(ctx); // release the DashMap read guard before the (potentially long) tunnel
                if let Ok(mut upstream) = TcpStream::connect(&target_host).await {
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
                } else {
                    let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                }
            }
            EgressDecision::Deny { host, reason } => {
                let session_id = ctx.session_id;
                drop(ctx);
                let _ = socket.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                // §6.6: "A blocked request produces a real Deny task record
                // with the URL, not a network error the model must guess
                // at." The proxy operates below the task-tracking layer and
                // has no `TaskId` in scope at connect time (only
                // `session_id`), so a `Note` is the honest record here;
                // Task 24 wires this proxy into the real task-admission
                // path, where a `TaskFailed` tied to the actual blocked
                // task belongs.
                let event = runner.record_note(
                    session_id,
                    0, // placeholder seq — EventWriter::append assigns the real one
                    now_ts(),
                    None,
                    NoteLevel::Warn,
                    format!("egress denied: {host} ({reason})"),
                    1, // schema_v
                );
                let _ = writer.append(event).await;
            }
        }
    }
}

impl Default for LoopbackProxy {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Minimal HTTP/1.1 CONNECT request-line + header parse — just enough to
/// extract the target host:port and the bearer token, never a general HTTP
/// parser.
async fn read_connect_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Option<(String, String)> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await.ok()?;
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "CONNECT" {
        return None;
    }
    let target_host = parts.next()?.to_string();

    let mut token = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.ok()? == 0 {
            return None;
        }
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .strip_prefix("Proxy-Authorization: Bearer ")
            .or_else(|| line.strip_prefix("Authorization: Bearer "))
        {
            token = Some(value.trim().to_string());
        }
    }
    Some((token?, target_host))
}
