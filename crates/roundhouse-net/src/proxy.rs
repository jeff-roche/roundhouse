//! The per-session loopback egress proxy (§6.6): one accepting listener,
//! per-session token disambiguation — the parenthetical the spec explicitly
//! allows in place of one OS listener per session. Minimal HTTP CONNECT
//! support only: we match the CONNECT target and never terminate TLS,
//! matching §6.6's default (non-`intercept`) mode.
//!
//! **Fix-round-1 architecture note:** every real connection this proxy ever
//! makes now goes through [`gate_connect`], which resolves the CONNECT
//! target's host to real `SocketAddr`s exactly once, checks the IP-level
//! deny rules against every resolved candidate, and — critically — connects
//! to the *specific* `SocketAddr` it just checked rather than handing the
//! original host string back to `TcpStream::connect` for a second,
//! independent resolution. That second resolution is what made the
//! previous version of this file structurally unable to defend against
//! DNS-rebinding-shaped bypasses: there was no "checked address" at all,
//! only a checked *string*, and the string was never what a real TCP
//! connection actually reaches.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use roundhouse_core::{NoteLevel, SessionId, TaskRunner, Timestamp};
use roundhouse_store::EventWriter;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::policy::{normalize_host, ConnectFilter, EgressPolicy, MatchKind};

pub struct SessionEgressContext {
    pub session_id: SessionId,
    pub policy: EgressPolicy,
}

/// Hard cap on the total bytes read for one CONNECT preamble (request line
/// and headers, combined). Security-review finding: an unbounded
/// `read_line` into a `String` with no terminator let a single connection
/// grow a real process's RSS by however many bytes the client felt like
/// sending (verified: 1.5 GiB, sustained ~1.7 GiB/sec), reachable *before*
/// the bearer-token check even runs. Wrapping the socket in
/// [`tokio::io::AsyncReadExt::take`] before parsing bounds this
/// structurally: once the budget is exhausted, the underlying reader looks
/// like EOF, `read_line` returns whatever partial, non-newline-terminated
/// data it has, and `read_connect_request` treats that as a malformed
/// request and drops the connection — never buffers past this ceiling.
const MAX_PREAMBLE_BYTES: u64 = 64 * 1024;

/// How long a client gets to complete the CONNECT handshake (send a
/// complete request line + headers) before the connection is dropped.
/// Security-review finding: 200 connections opened and never sent a byte
/// each parked a spawned task in `read_line` forever ("slowloris").
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an established tunnel may sit with no bytes flowing in either
/// direction before it's torn down. Security-review finding: an ALLOWED
/// tunnel to an upstream that accepts and then goes silent pinned a task
/// and two file descriptors forever, with nothing bounding it.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound on concurrently accepted (in-flight) connections. Backs the
/// accept loop with a semaphore so that once this many connections are
/// being handled, the loop stops calling `accept()` until one frees up —
/// bounding both spawned-task and file-descriptor growth under a slowloris
/// or handshake-timeout-exhaustion pattern, rather than accepting
/// unboundedly and relying on the handshake/idle timeouts alone to clean
/// up after the fact.
const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// Cap on the host text recorded into a durable `Note` event. Security-
/// review finding: the raw, attacker-controlled CONNECT target flowed
/// unbounded and unsanitized into the immutable, append-only event log —
/// both a terminal-injection risk against the operator's TUI (which
/// renders this log as a trusted audit trail) and an unmetered
/// amplification vector (the event table can never be pruned, per this
/// project's own event-sourcing design).
const MAX_LOGGED_HOST_CHARS: usize = 256;

/// The per-session loopback egress proxy. Holds no store/runner state of
/// its own — those are supplied to [`LoopbackProxy::serve`] so that a
/// single process-wide `TaskRunner` (per S-LOG-1, `TaskRunner::bootstrap()`
/// may only be called once) can be shared across every proxy instance and
/// every other daemon subsystem.
pub struct LoopbackProxy {
    sessions: DashMap<String, SessionEgressContext>,
    handshake_timeout: Duration,
    idle_timeout: Duration,
    max_concurrent_connections: usize,
}

impl LoopbackProxy {
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_HANDSHAKE_TIMEOUT,
            DEFAULT_IDLE_TIMEOUT,
            DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        )
    }

    /// Same as [`Self::new`], with explicit timeout/concurrency limits —
    /// primarily so tests can exercise the handshake-timeout and
    /// idle-timeout paths deterministically in well under a second instead
    /// of waiting out the production defaults.
    pub fn with_limits(
        handshake_timeout: Duration,
        idle_timeout: Duration,
        max_concurrent_connections: usize,
    ) -> Self {
        Self {
            sessions: DashMap::new(),
            handshake_timeout,
            idle_timeout,
            max_concurrent_connections,
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
    /// per-connection handler it spawns must be able to outlive the
    /// caller's stack frame. `writer` is cheap to clone (an `mpsc::Sender`
    /// internally), so one handle is cloned per accepted connection.
    pub async fn serve(
        self: Arc<Self>,
        runner: &'static TaskRunner,
        writer: EventWriter,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let this = self.clone();
        let concurrency = Arc::new(Semaphore::new(this.max_concurrent_connections));
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _)) => {
                        // Backpressure: block accepting further connections
                        // once `max_concurrent_connections` are already
                        // in-flight, rather than letting spawned tasks and
                        // file descriptors grow unboundedly. The permit
                        // moves into the handler and is released when it
                        // finishes.
                        let Ok(permit) = concurrency.clone().acquire_owned().await else {
                            break; // semaphore closed — proxy is shutting down
                        };
                        let this = this.clone();
                        let writer = writer.clone();
                        tokio::spawn(async move {
                            this.handle_connection(socket, runner, writer).await;
                            drop(permit);
                        });
                    }
                    Err(e) if is_transient_accept_error(&e) => {
                        // Security-review finding: a blanket `break` on
                        // *any* accept() error let a transient condition
                        // (most relevantly EMFILE/ENFILE under fd
                        // pressure, trivially reachable via the slowloris
                        // pattern the handshake-timeout/concurrency-cap
                        // fixes above address) permanently and silently
                        // kill all agent-lane network egress until a full
                        // daemon restart. `tracing`, not a `Note` event: no
                        // session is in scope for a listener-wide condition
                        // like this one, and inventing a placeholder
                        // `SessionId` to force it into the event log would
                        // be the same kind of dishonest workaround this
                        // crate's original task addendum explicitly
                        // rejected for `TaskId`.
                        tracing::warn!(
                            error = %e,
                            "roundhouse-net: transient accept() error, continuing to serve"
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "roundhouse-net: fatal accept() error, loopback proxy listener stopping"
                        );
                        break;
                    }
                }
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
        // Bound the CONNECT preamble read (finding: unbounded read_line
        // OOM) and the time it may take to arrive (finding: slowloris).
        let bounded = socket.take(MAX_PREAMBLE_BYTES);
        let mut reader = BufReader::new(bounded);
        let parsed = timeout(self.handshake_timeout, read_connect_request(&mut reader)).await;
        let mut socket = reader.into_inner().into_inner();

        let Ok(Some((token, target_host))) = parsed else {
            // Either the handshake timed out, or the preamble was
            // malformed/oversized — either way, no response is owed to a
            // client that hasn't proven it can complete a well-formed
            // request within budget; just drop the connection.
            return;
        };

        // Fail-closed: an unknown/invalid bearer token is rejected with
        // 407 before any allowlist evaluation happens at all — the lookup
        // below is the only gate a request has to pass before
        // `gate_connect` (and therefore `ConnectFilter`) even runs.
        let Some(ctx) = self.sessions.get(&token) else {
            let _ = socket
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await;
            return;
        };
        let session_id = ctx.session_id;

        match gate_connect(&ctx.policy, &target_host).await {
            GateResult::Allow(checked_addr) => {
                drop(ctx); // release the DashMap read guard before the (potentially long) tunnel
                           // Connect to the exact address just resolved and checked —
                           // never re-resolve `target_host` here. Re-resolving would
                           // reopen the DNS-rebinding-shaped TOCTOU the whole
                           // `gate_connect` pipeline exists to close.
                if let Ok(mut upstream) = TcpStream::connect(checked_addr).await {
                    let _ = socket
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await;
                    let result = copy_bidirectional_with_idle_timeout(
                        &mut socket,
                        &mut upstream,
                        self.idle_timeout,
                    )
                    .await;
                    if let Err(e) = result {
                        tracing::debug!(error = %e, "roundhouse-net: tunnel ended");
                    }
                } else {
                    let _ = socket.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                    let text = format!(
                        "egress proxy: failed to reach allowlisted upstream {}",
                        sanitize_for_event_text(&target_host)
                    );
                    let event =
                        runner.record_note(session_id, 0, now_ts(), None, NoteLevel::Warn, text, 1);
                    let _ = writer.append(event).await;
                }
            }
            GateResult::Deny { host, reason } => {
                drop(ctx);
                let _ = socket.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await;
                // §6.6: "A blocked request produces a real Deny task record
                // with the URL, not a network error the model must guess
                // at." The proxy operates below the task-tracking layer and
                // has no `TaskId` in scope at connect time (only
                // `session_id`), so a `Note` is the honest record here;
                // Task 24 wires this proxy into the real task-admission
                // path, where a `TaskFailed` tied to the actual blocked
                // task belongs. The host text is truncated and stripped of
                // control characters before it's ever formatted into this
                // durable, append-only, TUI-rendered event.
                let text = format!(
                    "egress denied: {} ({reason})",
                    sanitize_for_event_text(&host)
                );
                let event =
                    runner.record_note(session_id, 0, now_ts(), None, NoteLevel::Warn, text, 1);
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

enum GateResult {
    Allow(SocketAddr),
    Deny { host: String, reason: String },
}

/// The single pipeline every CONNECT target passes through before a real
/// connection is ever attempted:
///
/// 1. Split `target` into host/port and normalize the host (lowercase,
///    strip a trailing root-anchor dot) — once, before any check.
/// 2. Resolve the normalized host to real `SocketAddr`s via
///    `tokio::net::lookup_host` — the actual resolver `TcpStream::connect`
///    would otherwise use, invoked here *instead of* there. A host that
///    fails to resolve, or resolves to zero addresses, is denied
///    (fail-closed) rather than falling through any path that would let it
///    proceed unresolved.
/// 3. For every resolved candidate, canonicalize the IP
///    (`IpAddr::to_canonical()`, collapsing IPv4-mapped-IPv6 spellings down
///    to their real IPv4 form) and check it against
///    `ConnectFilter::deny_reason_for_metadata_ip` — unconditionally,
///    before the allowlist is even consulted, on every candidate, not just
///    the first.
/// 4. Check the *hostname* against the allowlist (a legitimate,
///    intentionally string-based check — operators allow by hostname).
/// 5. If the only matching allowlist entry was a **wildcard**, additionally
///    check every resolved candidate against
///    `ConnectFilter::deny_reason_for_private_range` — an **exact** match
///    skips this, since it represents explicit, specific operator intent
///    (see `MatchKind`'s doc comment).
/// 6. Return the *first resolved, already-checked* `SocketAddr` — the
///    caller connects to exactly this address, never re-resolving
///    `target`.
async fn gate_connect(policy: &EgressPolicy, target: &str) -> GateResult {
    let Some((bare_host, port)) = split_host_port(target) else {
        return GateResult::Deny {
            host: target.to_string(),
            reason: "malformed CONNECT target".to_string(),
        };
    };
    let normalized_host = normalize_host(bare_host);
    let lookup_target = format!("{normalized_host}:{port}");

    let addrs: Vec<SocketAddr> = match tokio::net::lookup_host(&lookup_target).await {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    };
    if addrs.is_empty() {
        return GateResult::Deny {
            host: target.to_string(),
            reason: "DNS resolution failed or returned no addresses".to_string(),
        };
    }

    // Metadata check: unconditional, on every resolved candidate, before
    // the allowlist is consulted at all.
    for addr in &addrs {
        let canonical = addr.ip().to_canonical();
        if let Some(reason) = ConnectFilter::deny_reason_for_metadata_ip(canonical) {
            return GateResult::Deny {
                host: target.to_string(),
                reason,
            };
        }
    }

    let match_kind = match policy.match_kind(&normalized_host) {
        Some(kind) => kind,
        None => {
            return GateResult::Deny {
                host: target.to_string(),
                reason: "not on the session's egress allowlist".to_string(),
            }
        }
    };

    if match_kind == MatchKind::Wildcard {
        for addr in &addrs {
            let canonical = addr.ip().to_canonical();
            if let Some(reason) = ConnectFilter::deny_reason_for_private_range(canonical) {
                return GateResult::Deny {
                    host: target.to_string(),
                    reason,
                };
            }
        }
    }

    GateResult::Allow(addrs[0])
}

/// Splits a CONNECT target into `(host, port)`, handling both plain
/// `host:port` and bracketed IPv6-literal `[addr]:port` forms — the naive
/// `rsplit_once(':')` this replaced breaks on IPv6 literals, which contain
/// multiple colons.
fn split_host_port(target: &str) -> Option<(&str, &str)> {
    if let Some(rest) = target.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = rest.get(end + 1..)?;
        let port = after.strip_prefix(':')?;
        Some((host, port))
    } else {
        target.rsplit_once(':')
    }
}

/// Whether an `accept()` failure is transient (worth retrying the loop for)
/// or fatal (worth breaking the loop for). Errno values are Linux-specific
/// (this crate's only supported target); `raw_os_error` is `None` on
/// non-Unix platforms, so the fallback there is `ErrorKind`-based only.
fn is_transient_accept_error(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    if matches!(e.kind(), ConnectionAborted | WouldBlock | Interrupted) {
        return true;
    }
    matches!(
        e.raw_os_error(),
        Some(23) // ENFILE
            | Some(24) // EMFILE
            | Some(105) // ENOBUFS
            | Some(12) // ENOMEM
    )
}

/// Truncates to `MAX_LOGGED_HOST_CHARS` characters and strips every Unicode
/// control character (C0 0x00-0x1F, DEL 0x7F, C1 0x80-0x9F — covers NUL,
/// BEL, ESC/ANSI-escape sequences, and embedded newlines) before a raw,
/// attacker-controlled CONNECT target host is ever formatted into a
/// durable, append-only, TUI-rendered event's text.
fn sanitize_for_event_text(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control())
        .take(MAX_LOGGED_HOST_CHARS)
        .collect()
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
/// parser. `reader` is expected to already be wrapped in a byte-budgeted
/// reader (see `MAX_PREAMBLE_BYTES`) by the caller; this function has no
/// bound of its own beyond "stop if a line never terminates before the
/// budget runs out," which falls out naturally from `read_line` returning
/// a partial, non-newline-terminated buffer once the wrapped reader hits
/// its cap (looks like EOF from here).
async fn read_connect_request<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Option<(String, String)> {
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await.ok()?;
    if n == 0 || !request_line.ends_with('\n') {
        return None; // EOF, or the byte budget ran out mid-line
    }
    let mut parts = request_line.split_whitespace();
    if parts.next()? != "CONNECT" {
        return None;
    }
    let target_host = parts.next()?.to_string();

    let mut token = None;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.ok()?;
        if n == 0 || !line.ends_with('\n') {
            return None; // EOF, or the byte budget ran out mid-header
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

/// `tokio::io::copy_bidirectional` with no way to bound how long an idle
/// (no bytes flowing either direction) tunnel sits open — this wraps it
/// with an idle timer that resets on every successful read from either
/// side, torn down (returning `ErrorKind::TimedOut`) if neither side
/// produces a byte within `idle_timeout`. Deliberately hand-rolled rather
/// than racing the whole `copy_bidirectional` future against one fixed
/// timeout, which would kill a legitimate long-lived-but-active tunnel
/// (e.g. a multi-minute download) exactly as readily as a truly idle one.
async fn copy_bidirectional_with_idle_timeout(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
) -> io::Result<()> {
    let (mut client_r, mut client_w) = client.split();
    let (mut upstream_r, mut upstream_w) = upstream.split();
    let mut client_buf = [0u8; 8192];
    let mut upstream_buf = [0u8; 8192];

    loop {
        tokio::select! {
            result = client_r.read(&mut client_buf) => {
                match result? {
                    0 => return Ok(()),
                    n => upstream_w.write_all(&client_buf[..n]).await?,
                }
            }
            result = upstream_r.read(&mut upstream_buf) => {
                match result? {
                    0 => return Ok(()),
                    n => client_w.write_all(&upstream_buf[..n]).await?,
                }
            }
            () = tokio::time::sleep(idle_timeout) => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "egress tunnel idle timeout"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_host_port_handles_plain_and_ipv6_bracket_forms() {
        assert_eq!(split_host_port("crates.io:443"), Some(("crates.io", "443")));
        assert_eq!(split_host_port("[::1]:80"), Some(("::1", "80")));
        assert_eq!(
            split_host_port("[::ffff:169.254.169.254]:80"),
            Some(("::ffff:169.254.169.254", "80"))
        );
        assert_eq!(split_host_port("no-port"), None);
    }

    #[test]
    fn sanitize_for_event_text_strips_control_chars_and_truncates() {
        let raw = format!("evil\u{1b}[2J\u{7}host{}", "x".repeat(1000));
        let cleaned = sanitize_for_event_text(&raw);
        assert!(!cleaned.chars().any(|c| c.is_control()));
        assert!(cleaned.chars().count() <= MAX_LOGGED_HOST_CHARS);
        assert!(cleaned.starts_with("evil["));
    }

    #[test]
    fn transient_accept_errors_are_classified_correctly() {
        // Deterministic construction via raw OS error injection — the
        // security review's own reproduction required real fd exhaustion,
        // which isn't reproducible hermetically; this exercises the exact
        // classification logic that decides continue-vs-break instead.
        assert!(is_transient_accept_error(&io::Error::from_raw_os_error(24))); // EMFILE
        assert!(is_transient_accept_error(&io::Error::from_raw_os_error(23))); // ENFILE
        assert!(is_transient_accept_error(&io::Error::from(
            io::ErrorKind::ConnectionAborted
        )));
        assert!(is_transient_accept_error(&io::Error::from(
            io::ErrorKind::Interrupted
        )));
        // EBADF/EINVAL-shaped errors on the listener itself are not
        // transient — a broken listener socket should stop the loop.
        assert!(!is_transient_accept_error(&io::Error::from_raw_os_error(9))); // EBADF
        assert!(!is_transient_accept_error(&io::Error::from(
            io::ErrorKind::InvalidInput
        )));
    }
}
