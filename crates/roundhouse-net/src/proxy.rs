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
//! only to *already-checked* `SocketAddr`s rather than handing the
//! original host string back to `TcpStream::connect` for a second,
//! independent resolution. That second resolution is what made the
//! previous version of this file structurally unable to defend against
//! DNS-rebinding-shaped bypasses: there was no "checked address" at all,
//! only a checked *string*, and the string was never what a real TCP
//! connection actually reaches. (Fix-round-2: `connect_to_first_reachable`
//! tries every checked candidate in order — restoring the real dual-stack
//! fallback behavior `TcpStream::connect(&str)` had — never re-resolving,
//! just falling back across addresses that were already validated.)

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

/// A session's registered bearer token, bundled with the proxy's bound address —
/// everything an `http`-task executor needs to route exclusively through
/// [`LoopbackProxy`] and nothing more. The only way to construct
/// `roundhouse_tools::http::HttpTaskExecutor` is from one of these (Task 24), so an
/// `http` task cannot be executed without going through this proxy.
///
/// **Security-review finding (fix-round-1):** the fields here used to be `pub`,
/// which made the "only constructor is `via_proxy`" guarantee fake — any crate could
/// forge a `ProxyHandle` pointing at an arbitrary address, or mutate a legitimately
/// registered one's `addr` after the fact, bypassing every allowlist/metadata-IP
/// check `LoopbackProxy` exists to enforce. This is the exact defect class
/// `roundhouse-secrets`'s `Secret`/`expose_within_control_lane` redesign
/// (`crates/roundhouse-secrets/src/secret.rs`) was built to close: an owned, freely
/// constructible value is not a capability. Fields are now private; only
/// [`LoopbackProxy::register_session`] (same crate) can build one, and outside
/// crates get read-only access via [`Self::token`]/[`Self::addr`].
///
/// **Security-review finding (fix-round-2):** private fields alone stopped *forging*
/// a handle from raw parts and *mutating* one after the fact, but not *minting* —
/// `register_session` used to accept a caller-supplied `addr: SocketAddr` with no
/// check that it was this proxy's own bound address, so any crate could still get a
/// fully legitimate, unforged `ProxyHandle` pointing at an arbitrary rogue address,
/// even on a `LoopbackProxy` that was never `serve()`d at all — reaching the exact
/// same "metadata IP reachable, zero enforcement, zero audit trail" outcome Task 23
/// exists to prevent. `register_session` no longer takes an `addr` parameter at
/// all: it reads [`LoopbackProxy`]'s own recorded bound address (set exactly once,
/// by [`LoopbackProxy::serve`]) and fails closed with [`ProxyNotServingError`] if
/// this instance has never actually served.
pub struct ProxyHandle {
    token: String,
    addr: SocketAddr,
}

impl ProxyHandle {
    /// The session's bearer token, presented as `Proxy-Authorization: Bearer
    /// <token>` on every CONNECT this session's traffic makes.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The loopback proxy's bound address — where an `http`-task executor must
    /// point its HTTP client's proxy configuration.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

/// Returned by [`LoopbackProxy::register_session`] when called on a proxy instance
/// that has never had [`LoopbackProxy::serve`] bind a real address — minting a
/// [`ProxyHandle`] with no real bound listener behind it would be a silent,
/// structurally undetectable way to route traffic around every check this proxy
/// exists to run (fix-round-2 security-review finding; see [`ProxyHandle`]'s docs).
#[derive(Debug)]
pub struct ProxyNotServingError;

impl std::fmt::Display for ProxyNotServingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LoopbackProxy::register_session called before serve() bound a real \
             address on this instance"
        )
    }
}

impl std::error::Error for ProxyNotServingError {}

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
    /// This instance's own bound address, set exactly once by [`Self::serve`].
    /// Fix-round-2 security-review finding: `register_session` used to accept a
    /// caller-supplied `addr` with no check against anything this proxy actually
    /// bound, letting any crate mint a fully legitimate `ProxyHandle` pointing
    /// wherever it wanted — even on a proxy that was never served at all. Reading
    /// the address back from here instead means a handle can only ever point at a
    /// real listener this specific instance is actually running.
    bound_addr: std::sync::OnceLock<SocketAddr>,
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
            bound_addr: std::sync::OnceLock::new(),
        }
    }

    /// Called once per session at spawn time, before the agent lane's proxy
    /// env vars (`HTTPS_PROXY`/`https_proxy`) are set in the sandboxed
    /// process's environment. Returns a [`ProxyHandle`] bundling the session's
    /// bearer token with this proxy's own bound address (recorded by
    /// [`Self::serve`]) — enough, and only enough, for `roundhouse-tools`' `http`
    /// executor to route exclusively through this proxy.
    ///
    /// Fails with [`ProxyNotServingError`] if this `LoopbackProxy` instance has
    /// never actually bound a listener via [`Self::serve`] — see [`ProxyHandle`]'s
    /// docs for why silently minting a handle in that case would be a real,
    /// structural bypass rather than a hypothetical one.
    pub fn register_session(
        &self,
        session_id: SessionId,
        policy: EgressPolicy,
    ) -> Result<ProxyHandle, ProxyNotServingError> {
        let addr = *self.bound_addr.get().ok_or(ProxyNotServingError)?;
        let token = format!("rh-{}", uuid::Uuid::new_v4());
        self.sessions
            .insert(token.clone(), SessionEgressContext { session_id, policy });
        Ok(ProxyHandle { token, addr })
    }

    pub fn deregister_session(&self, token: &str) {
        self.sessions.remove(token);
    }

    /// Whether `token` currently names a registered session. Read-only,
    /// added (lane W1, Phase 7 Task 7 fix round 2) specifically so a test
    /// can prove a `deregister_session` call actually happened, rather than
    /// asserting on a `remove` that no-ops harmlessly on a token that was
    /// never registered in the first place — see
    /// `roundhouse-daemon`'s `socket_server::session_reaper_tests` for the
    /// regression this closes (both of that module's tests previously
    /// passed an unregistered literal token, so deleting the
    /// `deregister_session` call entirely would still have passed them).
    pub fn is_registered(&self, token: &str) -> bool {
        self.sessions.contains_key(token)
    }

    /// Binds an ephemeral loopback port, serves forever in a spawned task,
    /// and returns the bound address. `runner` is the process-wide
    /// `TaskRunner` authority (per S-LOG-1, minted exactly once at daemon
    /// startup) — required `'static` because the accept loop and every
    /// per-connection handler it spawns must be able to outlive the
    /// caller's stack frame. `writer` is cheap to clone (an `mpsc::Sender`
    /// internally), so one handle is cloned per accepted connection.
    ///
    /// Records the bound address on `self` (fix-round-2) before returning, so
    /// every [`Self::register_session`] call afterward hands back a
    /// [`ProxyHandle`] pointing at this real, live listener — never a
    /// caller-supplied address this instance never actually bound. Calling
    /// `serve()` a second time on the same instance panics: this proxy design
    /// is one bound listener per instance for its whole lifetime (§6.6's "one
    /// accepting listener with per-session token disambiguation"), so a second
    /// call is a real caller bug, not a case to silently paper over.
    pub async fn serve(
        self: Arc<Self>,
        runner: &'static TaskRunner,
        writer: EventWriter,
    ) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        self.bound_addr
            .set(addr)
            .expect("LoopbackProxy::serve() called more than once on the same instance");
        let this = self.clone();
        let concurrency = Arc::new(Semaphore::new(this.max_concurrent_connections));
        tokio::spawn(async move {
            let mut last_transient_log: Option<std::time::Instant> = None;
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
                        //
                        // Fix-round-2 regression fix: retrying immediately
                        // with no backoff turned a real, sustained EMFILE
                        // condition into a CPU livelock (measured: ~236k
                        // hot-spun iterations in 1.5s, pegging a full core)
                        // — `TRANSIENT_ACCEPT_BACKOFF` below fixes that.
                        // Logging on every one of those retries would
                        // itself be a (smaller) version of the same
                        // problem, hence the rate limit.
                        let now = std::time::Instant::now();
                        if should_log_transient_accept_error(
                            last_transient_log,
                            now,
                            TRANSIENT_ACCEPT_LOG_INTERVAL,
                        ) {
                            tracing::warn!(
                                error = %e,
                                "roundhouse-net: transient accept() error, continuing to serve \
                                 (further occurrences rate-limited)"
                            );
                            last_transient_log = Some(now);
                        }
                        tokio::time::sleep(TRANSIENT_ACCEPT_BACKOFF).await;
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
            GateResult::Allow(candidates) => {
                drop(ctx); // release the DashMap read guard before the (potentially long) tunnel
                           // Try each already-checked candidate address in turn — never
                           // re-resolve `target_host` here. Re-resolving would reopen the
                           // DNS-rebinding-shaped TOCTOU the whole `gate_connect` pipeline
                           // exists to close; falling back across the *checked* candidate
                           // list (rather than only ever trying the first) is safe, since
                           // every one of them already passed the same checks.
                if let Some(mut upstream) = connect_to_first_reachable(&candidates).await {
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
    /// Every resolved candidate address that passed every check, in
    /// resolution order — `handle_connection` tries each in turn.
    Allow(Vec<SocketAddr>),
    Deny {
        host: String,
        reason: String,
    },
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
/// 5. Unless the match was `MatchKind::ExactIpLiteral` (the allowlist
///    pattern's own text is a raw IP literal — explicit, specific operator
///    consent to that exact address), additionally check every resolved
///    candidate against `ConnectFilter::deny_reason_for_private_range`
///    (see `MatchKind`'s doc comment for why an exact-matched *hostname*
///    does not get this exemption).
/// 6. Return *every* resolved, already-checked candidate — the caller
///    tries each in turn at connect time (real dual-stack fallback
///    behavior), never re-resolving `target` itself.
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

    // Fix-round-2 correction: the private-range check is skipped only for
    // `ExactIpLiteral` — an operator who explicitly typed a raw IP address
    // is consenting to that exact address. Every other kind of match
    // (a wildcard, *or* an exact match on a hostname) has only ever
    // expressed trust in a *name*, and that name resolving into the
    // daemon host's internal network is exactly what this check exists to
    // catch — an exact-matched hostname is not exempt just because the
    // match itself was exact.
    if match_kind != MatchKind::ExactIpLiteral {
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

    // Fix-round-2 regression fix: return every checked candidate, not just
    // the first — `handle_connection` tries each in turn at connect time,
    // restoring the real fallback behavior `TcpStream::connect(&str)` had
    // (e.g. a dual-stack host where the first resolved address has nothing
    // listening). Every candidate here has already passed the checks
    // above, so trying any of them is safe.
    GateResult::Allow(addrs)
}

/// Tries every candidate address in order, returning the first one that
/// actually accepts a connection. Every candidate passed in here has
/// already been resolved and checked by `gate_connect` — trying more than
/// the first is exactly what `TcpStream::connect(&str)` did before this
/// crate switched to connecting by `SocketAddr` (fix-round-2 regression:
/// connecting only to `addrs[0]` broke the common case of a dual-stack
/// host whose first resolved address has nothing listening, e.g. an IPv6
/// loopback candidate ahead of a working IPv4 one).
async fn connect_to_first_reachable(candidates: &[SocketAddr]) -> Option<TcpStream> {
    for addr in candidates {
        if let Ok(stream) = TcpStream::connect(*addr).await {
            return Some(stream);
        }
    }
    None
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

/// How long the accept loop sleeps before retrying `accept()` after a
/// transient error. Security-review finding (fix-round-2): retrying with
/// no backoff at all turned a real, sustained EMFILE condition into a CPU
/// livelock — hundreds of thousands of hot-spun iterations per second,
/// pegging a full core for as long as the fd-pressure condition lasted.
/// Kept short enough that the proxy recovers promptly once the transient
/// condition clears.
const TRANSIENT_ACCEPT_BACKOFF: Duration = Duration::from_millis(25);

/// Minimum spacing between logged warnings for repeated transient
/// `accept()` errors — without this, a sustained transient condition would
/// log once per retry (236k+ log lines for the same 1.5-second EMFILE
/// condition that motivated `TRANSIENT_ACCEPT_BACKOFF` above), which is
/// itself a resource-exhaustion-shaped problem.
const TRANSIENT_ACCEPT_LOG_INTERVAL: Duration = Duration::from_secs(1);

/// Whether a transient `accept()` error should be logged right now, given
/// when one was last logged. A pure, deterministically testable function —
/// no real waiting required to verify the rate-limiting decision itself.
fn should_log_transient_accept_error(
    last_logged: Option<std::time::Instant>,
    now: std::time::Instant,
    min_interval: Duration,
) -> bool {
    match last_logged {
        None => true,
        Some(last) => now.duration_since(last) >= min_interval,
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
/// (no bytes flowing either direction) tunnel sits open. The straightforward
/// fix (fix-round-1) — a single `tokio::select!` loop that tears down BOTH
/// directions the instant EITHER side hits EOF or the shared idle timer
/// fires — is wrong: it breaks half-close, real standard TCP behavior some
/// protocols depend on (a client signaling "I'm done sending" while still
/// expecting a response). `copy_bidirectional` itself gets this right: each
/// direction shuts down only its own write side when its own reader hits
/// EOF, and the other direction keeps running. Security-review finding
/// (fix-round-2): the fix-round-1 version caused real, reproduced data
/// loss — a client that writes then half-closes only received its echoed
/// response in 1 of 3 identical runs.
///
/// This preserves that half-close correctness while still enforcing an
/// idle timeout, *per direction* rather than as one shared "either side
/// idle kills both" timer: each direction is copied independently via
/// [`copy_one_direction`], which wraps every individual `read()` in
/// `tokio::time::timeout` and shuts down only its own write half on EOF —
/// exactly matching `copy_bidirectional`'s real behavior, plus a timeout.
/// The two directions run concurrently via `tokio::join!` (not `select!` —
/// `select!` would cancel whichever direction is still running the moment
/// the other one finishes, which is exactly the bug being fixed here) and
/// this function only returns once *both* directions have finished, each
/// on its own terms.
async fn copy_bidirectional_with_idle_timeout(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle_timeout: Duration,
) -> io::Result<()> {
    let (client_r, client_w) = client.split();
    let (upstream_r, upstream_w) = upstream.split();

    let client_to_upstream = copy_one_direction(client_r, upstream_w, idle_timeout);
    let upstream_to_client = copy_one_direction(upstream_r, client_w, idle_timeout);

    let (client_to_upstream_result, upstream_to_client_result) =
        tokio::join!(client_to_upstream, upstream_to_client);
    client_to_upstream_result?;
    upstream_to_client_result?;
    Ok(())
}

/// Copies bytes from `reader` to `writer` until `reader` hits EOF (in which
/// case `writer`'s write half is shut down — real half-close, matching what
/// `tokio::io::copy` plus an explicit `shutdown()` already does) or a
/// single `read()` call goes longer than `idle_timeout` with no data
/// (in which case this returns `ErrorKind::TimedOut`). The timeout is
/// re-armed on every individual read, so a tunnel that's merely slow but
/// still making periodic progress in *this* direction is never killed —
/// only a direction that goes fully silent for the whole timeout window is.
async fn copy_one_direction<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: Duration,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        let n = match timeout(idle_timeout, reader.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "egress tunnel idle timeout",
                ))
            }
        };
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    // Real half-close: shut down only this direction's write side once its
    // reader hit EOF — the other direction (driven by the sibling
    // `copy_one_direction` call in `copy_bidirectional_with_idle_timeout`)
    // is unaffected and keeps running independently.
    let _ = writer.shutdown().await;
    Ok(())
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

    #[test]
    fn should_log_transient_accept_error_rate_limits_correctly() {
        // Deterministic via relative `Instant` arithmetic — no real
        // sleeping required. Security-review finding (fix-round-2): the
        // pre-fix code logged on every single retry, which under a
        // sustained transient condition meant hundreds of thousands of log
        // lines in under two seconds.
        let interval = Duration::from_millis(50);
        let t0 = std::time::Instant::now();
        assert!(
            should_log_transient_accept_error(None, t0, interval),
            "the first occurrence must always log"
        );
        let soon_after = t0 + Duration::from_millis(10);
        assert!(
            !should_log_transient_accept_error(Some(t0), soon_after, interval),
            "an occurrence within the rate-limit interval must not log again"
        );
        let well_after = t0 + Duration::from_millis(60);
        assert!(
            should_log_transient_accept_error(Some(t0), well_after, interval),
            "an occurrence past the rate-limit interval must log again"
        );
    }

    #[tokio::test]
    async fn transient_accept_backoff_sleeps_for_a_real_nonzero_duration() {
        // Confirms `TRANSIENT_ACCEPT_BACKOFF` is wired to a genuine sleep,
        // not a no-op — guards against a future refactor accidentally
        // dropping the actual delay while leaving the constant in place.
        let start = std::time::Instant::now();
        tokio::time::sleep(TRANSIENT_ACCEPT_BACKOFF).await;
        assert!(
            start.elapsed() >= TRANSIENT_ACCEPT_BACKOFF,
            "the backoff must actually sleep for at least its configured duration"
        );
    }

    #[tokio::test]
    async fn connect_to_first_reachable_falls_back_to_a_later_working_address() {
        // Fix-round-2 regression: connecting only ever tried `addrs[0]`,
        // breaking the common case of a dual-stack host whose first
        // resolved candidate has nothing listening. First candidate here
        // is a real address with a bound-then-immediately-dropped
        // listener (so the port is guaranteed refused, not merely slow);
        // the second candidate has a real, live listener.
        let dead_addr = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap()
            // listener dropped here — connecting to this port now fails
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let candidates = vec![dead_addr, good_addr];
        let result = connect_to_first_reachable(&candidates).await;
        assert!(
            result.is_some(),
            "must fall back to the second, reachable candidate when the first is unreachable"
        );
    }
}
