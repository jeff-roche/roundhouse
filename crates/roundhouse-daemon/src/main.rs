//! The daemon binary: wiring, API server, and lifecycle for `round daemon`
//! — the long-running process every `roundhouse-cli` client attaches to or
//! sends requests through. Depends on nearly every other crate in the
//! workspace (it's one of only two crates — the other is
//! `roundhouse-cli` — allowed to; nothing else may depend on either).
//!
//! Phase 1 ran exactly one scripted demo session (the vertical-slice exit
//! criterion) and served its updates to one attached client — see the
//! now-retired `run_demo_session`, still kept in `roundhouse_daemon::demo`
//! as an integration-test fixture (`tests/exit_criterion_demo.rs`) but no
//! longer called from here. Phase 7, Task 7 replaces that scripted boot
//! path with the real one: `TaskRunner::bootstrap()` (via `EngineHandles`)
//! → `boot::run_boot_sequence` → Task 3's real `accept_loop`, serving an
//! arbitrary number of concurrent `round attach`/`round create`/`round run`
//! clients against a real `SessionRegistry` whose entries are real
//! `SessionActor`s (`session_bootstrap::create_real_session`), each backed
//! by real isolation, a real per-session `PolicyEngine`, this session's
//! configured MCP servers (if any), real redaction, and a real egress
//! registration with the daemon's one shared `LoopbackProxy`.
//!
//! **What this task does NOT wire (see the task report for the full
//! rationale):** there is still no `ClientRequest` variant that names "do
//! something inside an already-created session" — `roundhouse-proto`'s wire
//! types are a frozen Phase 0 contract, and extending them is out of this
//! lane's charter (see `socket_server::drive_session`'s own doc comment on
//! the `Attach`/`CreateSession`-only handshake). So a session created here
//! is real and reachable, but nothing yet drives a chat turn against it
//! from a live client — that remains a later task's integration point
//! (most plausibly `roundhouse-web`'s HTTP layer, Task 9).
#![forbid(unsafe_code)]

use clap::Parser;
use roundhouse_bus::local_bus::LocalBus;
use roundhouse_core::{OnDegrade, Tier};
use roundhouse_daemon::mcp_config;
use roundhouse_daemon::session_bootstrap::DaemonResources;
use roundhouse_daemon::session_registry::SessionRegistry;
use roundhouse_daemon::socket_server::{accept_loop, bind_socket};
use roundhouse_engine::EngineHandles;
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_provider::{
    AnthropicMessagesProvider, BoxFut, Capabilities, ChatRequest, ChatStream, HttpRequest,
    HttpResponseStream, HttpTransport, ModelId, ModelInfo, Plan, Provider, ProviderError,
    RequestCtx, ReqwestTransport, TokenCount, TransportError,
};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::Isolate;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Owner-only. Everything the daemon writes lives under a directory with this
/// mode, so no other unprivileged user on the host can pre-plant a symlink at a
/// path the daemon is about to open with `O_CREAT`.
const RUNTIME_DIR_MODE: u32 = 0o700;

/// `round-daemon-internal`'s own argument parsing — deliberately tiny.
/// `round daemon` (`roundhouse-cli`'s subcommand, `commands::daemon::run`)
/// execs this binary with no arguments today; an operator or test that needs
/// a non-default socket path invokes this binary directly with `--socket`
/// (the lane file's own correction: "the daemon binary needs a --socket
/// flag, not a daemon subcommand of its own" — this is that flag).
#[derive(Debug, Parser)]
#[command(
    name = "round-daemon-internal",
    about = "The real round daemon process (internal — spawned by `round daemon`, not run directly)",
    long_about = None
)]
struct Args {
    /// Unix socket path to bind. Falls back to `$ROUND_SOCKET`, then
    /// `roundhouse_tui::default_socket_path()` — unchanged from before this
    /// flag existed, so an operator who already relies on `$ROUND_SOCKET`
    /// sees no behavior change.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Ruling W1-R95: every real session asks for `Tier::Sandbox`, and by
    /// default (`OnDegrade::Refuse`, §6.5's documented default) this daemon
    /// refuses to create a session at all on a host that cannot achieve it —
    /// fail closed. Setting this flag is an explicit, operator-made
    /// decision to instead allow a session to run at a lower tier, down to
    /// the one named here (`OnDegrade::AllowDownTo`), on a host where
    /// `Sandbox` genuinely isn't available (no `bwrap` at the production
    /// install path, no landlock support, a container missing the right
    /// capabilities). Every real degradation is still recorded as a
    /// `Degradation` `Note` event by `create_session_isolation` (§6.5 rule
    /// 3) regardless of this flag — this only controls whether a shortfall
    /// refuses the session or is merely recorded. Accepts (case-insensitive):
    /// `none`, `worktree`, `sandbox`, `container`, `remote`. Setting this
    /// logs a warning naming the chosen floor on every boot, for the
    /// process's whole life — and setting it to `none` specifically logs a
    /// distinct, louder warning, because that value permanently disarms
    /// `sealed_tier_shortfall` (the sealed-floor rule that detects a live
    /// mid-session isolation downgrade): with a floor of `Tier::None`,
    /// `attested_tier < requested_tier` can never hold, for any tier, so
    /// that detector goes dark for the rest of the process.
    #[arg(long, value_parser = parse_tier)]
    allow_degraded_to: Option<Tier>,
}

/// Ruling W1-R96 (fix round 1): installs a real `tracing` subscriber before
/// anything else runs. Before this, `grep -rn "tracing_subscriber\|
/// set_global_default" crates/` returned nothing workspace-wide — every
/// `tracing::warn!`/`error!` this binary (and `roundhouse-engine`, which
/// runs inside this same process) emits was a discarded no-op. That
/// silently dropped, among others: the CF-12(c) `NetworkConfigError`
/// fallback that degrades every session's egress to deny-all (whose own
/// in-code justification is "loud (logged) and safe" — it was not loud);
/// a `CreateSession` construction failure; the `MAX_WORKSPACE_NAME_BYTES`
/// rejection; and `wire_redaction_for_session`'s "dropped N secret
/// value(s)" warning, which is W1-R27's entire observability requirement
/// for a value too short to safely redact.
///
/// Writes to stderr (not stdout, which this binary's own `println!` lines
/// use for operator status) and defaults to `info` level — showing
/// `warn`/`error` without the operator needing to know `RUST_LOG` exists —
/// while still honoring `$RUST_LOG` for anyone who wants `debug`/`trace`.
fn install_tracing_subscriber() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
}

/// `clap` value-parser for `--allow-degraded-to`.
fn parse_tier(raw: &str) -> Result<Tier, String> {
    match raw.to_ascii_lowercase().as_str() {
        "none" => Ok(Tier::None),
        "worktree" => Ok(Tier::Worktree),
        "sandbox" => Ok(Tier::Sandbox),
        "container" => Ok(Tier::Container),
        "remote" => Ok(Tier::Remote),
        other => Err(format!(
            "{other:?} is not a valid tier (expected one of: none, worktree, sandbox, \
             container, remote)"
        )),
    }
}

/// The one process-wide `TaskRunner`, obtained exactly once via
/// `EngineHandles::bootstrap` (which panics on a second call — see
/// `roundhouse_core::TaskRunner::bootstrap`'s own doc comment) and exposed
/// as `&'static` through this `OnceLock` rather than a bare local binding:
/// `SessionActor::new` (and everything `session_bootstrap` builds around it)
/// requires `runner: &'static TaskRunner`, and a local `let handles = ...`
/// inside `main`'s own stack frame cannot honestly produce that lifetime —
/// only a `'static` place can.
static HANDLES: std::sync::OnceLock<EngineHandles> = std::sync::OnceLock::new();

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    install_tracing_subscriber();
    let args = Args::parse();

    // Keyed on the *presence* of `ANTHROPIC_API_KEY` rather than on a flag, so
    // the no-key path is the default: with no key set this binary opens zero
    // outbound provider connections, matching §12.5's "zero outbound
    // connections before first session creation" budget. Only an operator who
    // has deliberately exported a key gets a live, billable request from any
    // session created against this daemon.
    //
    // The key is moved straight into `RequestCtx` and never touched again
    // here: it is not logged, and neither `RequestCtx` nor `HttpRequest`
    // derives `Debug`, so no formatter downstream can print it either (§9.9).
    //
    // An empty `ANTHROPIC_API_KEY=` counts as unset: it is what `unset` looks
    // like to a half-written shell profile or a CI job with an unpopulated
    // secret, and taking the live path with an empty credential would trade a
    // working daemon for every session's first request 401-ing.
    let (provider, request_ctx): (Arc<dyn Provider>, RequestCtx) =
        match std::env::var("ANTHROPIC_API_KEY")
            .ok()
            .filter(|key| !key.is_empty())
        {
            Some(api_key) => (
                Arc::new(AnthropicMessagesProvider::new()),
                RequestCtx {
                    trace_id: None,
                    transport: Arc::new(ReqwestTransport::new()),
                    api_key,
                    credentials: None,
                },
            ),
            None => (
                Arc::new(NoProviderConfigured) as Arc<dyn Provider>,
                RequestCtx {
                    trace_id: None,
                    transport: Arc::new(NoTransportConfigured),
                    api_key: "no-anthropic-api-key-configured".into(),
                    credentials: None,
                },
            ),
        };

    // `EngineHandles::bootstrap` is `TaskRunner::bootstrap()`'s real, intended
    // call site (its own doc comment: "called exactly once ... at daemon
    // startup, and threaded through from there" — it panics on a second
    // call). Stored in the `'static` `HANDLES` (see that item's own doc
    // comment) rather than a local binding.
    let handles = HANDLES.get_or_init(|| {
        EngineHandles::bootstrap(Arc::new(LocalBus::new()), vec![provider.clone()])
    });
    let runner = &handles.task_runner;

    // Every artifact below (socket, event log, scratch state) goes inside
    // one private directory rather than straight into the shared temp dir.
    // Writing predictable names into a world-writable `/tmp` lets any other
    // local user pre-create one as a symlink; both `tokio::fs::write` and
    // SQLite's `O_CREAT` open follow symlinks, so the daemon would truncate
    // a file the attacker chose, as the victim.
    let runtime_dir = roundhouse_tui::default_runtime_dir();
    prepare_runtime_dir(&runtime_dir)?;

    let socket_path = args
        .socket
        .or_else(|| std::env::var_os("ROUND_SOCKET").map(PathBuf::from))
        .unwrap_or_else(roundhouse_tui::default_socket_path);
    remove_stale_socket(&socket_path)?;

    // Absolute by construction (`default_runtime_dir`'s own contract) and
    // asserted as such by `SessionActor::new` — this session-independent
    // path anchors both `sealed_state_dir_write` and, via
    // `session_bootstrap::create_real_session`, every session's `SealedContext`.
    let state_dir = runtime_dir.clone();
    // The REAL, canonicalized path of this running binary — what
    // `sealed_daemon_binary_write` protects. `std::env::current_exe()`
    // itself may return a symlink (e.g. `/proc/self/exe` on some
    // platforms); canonicalizing resolves to the real underlying file, the
    // same pattern `commands::daemon::daemon_binary_path` already uses in
    // `roundhouse-cli`.
    let daemon_binary = std::fs::canonicalize(std::env::current_exe()?)?;

    let store_path = runtime_dir.join("events.db");

    // Boot sequence (S-SESS-4): reclassify any task left in `Created`/`Decided`/
    // `Running` state by a previous daemon process that died mid-run, and
    // enumerate tasks left `Suspended` (e.g. mid-approval) so they are at least
    // visible again after a restart. Without the first half, a `round daemon`
    // killed mid-session leaves those tasks stuck in the log forever. Task 15
    // added the `ApprovalRegistry` constructed just below and threaded it
    // through `run_boot_sequence` — this is the actual re-arm site: every
    // persisted `Suspended{AwaitingApproval}` task gets registered live here,
    // so a restarted daemon's registry isn't empty even though the approvals
    // were always correctly sitting in the database. Runs once, here, between
    // opening the store and starting the accept loop — on a fresh
    // `store_path` this is a cheap no-op scan over an empty `tasks` table.
    let recovery_store = roundhouse_store::open(&store_path).await?;
    let recovery_writer = roundhouse_store::spawn_writer(recovery_store).await;
    let recovery_pool_for_scan = roundhouse_store::open(&store_path).await?;
    let approval_registry = roundhouse_policy::registry::ApprovalRegistry::new();
    let boot_report = roundhouse_daemon::boot::run_boot_sequence(
        &recovery_pool_for_scan,
        &recovery_writer,
        runner,
        &approval_registry,
    )
    .await?;
    if !boot_report.interrupted.is_empty() || !boot_report.suspended.is_empty() {
        println!(
            "boot recovery: {} task(s) interrupted, {} task(s) still suspended from a previous daemon run",
            boot_report.interrupted.len(),
            boot_report.suspended.len()
        );
    }
    // CF-12(a): `recovery_writer` keeps `spawn_writer`'s empty default
    // redactor — deliberately. `recover_interrupted_tasks` (called above)
    // only ever appends synthetic `Interrupted` markers keyed by task/session
    // id (`roundhouse-store/src/recovery.rs`), never user- or
    // model-controlled text, so there is nothing here for a `Redactor` to
    // protect. Named explicitly in the task report as one of the three
    // `EventWriter`s this daemon can append through.

    // CF-11: `project_root` is what makes `default_layers`'s Project scope
    // (and therefore `mcp_config::load_mcp_servers`'s/`load_network_config`'s
    // own narrow-only project-scope handling) reachable at all — this daemon
    // has no other source of a filesystem project root: `ClientRequest::
    // CreateSession`'s `workspace_name` is a plain `String` label, not a
    // path (see CF-17's own note in the task report). The daemon's own
    // current working directory is the only real candidate; an operator who
    // runs `round daemon` from inside their project gets project-scoped
    // config, one who doesn't gets user-global only.
    let project_root = std::env::current_dir().ok();

    // Fix round 3, MUST 3: this used to propagate `McpConfigError` straight
    // out of `main` via `?`, which `color_eyre` then renders to stderr —
    // entirely bypassing the `tracing` subscriber (and therefore 0.3.23's
    // own ANSI-escape sanitization). `McpConfigError::Parse`'s `Display`
    // (via `toml::de::Error`) embeds a verbatim snippet of the offending
    // source line at the parse-error location — for `[[mcp_server]]`
    // config specifically, that line can be an `env = [["KEY", "sk-…"]]`
    // entry, i.e. one of the OPERATOR'S OWN real secret values (project-
    // scoped `[[mcp_server]]` layers are structurally dropped before any
    // file is ever read — see `mcp_config`'s own module doc comment — so
    // this is not the hostile-cloned-repo attack; it is CF-11(c) for the
    // operator's own config, printing a credential verbatim to stderr and
    // the journal on a config typo). Same `kind()`-only logging discipline
    // as the `[network]` config fallback just below, and the same
    // fail-closed-but-non-fatal decision: a malformed `[[mcp_server]]`
    // config degrades this boot to zero configured MCP servers rather than
    // refusing to boot at all — strictly less capability, never more.
    let mcp_configs = match mcp_config::load_mcp_servers(project_root.as_deref()) {
        Ok(configs) => configs,
        Err(err) => {
            tracing::error!(
                target: "roundhouse_daemon::boot",
                error_kind = err.kind(),
                "failed to load [[mcp_server]] config; falling back to no configured MCP \
                 servers for every session rather than failing the whole daemon boot"
            );
            Vec::new()
        }
    };

    // CF-12(c): `load_network_config` has zero production callers before
    // this task. Fail-closed decision (stated explicitly, per the task
    // brief, since nothing in the code constrains this choice): a
    // `NetworkConfigError` this call still surfaces (a malformed OPERATOR
    // config, i.e. the Builtin/UserGlobal layer specifically — fix round 1,
    // SHOULD item: `load_network_config_from_layers` now absorbs a broken
    // NARROWER project/workspace layer internally, falling back to the
    // wider scope's own result rather than erroring at all, so a hostile
    // cloned repo's config can no longer collapse this whole call to an
    // error) does NOT fail the whole daemon boot — it falls back to
    // `NetworkConfig::default()` (an empty allowlist, which
    // `EgressPolicy::matches` treats as deny-all), the same fail-closed
    // default an absent `[network]` section already gets. A config typo
    // degrading every session's egress to "denied" is loud (logged) and
    // safe; refusing to boot the whole daemon over one malformed section
    // would be a larger, over-restrictive blast radius for a mistake that
    // doesn't compromise anything by failing closed instead.
    let network_config = match roundhouse_config::load_network_config(project_root.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            // Fix round 2, MUST 1: `err.kind()`, never `err`'s own
            // `Display` — by the time an error reaches here it's the
            // OPERATOR's own (Builtin/UserGlobal) config (a rejected
            // PROJECT layer no longer propagates at all — fix round 1's
            // own SHOULD item), but `NetworkConfigError::kind`'s own doc
            // comment states why that still isn't a reason to render a
            // parser snippet into a log line (CF-11(c), copy-pasted or
            // journal-displayed operator config).
            //
            // Fix round 3, MUST 1: `target: "roundhouse_daemon::boot"` —
            // without an explicit target, every `tracing` call in this file
            // logs under this BINARY's own crate name
            // (`round_daemon_internal`, from `[[bin]] name` in this crate's
            // `Cargo.toml`), not the library crate name
            // (`roundhouse_daemon`) every other module in this crate logs
            // under. Proven: `RUST_LOG=roundhouse_daemon=debug` — the
            // obvious "show me everything this daemon does" filter — shows
            // every OTHER line in this codebase and silently drops every
            // line in `main.rs` specifically. Every `tracing` call in this
            // file gets the same explicit target for the same reason.
            tracing::error!(
                target: "roundhouse_daemon::boot",
                error_kind = err.kind(),
                "failed to load [network] config; falling back to an empty \
                 (deny-all) egress allowlist for every session rather than \
                 failing the whole daemon boot"
            );
            roundhouse_config::NetworkConfig::default()
        }
    };

    // A real probe of THIS host's actual isolation mechanisms (landlock,
    // bwrap, seccomp, seatbelt) — `probe_cached` genuinely exercises each
    // one via real syscalls (§6.5 rule 1: fail-open is made structurally
    // impossible by actually exercising each mechanism), not a placeholder.
    // `BwrapLandlockIsolate::test_with_probe`'s name notwithstanding, it is
    // not test-gated (`#[cfg(test)]`) — it is a plain, always-`pub`
    // constructor that takes a caller-supplied `MechanismProbeReport` and
    // the production bwrap install path baked in
    // (`test_with_probe_and_bwrap_path`'s own doc comment calls this out
    // explicitly: "the production install path baked into `test_with_probe`").
    // `roundhouse-sandbox` is lane W5's crate, not this lane's, so renaming
    // this naming trap away is out of scope here — noted in the task report.
    let probe_report = roundhouse_sandbox::probe::probe_cached(&runtime_dir).await;
    let isolate: Arc<dyn Isolate> = Arc::new(BwrapLandlockIsolate::test_with_probe(probe_report));

    // The daemon-wide egress proxy: bound and serving exactly once, here, at
    // boot — before any session (and therefore any call to
    // `session_bootstrap::create_real_session`) exists, per
    // `create_session_with_egress`'s own doc comment.
    let proxy = Arc::new(LoopbackProxy::new());
    let proxy_store = roundhouse_store::open(&store_path).await?;
    let proxy_writer = roundhouse_store::spawn_writer(proxy_store).await;
    proxy.clone().serve(runner, proxy_writer.clone()).await?;

    let session_store = roundhouse_store::open(&store_path).await?;
    // Fix round 2, MUST 3: make an operator's `--allow-degraded-to` choice
    // loud, on every boot, for the process's whole life — proven, before
    // this fix, that starting with the flag printed NOTHING about it on
    // either stream, so the downgrade escape hatch was silently armed with
    // no operator-visible trace anywhere. `Tier::None` gets a distinct,
    // louder line naming the specific rule it disarms
    // (`sealed_tier_shortfall`) — see `create_real_session`'s own doc
    // comment on `OnDegrade::AllowDownTo(Tier::None)` for exactly what that
    // means. The flag itself is NOT rejected or narrowed here: it exists
    // precisely for a host that cannot achieve `Sandbox`, and refusing the
    // value that workflow needs would just push operators back toward
    // patching the default instead.
    let default_on_degrade = match args.allow_degraded_to {
        Some(tier) => {
            if tier == Tier::None {
                tracing::warn!(
                    target: "roundhouse_daemon::boot",
                    "--allow-degraded-to none is set: EVERY session on this daemon may run \
                     with NO isolation at all, and sealed_tier_shortfall (the sealed-floor rule \
                     that detects a live mid-session isolation downgrade) is PERMANENTLY \
                     DISARMED for the life of this process — attested_tier can never be lower \
                     than a floor of Tier::None, so the comparison is unsatisfiable for every \
                     tier. This is an explicit operator decision for a host that cannot achieve \
                     Tier::Sandbox; if that is not what you intended, restart without this flag."
                );
            } else {
                tracing::warn!(
                    target: "roundhouse_daemon::boot",
                    ?tier,
                    "--allow-degraded-to is set: sessions on this daemon may run with an \
                     isolation tier as low as {tier:?} instead of the requested Tier::Sandbox, \
                     recorded as a Degradation note per session rather than refusing to start"
                );
            }
            OnDegrade::AllowDownTo(tier)
        }
        None => OnDegrade::Refuse,
    };
    let resources = Arc::new(DaemonResources::new(
        session_store,
        isolate,
        proxy,
        state_dir,
        daemon_binary,
        mcp_configs,
        network_config,
        default_on_degrade,
        runner,
        provider,
        request_ctx,
        proxy_writer,
    ));

    let registry = Arc::new(SessionRegistry::new());

    // `bind_socket` (bind, then chmod to owner-only) runs here, synchronously,
    // in this stack frame, before `accept_loop` is ever spawned — restoring
    // the guarantee that a client dialing immediately after this function
    // returns will find a real, already-bound socket (`accept_loop`'s own
    // doc comment, ruling W1-R12).
    let listener = bind_socket(&socket_path)?;

    println!(
        "round daemon listening: socket={} state_dir={}",
        socket_path.display(),
        resources.state_dir.display()
    );

    // CF-13(2): `accept_loop`'s `Err` must terminate the daemon with a
    // non-zero exit — the socket file otherwise still exists and clients get
    // `ECONNREFUSED`, the identical operator-visible symptom as the old
    // zombie-daemon bug this lane's earlier rounds fixed, merely fail-closed
    // instead of fail-open. Spawned (rather than awaited directly) so a panic
    // inside it is caught by `JoinHandle` rather than taking this whole
    // `main` task down uncontrolled, but the handle is explicitly awaited and
    // its `Err` propagated — never `tokio::spawn(accept_loop(..))` with the
    // handle discarded, the exact pattern this ruling forbids.
    let accept_handle = tokio::spawn(accept_loop(listener, registry, resources));
    let result = match accept_handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(color_eyre::eyre::eyre!(err)),
        Err(join_err) => Err(color_eyre::eyre::eyre!(join_err.to_string())),
    };

    // Unlink on the way out: a bound Unix socket outlives the process that
    // created it, and a leftover one makes the next run's `bind` fail with
    // `EADDRINUSE` (and looks, to a client, like a daemon that never
    // answers). Best-effort — the run's own success/failure is what `result`
    // above already reports; a failure removing the socket must not mask
    // that.
    let _ = remove_stale_socket(&socket_path);
    result
}

/// Creates the daemon's runtime directory `0700`, or accepts an existing one
/// only if it is still a real, owner-only directory belonging to this user.
///
/// All three checks run against the *same* `symlink_metadata` result, so there
/// is no window between them. `symlink_metadata` does not follow symlinks, so a
/// pre-planted `runtime_dir -> /somewhere/else` is rejected here rather than
/// silently accepted as "a directory".
///
/// The three refusals, and why each is load-bearing:
/// 1. **Not a directory** — catches the symlink pre-plant directly.
/// 2. **Mode != 0700** — catches a directory left group- or world-writable, which
///    would let anyone drop a symlink *inside* it for the daemon to open.
/// 3. **Owned by another uid** — catches a `0700` directory the attacker owns.
///    Mode alone is not enough: running as root (or with `CAP_DAC_OVERRIDE`)
///    traverses a foreign `0700` directory freely, and SQLite opens `store_path`
///    with `O_CREAT` *following symlinks*, so an attacker-owned directory is a
///    root-clobber primitive. Even unprivileged, accepting a directory whose
///    entries the attacker controls leaves a TOCTOU window in which they can
///    swap a symlink in between this check and the later open.
fn prepare_runtime_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new()
        .mode(RUNTIME_DIR_MODE)
        .create(dir)
    {
        // Freshly created by us, so it is by construction a directory, 0700, and
        // ours — none of the checks below can fail.
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir)?;
            if !meta.file_type().is_dir() {
                return Err(std::io::Error::new(
                    ErrorKind::AlreadyExists,
                    format!(
                        "{} exists but is not a directory; refusing to use it",
                        dir.display()
                    ),
                ));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode != RUNTIME_DIR_MODE {
                return Err(std::io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!(
                        "{} has mode {mode:04o}, expected {RUNTIME_DIR_MODE:04o}; \
                         refusing to write runtime state into a directory others can reach",
                        dir.display()
                    ),
                ));
            }
            check_owned_by_current_user(dir, &meta)?;
            Ok(())
        }
        Err(err) => Err(err),
    }
}

/// Rejects a runtime directory owned by anyone but the current user.
///
/// Linux-only, because the uid is read from `/proc/self` — `std::fs::metadata`
/// on it reports the current process's own uid, which is the whole trick that
/// makes this dependency-free (`getuid()` itself would mean taking on `libc` or
/// `rustix`). Failing to read `/proc` is treated as a hard error, not as a pass:
/// an ownership check that silently no-ops when it can't run isn't a check.
///
/// **`metadata`, never `symlink_metadata`, on this one path.** `/proc/self` is a
/// *symlink* to `/proc/<pid>`, and like every `/proc` symlink it is itself owned
/// by `root:root` — so `symlink_metadata` here would report uid 0 for every
/// process and make this check reject every directory (or, worse, pass when
/// running as root). Following it reaches the real `/proc/<pid>` directory,
/// whose owner is this process's uid. This is the one place in this file where
/// following a symlink is the correct behavior; every other call deliberately
/// uses `symlink_metadata` for the opposite reason.
#[cfg(target_os = "linux")]
fn check_owned_by_current_user(dir: &Path, meta: &std::fs::Metadata) -> std::io::Result<()> {
    let current_uid = std::fs::metadata("/proc/self")
        .map_err(|err| {
            std::io::Error::new(
                err.kind(),
                format!("cannot read /proc/self to determine this process's uid: {err}"),
            )
        })?
        .uid();
    let owner_uid = meta.uid();
    if owner_uid != current_uid {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            format!(
                "{} is owned by uid {owner_uid}, not this process's uid {current_uid}; \
                 refusing to write runtime state into another user's directory",
                dir.display()
            ),
        ));
    }
    Ok(())
}

/// Non-Linux fallback: no `/proc`, and reading the uid otherwise would mean
/// adding `libc`/`rustix` for one syscall.
///
/// The gap is narrow in practice on the platform that matters here: macOS gives
/// each user a private, per-user `$TMPDIR` (`/var/folders/...`, mode `0700`), so
/// the shared-directory pre-plant this check defends against does not arise on
/// the fallback path there the way it does under a world-writable `/tmp`. Linux —
/// where `temp_dir()` really is the shared `/tmp` — gets the real check above.
#[cfg(not(target_os = "linux"))]
fn check_owned_by_current_user(_dir: &Path, _meta: &std::fs::Metadata) -> std::io::Result<()> {
    Ok(())
}

/// The `Provider` used when no `ANTHROPIC_API_KEY` is set: every method
/// returns an error rather than doing anything, since nothing in this task
/// drives a real chat turn against it yet (see this file's module doc
/// comment) — a placeholder that costs nothing and opens zero connections,
/// not a scripted demo. Deliberately NOT `demo::FakeEditProvider`
/// (`roundhouse_daemon::demo` is kept only as an integration-test fixture,
/// per that module's own doc comment — reaching into it from the real boot
/// path would blur exactly the line this task exists to draw).
struct NoProviderConfigured;

impl Provider for NoProviderConfigured {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Err(ProviderError::Unsupported(
            "no ANTHROPIC_API_KEY configured for this daemon".into(),
        ))
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async {
            Err(ProviderError::Unsupported(
                "no ANTHROPIC_API_KEY configured for this daemon".into(),
            ))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(vec![]) })
    }
}

/// Paired with [`NoProviderConfigured`], which never dispatches through the
/// transport — but `RequestCtx` requires one, so this fills the slot.
struct NoTransportConfigured;

impl HttpTransport for NoTransportConfigured {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async {
            Err(TransportError::Io(
                "no ANTHROPIC_API_KEY configured; this daemon has no live transport".into(),
            ))
        })
    }
}

/// Removes a leftover socket from a previous run, and *only* a socket.
///
/// An unconditional `remove_file` here would delete whatever happened to sit at
/// the path — including a file the operator pointed `$ROUND_SOCKET` at by
/// mistake. `symlink_metadata` does not follow symlinks, so a symlink at this
/// path is reported as a symlink (not a socket) and is refused rather than
/// followed.
fn remove_stale_socket(path: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(std::io::Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "{} exists and is not a socket; refusing to remove it",
                path.display()
            ),
        )),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tier_accepts_every_real_tier_case_insensitively() {
        assert_eq!(parse_tier("none"), Ok(Tier::None));
        assert_eq!(parse_tier("NONE"), Ok(Tier::None));
        assert_eq!(parse_tier("Worktree"), Ok(Tier::Worktree));
        assert_eq!(parse_tier("sandbox"), Ok(Tier::Sandbox));
        assert_eq!(parse_tier("Container"), Ok(Tier::Container));
        assert_eq!(parse_tier("REMOTE"), Ok(Tier::Remote));
    }

    #[test]
    fn parse_tier_rejects_an_unknown_value() {
        assert!(parse_tier("supersandbox").is_err());
    }

    #[test]
    fn args_parse_allow_degraded_to() {
        let args = Args::parse_from(["round-daemon-internal", "--allow-degraded-to", "worktree"]);
        assert_eq!(args.allow_degraded_to, Some(Tier::Worktree));
    }

    #[test]
    fn args_default_to_no_degradation_allowed() {
        let args = Args::parse_from(["round-daemon-internal"]);
        assert_eq!(args.allow_degraded_to, None);
    }
}
