// crates/roundhouse-mcp/src/host.rs
use crate::config::McpServerConfig;
use crate::executor::{McpExecutor, TaskInput, TaskSpawner, TerminalOutcome};
use crate::namespace::{NamespaceCollisionError, ToolNamespace};
use crate::transport::stdio::StdioMcpTransport;
use crate::transport::McpTransport;
use crate::wire::{DiscoverResult, McpError};
use roundhouse_core::{Origin, SessionId, TaskError, TaskId, TaskKind, Usage};
use roundhouse_policy::{Policy, ServerId};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum McpHostError {
    #[error("spawning MCP server '{server}' failed: {source}")]
    Spawn {
        server: String,
        #[source]
        source: McpError,
    },
    #[error("discovering tools on MCP server '{server}' failed: {source}")]
    Discover {
        server: String,
        #[source]
        source: McpError,
    },
    #[error("tool namespace collision: {0}")]
    Namespace(#[from] NamespaceCollisionError),
    /// Reconciled shape (plan preamble's assumed-shape rule): the brief
    /// assumed `ToolDef` had an all-`pub` struct literal, but Phase 0's real
    /// `ToolDef` has private fields (S-TOOL-9) and its one wire-sourced
    /// constructor, `ToolDef::from_wire_parts`, takes the schema as a
    /// `serde_json::Map` — a non-object root cannot be represented. A
    /// server announcing a non-object `inputSchema` is malformed server
    /// output, so startup fails closed with a named error instead of
    /// exposing a hand-broken schema to the model. The value itself is
    /// never echoed — only its type — so an untrusted payload can't ride
    /// out through an error message.
    #[error("MCP server '{server}' tool '{tool}' has a non-object input_schema (got {actual}) — refusing to expose it as a provider ToolDef")]
    ToolDef {
        server: String,
        tool: String,
        actual: &'static str,
    },
}

/// `serde_json::Value` has no `type_name`; this is the honest description
/// a fail-closed error can carry without echoing the untrusted payload.
fn type_desc(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// One configured server that made it through spawn + discovery.
struct StartedServer {
    server: ServerId,
    transport: Arc<dyn McpTransport>,
    discovery_task: TaskId,
    discovery: DiscoverResult,
}

/// A per-server startup failure, carrying the already-spawned transport
/// (`Some`) so `McpHost::start` can tear its child process down instead
/// of dropping it — dropping a live transport without reaching
/// `shutdown()` is exactly the orphaned-child-process bug the Phase 3
/// review flagged (Critical: "MCP child processes are never killed").
struct StartFailure {
    transport: Option<Arc<dyn McpTransport>>,
    error: McpHostError,
}

/// Spawns and discovers ONE server. Every failure path here returns the
/// spawned transport (when there is one) rather than dropping it: no
/// caller of `StdioMcpTransport::spawn` may hold a live child that no
/// `shutdown()` will ever reach.
///
/// The minted discovery task's lifecycle is CLOSED inside this function:
/// the moment discovery resolves, its terminal record goes out through
/// `TaskSpawner::record_terminal` — `Completed` (with the discovered
/// protocol version and tool names as the task output) on success,
/// `Failed` (the transport error, non-retryable: startup fails closed and
/// nothing re-runs this task in-process) on failure. A task minted through
/// the real creation authority must never be left permanently in-flight —
/// S-LOG-1's lifecycle rule.
async fn start_server(
    config: McpServerConfig,
    session: SessionId,
    task_spawner: Arc<dyn TaskSpawner>,
) -> Result<StartedServer, StartFailure> {
    let transport = match StdioMcpTransport::spawn(&config).await {
        Ok(t) => Arc::new(t) as Arc<dyn McpTransport>,
        Err(source) => {
            // Nothing was left running: `spawn`'s own post-fork failure
            // paths drop the child, and `KillOnDrop` covers that drop.
            return Err(StartFailure {
                transport: None,
                error: McpHostError::Spawn {
                    server: config.id.0.clone(),
                    source,
                },
            });
        }
    };

    // finding 4: the discovery task is minted through the real
    // task-creation authority (S-LOG-1). The input is this crate's own
    // reconciled `TaskInput::Mcp` (`executor.rs`'s note: Phase 0's frozen
    // core `TaskInput` has no `Mcp` variant and cannot gain one without a
    // dependency cycle) describing the discovery itself — the id the
    // namespace stamps tool descriptions' provenance with.
    let discovery_task = task_spawner
        .spawn_task(
            session,
            None,
            TaskKind::Mcp,
            Origin::System,
            TaskInput::Mcp {
                server: config.id.clone(),
                tool: "server/discover".into(),
                args: serde_json::json!({}),
            },
        )
        .await;

    // Task 11 fix (review finding 1): whichever way discovery resolves, its
    // terminal record goes out through `record_terminal` before anything
    // else happens. The terminal payload is exactly what core's
    // `record_task_completed`/`record_task_failed` fold into the
    // `TaskCompleted`/`TaskFailed` events; session/seq/timestamp/`schema_v`
    // stay engine-side, same as every other seam call.
    match transport.discover().await {
        Ok(discovery) => {
            let tool_names: Vec<String> = discovery.tools.iter().map(|t| t.name.clone()).collect();
            let output = roundhouse_core::TaskOutput::Json(serde_json::json!({
                "protocol_version": discovery.protocol_version.clone(),
                "tools": tool_names,
            }));
            task_spawner
                .record_terminal(
                    discovery_task,
                    TerminalOutcome::Completed {
                        output,
                        usage: Usage::default(),
                    },
                )
                .await;
            Ok(StartedServer {
                server: config.id.clone(),
                transport,
                discovery_task,
                discovery,
            })
        }
        Err(source) => {
            task_spawner
                .record_terminal(
                    discovery_task,
                    TerminalOutcome::Failed {
                        error: TaskError {
                            message: source.to_string(),
                            // Same category the executor assigns to
                            // transport-level failures.
                            category: "executor_error".into(),
                        },
                        retryable: false,
                    },
                )
                .await;
            Err(StartFailure {
                transport: Some(transport),
                error: McpHostError::Discover {
                    server: config.id.0.clone(),
                    source,
                },
            })
        }
    }
}

/// Best-effort teardown of every live connection a partial start left
/// behind — used on each `McpHost::start` error path after servers have
/// already spawned. Errors are swallowed HERE because this only runs on a
/// path that is already returning its own named startup error; the
/// KillOnDrop backstop still covers the direct child of anything this
/// graceful path fails to stop.
async fn shutdown_all<'a>(transports: impl IntoIterator<Item = &'a Arc<dyn McpTransport>>) {
    for transport in transports {
        let _ = transport.shutdown().await;
    }
}

/// finding 4: the daemon/engine integration point this plan was missing
/// entirely — `McpHost::start` is the one place `roundhouse-mcp` code
/// spawns servers and builds the namespace/executor from something
/// resembling real startup, not test scaffolding.
///
/// ⚠️ KNOWN GAP (Phase 3 review, 2026-09-01): `roundhouse-daemon` does NOT
/// call `McpHost::start` yet — no daemon code path spawns or dispatches to
/// an MCP server. The dependency exists, the integration does not. This is
/// deliberately flagged, not papered over: the real `TaskSpawner` (the
/// production implementation wrapping `TaskRunner` and the session's seq
/// counter) is `roundhouse-engine`'s side of the seam, out of this crate's
/// boundary by design, and wiring it plus loading `mcp.servers` from
/// layered config into daemon boot is the remaining Phase 3 daemon work.
/// Until that lands, treat every "consumed by the daemon" path below as
/// an interface contract under test here — NOT as shipped behavior.
pub struct McpHost {
    pub executor: Arc<McpExecutor>,
    tool_defs: Vec<roundhouse_provider::ToolDef>,
}

impl McpHost {
    /// Spawns every configured MCP server, discovers its tools through a
    /// REAL task minted via `TaskSpawner::spawn_task` (finding 4 / S-LOG-1:
    /// never a bare `TaskId::new()` standing in for a task that doesn't
    /// exist anywhere queryable), and exposes the one aggregated namespaced
    /// tool list whatever assembles the `infer` task's `tools:
    /// Vec<ToolDef>` field should draw from. See the KNOWN GAP note on
    /// [`McpHost`] — the daemon consumer is not wired yet.
    ///
    /// Startup is all-or-nothing (it fails closed if ANY server fails) and
    /// CONFIRMED-teardown on every path: the moment any failure is known,
    /// every child process spawned by this call — successful servers
    /// included — goes through `McpTransport::shutdown` before the error
    /// is returned (Phase 3 review fix: the old code returned early on
    /// discover/namespace/`ToolDef` failures, silently orphaning the
    /// servers that HAD started, compounding on every retried start after
    /// a config fix).
    ///
    /// Servers are spawned and discovered CONCURRENTLY (Phase 3 review
    /// fix, Efficiency): daemon-ready latency is the slowest server's
    /// spawn+discover round trip, not the sum of all N.
    pub async fn start(
        configs: Vec<McpServerConfig>,
        session: SessionId,
        policy: Arc<dyn Policy>,
        task_spawner: Arc<dyn TaskSpawner>,
    ) -> Result<Self, McpHostError> {
        // finding 6: `Vec`, not `HashMap<ServerId, _>` — `ServerId` has no
        // `Hash` (see `McpExecutor::new`'s doc comment); `McpExecutor::new`
        // takes exactly this shape.
        let results = futures::future::join_all(
            configs
                .into_iter()
                .map(|config| start_server(config, session, task_spawner.clone())),
        )
        .await;

        // `join_all` preserves input order, so "first CONFIGURED server's
        // failure wins" stays deterministic regardless of which server
        // actually failed first in wall-clock time.
        let mut started: Vec<StartedServer> = Vec::new();
        let mut failures: Vec<StartFailure> = Vec::new();
        for result in results {
            match result {
                Ok(s) => started.push(s),
                Err(f) => failures.push(f),
            }
        }

        if !failures.is_empty() {
            let live: Vec<Arc<dyn McpTransport>> = started
                .iter()
                .map(|s| s.transport.clone())
                .chain(failures.iter().filter_map(|f| f.transport.clone()))
                .collect();
            shutdown_all(&live).await;
            return Err(failures
                .into_iter()
                .next()
                .expect("checked non-empty")
                .error);
        }

        let mut connections: Vec<(ServerId, Arc<dyn McpTransport>)> = Vec::new();
        let mut discovered = Vec::new();
        for s in started {
            connections.push((s.server.clone(), s.transport));
            discovered.push((s.server, s.discovery_task, s.discovery));
        }

        let namespace = match ToolNamespace::build(&discovered) {
            Ok(n) => n,
            // Phase 3 review fix (Critical, second bullet): a collision
            // here used to drop the already-spawned transports without any
            // teardown.
            Err(e) => {
                shutdown_all(connections.iter().map(|(_, t)| t)).await;
                return Err(e.into());
            }
        };
        let tool_defs = match build_tool_defs(&namespace) {
            Ok(d) => d,
            Err(e) => {
                shutdown_all(connections.iter().map(|(_, t)| t)).await;
                return Err(e);
            }
        };

        let executor = Arc::new(McpExecutor::new(
            connections,
            namespace,
            policy,
            task_spawner,
        ));
        Ok(McpHost {
            executor,
            tool_defs,
        })
    }

    /// The aggregated namespaced tool list across every successfully started
    /// server — the single source an `infer` task's `tools: Vec<ToolDef>`
    /// field draws from.
    pub fn tool_defs(&self) -> &[roundhouse_provider::ToolDef] {
        &self.tool_defs
    }

    /// Tear down every server connection — the daemon-shutdown hook that
    /// makes `McpTransport::shutdown` reachable from the ONLY production
    /// owner of live transports (`McpExecutor`'s `Arc` map). Delegates to
    /// [`McpExecutor::shutdown`]; see that method for the error contract.
    pub async fn shutdown(&self) -> Result<(), McpError> {
        self.executor.shutdown().await
    }
}

/// §12.7/S-TOOL-9 note, reconciled against Phase 0's real contract: the
/// brief expected an all-`pub` `ToolDef` struct literal in `start`, but
/// the delivered `ToolDef` has private fields and precisely one sanctioned
/// typed-schema constructor (`tool_def_from_schema::<T>`). An MCP server's
/// `input_schema` is externally-supplied JSON with no corresponding Rust
/// type — there is nothing to hand as `T` — so the narrow, reviewed
/// wire-source path the `ToolDef` doc comment reserves for this case
/// (`ToolDef::from_wire_parts`, object root enforced by its
/// `serde_json::Map` parameter) is what builds the list, and a non-object
/// schema from a server fails startup closed rather than being laundered
/// through. That provider-side addition is a Phase 0 contract amendment,
/// not something the brief's sketch could express.
///
/// Phase 3 review fix (Correctness): `from_wire_parts` now also takes the
/// tool's `Provenance` — the namespace's `Trust::Untrusted` stamp and the
/// discovery task id — because the §6.8 trust mitigation ("a session that
/// reads untrusted content loses standing permission, downgrades to Ask")
/// runs engine-side against THIS list, where a provenance flag that stops
/// at `NamespacedToolDef` is unreadable. `McpHost::start` returns
/// `Err(McpHostError::ToolDef)` (type name only, never the untrusted
/// payload) on a non-object schema.
fn build_tool_defs(
    namespace: &ToolNamespace,
) -> Result<Vec<roundhouse_provider::ToolDef>, McpHostError> {
    namespace
        .tools()
        .iter()
        .map(|t| {
            let schema = match &t.input_schema {
                serde_json::Value::Object(map) => map.clone(),
                other => {
                    return Err(McpHostError::ToolDef {
                        server: t.server.0.clone(),
                        tool: t.original_name.clone(),
                        actual: type_desc(other),
                    })
                }
            };
            Ok(roundhouse_provider::ToolDef::from_wire_parts(
                t.namespaced_name.clone(),
                t.description.clone(),
                schema,
                t.description_provenance.clone(),
            ))
        })
        .collect()
}
