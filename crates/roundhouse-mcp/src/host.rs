// crates/roundhouse-mcp/src/host.rs
use crate::config::McpServerConfig;
use crate::executor::{McpExecutor, TaskInput, TaskSpawner};
use crate::namespace::{NamespaceCollisionError, ToolNamespace};
use crate::transport::stdio::StdioMcpTransport;
use crate::transport::McpTransport;
use crate::wire::McpError;
use roundhouse_core::{Origin, SessionId, TaskKind};
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

/// finding 4: the daemon/engine integration this plan was missing entirely.
/// `McpHost::start` is the one place `roundhouse-mcp` code spawns servers
/// and builds the namespace/executor from something resembling real
/// startup, not test scaffolding.
pub struct McpHost {
    pub executor: Arc<McpExecutor>,
    tool_defs: Vec<roundhouse_provider::ToolDef>,
}

impl McpHost {
    /// Spawns every configured MCP server, discovers its tools through a
    /// REAL task minted via `TaskSpawner::spawn_task` (finding 4 / S-LOG-1:
    /// never a bare `TaskId::new()` standing in for a task that doesn't
    /// exist anywhere queryable), and exposes the one aggregated namespaced
    /// tool list whatever assembles the `infer` task's `tools: Vec<ToolDef>`
    /// field should draw from. Consumed by `roundhouse-daemon` (out of this
    /// phase's crate boundary, same as `roundhouse-engine`'s real
    /// `TaskSpawner` implementation).
    pub async fn start(
        configs: Vec<McpServerConfig>,
        session: SessionId,
        policy: Arc<dyn Policy>,
        task_spawner: Arc<dyn TaskSpawner>,
    ) -> Result<Self, McpHostError> {
        // finding 6: `Vec`, not `HashMap<ServerId, _>` — `ServerId` has no
        // `Hash` (see `McpExecutor::new`'s doc comment); `McpExecutor::new`
        // takes exactly this shape.
        let mut connections: Vec<(ServerId, Arc<dyn McpTransport>)> = Vec::new();
        let mut discovered = Vec::new();

        for config in &configs {
            let transport =
                StdioMcpTransport::spawn(config)
                    .await
                    .map_err(|source| McpHostError::Spawn {
                        server: config.id.0.clone(),
                        source,
                    })?;

            // finding 4: minted through the real task-creation authority
            // (S-LOG-1). The input is this crate's own reconciled
            // `TaskInput::Mcp` (`executor.rs`'s note: Phase 0's frozen core
            // `TaskInput` has no `Mcp` variant and cannot gain one without a
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

            let result = transport
                .discover()
                .await
                .map_err(|source| McpHostError::Discover {
                    server: config.id.0.clone(),
                    source,
                })?;
            discovered.push((config.id.clone(), discovery_task, result));
            connections.push((
                config.id.clone(),
                Arc::new(transport) as Arc<dyn McpTransport>,
            ));
        }

        let namespace = ToolNamespace::build(&discovered)?;
        // §12.7/S-TOOL-9 note, reconciled against Phase 0's real contract:
        // the brief expected an all-`pub` `ToolDef` struct literal here, but
        // the delivered `ToolDef` has private fields and precisely one
        // sanctioned typed-schema constructor (`tool_def_from_schema::<T>`).
        // An MCP server's `input_schema` is externally-supplied JSON with no
        // corresponding Rust type — there is nothing to hand as `T` — so the
        // narrow, reviewed wire-source path the `ToolDef` doc comment
        // reserves for this case (`ToolDef::from_wire_parts`, object root
        // enforced by its `serde_json::Map` parameter) is what builds the
        // list, and a non-object schema from a server fails startup closed
        // rather than being laundered through. That provider-side addition
        // is a Phase 0 contract amendment, not something the brief's sketch
        // could express.
        let tool_defs = namespace
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
                ))
            })
            .collect::<Result<Vec<_>, McpHostError>>()?;

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
}
