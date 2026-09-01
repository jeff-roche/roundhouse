//! Task 11 — the daemon/engine integration the earlier tasks were missing
//! entirely (plan finding 4): `McpHost::start` spawns every configured MCP
//! server, discovers its tools through a REAL task minted via
//! `TaskSpawner::spawn_task` (S-LOG-1 — never a bare `TaskId::new()`
//! conjured inline with nothing behind it), builds the namespace/executor,
//! and exposes the one aggregated namespaced `ToolDef` list an `infer`
//! task's `tools: Vec<ToolDef>` field draws from — all against a real
//! spawned child process (the Task 9 `fake-mcp-stdio-server` binary).
//!
//! Reconciled shapes (per the plan preamble's assumed-shape rule): the
//! brief sketched `TaskInput::Mcp` as a `roundhouse_core` variant, but
//! Phase 0's frozen core `TaskInput` is deliberately minimal
//! (Json/Text/Blob) — the executor's local shapes (Tasks 8/8b) are the real
//! ones. Likewise `ToolDef`'s fields are private (`roundhouse-provider`
//! S-TOOL-9), so the tool-list assertion goes through the `name()`
//! accessor rather than a `t.name` field.
use async_trait::async_trait;
use roundhouse_core::{Origin, PolicyDecision, SessionId, SuspendReason, TaskId, TaskKind};
use roundhouse_mcp::config::{McpServerConfig, McpTransportKind};
use roundhouse_mcp::executor::{TaskExecutor, TaskInput, TaskSpawner, TerminalOutcome};
use roundhouse_mcp::host::{McpHost, McpHostError};
use roundhouse_policy::{Policy, PolicyInput, ServerId, Taint};
use std::sync::{Arc, Mutex};

struct AllowAllPolicy;
impl Policy for AllowAllPolicy {
    fn decide(&self, _input: &PolicyInput) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

#[derive(Default)]
struct RecordingTaskSpawner {
    created: Mutex<Vec<(TaskKind, TaskInput, TaskId)>>,
    terminal: Mutex<Vec<(TaskId, TerminalOutcome)>>,
}

#[async_trait]
impl TaskSpawner for RecordingTaskSpawner {
    async fn spawn_task(
        &self,
        _session: SessionId,
        _parent: Option<TaskId>,
        kind: TaskKind,
        _origin: Origin,
        input: TaskInput,
    ) -> TaskId {
        let id = TaskId::new();
        self.created.lock().unwrap().push((kind, input, id));
        id
    }
    async fn suspend_task(&self, _task: TaskId, _reason: SuspendReason) {}
    async fn record_decision(&self, _task: TaskId, _decision: PolicyDecision) {}
    async fn record_terminal(&self, task: TaskId, outcome: TerminalOutcome) {
        self.terminal.lock().unwrap().push((task, outcome));
    }
}

#[tokio::test]
async fn start_spawns_configured_servers_and_exposes_a_namespaced_tool_list() {
    let bin = env!("CARGO_BIN_EXE_fake-mcp-stdio-server");
    let configs = vec![McpServerConfig {
        id: ServerId("fake".into()),
        transport: McpTransportKind::Stdio {
            command: bin.into(),
            args: vec![],
            env: vec![],
            pinned_binary_hash: None,
        },
    }];
    let session = SessionId::new();
    let task_spawner = Arc::new(RecordingTaskSpawner::default());

    let host = McpHost::start(
        configs,
        session,
        Arc::new(AllowAllPolicy),
        task_spawner.clone(),
    )
    .await
    .expect("host startup");

    // finding 4: the tool list an `infer` task's `tools: Vec<ToolDef>` field
    // would draw from is real and namespaced.
    let names: Vec<&str> = host.tool_defs().iter().map(|t| t.name()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("fake__") && n.contains("whoami")),
        "expected a namespaced whoami tool, got: {names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("fake__") && n.contains("book_flight")),
        "expected a namespaced book_flight tool, got: {names:?}"
    );

    // finding 4: the discovery task was obtained through TaskSpawner — a
    // real, recorded `mcp`-kind task — never a bare `TaskId::new()`
    // conjured inline with nothing behind it.
    let discovery_task_id = {
        let created = task_spawner.created.lock().unwrap();
        assert_eq!(
            created.len(),
            1,
            "exactly one discovery task per configured server"
        );
        assert!(matches!(created[0].0, TaskKind::Mcp));
        created[0].2
    };

    // Task 11 fix (review finding 1): that minted discovery task's
    // lifecycle is CLOSED — exactly one terminal record, naming the same
    // id `spawn_task` returned, `Completed` on successful startup. S-LOG-1:
    // a minted task record exists only as a complete lifecycle, never a
    // dangling creation left permanently in-flight.
    {
        let terminal = task_spawner.terminal.lock().unwrap();
        assert_eq!(
            terminal.len(),
            1,
            "the discovery task got exactly one terminal record"
        );
        assert_eq!(
            terminal[0].0, discovery_task_id,
            "the terminal record names the minted discovery task id"
        );
        match &terminal[0].1 {
            TerminalOutcome::Completed { output, usage } => {
                assert_eq!(
                    usage.input_tokens + usage.output_tokens + usage.cache_read_tokens,
                    0,
                    "discovery runs no inference"
                );
                // The terminal output folds what discovery actually
                // produced: the protocol version and discovered tool names.
                match output {
                    roundhouse_core::TaskOutput::Json(v) => {
                        assert_eq!(v["protocol_version"], "2026-07-28");
                        let tools = v["tools"].as_array().expect("tools array");
                        assert!(
                            tools.iter().any(|t| t == "whoami"),
                            "terminal output names the discovered tools, got: {v}"
                        );
                    }
                    other => panic!("expected Json discovery output, got {other:?}"),
                }
            }
            other => panic!("expected a Completed terminal record, got {other:?}"),
        }
    }

    // The executor built from that discovery is real and dispatchable.
    let whoami = host
        .executor
        .namespace_tool_name("whoami")
        .expect("whoami registered");
    let ctx = roundhouse_mcp::executor::TaskCtx {
        task: TaskId::new(),
        session,
        parent: None,
        taint: Taint::Tainted,
    };
    let outcome = host
        .executor
        .execute(
            &ctx,
            &TaskInput::Mcp {
                server: ServerId("fake".into()),
                tool: whoami,
                args: serde_json::json!({}),
            },
            None,
        )
        .await;
    assert!(matches!(
        outcome,
        roundhouse_mcp::executor::ExecutorOutcome::Completed { .. }
    ));
}

// Task 11 fix, finding 2: the fail-closed `ToolDef::from_wire_parts` path —
// a server announcing a non-object `inputSchema` must fail startup closed
// with the safe type-only error (`McpHostError::ToolDef`), and the
// untrusted schema payload itself must never ride out through the error.
// The fake server's `bad-schema` argv mode serves exactly that shape.
#[tokio::test]
async fn non_object_discovered_schema_fails_startup_closed_without_leaking_the_payload() {
    let bin = env!("CARGO_BIN_EXE_fake-mcp-stdio-server");
    let configs = vec![McpServerConfig {
        id: ServerId("fake".into()),
        transport: McpTransportKind::Stdio {
            command: bin.into(),
            args: vec!["bad-schema".into()],
            env: vec![],
            pinned_binary_hash: None,
        },
    }];

    // `McpHost` is not `Debug`, so no `expect_err` — match the error out.
    let err = match McpHost::start(
        configs,
        SessionId::new(),
        Arc::new(AllowAllPolicy),
        Arc::new(RecordingTaskSpawner::default()),
    )
    .await
    {
        Ok(_) => panic!("a non-object input schema must fail startup closed"),
        Err(err) => err,
    };

    match &err {
        McpHostError::ToolDef {
            server,
            tool,
            actual,
        } => {
            assert_eq!(server, "fake");
            assert_eq!(tool, "bad_schema");
            assert_eq!(
                *actual, "string",
                "the error carries the value's TYPE only, never the value"
            );
        }
        other => panic!("expected McpHostError::ToolDef, got {other:?}"),
    }

    // The payload marker the fake server announces as its `inputSchema`
    // must not appear in Display (the daemon startup-log path) or Debug
    // (the panic path) — only the type name ("string") may.
    const PAYLOAD: &str = "__UNTRUSTED_SCHEMA_PAYLOAD__";
    assert!(
        !err.to_string().contains(PAYLOAD),
        "Display leaked the schema payload: {err}"
    );
    assert!(
        !format!("{err:?}").contains(PAYLOAD),
        "Debug leaked the schema payload: {err:?}"
    );
}

// Task 11 fix (review finding 1), failure branch: when discovery itself
// fails, the minted discovery task still gets its terminal record —
// `Failed`, non-retryable — instead of dangling in-flight forever. A real
// child that spawns fine but speaks no protocol (`/bin/true` exits
// immediately) drives the transport's EOF path end to end.
#[tokio::test]
async fn discovery_failure_records_the_discovery_task_failed_not_in_flight() {
    let configs = vec![McpServerConfig {
        id: ServerId("gone".into()),
        transport: McpTransportKind::Stdio {
            command: "/bin/true".into(),
            args: vec![],
            env: vec![],
            pinned_binary_hash: None,
        },
    }];
    let task_spawner = Arc::new(RecordingTaskSpawner::default());

    let err = match McpHost::start(
        configs,
        SessionId::new(),
        Arc::new(AllowAllPolicy),
        task_spawner.clone(),
    )
    .await
    {
        Ok(_) => panic!("a server that exits before discovery must fail startup"),
        Err(err) => err,
    };
    assert!(
        matches!(err, McpHostError::Discover { .. }),
        "expected McpHostError::Discover, got {err:?}"
    );

    // Exactly one task was minted, and it was closed out Failed — named by
    // the same id `spawn_task` returned (S-LOG-1: complete lifecycle, no
    // dangling creation).
    let discovery_task_id = {
        let created = task_spawner.created.lock().unwrap();
        assert_eq!(created.len(), 1, "the task was minted before discover ran");
        assert!(matches!(created[0].0, TaskKind::Mcp));
        created[0].2
    };
    {
        let terminal = task_spawner.terminal.lock().unwrap();
        assert_eq!(terminal.len(), 1, "exactly one terminal record");
        assert_eq!(
            terminal[0].0, discovery_task_id,
            "the terminal record names the minted discovery task id"
        );
        match &terminal[0].1 {
            TerminalOutcome::Failed { error, retryable } => {
                assert!(
                    !retryable,
                    "startup fails closed — nothing re-runs the discovery task in-process"
                );
                assert_eq!(
                    error.category, "executor_error",
                    "same category the executor assigns to transport-level failures"
                );
                assert!(
                    !error.message.is_empty(),
                    "the transport error message is preserved in the task record"
                );
            }
            other => panic!("expected a Failed terminal record, got {other:?}"),
        }
    }
}
