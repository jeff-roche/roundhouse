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
use roundhouse_mcp::executor::{TaskExecutor, TaskInput, TaskSpawner};
use roundhouse_mcp::host::McpHost;
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
    created: Mutex<Vec<(TaskKind, TaskInput)>>,
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
        self.created.lock().unwrap().push((kind, input));
        TaskId::new()
    }
    async fn suspend_task(&self, _task: TaskId, _reason: SuspendReason) {}
    async fn record_decision(&self, _task: TaskId, _decision: PolicyDecision) {}
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
    {
        let created = task_spawner.created.lock().unwrap();
        assert_eq!(
            created.len(),
            1,
            "exactly one discovery task per configured server"
        );
        assert!(matches!(created[0].0, TaskKind::Mcp));
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
