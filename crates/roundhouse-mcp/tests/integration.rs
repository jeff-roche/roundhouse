//! Task 9 — the plan's one end-to-end proof: spawn a REAL child process
//! (the `fake-mcp-stdio-server` binary), discover its tools, namespace
//! them, dispatch through the executor's policy gate, suspend on a real
//! `input_required` result (MRTR round 0 → 1), resume with elicitation
//! answers, and complete — all against a real OS process speaking the
//! newline-JSON-RPC wire `StdioMcpTransport` writes.
//!
//! Note on test doubles: `crate::testing::FakeMcpTransport` (Task 5) is
//! `#[cfg(test)]`-gated inside the library, so it is not visible here —
//! `tests/*.rs` link `roundhouse_mcp` as an ordinary external dependency,
//! and `cfg(test)` items never cross that boundary. This file defines its
//! own tiny `AllowAllPolicy`/`NoopTaskSpawner` doubles (the same
//! self-contained-test-double pattern Task 10's `tests/untrusted_boundary.rs`
//! will use).
//!
//! Reconciled shapes (per the plan preamble's assumed-shape rule): the
//! brief sketched `TaskInput`/`TaskOutput`/`ContentBlock` as
//! `roundhouse_core` items, but Phase 0's frozen core `TaskInput` is
//! deliberately minimal (Json/Text/Blob) and `ContentBlock` lives in
//! `roundhouse-provider` — the executor's local shapes (Tasks 8/8b) are the
//! real ones this test drives. `SuspendReason::AwaitingElicitation` also
//! carries the elicit schema, so the suspension pattern must be
//! `AwaitingElicitation { .. }`.
use async_trait::async_trait;
use roundhouse_core::{Origin, PolicyDecision, SessionId, SuspendReason, TaskId, TaskKind, Trust};
use roundhouse_mcp::config::{McpServerConfig, McpTransportKind};
use roundhouse_mcp::executor::{
    ExecutorOutcome, McpExecutor, McpRetryState, ResumptionInput, TaskCtx, TaskExecutor, TaskInput,
    TaskOutput, TaskSpawner,
};
use roundhouse_mcp::namespace::ToolNamespace;
use roundhouse_mcp::transport::stdio::StdioMcpTransport;
use roundhouse_mcp::transport::McpTransport;
use roundhouse_mcp::wire::RequestState;
use roundhouse_policy::{Policy, PolicyInput, ServerId, Taint};
use roundhouse_provider::ContentBlock;
use std::sync::Arc;

struct AllowAllPolicy;
impl Policy for AllowAllPolicy {
    fn decide(&self, _input: &PolicyInput) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

struct NoopTaskSpawner;
#[async_trait]
impl TaskSpawner for NoopTaskSpawner {
    async fn spawn_task(
        &self,
        _session: SessionId,
        _parent: Option<TaskId>,
        _kind: TaskKind,
        _origin: Origin,
        _input: TaskInput,
    ) -> TaskId {
        TaskId::new()
    }
    async fn suspend_task(&self, _task: TaskId, _reason: SuspendReason) {}
    async fn record_decision(&self, _task: TaskId, _decision: PolicyDecision) {}
}

#[tokio::test]
async fn full_lifecycle_against_a_real_child_process() {
    let bin = env!("CARGO_BIN_EXE_fake-mcp-stdio-server");
    let config = McpServerConfig {
        id: ServerId("fake".into()),
        transport: McpTransportKind::Stdio {
            command: bin.into(),
            args: vec![],
            env: vec![],
            pinned_binary_hash: None,
        },
    };

    let transport = StdioMcpTransport::spawn(&config).await.expect("spawn");
    let discovery_task = TaskId::new();
    let discovered = transport.discover().await.expect("discover");
    assert_eq!(discovered.protocol_version, "2026-07-28");
    assert!(discovered.tools.iter().any(|t| t.name == "whoami"));
    assert!(
        discovered.tools.iter().any(|t| t.name == "book_flight"),
        "book_flight is the tool that demands elicitation"
    );

    let ns = ToolNamespace::build(&[(config.id.clone(), discovery_task, discovered)])
        .expect("no namespace collisions with one server");
    let connections: Vec<(ServerId, Arc<dyn McpTransport>)> = vec![(
        config.id.clone(),
        Arc::new(transport) as Arc<dyn McpTransport>,
    )];
    let executor = McpExecutor::new(
        connections,
        ns,
        Arc::new(AllowAllPolicy),
        Arc::new(NoopTaskSpawner),
    );

    // 1. Plain happy-path call.
    let whoami_name = executor
        .namespace_tool_name("whoami")
        .expect("whoami registered");
    let session = SessionId::new();
    let ctx = TaskCtx {
        task: TaskId::new(),
        session,
        parent: None,
        taint: Taint::Tainted,
    };
    let outcome = executor
        .execute(
            &ctx,
            &TaskInput::Mcp {
                server: config.id.clone(),
                tool: whoami_name,
                args: serde_json::json!({}),
            },
            None,
        )
        .await;
    match outcome {
        ExecutorOutcome::Completed {
            output: TaskOutput::Mcp { content, is_error },
            ..
        } => {
            assert!(!is_error);
            assert_eq!(content.len(), 1);
            assert!(
                matches!(content[0].1.trust, Trust::Untrusted),
                "§6.8: MCP results are unconditionally untrusted"
            );
        }
        other => panic!("expected Completed, got {other:?}"),
    }

    // 2. A tool that requires one round of elicitation before completing.
    let book_name = executor
        .namespace_tool_name("book_flight")
        .expect("book_flight registered");
    let ctx2 = TaskCtx {
        task: TaskId::new(),
        session,
        parent: None,
        taint: Taint::Tainted,
    };
    let input2 = TaskInput::Mcp {
        server: config.id.clone(),
        tool: book_name,
        args: serde_json::json!({"destination": "SFO"}),
    };

    let suspended = executor.execute(&ctx2, &input2, None).await;
    assert!(
        matches!(
            suspended,
            ExecutorOutcome::Suspended {
                reason: SuspendReason::AwaitingElicitation { .. }
            }
        ),
        "expected the parent mcp task suspended pending a real elicit task, got {suspended:?}"
    );
    // In production the engine reads `mcp_resume_context` back off the
    // completed `elicit` child task's own `TaskInput`; this test's
    // `NoopTaskSpawner` doesn't persist that task, so it reconstructs the
    // equivalent resume state directly — the point of this test is the
    // transport/MRTR round-trip, not the (already-tested, Task 8b)
    // elicit-task bookkeeping.
    let resume_state = McpRetryState {
        server: config.id.clone(),
        tool: "book_flight".into(),
        args: serde_json::json!({"destination": "SFO"}),
        request_state: RequestState("opaque-booking-state-1".into()),
        round: 1,
    };

    let completed = executor
        .execute(
            &ctx2,
            &input2,
            Some(ResumptionInput::ElicitationAnswers {
                state: resume_state,
                answers: serde_json::json!({"fare_class": "economy"}),
            }),
        )
        .await;
    match completed {
        ExecutorOutcome::Completed {
            output: TaskOutput::Mcp { content, .. },
            ..
        } => {
            assert!(
                matches!(&content[0].0, ContentBlock::Text { text, .. } if text.contains("booked"))
            );
        }
        other => panic!("expected Completed after resume, got {other:?}"),
    }
    // Dropping the executor (and with it the transport's last Arc) closes
    // the child's stdin — the same EOF mechanism `shutdown()` relies on —
    // so the real process exits on its own rather than leaking past the
    // test. Explicit `shutdown()` lifecycle behavior is Task 6's coverage.
}
