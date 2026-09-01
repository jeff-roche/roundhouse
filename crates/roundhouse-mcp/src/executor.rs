// crates/roundhouse-mcp/src/executor.rs
use crate::namespace::ToolNamespace;
use crate::transport::McpTransport;
use crate::wire::{JsonRpcId, JsonRpcIdGen, McpContentBlock, McpResultType, ToolCallRequest};
use async_trait::async_trait;
use base64::Engine;
use roundhouse_core::{
    Origin, PolicyDecision, Provenance, SessionId, SuspendReason, TaskError, TaskId, TaskKind,
    Trust, Usage,
};
use roundhouse_policy::{Policy, PolicyInput, ServerId, Taint, TaskParams};
use roundhouse_provider::{ContentBlock, MediaSource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// This crate's own task-execution seam (the plan's "Phase 3's Own Local
/// Types"): no phase — Phase 0 or otherwise — defines a `TaskExecutor`/
/// `TaskCtx` pair anywhere, so the shapes below are this crate's own, used
/// only inside `roundhouse-mcp` and by whatever engine code eventually
/// calls into it. Reconcile with `roundhouse-engine`'s actual executor
/// trait before wiring this crate into a workspace where such a trait
/// already exists.
#[derive(Debug, Clone)]
pub struct TaskCtx {
    pub task: TaskId,
    pub session: SessionId,
    pub parent: Option<TaskId>,
    /// §6.2/§6.8 — fed straight into `PolicyInput.taint` on every dispatch
    /// (finding 2's policy gate). Threaded in by whatever calls `execute`;
    /// this crate never invents a taint value on its own.
    pub taint: Taint,
}

/// # Reconciled input shape (plan preamble's assumed-shape rule)
///
/// The Phase 3 plan's "Assumed Frozen Contracts" block sketches
/// `TaskInput::Mcp` as a `roundhouse-core` variant, but Phase 0's actual
/// frozen `roundhouse_core::TaskInput` is deliberately minimal
/// (`Json`/`Text`/`Blob`, §4.1/§4.5) — and the assumed shape cannot be
/// added there: `server` is `roundhouse_policy::ServerId`, and
/// `roundhouse-policy` depends on `roundhouse-core`, so a core-side
/// variant would be a dependency cycle. Per the plan preamble ("assumed
/// shape — reconcile with Phase 0's actual definition before merging") and
/// the same ground-truth reasoning that moved `TaskExecutor`/`TaskCtx`/
/// `ExecutorOutcome`/`TaskSpawner` into this crate, the MCP task-input
/// shape is defined here, where every type it names is already in scope.
/// Task 8b extends this enum with the `Elicit` variant.
#[derive(Debug, Clone)]
pub enum TaskInput {
    Mcp {
        server: ServerId,
        tool: String,
        args: serde_json::Value,
    },
}

/// See [`TaskInput`]'s reconciliation note: the MCP result shape
/// (`Vec<(ContentBlock, Provenance)>` + `is_error`) carries
/// `roundhouse_provider::ContentBlock`, so it cannot live on
/// `roundhouse_core::TaskOutput` either (same dependency direction). §6.8:
/// every content block carries provenance, and MCP results are
/// unconditionally `Trust::Untrusted` — see `McpExecutor::decode_content`.
#[derive(Debug)]
pub enum TaskOutput {
    Mcp {
        content: Vec<(ContentBlock, Provenance)>,
        is_error: bool,
    },
}

#[derive(Debug, Clone)]
pub enum ResumptionInput {
    ElicitationAnswers {
        state: McpRetryState,
        answers: serde_json::Value,
    },
}

/// MRTR resume state (§10.1): everything a retry needs to re-issue the
/// ORIGINAL request carrying fresh elicitation answers. Defined here
/// (Task 8) rather than in Task 8b only because [`ResumptionInput`] cannot
/// compile without it — Task 8b's MRTR loop is what constructs and
/// consumes it. `Serialize`/`Deserialize` so a suspension survives a
/// daemon restart (§6.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRetryState {
    pub server: ServerId,
    pub tool: String, // original (non-namespaced) name
    pub args: serde_json::Value,
    pub request_state: crate::wire::RequestState,
    pub round: u8,
}

/// The outcome of one `TaskExecutor::execute` call, shaped to lift
/// directly into the frozen task-lifecycle events: `Failed`'s `TaskError`
/// and `Suspended`'s `SuspendReason` are the real `roundhouse-core` types
/// (so the engine can fold them into `TaskFailed`/`TaskSuspended` events
/// unchanged — this executor emits the `"policy_denied"`/"executor_error"
/// categories `roundhouse-core`'s `TaskError` doc comment names), and
/// `Completed`'s `usage` is the real `Usage` (all zero: a tool call runs
/// no inference). `Completed`'s `output` is the local [`TaskOutput`] — see
/// its reconciliation note.
#[derive(Debug)]
pub enum ExecutorOutcome {
    Completed { output: TaskOutput, usage: Usage },
    Failed { error: TaskError, retryable: bool },
    Suspended { reason: SuspendReason },
}

/// This crate's own task-execution seam. Named and shaped like what every
/// per-kind task executor across the phases will eventually need (§5.2's
/// "Task executors" crate row, §13.2's phase table), but nothing outside
/// `roundhouse-mcp` defines or mandates this trait today.
#[async_trait]
pub trait TaskExecutor: Send + Sync {
    async fn execute(
        &self,
        ctx: &TaskCtx,
        input: &TaskInput,
        resume: Option<ResumptionInput>,
    ) -> ExecutorOutcome;
}

/// This crate's seam onto the daemon's real task-lifecycle authority
/// (`roundhouse_core::TaskRunner`, Phase 0's S-LOG-1 mechanism).
/// `roundhouse-mcp` never touches `TaskRunner::record_*` directly: those
/// methods need a session's append-only `seq` counter and `schema_v`, both
/// store/engine-owned state this crate has no business holding. Instead it
/// asks for a task to be minted/recorded through this trait and is handed
/// back the resulting `TaskId` — the ONLY sanctioned way this crate
/// obtains a `TaskId` for a task it did not receive from its own caller
/// (S-LOG-1). The real production implementation (wrapping `TaskRunner`
/// plus the session's seq counter) is `roundhouse-engine`'s to build,
/// outside this crate's boundary, the same way this crate never implements
/// `Policy` either. Every task's tests implement `TaskSpawner` with an
/// in-process recording fake, the same pattern `FakeMcpTransport` (Task 5)
/// already establishes for `McpTransport`. Task 8 only exercises
/// `record_decision`; Task 8b's MRTR loop adds the `spawn_task`/
/// `suspend_task` callers.
#[async_trait]
pub trait TaskSpawner: Send + Sync {
    /// Creates and records a new task (a real `TaskCreated` event),
    /// returning the minted `TaskId`.
    async fn spawn_task(
        &self,
        session: SessionId,
        parent: Option<TaskId>,
        kind: TaskKind,
        origin: Origin,
        input: TaskInput,
    ) -> TaskId;

    /// Records a `TaskSuspended` event for an already-created task.
    async fn suspend_task(&self, task: TaskId, reason: SuspendReason);

    /// Records a `TaskDecided` event — the audit trail for finding 2's
    /// `Policy::decide` wiring (§6.2: every decision is logged, not just
    /// acted on).
    async fn record_decision(&self, task: TaskId, decision: PolicyDecision);
}

pub struct McpExecutor {
    connections: HashMap<String, Arc<dyn McpTransport>>,
    namespace: ToolNamespace,
    id_gens: HashMap<String, JsonRpcIdGen>,
    policy: Arc<dyn Policy>,
    task_spawner: Arc<dyn TaskSpawner>,
}

impl McpExecutor {
    /// finding 6: takes `Vec<(ServerId, _)>`, not `HashMap<ServerId, _>` —
    /// `ServerId` has no `Hash` (Phase 0's real derive list, confirmed
    /// against `roundhouse-policy`'s Task 6), so a `HashMap<ServerId, _>`
    /// cannot be built by ANY caller, not just internally. The `String`-
    /// keyed map this type actually dispatches through is built here.
    pub fn new(
        connections: Vec<(ServerId, Arc<dyn McpTransport>)>,
        namespace: ToolNamespace,
        policy: Arc<dyn Policy>,
        task_spawner: Arc<dyn TaskSpawner>,
    ) -> Self {
        let id_gens = connections
            .iter()
            .map(|(id, _)| (id.0.clone(), JsonRpcIdGen::default()))
            .collect();
        let connections = connections.into_iter().map(|(id, t)| (id.0, t)).collect();
        Self {
            connections,
            namespace,
            id_gens,
            policy,
            task_spawner,
        }
    }

    /// finding 2: the §6.2 policy gate every dispatch (initial call AND
    /// every MRTR retry, Task 8b) passes through before touching a
    /// transport. Returns `Ok(())` only on `PolicyDecision::Allow`.
    async fn gate(
        &self,
        ctx: &TaskCtx,
        server: &ServerId,
        tool: &str,
        args: &serde_json::Value,
    ) -> Result<(), ExecutorOutcome> {
        let params = TaskParams::Mcp {
            server: server.clone(),
            tool: tool.to_string(),
            args: args.clone(),
        };
        let decision = self.policy.decide(&PolicyInput {
            params: params.clone(),
            taint: ctx.taint,
        });
        self.task_spawner.record_decision(ctx.task, decision).await;
        match decision {
            PolicyDecision::Allow => Ok(()),
            PolicyDecision::Ask => Err(ExecutorOutcome::Suspended {
                // `PolicyDecision` carries no rule id (the verbatim §6.2
                // block: no payload on any variant), so the suspension
                // cannot name one.
                reason: SuspendReason::AwaitingApproval {
                    rule: None,
                    params_digest: params_digest(&params),
                },
            }),
            PolicyDecision::Deny => Err(ExecutorOutcome::Failed {
                error: TaskError {
                    message: format!(
                        "denied by policy: mcp tool '{tool}' on server '{}' is not permitted (§6.2 sealed floor — this covers MCP tools on unresolved servers)",
                        server.0
                    ),
                    category: "policy_denied".into(),
                },
                retryable: false,
            }),
        }
    }

    fn decode_content(
        blocks: Vec<McpContentBlock>,
        task: TaskId,
    ) -> Vec<(ContentBlock, Provenance)> {
        blocks
            .into_iter()
            .map(|b| {
                let block = match b {
                    McpContentBlock::Text { text } => ContentBlock::Text {
                        text,
                        cache: None,
                        citations: vec![],
                    },
                    // Reconciled 2026-08-28 against Phase 0's real `MediaSource`
                    // struct (see the comment above its assumed-shape
                    // declaration): base64-decode into real bytes rather than
                    // constructing a `Base64` enum variant that doesn't exist.
                    // A decode failure is data corruption from the server, not
                    // a policy or trust question — represented as empty `data`
                    // rather than panicking, so a malformed image still yields
                    // a (harmlessly empty) `ContentBlock` instead of crashing
                    // content decoding for the whole tool result.
                    McpContentBlock::Image {
                        media_type,
                        data_base64,
                    } => ContentBlock::Image {
                        source: MediaSource {
                            mime_type: media_type,
                            data: base64::engine::general_purpose::STANDARD
                                .decode(&data_base64)
                                .unwrap_or_default(),
                        },
                        cache: None,
                    },
                    // finding 5: resource TEXT belongs in `source` (it's
                    // content, not a label) and `media_type` is preserved
                    // instead of silently discarded. `title` gets the only
                    // human-readable thing the wire type actually carries
                    // (the URI) rather than the resource's own content.
                    McpContentBlock::Resource {
                        uri,
                        media_type,
                        text,
                    } => match text {
                        Some(text) => ContentBlock::Document {
                            source: MediaSource {
                                mime_type: media_type.unwrap_or_else(|| "text/plain".to_string()),
                                data: text.into_bytes(),
                            },
                            title: Some(uri),
                            cache: None,
                        },
                        // URI-only resource, no inline content to carry — see
                        // the comment above `MediaSource`'s declaration: Phase
                        // 0's real type has no bare-URL variant, so this is an
                        // empty-content Document whose `title` is the
                        // reference a model would `http`/`web`-fetch
                        // separately, not a Document with a URL "source".
                        None => ContentBlock::Document {
                            source: MediaSource {
                                mime_type: media_type
                                    .unwrap_or_else(|| "text/uri-list".to_string()),
                                data: Vec::new(),
                            },
                            title: Some(uri),
                            cache: None,
                        },
                    },
                };
                // §6.8: "MCP results AND tool descriptions" are untrusted,
                // unconditionally — there is no per-server trust override.
                (
                    block,
                    Provenance {
                        origin: Origin::System,
                        trust: Trust::Untrusted,
                        task,
                    },
                )
            })
            .collect()
    }
}

/// Mirrors `roundhouse-policy`'s (private) `approval::params_digest`: the
/// digest is over the `TaskParams`' `Debug` representation, so a grant
/// recorded against this executor's `AwaitingApproval` suspension can be
/// matched against one recorded by the policy engine's own approval flow.
/// If that helper is ever made public, this mirror should be replaced by a
/// call to it.
fn params_digest(params: &TaskParams) -> [u8; 32] {
    *blake3::hash(format!("{params:?}").as_bytes()).as_bytes()
}

#[async_trait]
impl TaskExecutor for McpExecutor {
    async fn execute(
        &self,
        ctx: &TaskCtx,
        input: &TaskInput,
        resume: Option<ResumptionInput>,
    ) -> ExecutorOutcome {
        let (server, tool, args) = match (input, resume) {
            (TaskInput::Mcp { server, tool, args }, None) => {
                (server.clone(), tool.clone(), args.clone())
            }
            _ => {
                return ExecutorOutcome::Failed {
                    error: TaskError {
                        message: "resume path not wired until Task 8b".into(),
                        category: "executor_error".into(),
                    },
                    retryable: false,
                }
            }
        };

        // finding 5: fail closed on an unresolvable namespaced name — never
        // forward an arbitrary string to the transport as if it were
        // already an original tool name.
        let original_tool = match self.namespace.resolve(&tool) {
            Some((_, original)) => original.to_string(),
            None => {
                return ExecutorOutcome::Failed {
                    error: TaskError {
                        message: format!(
                            "unknown namespaced tool '{tool}' — refusing to forward an unresolved name to the transport"
                        ),
                        category: "executor_error".into(),
                    },
                    retryable: false,
                }
            }
        };

        if let Err(outcome) = self.gate(ctx, &server, &original_tool, &args).await {
            return outcome;
        }

        let key = server.0.clone();
        let transport = match self.connections.get(&key) {
            Some(t) => t,
            None => {
                return ExecutorOutcome::Failed {
                    error: TaskError {
                        message: format!(
                            "no connection for server {:?} (policy allowed it, but it was never spawned)",
                            server.0
                        ),
                        category: "executor_error".into(),
                    },
                    retryable: false,
                }
            }
        };

        let jsonrpc_id = self
            .id_gens
            .get(&key)
            .map(|g| g.next())
            .unwrap_or(JsonRpcId(0));
        let result = transport
            .call_tool(ToolCallRequest {
                jsonrpc_id,
                tool: original_tool,
                args,
                request_state: None,
                input_responses: vec![],
            })
            .await;

        match result {
            Err(e) => ExecutorOutcome::Failed {
                error: TaskError {
                    message: e.to_string(),
                    category: "executor_error".into(),
                },
                retryable: true,
            },
            Ok(r) => match r.result_type {
                McpResultType::Ok => ExecutorOutcome::Completed {
                    output: TaskOutput::Mcp {
                        content: Self::decode_content(r.content, ctx.task),
                        is_error: r.is_error,
                    },
                    // All zero: a tool call runs no inference. The real core
                    // `Usage` has no `zero()`; `Default` is the same
                    // all-zero value.
                    usage: Usage::default(),
                },
                McpResultType::InputRequired { .. } => ExecutorOutcome::Failed {
                    error: TaskError {
                        message: "input_required not handled until Task 8b".into(),
                        category: "executor_error".into(),
                    },
                    retryable: false,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeMcpTransport, ScriptedResponse};
    use crate::wire::McpToolDef;
    use std::sync::Mutex;

    /// Test double for `Policy` (Phase 2's real sealed floor is not built
    /// yet — Phase 3 only needs to prove it calls `decide` and honors the
    /// result). Always returns a fixed decision, recording every input it
    /// was asked to judge so tests can assert the gate actually ran.
    struct FixedPolicy {
        decision: PolicyDecision,
        seen: Mutex<Vec<PolicyInput>>,
    }
    impl FixedPolicy {
        fn allow_all() -> Self {
            Self {
                decision: PolicyDecision::Allow,
                seen: Mutex::new(Vec::new()),
            }
        }
        fn deny_all() -> Self {
            Self {
                decision: PolicyDecision::Deny,
                seen: Mutex::new(Vec::new()),
            }
        }
    }
    impl Policy for FixedPolicy {
        fn decide(&self, input: &PolicyInput) -> PolicyDecision {
            self.seen.lock().unwrap().push(input.clone());
            self.decision
        }
    }

    /// Test double for `TaskSpawner`. Records every spawned/suspended/
    /// decided call so tests can assert the elicit-task-construction and
    /// audit-trail wiring (findings 3, 4, 2) actually happened.
    #[derive(Default)]
    struct RecordingTaskSpawner {
        created: Mutex<Vec<(TaskKind, TaskInput)>>,
        suspended: Mutex<Vec<(TaskId, SuspendReason)>>,
        decisions: Mutex<Vec<(TaskId, PolicyDecision)>>,
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
        async fn suspend_task(&self, task: TaskId, reason: SuspendReason) {
            self.suspended.lock().unwrap().push((task, reason));
        }
        async fn record_decision(&self, task: TaskId, decision: PolicyDecision) {
            self.decisions.lock().unwrap().push((task, decision));
        }
    }

    fn setup(
        script: Vec<ScriptedResponse>,
    ) -> (
        McpExecutor,
        Arc<FakeMcpTransport>,
        Arc<RecordingTaskSpawner>,
    ) {
        setup_with_policy(script, Arc::new(FixedPolicy::allow_all()))
    }

    fn setup_with_policy(
        script: Vec<ScriptedResponse>,
        policy: Arc<dyn Policy>,
    ) -> (
        McpExecutor,
        Arc<FakeMcpTransport>,
        Arc<RecordingTaskSpawner>,
    ) {
        let fake = Arc::new(FakeMcpTransport::new(
            vec![McpToolDef {
                name: "search".into(),
                description: "search things".into(),
                input_schema: serde_json::json!({}),
            }],
            script,
        ));
        let server = ServerId("github".into());
        let connections: Vec<(ServerId, Arc<dyn McpTransport>)> =
            vec![(server.clone(), fake.clone() as Arc<dyn McpTransport>)];

        let discovery_task = TaskId::new();
        let ns = ToolNamespace::build(&[(
            server,
            discovery_task,
            crate::wire::DiscoverResult {
                protocol_version: "2026-07-28".into(),
                tools: vec![McpToolDef {
                    name: "search".into(),
                    description: "search things".into(),
                    input_schema: serde_json::json!({}),
                }],
            },
        )])
        .unwrap();

        let task_spawner = Arc::new(RecordingTaskSpawner::default());
        (
            McpExecutor::new(connections, ns, policy, task_spawner.clone()),
            fake,
            task_spawner,
        )
    }

    fn ctx(task: TaskId) -> TaskCtx {
        TaskCtx {
            task,
            session: SessionId::new(),
            parent: None,
            taint: Taint::Tainted,
        }
    }

    #[tokio::test]
    async fn happy_path_decodes_content_with_untrusted_provenance() {
        let (executor, _fake, spawner) =
            setup(vec![ScriptedResponse::Ok(vec![McpContentBlock::Text {
                text: "result text".into(),
            }])]);

        let task_id = TaskId::new();
        let ctx = ctx(task_id);
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced,
            args: serde_json::json!({"q": "roundhouse"}),
        };

        let outcome = executor.execute(&ctx, &input, None).await;
        match outcome {
            ExecutorOutcome::Completed {
                output: TaskOutput::Mcp { content, is_error },
                usage,
            } => {
                assert!(!is_error);
                assert_eq!(content.len(), 1);
                let (block, provenance) = &content[0];
                assert!(matches!(block, ContentBlock::Text { text, .. } if text == "result text"));
                assert!(matches!(provenance.trust, Trust::Untrusted));
                assert_eq!(provenance.task, task_id);
                assert_eq!(usage.input_tokens, 0);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        // finding 2: the gate actually ran and was audited.
        assert_eq!(spawner.decisions.lock().unwrap().len(), 1);
        assert!(matches!(
            spawner.decisions.lock().unwrap()[0].1,
            PolicyDecision::Allow
        ));
    }

    #[tokio::test]
    async fn policy_deny_produces_an_audited_failure_not_a_transport_error() {
        // finding 2: an unresolved/disallowed server must be an audited
        // Deny, not whatever error the transport happens to raise.
        let (executor, _fake, spawner) =
            setup_with_policy(vec![], Arc::new(FixedPolicy::deny_all()));

        let task_id = TaskId::new();
        let ctx = ctx(task_id);
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced,
            args: serde_json::json!({}),
        };

        let outcome = executor.execute(&ctx, &input, None).await;
        match outcome {
            ExecutorOutcome::Failed { error, retryable } => {
                assert!(!retryable, "a policy denial must not be marked retryable");
                assert!(
                    error.message.contains("denied by policy"),
                    "message was: {}",
                    error.message
                );
                assert_eq!(error.category, "policy_denied");
            }
            other => panic!("expected an audited Failed(Deny), got {other:?}"),
        }
        assert!(matches!(
            spawner.decisions.lock().unwrap()[0].1,
            PolicyDecision::Deny
        ));
    }

    #[tokio::test]
    async fn unresolved_namespaced_tool_name_fails_closed_before_reaching_the_transport() {
        // finding 5: the old fallback treated an unresolvable name as if it
        // were already an original tool name and forwarded it anyway.
        let (executor, fake, _spawner) = setup(vec![]);
        let task_id = TaskId::new();
        let ctx = ctx(task_id);
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: "totally-made-up-tool-name".into(),
            args: serde_json::json!({}),
        };

        let outcome = executor.execute(&ctx, &input, None).await;
        assert!(matches!(
            outcome,
            ExecutorOutcome::Failed {
                retryable: false,
                ..
            }
        ));
        assert!(
            fake.calls.lock().unwrap().is_empty(),
            "the transport must never see an unresolved tool name"
        );
    }
}
