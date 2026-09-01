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
    /// finding 3 (Task 8b): the input of the REAL `elicit`-kind child task
    /// an `input_required` MCP result is normalised into — the thing that
    /// makes every elicitation enumerable via the same query path as any
    /// other suspended task (S-OBS-4). `schema`/`question` carry what the
    /// server asked for; `mcp_resume_context` carries the opaque serialized
    /// [`McpRetryState`] the parent `mcp` task needs in order to resume.
    /// The engine's job (outside this crate) is to read that context back
    /// off the completed elicit task's own `TaskInput` and hand it to
    /// `execute` again as `ResumptionInput::ElicitationAnswers` — exactly
    /// how MCP's own opaque `requestState` round-trips (§10.1). `None`
    /// there means a plain non-MCP elicitation with nothing to resume.
    Elicit {
        schema: Option<serde_json::Value>,
        question: Option<String>,
        mcp_resume_context: Option<serde_json::Value>,
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

/// The MRTR retry loop's hard bound (§10.1). §7.7 bounds every other
/// retry/relay loop in the design with a hop-style counter — `ttl_hops`
/// defaults to 8 for inter-agent message relaying, where each hop is a
/// cheap, fully-automated forward with no human in the loop. MRTR's loop is
/// structurally the same shape (bounded retries around a request, refuse
/// rather than loop forever), but each round blocks on a *synchronous human
/// response* — an `elicit` task — so a round costs minutes of a person's
/// attention, not a network hop. Five rounds keeps the same "bounded, not
/// infinite" guarantee while sizing the bound to that cost profile: enough
/// for a realistic multi-step elicitation ("pick an account" → "confirm
/// scope" → "enter a one-time code"), small enough that a bugged or
/// malicious server cannot demand input indefinitely. Exceeding the cap
/// fails the task loudly (non-retryable `Failed`) rather than silently
/// dropping the loop — §6's "fail-open is the actual bug".
pub const MRTR_ROUND_CAP: u8 = 5;

/// finding 6: an elicitation answers payload that isn't a non-empty JSON
/// object of `{id: value}` pairs is a rejected, structured error surfaced
/// as an audited non-retryable `Failed` — never a silently-empty
/// `Vec<InputResponse>` sent on to the transport as a no-answer retry.
#[derive(Debug, thiserror::Error)]
#[error("elicitation answer was not a non-empty JSON object of {{id: value}} pairs: {0}")]
pub struct MalformedAnswerError(String);

/// finding 6: `flatten_answers` fails CLOSED on anything that isn't a
/// non-empty JSON object of `{id: value}` pairs, instead of silently
/// returning an empty `Vec<InputResponse>`.
fn flatten_answers(
    answers: &serde_json::Value,
) -> Result<Vec<crate::wire::InputResponse>, MalformedAnswerError> {
    match answers.as_object() {
        Some(map) if !map.is_empty() => Ok(map
            .iter()
            .map(|(k, v)| crate::wire::InputResponse {
                id: k.clone(),
                value: v.clone(),
            })
            .collect()),
        Some(_) => Err(MalformedAnswerError("answers object was empty".into())),
        None => Err(MalformedAnswerError(format!(
            "expected a JSON object, got: {answers}"
        ))),
    }
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
/// `suspend_task` callers; Task 11's `McpHost::start` adds the
/// `record_terminal` caller — the discovery task it mints through
/// `spawn_task` gets exactly one terminal record the moment discovery
/// resolves, so a minted task is never left permanently in-flight
/// (S-LOG-1: a task record exists only as a complete lifecycle).
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

    /// Records the terminal `TaskCompleted`/`TaskFailed` event for a task
    /// previously minted by [`TaskSpawner::spawn_task`]. Every minted task
    /// gets exactly one terminal record — S-LOG-1's lifecycle rule means a
    /// task creation is never left dangling without its terminal event.
    ///
    /// Reconciliation (same rule as the methods above): the real core
    /// calls (`TaskRunner::record_task_completed`/
    /// `record_task_failed`) additionally need a session id, the
    /// append-only `seq`, a timestamp, and `schema_v` — store/engine-owned
    /// state this crate has no business holding — so this seam carries
    /// only the task id and the terminal payload ([`TerminalOutcome`]),
    /// which the engine implementation maps 1:1 onto those two calls.
    async fn record_terminal(&self, task: TaskId, outcome: TerminalOutcome);
}

/// The terminal outcome of a task, shaped to lift 1:1 onto the real core
/// task-lifecycle events: `Completed` carries exactly what
/// `roundhouse_core::TaskRunner::record_task_completed` folds into a
/// `TaskCompleted` event (a core [`roundhouse_core::TaskOutput`] plus
/// [`Usage`]), `Failed` exactly what `record_task_failed` folds into a
/// `TaskFailed` event (a [`TaskError`] plus its `retryable` flag).
/// (Core's `TaskOutput` is referenced by its full path here — this
/// module's own `TaskOutput` above is the executor's MCP result shape,
/// not the event-payload shape.)
#[derive(Debug, Clone)]
pub enum TerminalOutcome {
    Completed {
        output: roundhouse_core::TaskOutput,
        usage: Usage,
    },
    Failed {
        error: TaskError,
        retryable: bool,
    },
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

    /// Test/integration convenience: look up the namespaced name for a
    /// known original tool name. Production callers already have the
    /// namespaced name from whatever presented the tool list to the model.
    pub fn namespace_tool_name(&self, original_name: &str) -> Option<String> {
        self.namespace
            .tools()
            .iter()
            .find(|t| t.original_name == original_name)
            .map(|t| t.namespaced_name.clone())
    }

    /// Shut down every server connection (Phase 3 review fix: this is the
    /// only production path that reaches `McpTransport::shutdown` — the
    /// executor owns the last `Arc`s, and without a `&self` teardown
    /// reachable through them every MCP child process was orphaned at
    /// daemon shutdown). Best-effort with a loud tail: EVERY connection is
    /// attempted even if one fails to confirm down (one wedged server must
    /// not keep the others' processes alive), and the first error is
    /// returned so a partial teardown is reported, not laundered into
    /// `Ok(())`. `McpHost::shutdown` delegates here; the daemon boot wiring
    /// is a separately-tracked Phase 3 gap (see the KNOWN GAP note in
    /// `host.rs`).
    pub async fn shutdown(&self) -> Result<(), crate::wire::McpError> {
        let mut first_err = None;
        for (server, transport) in &self.connections {
            if let Err(e) = transport.shutdown().await {
                tracing::warn!(
                    server,
                    error = %e,
                    "MCP transport shutdown could not be confirmed"
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
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
    /// One code path per case: `(Mcp, None)` is the initial dispatch,
    /// `(anything, Some(ElicitationAnswers))` is the MRTR retry, and every
    /// other combination fails closed. Both live paths pass the §6.2 policy
    /// gate (finding 2: every dispatch passes policy, not just the first).
    async fn execute(
        &self,
        ctx: &TaskCtx,
        input: &TaskInput,
        resume: Option<ResumptionInput>,
    ) -> ExecutorOutcome {
        match (input, resume) {
            (TaskInput::Mcp { server, tool, args }, None) => {
                // finding 5: fail closed on an unresolvable namespaced name —
                // never forward an arbitrary string to the transport as if it
                // were already an original tool name.
                let original_tool = match self.namespace.resolve(tool) {
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
                if let Err(outcome) = self.gate(ctx, server, &original_tool, args).await {
                    return outcome;
                }
                // The initial dispatch is round 0; an `input_required` answer
                // suspends the task at round 1. Neither the server's
                // `request_state` nor any elicitation answers exist yet.
                self.dispatch(
                    ctx,
                    server.clone(),
                    original_tool,
                    args.clone(),
                    None,
                    vec![],
                    0,
                )
                .await
            }
            (_, Some(ResumptionInput::ElicitationAnswers { state, answers })) => {
                // The MRTR loop is bounded: a state already at the cap is
                // refused before anything else runs.
                if state.round >= MRTR_ROUND_CAP {
                    return ExecutorOutcome::Failed {
                        error: TaskError {
                            message: format!("MRTR round cap ({MRTR_ROUND_CAP}) exceeded"),
                            category: "executor_error".into(),
                        },
                        retryable: false,
                    };
                }
                // finding 6: reject a malformed answer instead of silently
                // treating it as "no answers."
                let input_responses = match flatten_answers(&answers) {
                    Ok(v) => v,
                    Err(e) => {
                        return ExecutorOutcome::Failed {
                            error: TaskError {
                                message: format!("rejected malformed elicitation answer: {e}"),
                                category: "executor_error".into(),
                            },
                            retryable: false,
                        }
                    }
                };
                // finding 2: gate the retry too — every dispatch passes
                // policy, not just the first one.
                if let Err(outcome) = self
                    .gate(ctx, &state.server, &state.tool, &state.args)
                    .await
                {
                    return outcome;
                }
                // MRTR retries the ORIGINAL request; the fresh answers ride
                // along as input_responses (see `ToolCallRequest`), the
                // original tool/args/server are unchanged from the first
                // call. `state.tool` is already the original (non-namespaced)
                // name — it was resolved before the first dispatch and stored.
                self.dispatch(
                    ctx,
                    state.server,
                    state.tool,
                    state.args,
                    Some(state.request_state),
                    input_responses,
                    state.round,
                )
                .await
            }
            _ => ExecutorOutcome::Failed {
                error: TaskError {
                    message: "unsupported (input, resume) combination".into(),
                    category: "executor_error".into(),
                },
                retryable: false,
            },
        }
    }
}

impl McpExecutor {
    /// THE one request/result path — both `execute` arms are it, differing
    /// only in the request payload. Looks up the connection for `server`,
    /// mints a fresh per-connection jsonrpc id (§10.1: a NEW id per call,
    /// MRTR retries included), issues the `tools/call`, and folds the
    /// transport result into an outcome: decode → `Completed` with
    /// untrusted provenance and all-zero `Usage`; transport error →
    /// retryable `Failed`; `InputRequired` →
    /// [`Self::suspend_for_elicitation`] at `round + 1` — the MRTR loop's
    /// only way forward.
    ///
    /// The initial dispatch passes `request_state: None`,
    /// `input_responses: vec![]`, `round: 0`. The MRTR retry (the
    /// `ResumptionInput::ElicitationAnswers` arm) re-issues the ORIGINAL
    /// request — same server/tool/args, `tool` already the original
    /// (non-namespaced) name — with the server's opaque `request_state`
    /// echoed verbatim and the fresh elicitation answers riding along as
    /// `input_responses` (§10.1).
    async fn dispatch(
        &self,
        ctx: &TaskCtx,
        server: ServerId,
        tool: String,
        args: serde_json::Value,
        request_state: Option<crate::wire::RequestState>,
        input_responses: Vec<crate::wire::InputResponse>,
        round: u8,
    ) -> ExecutorOutcome {
        let key = server.0.clone();
        let transport = match self.connections.get(&key) {
            Some(t) => t,
            None => {
                return ExecutorOutcome::Failed {
                    error: TaskError {
                        // `connections` is built once in `new` and never
                        // mutated, so a missing key always means the server
                        // was never spawned — accurate on the initial path
                        // and on a (practically unreachable) retry alike.
                        message: format!(
                            "no connection for server {:?} (policy allowed it, but it was never spawned)",
                            server.0
                        ),
                        category: "executor_error".into(),
                    },
                    retryable: false,
                };
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
                tool: tool.clone(),
                args: args.clone(),
                request_state,
                input_responses,
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
                McpResultType::InputRequired {
                    input_requests,
                    request_state,
                } => {
                    self.suspend_for_elicitation(
                        ctx,
                        server,
                        tool,
                        args,
                        input_requests,
                        request_state,
                        round + 1,
                    )
                    .await
                }
            },
        }
    }

    /// finding 3: normalises an MRTR `input_required` result into a REAL
    /// `elicit`-kind child task (never a bespoke payload riding on
    /// `SuspendReason`, which has no room for one — see the reconciliation
    /// note on [`TaskInput`]: the real Phase 0 variant carries only a
    /// `schema`), then suspends the PARENT `mcp` task on the real
    /// `SuspendReason::AwaitingElicitation`. This is what makes the
    /// elicitation enumerable via the same query path as any other
    /// suspended task (S-OBS-4). The opaque [`McpRetryState`] the parent
    /// needs to resume rides on the child task's `TaskInput::Elicit`
    /// `mcp_resume_context` — the engine reads it back off the completed
    /// elicit task and passes it in as `ResumptionInput::ElicitationAnswers`
    /// (§10.1, exactly how MCP's own opaque `requestState` round-trips).
    async fn suspend_for_elicitation(
        &self,
        ctx: &TaskCtx,
        server: ServerId,
        tool: String,
        args: serde_json::Value,
        input_requests: Vec<crate::wire::InputRequest>,
        request_state: crate::wire::RequestState,
        round: u8,
    ) -> ExecutorOutcome {
        // Belt-and-braces bound (the resume path checks `state.round >= cap`
        // before ever getting here): refuse rather than suspend past the cap.
        if round > MRTR_ROUND_CAP {
            return ExecutorOutcome::Failed {
                error: TaskError {
                    message: format!("MRTR round cap ({MRTR_ROUND_CAP}) exceeded"),
                    category: "executor_error".into(),
                },
                retryable: false,
            };
        }
        let resume_state = McpRetryState {
            server,
            tool,
            args,
            request_state,
            round,
        };
        let question = input_requests
            .iter()
            .map(|r| r.prompt.clone())
            .collect::<Vec<_>>()
            .join("; ");
        let schema = input_requests.iter().find_map(|r| r.schema.clone());
        let elicit_input = TaskInput::Elicit {
            schema: schema.clone(),
            question: Some(question),
            mcp_resume_context: Some(
                serde_json::to_value(&resume_state).expect("McpRetryState always serializes"),
            ),
        };

        self.task_spawner
            .spawn_task(
                ctx.session,
                Some(ctx.task),
                TaskKind::Elicit,
                Origin::System,
                elicit_input,
            )
            .await;
        // The real Phase 0 `SuspendReason::AwaitingElicitation` carries the
        // elicit JSON schema (§8). When the server supplied none, the
        // unconstrained empty schema `{}` is recorded — `Value::Null` would
        // fabricate a distinguishable "no schema" marker the variant has no
        // way to represent, and an empty object is the JSON-Schema-idiomatic
        // "anything allowed".
        let reason = SuspendReason::AwaitingElicitation {
            schema: schema.unwrap_or(serde_json::json!({})),
        };
        self.task_spawner
            .suspend_task(ctx.task, reason.clone())
            .await;

        ExecutorOutcome::Suspended { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{FakeMcpTransport, ScriptedResponse};
    use crate::wire::{InputRequest, McpToolDef, RequestState};
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
    /// decided/terminal call so tests can assert the elicit-task-
    /// construction and audit-trail wiring (findings 3, 4, 2) actually
    /// happened.
    #[derive(Default)]
    struct RecordingTaskSpawner {
        created: Mutex<Vec<(TaskKind, TaskInput)>>,
        suspended: Mutex<Vec<(TaskId, SuspendReason)>>,
        decisions: Mutex<Vec<(TaskId, PolicyDecision)>>,
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
            self.created.lock().unwrap().push((kind, input));
            TaskId::new()
        }
        async fn suspend_task(&self, task: TaskId, reason: SuspendReason) {
            self.suspended.lock().unwrap().push((task, reason));
        }
        async fn record_decision(&self, task: TaskId, decision: PolicyDecision) {
            self.decisions.lock().unwrap().push((task, decision));
        }
        async fn record_terminal(&self, task: TaskId, outcome: TerminalOutcome) {
            self.terminal.lock().unwrap().push((task, outcome));
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
        // The executor itself never records terminal state: it RETURNS
        // `ExecutorOutcome` and the ENGINE folds that into the
        // `TaskCompleted`/`TaskFailed` events. The one `record_terminal`
        // caller inside this crate is `McpHost::start`'s discovery task
        // (Task 11) — a dispatch-driven task's terminal record is not the
        // executor's to write.
        assert!(
            spawner.terminal.lock().unwrap().is_empty(),
            "the executor must not record terminal state for dispatched tasks"
        );
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

    #[tokio::test]
    async fn input_required_constructs_a_real_elicit_task_and_suspends_the_parent() {
        let (executor, fake, spawner) = setup(vec![ScriptedResponse::InputRequired {
            input_requests: vec![InputRequest {
                id: "acct".into(),
                prompt: "which account?".into(),
                schema: None,
            }],
            request_state: RequestState("opaque-blob-1".into()),
        }]);

        let task_id = TaskId::new();
        let ctx = ctx(task_id);
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced,
            args: serde_json::json!({}),
        };

        let outcome = executor.execute(&ctx, &input, None).await;
        assert!(
            matches!(
                outcome,
                ExecutorOutcome::Suspended {
                    reason: SuspendReason::AwaitingElicitation { .. }
                }
            ),
            "expected the parent `mcp` task suspended on AwaitingElicitation, got {outcome:?}"
        );
        assert_eq!(fake.calls.lock().unwrap().len(), 1);

        // finding 3: a REAL elicit-kind child task was constructed, not just
        // an in-memory suspension with nowhere to enumerate it (S-OBS-4).
        // Guards are scoped (not `drop`ped) so no MutexGuard is even in
        // scope across the awaits below.
        let resume_state = {
            let created = spawner.created.lock().unwrap();
            assert_eq!(created.len(), 1);
            assert!(matches!(created[0].0, TaskKind::Elicit));
            let resume_state = match &created[0].1 {
                TaskInput::Elicit {
                    schema: _,
                    question,
                    mcp_resume_context,
                } => {
                    assert!(question.as_deref().unwrap().contains("which account?"));
                    let ctx_val = mcp_resume_context
                        .clone()
                        .expect("resume context must be attached");
                    serde_json::from_value::<McpRetryState>(ctx_val)
                        .expect("resume context must deserialize back into McpRetryState")
                }
                other => panic!("expected TaskInput::Elicit, got {other:?}"),
            };
            assert_eq!(resume_state.round, 1);
            assert_eq!(
                resume_state.request_state,
                RequestState("opaque-blob-1".into())
            );
            resume_state
        };

        // finding 3: the PARENT task is the one suspended, via TaskSpawner.
        {
            let suspended = spawner.suspended.lock().unwrap();
            assert_eq!(suspended.len(), 1);
            assert_eq!(suspended[0].0, task_id);
            assert!(matches!(
                suspended[0].1,
                SuspendReason::AwaitingElicitation { .. }
            ));
        }

        // Human answers the elicit task; the engine calls execute() again on
        // the PARENT with the resume payload it read back off the elicit
        // task's own TaskInput.
        let outcome2 = executor
            .execute(
                &ctx,
                &input,
                Some(ResumptionInput::ElicitationAnswers {
                    state: resume_state,
                    answers: serde_json::json!({"acct": "personal"}),
                }),
            )
            .await;
        // setup()'s script only had one scripted response, so the retry hits
        // "script exhausted" — proving the retry actually re-invoked
        // call_tool with a NEW jsonrpc id and the echoed request_state,
        // which is exactly what this test exists to check.
        assert!(matches!(
            outcome2,
            ExecutorOutcome::Failed {
                retryable: true,
                ..
            }
        ));
        // The fake records every call, so the §10.1 MRTR requirements the
        // comment above claims are asserted directly: the retry is a SECOND
        // transport call, carrying a NEW jsonrpc id and the ORIGINAL
        // request_state echoed verbatim.
        {
            let calls = fake.calls.lock().unwrap();
            assert_eq!(calls.len(), 2, "the retry must re-invoke call_tool");
            assert_ne!(
                calls[1].jsonrpc_id, calls[0].jsonrpc_id,
                "MRTR: a NEW id per retry (§10.1)"
            );
            assert_eq!(
                calls[1].request_state,
                Some(RequestState("opaque-blob-1".into())),
                "MRTR: the server's request_state echoed verbatim on retry (§10.1)"
            );
            assert_eq!(
                calls[1].tool, "search",
                "MRTR retries the ORIGINAL (non-namespaced) request"
            );
            assert_eq!(calls[1].input_responses.len(), 1);
            assert_eq!(calls[1].input_responses[0].id, "acct");
        }
        // finding 2: the retry passed the policy gate too (initial Allow +
        // retry Allow = two audited decisions).
        assert_eq!(
            spawner.decisions.lock().unwrap().len(),
            2,
            "finding 2: every dispatch passes policy, retries included"
        );
    }

    #[tokio::test]
    async fn round_cap_fails_loudly_instead_of_looping_forever() {
        let script = (0..10)
            .map(|_| ScriptedResponse::InputRequired {
                input_requests: vec![InputRequest {
                    id: "x".into(),
                    prompt: "again?".into(),
                    schema: None,
                }],
                request_state: RequestState("blob".into()),
            })
            .collect();
        let (executor, _fake, spawner) = setup(script);

        let ctx = ctx(TaskId::new());
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced.clone(),
            args: serde_json::json!({}),
        };

        let mut outcome = executor.execute(&ctx, &input, None).await;
        for round in 1..=super::MRTR_ROUND_CAP {
            let state = if matches!(outcome, ExecutorOutcome::Suspended { .. }) {
                let ctx_val = spawner.created.lock().unwrap().last().unwrap().1.clone();
                match ctx_val {
                    TaskInput::Elicit {
                        mcp_resume_context: Some(v),
                        ..
                    } => serde_json::from_value::<McpRetryState>(v).unwrap(),
                    other => panic!(
                        "round {round}: expected TaskInput::Elicit with a resume context, got {other:?}"
                    ),
                }
            } else if round == super::MRTR_ROUND_CAP {
                assert!(matches!(outcome, ExecutorOutcome::Failed { .. }));
                break;
            } else {
                panic!("round {round}: expected Suspended, got {outcome:?}");
            };
            outcome = executor
                .execute(
                    &ctx,
                    &input,
                    Some(ResumptionInput::ElicitationAnswers {
                        state,
                        answers: serde_json::json!({"x": "ok"}),
                    }),
                )
                .await;
        }

        assert!(
            matches!(
                outcome,
                ExecutorOutcome::Failed {
                    retryable: false,
                    ..
                }
            ),
            "expected a hard failure once MRTR_ROUND_CAP is exceeded, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn malformed_elicitation_answer_is_rejected_not_silently_dropped() {
        // finding 6: `flatten_answers` used to return an empty Vec for any
        // non-object answers payload — a silent fail-open. It must now fail
        // closed with a structured, audited error instead.
        let (executor, fake, _spawner) = setup(vec![ScriptedResponse::InputRequired {
            input_requests: vec![InputRequest {
                id: "acct".into(),
                prompt: "which account?".into(),
                schema: None,
            }],
            request_state: RequestState("opaque-blob-1".into()),
        }]);
        let ctx = ctx(TaskId::new());
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced,
            args: serde_json::json!({}),
        };

        let outcome = executor.execute(&ctx, &input, None).await;
        let state = McpRetryState {
            server: ServerId("github".into()),
            tool: "search".into(),
            args: serde_json::json!({}),
            request_state: RequestState("opaque-blob-1".into()),
            round: 1,
        };
        let _ = outcome; // only used to drive the transport once above

        let malformed = executor
            .execute(
                &ctx,
                &input,
                Some(ResumptionInput::ElicitationAnswers {
                    state: state.clone(),
                    answers: serde_json::json!("not an object"),
                }),
            )
            .await;
        match malformed {
            ExecutorOutcome::Failed { error, retryable } => {
                assert!(
                    !retryable,
                    "a malformed answer must be rejected, not silently treated as empty"
                );
                assert!(
                    error
                        .message
                        .contains("rejected malformed elicitation answer"),
                    "message was: {}",
                    error.message
                );
            }
            other => panic!("expected a hard rejection, got {other:?}"),
        }
        // Only the ONE call from the initial dispatch above — the malformed
        // retry must never reach the transport at all.
        assert_eq!(fake.calls.lock().unwrap().len(), 1);

        // The strict half of the same rule: an EMPTY answers object is also
        // rejected, never flattened into a silent no-answer retry.
        let empty = executor
            .execute(
                &ctx,
                &input,
                Some(ResumptionInput::ElicitationAnswers {
                    state,
                    answers: serde_json::json!({}),
                }),
            )
            .await;
        assert!(
            matches!(
                empty,
                ExecutorOutcome::Failed {
                    retryable: false,
                    ..
                }
            ),
            "an empty answers object must also be rejected, got {empty:?}"
        );
        assert_eq!(
            fake.calls.lock().unwrap().len(),
            1,
            "neither malformed retry may reach the transport"
        );
    }

    #[tokio::test]
    async fn retry_repasses_policy_gate_so_a_denied_retry_never_reaches_the_transport() {
        // finding 2: every dispatch passes policy — the FIRST call went out
        // under an allowing policy, but by the time the human answers the
        // elicit task, the policy denies. The retry must be refused by the
        // gate itself, never forwarded to the transport.
        let (executor, fake, spawner) =
            setup_with_policy(vec![], Arc::new(FixedPolicy::deny_all()));
        let ctx = ctx(TaskId::new());
        let namespaced = executor.namespace.tools()[0].namespaced_name.clone();
        let input = TaskInput::Mcp {
            server: ServerId("github".into()),
            tool: namespaced,
            args: serde_json::json!({}),
        };

        // The engine would hand back the McpRetryState it read off the
        // completed elicit task; here it is hand-constructed with the same
        // fields the executor would have serialized.
        let state = McpRetryState {
            server: ServerId("github".into()),
            tool: "search".into(),
            args: serde_json::json!({}),
            request_state: RequestState("opaque-blob-1".into()),
            round: 1,
        };
        let outcome = executor
            .execute(
                &ctx,
                &input,
                Some(ResumptionInput::ElicitationAnswers {
                    state,
                    answers: serde_json::json!({"acct": "personal"}),
                }),
            )
            .await;
        match outcome {
            ExecutorOutcome::Failed { error, retryable } => {
                assert!(!retryable);
                assert!(
                    error.message.contains("denied by policy"),
                    "message was: {}",
                    error.message
                );
                assert_eq!(error.category, "policy_denied");
            }
            other => panic!("expected the gate to refuse the retry, got {other:?}"),
        }
        assert!(
            fake.calls.lock().unwrap().is_empty(),
            "a denied retry must never reach the transport"
        );
        assert_eq!(
            spawner.decisions.lock().unwrap().len(),
            1,
            "the retry's gate decision must be audited"
        );
    }

    #[tokio::test]
    async fn executor_shutdown_reaches_every_connection() {
        // Phase 3 review fix (Critical): `shutdown()` must be reachable
        // through the executor's `Arc<dyn McpTransport>` map — the only
        // production holder of live transports — and it must attempt ALL
        // of them, not stop at the first.
        let fake_a = Arc::new(FakeMcpTransport::new(
            vec![McpToolDef {
                name: "search".into(),
                description: "search things".into(),
                input_schema: serde_json::json!({}),
            }],
            vec![],
        ));
        let fake_b = Arc::new(FakeMcpTransport::new(
            vec![McpToolDef {
                name: "search".into(),
                description: "search other things".into(),
                input_schema: serde_json::json!({}),
            }],
            vec![],
        ));
        let server_a = ServerId("github".into());
        let server_b = ServerId("gitlab".into());
        let connections: Vec<(ServerId, Arc<dyn McpTransport>)> = vec![
            (server_a.clone(), fake_a.clone() as Arc<dyn McpTransport>),
            (server_b.clone(), fake_b.clone() as Arc<dyn McpTransport>),
        ];
        let disc = |name: &str| crate::wire::DiscoverResult {
            protocol_version: "2026-07-28".into(),
            tools: vec![McpToolDef {
                name: "search".into(),
                description: name.into(),
                input_schema: serde_json::json!({}),
            }],
        };
        let ns = ToolNamespace::build(&[
            (server_a, TaskId::new(), disc("search things")),
            (server_b, TaskId::new(), disc("search other things")),
        ])
        .unwrap();
        let executor = McpExecutor::new(
            connections,
            ns,
            Arc::new(FixedPolicy::allow_all()),
            Arc::new(RecordingTaskSpawner::default()),
        );

        executor.shutdown().await.unwrap();
        assert_eq!(
            fake_a.shutdowns.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            fake_b.shutdowns.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
}
