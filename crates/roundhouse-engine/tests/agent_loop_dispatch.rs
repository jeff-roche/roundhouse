//! Phase 7, Task 5's own integration suite: the three properties the spec's
//! tests exist to prove, per `.superpowers/sdd/W1/task-5-brief-v2.md`.
//!
//! Fixture setup mirrors Phase 2's `admission_integration.rs` exactly
//! (`Store::open`+`spawn_writer`, `PolicyEngine::from_rules`,
//! `BwrapLandlockIsolate::test_with_probe`, `SessionActor::new` directly —
//! there is no `SessionActor::spawn_test_with` helper anywhere in this
//! workspace, despite the lane file's stale sketch comment implying one).

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use futures::stream;
use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionSpec, SessionState, TaskKind, Tier,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig, AgentLoopError};
use roundhouse_engine::{tool_catalog, SessionActor};
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_policy::FsOp;
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ContentBlock,
    HttpRequest, HttpResponseStream, HttpTransport, ModelId, Params, Plan, Provider, ProviderError,
    ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent,
    TokenCount, ToolChoice, TransportError,
};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::Isolate;
use roundhouse_store::{open, session_events, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call per-process, and every
/// test in this binary shares one process — one shared `&'static TaskRunner`
/// for all tests here, matching `admission_integration.rs`/`chat_infer_tree.rs`.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

struct NoopTransport;
impl HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFut<'a, Result<HttpResponseStream, TransportError>> {
        unreachable!("scripted test providers never call the transport directly")
    }
}

fn fake_ctx() -> RequestCtx {
    RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: "test".into(),
        credentials: None,
    }
}

fn empty_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("test-model".into()),
        system: vec![],
        messages: vec![],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: std::collections::BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// A `BwrapLandlockIsolate` whose probe reports every mechanism `Available`
/// except Seatbelt (n/a off macOS) — achieves `Tier::Sandbox` deterministically,
/// hermetically, with no real bwrap/landlock syscalls made. Matches
/// `admission_integration.rs`'s identical helper.
fn available_isolate() -> BwrapLandlockIsolate {
    BwrapLandlockIsolate::test_with_probe(MechanismProbeReport {
        landlock: MechanismStatus::Available,
        bwrap: MechanismStatus::Available,
        seccomp: MechanismStatus::Available,
        seatbelt: MechanismStatus::Unavailable {
            reason: "n/a".into(),
        },
    })
}

/// Builds a real `SessionActor` over a fresh on-disk store. `config_rules`
/// are ordinary config-derived rules; the compiled-in sealed floor is
/// checked first regardless and cannot be overridden by them (see
/// `PolicyEngine::decide_sealed`'s own doc comment) — the denial test below
/// relies on exactly that ordering.
async fn new_actor(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    daemon_binary: std::path::PathBuf,
    config_rules: Vec<CompiledRule>,
) -> (
    SessionActor,
    roundhouse_store::EventWriter,
    std::path::PathBuf,
    SessionId,
) {
    let db_path = dir.join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let policy = Arc::new(PolicyEngine::from_rules(config_rules));
    let isolate: Arc<dyn Isolate> = Arc::new(available_isolate());
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let session_id = SessionId::new();

    let actor = SessionActor::new(
        session_id,
        writer.clone(),
        SessionState::Running,
        &RUNNER,
        policy,
        state_dir,
        daemon_binary,
        isolate,
        handle,
        spec,
        tool_catalog::builtin_tool_defs(),
    );

    (actor, writer, db_path, session_id)
}

/// A scripted `Provider`: on its first call returns one `ToolUse` block for
/// the given tool name/input; on every later call returns a final
/// text-only block — proving the loop actually re-invokes the provider with
/// the tool result folded back in, not just dispatching once.
struct ScriptedToolCallProvider {
    tool_name: String,
    tool_input: serde_json::Value,
    calls: AtomicU32,
    requests: Mutex<Vec<ChatRequest>>,
}

impl ScriptedToolCallProvider {
    fn new(tool_name: &str, tool_input: serde_json::Value) -> Self {
        ScriptedToolCallProvider {
            tool_name: tool_name.to_string(),
            tool_input,
            calls: AtomicU32::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ChatRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl Provider for ScriptedToolCallProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        self.requests.lock().unwrap().push(req.clone());
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let tool_name = self.tool_name.clone();
        let tool_args = self.tool_input.to_string();
        Box::pin(async move {
            let events = if call == 0 {
                vec![
                    StreamEvent::BlockStart {
                        index: 0,
                        kind: BlockKind::ToolUse {
                            name: tool_name,
                            provider_id: Some("call_0".to_string()),
                        },
                    },
                    StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::ToolArgsFragment(tool_args),
                    },
                    StreamEvent::BlockStop { index: 0 },
                    StreamEvent::MessageStop,
                ]
            } else {
                vec![
                    StreamEvent::BlockStart {
                        index: 0,
                        kind: BlockKind::Text,
                    },
                    StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::Text("done".to_string()),
                    },
                    StreamEvent::BlockStop { index: 0 },
                    StreamEvent::MessageStop,
                ]
            };
            Ok(ChatStream(Box::pin(stream::iter(events))))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

/// A scripted `Provider` that ALWAYS returns another `ToolUse` block —
/// never stops on its own — used to prove `max_turns` is a hard ceiling.
struct AlwaysToolUseProvider {
    tool_name: String,
    tool_input: serde_json::Value,
    calls: AtomicU32,
}

impl AlwaysToolUseProvider {
    fn new(tool_name: &str, tool_input: serde_json::Value) -> Self {
        AlwaysToolUseProvider {
            tool_name: tool_name.to_string(),
            tool_input,
            calls: AtomicU32::new(0),
        }
    }
}

impl Provider for AlwaysToolUseProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let tool_name = self.tool_name.clone();
        let tool_args = self.tool_input.to_string();
        Box::pin(async move {
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::ToolUse {
                        name: tool_name,
                        provider_id: Some(format!("call_{call}")),
                    },
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::ToolArgsFragment(tool_args),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::MessageStop,
            ];
            Ok(ChatStream(Box::pin(stream::iter(events))))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
}

#[tokio::test]
async fn a_model_issued_tool_use_is_admitted_dispatched_and_its_result_folded_back_into_the_next_turn(
) {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("fixture.txt");
    std::fs::write(&fixture, "hello from the fixture file").unwrap();

    let (actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::FsPrefix {
                op: FsOp::Read,
                prefix: dir.path().canonicalize().unwrap(),
            },
        )],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": fixture.to_string_lossy() }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &writer,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig { max_turns: 4 },
    )
    .await
    .unwrap();

    // The loop must have actually run the "read" executor (not just planned
    // to) — assert on a real side effect: a Read task exists in the event log.
    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                ..
            }
        )),
        "the model's ToolUse{{name: \"read\"}} must produce a real Read task, not a bypass"
    );

    assert!(
        matches!(blocks.last(), Some(ContentBlock::Text { .. })),
        "the loop must re-invoke the provider after the tool result and return its final text, \
         got {blocks:?}"
    );

    // Stronger than the spec's own floor: prove the tool result was actually
    // folded back into the SECOND call's request messages, not merely that
    // a second call happened.
    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        2,
        "the provider must be called exactly twice"
    );
    let second_request_has_tool_result = requests[1].messages.iter().any(|m| {
        m.content.iter().any(|b| {
            matches!(
                b,
                ContentBlock::ToolResult {
                    is_error: false,
                    ..
                }
            )
        })
    });
    assert!(
        second_request_has_tool_result,
        "the second provider call's messages must carry the first call's tool result"
    );
}

#[tokio::test]
async fn a_sealed_floor_denial_on_a_dispatched_tool_call_surfaces_as_a_tool_result_error_not_a_panic_or_silent_skip(
) {
    let dir = tempfile::tempdir().unwrap();
    // A real, canonicalizable state_dir — this exercises the actual compiled-in
    // `sealed:state-dir-write` rule (protecting the daemon's own event log from
    // being overwritten by the agent), rather than depending on the test
    // machine's real $HOME/.ssh existing (or, worse, creating files under it).
    let state_dir = dir.path().canonicalize().unwrap().join("state");
    std::fs::create_dir_all(&state_dir).unwrap();
    let malicious_target = state_dir.join("events.db");

    let (actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        state_dir,
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "write",
        serde_json::json!({
            "path": malicious_target.to_string_lossy(),
            "contents": "pwned",
        }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &writer,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig { max_turns: 4 },
    )
    .await
    .unwrap();

    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "a sealed-floor denial must reach the model as a real tool error, got {blocks:?}"
    );

    // The malicious write must never have actually happened.
    assert!(
        !malicious_target.exists(),
        "a denied write must never touch the filesystem"
    );

    // A denied call must still be a real, queryable attempt in the
    // append-only log — TaskCreated, then TaskFailed (mirroring
    // `McpExecutor::gate`'s mint-then-record-outcome precedent) — never a
    // silent non-event that leaves no trace of the model's attempt.
    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Write,
                ..
            }
        )),
        "a tool call denied at admission must still be recorded as a real, queryable TaskCreated"
    );
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed {
                retryable: false,
                ..
            }
        )),
        "a tool call denied at admission must be recorded TaskFailed, not left dangling"
    );
}

#[tokio::test]
async fn max_turns_is_a_hard_ceiling_against_a_provider_that_never_stops_calling_tools() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("fixture.txt");
    std::fs::write(&fixture, "content").unwrap();

    let (actor, writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::FsPrefix {
                op: FsOp::Read,
                prefix: dir.path().canonicalize().unwrap(),
            },
        )],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = AlwaysToolUseProvider::new(
        "read",
        serde_json::json!({ "path": fixture.to_string_lossy() }),
    );
    let ctx = fake_ctx();

    let result = run_agent_loop(
        &actor,
        &writer,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig { max_turns: 3 },
    )
    .await;

    assert!(
        matches!(result, Err(AgentLoopError::MaxTurnsExceeded(3))),
        "a provider that never stops calling tools must hit the hard ceiling, got {result:?}"
    );
}
