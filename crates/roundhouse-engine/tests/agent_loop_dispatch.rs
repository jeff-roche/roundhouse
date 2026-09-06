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
    EventPayload, OnDegrade, SessionId, SessionSpec, SessionState, TaskId, TaskKind, Tier,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig, AgentLoopError};
use roundhouse_engine::mcp_spawner::{EngineTaskSpawner, SessionMcp};
use roundhouse_engine::{tool_catalog, SessionActor};
use roundhouse_mcp::executor::TaskSpawner as McpTaskSpawner;
use roundhouse_mcp::namespace::ToolNamespace;
use roundhouse_mcp::transport::McpTransport;
use roundhouse_mcp::wire::{
    DiscoverResult, InputRequest, McpContentBlock, McpError, McpResult, McpResultType, McpToolDef,
    RequestState, ToolCallRequest,
};
use roundhouse_policy::engine::{
    ArgMatcher, CompiledRule, Outcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::{FsOp, ServerId};
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
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    let policy = Arc::new(PolicyEngine::from_rules(config_rules));
    new_actor_with_engine(dir, state_dir, daemon_binary, policy).await
}

/// `new_actor`, but over a caller-supplied `PolicyEngine` (fix round D).
/// Every MCP test now shares ONE engine between the `SessionActor` and the
/// `SessionMcp`, which is both what Task 7's production wiring will do and
/// the only way to write a test where `admit_task` and `McpExecutor::gate`
/// are known to be judging against the same rules.
async fn new_actor_with_engine(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    daemon_binary: std::path::PathBuf,
    policy: Arc<PolicyEngine>,
) -> (
    SessionActor,
    roundhouse_store::EventWriter,
    std::path::PathBuf,
    SessionId,
) {
    let db_path = dir.join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

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

    let (actor, _writer, db_path, session_id) = new_actor(
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
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
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
async fn an_admitted_executor_failure_does_not_disclose_its_host_path_to_the_model() {
    let dir = tempfile::tempdir().unwrap();
    let failing_path = dir.path().join("a-directory-read-as-a-file");
    std::fs::create_dir(&failing_path).unwrap();
    let (actor, _writer, _db, _session) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon"),
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
    let provider = ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": failing_path.to_string_lossy() }),
    );
    run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &fake_ctx(),
        actor.tool_defs(),
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 2,
            max_tool_calls_per_turn: 1,
        },
    )
    .await
    .unwrap();
    let rendered = provider.requests()[1]
        .messages
        .iter()
        .flat_map(|message| message.content.iter())
        .filter_map(|block| match block {
            ContentBlock::ToolResult { content, .. } => Some(
                content
                    .iter()
                    .map(|part| part.text.as_str())
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect::<String>();
    assert!(rendered.contains("tool execution failed"));
    assert!(!rendered.contains(&failing_path.to_string_lossy().to_string()));
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

    let (actor, _writer, db_path, session_id) = new_actor(
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
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
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

    let (actor, _writer, _db_path, _session_id) = new_actor(
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
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 3,
            max_tool_calls_per_turn: 10,
        },
    )
    .await;

    assert!(
        matches!(result, Err(AgentLoopError::MaxTurnsExceeded(3))),
        "a provider that never stops calling tools must hit the hard ceiling, got {result:?}"
    );
}

/// Fix round A, MUST item 3: the highest-consequence built-in (`shell`) had
/// zero coverage through the real dispatch path — `tool_dispatch.rs`'s own
/// `execute_builtin_shell_*` tests all call `execute_builtin` directly,
/// bypassing `admit_task` entirely, and every `agent_loop_dispatch.rs` test
/// above uses `FsPrefix{Read}`. These two tests drive a model `ToolUse{name:
/// "shell"}` through `run_agent_loop` -> `admit_task` -> the real
/// `spawn_cancellable`-based executor, for both an allowed and a denied
/// case.
///
/// The workspace-root-contained fixture (a real, executable script inside a
/// tempdir under this test binary's own `std::env::current_dir()`) exists
/// because fix round A's `resolve_shell_cwd`/`resolve_shell_program`
/// (`tool_dispatch.rs`) require a shell dispatch's `cwd` — and any relative
/// `program` resolved against it — to stay inside the daemon's own working
/// directory (ruling W1-R58); an ordinary `tempfile::tempdir()` under
/// `/tmp` would be rejected before ever reaching `admit_task`.
fn workspace_contained_script(
    contents: &str,
    name: &str,
) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let script = dir.path().join(name);
    std::fs::write(&script, contents).unwrap();
    #[cfg(unix)]
    {
        let mut perms = std::fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).unwrap();
    }
    (dir, script)
}

#[tokio::test]
async fn a_model_issued_shell_tool_use_is_admitted_dispatched_through_the_real_gate() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\necho shell-ran-for-real\n", "safe.sh");
    // `task_params_for` resolves the model's relative `./safe.sh` against
    // `cwd` to this exact canonical path — the config Allow rule below must
    // match that resolved, canonicalized string (ruling W1-R57: policy
    // judges the real binary, never the raw model string).
    let canonical_script = script.canonicalize().unwrap();

    let (actor, _writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::Shell {
                program: canonical_script.to_string_lossy().to_string(),
                matcher: ArgMatcher::ArgvPrefix(vec![]),
                allow_interpreter: false,
            },
        )],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "shell",
        serde_json::json!({
            "program": "./safe.sh",
            "argv": [],
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert!(
        blocks.iter().any(|b| matches!(
            b,
            ContentBlock::ToolResult { is_error: false, content, .. }
                if content.iter().any(|p| p.text.contains("shell-ran-for-real"))
        )),
        "the real script's stdout must come back as a non-error tool result, got {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Shell,
                ..
            }
        )),
        "an admitted shell call must produce a real Shell task, not a bypass"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskCompleted { .. })),
        "the admitted shell call must complete, not just be created"
    );
}

#[tokio::test]
async fn a_model_issued_shell_tool_use_with_no_matching_policy_rule_is_denied_through_the_real_gate(
) {
    let (dir, _script) =
        workspace_contained_script("#!/bin/sh\necho should-never-run\n", "unapproved.sh");

    // Zero config rules: an unmatched TaskParams::Shell falls to the
    // documented default (`Ask` -> refused, engine.rs's own "unattended
    // default" framing) — the real admission gate denying a shell call
    // nothing authorized, not a sealed-floor-specific case.
    let (actor, _writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "shell",
        serde_json::json!({
            "program": "./unapproved.sh",
            "argv": [],
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "a shell call with no matching policy rule must be denied as a real tool error, got \
         {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    let shell_task_id = events
        .iter()
        .find(|e| {
            matches!(
                &e.payload,
                EventPayload::TaskCreated {
                    kind: TaskKind::Shell,
                    ..
                }
            )
        })
        .and_then(|e| e.task_id)
        .expect("a denied shell call must still be recorded as a real, queryable TaskCreated");
    // The session's chat/infer task pair also completes normally (the
    // provider's second turn returns a final text block) — this assertion
    // is scoped to the SHELL task's own id specifically, not "any
    // TaskCompleted event in the session."
    assert!(
        !events.iter().any(|e| e.task_id == Some(shell_task_id)
            && matches!(&e.payload, EventPayload::TaskCompleted { .. })),
        "a denied shell call must never reach TaskCompleted — the script must never have run"
    );
}

#[tokio::test]
async fn a_model_issued_shell_command_is_classified_and_executes_each_node() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\necho shell-command-ran\n", "command.sh");
    let canonical_script = script.canonicalize().unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::Shell {
                program: canonical_script.to_string_lossy().to_string(),
                matcher: ArgMatcher::ArgvPrefix(vec![]),
                allow_interpreter: false,
            },
        )],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": "./command.sh",
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks.iter().any(|block| matches!(
        block,
        ContentBlock::ToolResult { is_error: false, content, .. }
            if content.iter().any(|part| part.text.contains("shell-command-ran"))
    )));
}

#[tokio::test]
async fn shell_command_refuses_opaque_syntax_before_execution() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": "echo $(id)",
            "cwd": std::env::current_dir().unwrap().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks.iter().any(|block| matches!(
        block,
        ContentBlock::ToolResult { is_error: true, content, .. }
            if content.iter().any(|part| part.text.contains("inner command"))
    )));
}

#[tokio::test]
async fn shell_command_refuses_pipelines_before_any_node_executes() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": "printf x | wc -c",
            "cwd": std::env::current_dir().unwrap().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks.iter().any(|block| matches!(
        block,
        ContentBlock::ToolResult { is_error: true, content, .. }
            if content.iter().any(|part| part.text.contains("pipelines"))
    )));
}

#[tokio::test]
async fn shell_command_refuses_a_conjunction_before_its_rhs_can_run() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\ntouch side-effect-ran\n", "side-effect.sh");
    let side_effect = dir.path().join("side-effect-ran");
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": format!("false && {}", script.display()),
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks.iter().any(|block| matches!(
        block,
        ContentBlock::ToolResult { is_error: true, content, .. }
            if content.iter().any(|part| part.text.contains("control-flow"))
    )));
    assert!(
        !side_effect.exists(),
        "a refused conjunction must not flatten and execute its skipped RHS"
    );
}

#[tokio::test]
async fn shell_command_refuses_function_and_subshell_syntax_before_execution() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\ntouch function-body-ran\n", "function-body.sh");
    let marker = dir.path().join("function-body-ran");
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": format!("f() ({})", script.display()),
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks.iter().any(|block| matches!(
        block,
        ContentBlock::ToolResult { is_error: true, content, .. }
            if !content.is_empty()
    )));
    assert!(
        !marker.exists(),
        "unsupported function bodies must never execute"
    );
}

#[tokio::test]
async fn shell_command_refuses_ast_compounds_without_running_their_body() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\ntouch brace-body-ran\n", "brace-body.sh");
    let marker = dir.path().join("brace-body-ran");
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": format!("{{ {} }}", script.display()),
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks
        .iter()
        .any(|block| matches!(block, ContentBlock::ToolResult { is_error: true, .. })));
    assert!(!marker.exists(), "AST compound bodies must never execute");
}

#[tokio::test]
async fn shell_command_refuses_keyword_compounds_without_running_their_body() {
    let (dir, script) =
        workspace_contained_script("#!/bin/sh\ntouch keyword-body-ran\n", "keyword-body.sh");
    let marker = dir.path().join("keyword-body-ran");
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": format!("if true; then {}; fi", script.display()),
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks
        .iter()
        .any(|block| matches!(block, ContentBlock::ToolResult { is_error: true, .. })));
    assert!(
        !marker.exists(),
        "keyword compound bodies must never execute"
    );
}

#[tokio::test]
async fn shell_command_refuses_the_arithmetic_for_loop_before_touching_the_victim() {
    let (dir, _script) = workspace_contained_script("#!/bin/sh\n", "unused.sh");
    let victim = dir.path().join("victim");
    std::fs::write(&victim, "must survive").unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;
    let provider = ScriptedToolCallProvider::new(
        "shell_command",
        serde_json::json!({
            "command": format!(
                "for ((i=0; i<1; i++)); do rm -rf {}; done",
                victim.display()
            ),
            "cwd": dir.path().to_string_lossy(),
        }),
    );
    let tools = actor.tool_defs().to_vec();
    let ctx = fake_ctx();
    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();
    assert!(blocks
        .iter()
        .any(|block| matches!(block, ContentBlock::ToolResult { is_error: true, .. })));
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "must survive");
}

/// Fix round A, ruling W1-R59 ("redact, don't ask"): a dispatched tool's
/// result must be scanned through the session's own live redactor BEFORE
/// it is folded into the next turn's `request.messages` — the direct path
/// F1's leaked-key reproduction would otherwise cross the network boundary
/// to the provider. This drives a real `read` call whose file content is a
/// registered live secret, and asserts the SECOND provider call (the one
/// carrying the first call's tool result) never sees the raw secret.
#[tokio::test]
async fn a_leaked_secret_in_a_tool_result_is_redacted_before_it_reaches_the_next_provider_call() {
    let dir = tempfile::tempdir().unwrap();
    let secret_file = dir.path().join("secret.txt");
    let live_secret = "sk-ant-DAEMON-SECRET-abc123";
    std::fs::write(&secret_file, live_secret).unwrap();

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
    writer.set_redactor(roundhouse_store::redact::Redactor::build(&[
        live_secret.to_string()
    ]));

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": secret_file.to_string_lossy() }),
    );
    let ctx = fake_ctx();

    run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let requests = provider.requests();
    assert_eq!(
        requests.len(),
        2,
        "the provider must be called exactly twice"
    );
    let second_request_text = requests[1]
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolResult { content, .. } => Some(
                content
                    .iter()
                    .map(|p| p.text.clone())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !second_request_text.contains(live_secret),
        "a live secret in a tool's result must never reach the next outbound provider \
         request unredacted, got: {second_request_text:?}"
    );
    assert!(
        second_request_text.contains("[REDACTED]"),
        "the redaction placeholder must appear in its place, got: {second_request_text:?}"
    );
}

/// A scripted `Provider` that returns `count` `ToolUse` blocks in a single
/// turn — used to prove `max_tool_calls_per_turn` (fix round A, SHOULD item
/// F7) bounds fan-out WITHIN one turn, independent of `max_turns`.
struct ManyToolUsesInOneTurnProvider {
    count: usize,
}

impl Provider for ManyToolUsesInOneTurnProvider {
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
        let count = self.count;
        Box::pin(async move {
            let mut events = Vec::new();
            for i in 0..count {
                events.push(StreamEvent::BlockStart {
                    index: i as u32,
                    kind: BlockKind::ToolUse {
                        name: "read".to_string(),
                        provider_id: Some(format!("call_{i}")),
                    },
                });
                events.push(StreamEvent::BlockDelta {
                    index: i as u32,
                    delta: BlockDelta::ToolArgsFragment(
                        serde_json::json!({ "path": "/nonexistent" }).to_string(),
                    ),
                });
                events.push(StreamEvent::BlockStop { index: i as u32 });
            }
            events.push(StreamEvent::MessageStop);
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
async fn max_tool_calls_per_turn_is_a_hard_ceiling_independent_of_max_turns() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    // 5 ToolUse blocks in the model's ONE turn, with a per-turn ceiling of 3
    // — max_turns is generous (10) so only the per-turn cap can be what
    // fires.
    let provider = ManyToolUsesInOneTurnProvider { count: 5 };
    let ctx = fake_ctx();

    let result = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 10,
            max_tool_calls_per_turn: 3,
        },
    )
    .await;

    assert!(
        matches!(result, Err(AgentLoopError::TooManyToolCallsInOneTurn(5, 3))),
        "5 tool calls in one turn must exceed a per-turn ceiling of 3, got {result:?}"
    );
}

/// Fix round A, SHOULD item F10 (audit asymmetry): an MCP-shaped tool call
/// must be recorded as a real, queryable attempt too, even though this
/// dispatch cannot execute it (the MCP arm is deliberately unwired — see
/// `agent_loop.rs`'s module doc comment). Before this fix, `mcp_dispatch_refusal`
/// minted nothing at all.
#[tokio::test]
async fn a_mcp_shaped_tool_call_is_recorded_as_a_real_attempt_even_though_it_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    // "__" makes this resolve as an MCP-shaped namespaced tool name per
    // `tool_catalog::resolve_tool_target`'s own invariant.
    let provider = ScriptedToolCallProvider::new("github__search", serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "an MCP-shaped call must still surface as a real tool error, got {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Mcp,
                ..
            }
        )),
        "an MCP-shaped tool call must be recorded as a real, queryable TaskCreated even \
         though the MCP arm refuses to dispatch it"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskFailed { .. })),
        "the refusal must be recorded as a real TaskFailed, not left dangling"
    );
}

/// Fix round B, ruling W1-R53/W1-R64: a dispatched tool call's `TaskCreated`
/// must be a real CHILD of the chat turn that issued it — before this fix,
/// every dispatched tool task was recorded with `parent: None`, making the
/// session's task log a flat list rather than the queryable tree this
/// repo's core bet (`AGENTS.md`) describes.
#[tokio::test]
async fn a_dispatched_tool_calls_task_is_a_real_child_of_the_chat_turn_that_issued_it() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = dir.path().join("fixture.txt");
    std::fs::write(&fixture, "hello from the fixture file").unwrap();

    let (actor, _writer, db_path, session_id) = new_actor(
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

    run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();

    let chat_task_id = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated {
                kind: TaskKind::Chat,
                ..
            } => e.task_id,
            _ => None,
        })
        .expect("a chat task must have been recorded");

    let read_task_parent = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                parent,
                ..
            } => Some(*parent),
            _ => None,
        })
        .expect("a read task must have been recorded");

    assert_eq!(
        read_task_parent,
        Some(chat_task_id),
        "the dispatched read task's parent must be the chat turn that issued it, not None"
    );
}

// =======================================================================================
// Fix round C2 — the MCP arm. `roundhouse_mcp::testing`'s own fakes
// (`FakeMcpTransport` et al.) are `#![cfg(test)]`-gated INSIDE that crate,
// so they don't exist when `roundhouse-mcp` is compiled as an ordinary
// dependency of this integration-test binary — everything below is this
// crate's own, built directly against `roundhouse-mcp`'s public,
// non-test-gated `McpTransport`/`Policy`/`TaskSpawner` traits, exactly the
// shapes a real MCP server / policy / engine wiring present in production.
// =======================================================================================

enum ScriptedMcpResponse {
    Ok {
        content: Vec<McpContentBlock>,
        is_error: bool,
    },
    InputRequired {
        input_requests: Vec<InputRequest>,
        request_state: RequestState,
    },
    /// Never resolves — a wedged or deliberately-stalling MCP server. The
    /// `AtomicBool` flips when the hanging future is DROPPED, which is the
    /// only observable difference between "the dispatch was really abandoned"
    /// and "we stopped waiting but it is still running detached" (fix round
    /// D, ruling W1-R81 finding I2 levels 2 and 3).
    Hang(Arc<std::sync::atomic::AtomicBool>),
}

/// Flips its flag on drop. Held across the `pending()` await inside a
/// `Hang` response so the flag flips exactly when that future is dropped.
struct DropFlag(Arc<std::sync::atomic::AtomicBool>);
impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct ScriptedMcpTransport {
    tools: Vec<McpToolDef>,
    script: Mutex<std::collections::VecDeque<ScriptedMcpResponse>>,
    calls: Mutex<Vec<ToolCallRequest>>,
}

impl ScriptedMcpTransport {
    fn new(tools: Vec<McpToolDef>, script: Vec<ScriptedMcpResponse>) -> Self {
        ScriptedMcpTransport {
            tools,
            script: Mutex::new(script.into()),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }
}

#[async_trait::async_trait]
impl McpTransport for ScriptedMcpTransport {
    async fn discover(&self) -> Result<DiscoverResult, McpError> {
        Ok(DiscoverResult {
            protocol_version: "2026-07-28".into(),
            tools: self.tools.clone(),
        })
    }

    async fn call_tool(&self, req: ToolCallRequest) -> Result<McpResult, McpError> {
        self.calls.lock().unwrap().push(req);
        // Popped into a local BEFORE the match so no `MutexGuard` is held
        // across the `Hang` arm's await (a `MutexGuard` is not `Send`, and
        // `McpTransport::call_tool` returns a `Send` future).
        let next = self.script.lock().unwrap().pop_front();
        match next {
            None => Err(McpError::Protocol(
                "scripted transport script exhausted".into(),
            )),
            Some(ScriptedMcpResponse::Ok { content, is_error }) => Ok(McpResult {
                result_type: McpResultType::Ok,
                content,
                is_error,
            }),
            Some(ScriptedMcpResponse::InputRequired {
                input_requests,
                request_state,
            }) => Ok(McpResult {
                result_type: McpResultType::InputRequired {
                    input_requests,
                    request_state,
                },
                content: vec![],
                is_error: false,
            }),
            Some(ScriptedMcpResponse::Hang(dropped)) => {
                let _flag = DropFlag(dropped);
                std::future::pending::<()>().await;
                unreachable!("a Hang response never resolves")
            }
        }
    }

    async fn shutdown(&self) -> Result<(), McpError> {
        Ok(())
    }
}

/// The one MCP server id every fixture in this section uses.
const FAKE_SERVER: &str = "fake-server";

/// A real `PolicyEngine` with a real `sealed_ctx_provider` installed — the
/// shape both mints of a `SessionMcp` demand, and the shape
/// `McpExecutor::gate` actually consults through
/// `impl crate::Policy for PolicyEngine`.
///
/// **Fix round D, ruling W1-R81 finding I4.** Before this round every MCP
/// test in this file built its executor with `FixedPolicy(Allow)`, an
/// `Arc<dyn Policy>` test double — so no test anywhere exercised the real
/// sealed floor on the MCP arm, while the built-in arm had exactly such a
/// test. `SessionMcp::from_parts` now takes the CONCRETE
/// `Arc<PolicyEngine>`, which makes that substitution a compile error rather
/// than a thing a test (or a future production caller) can quietly do. Every
/// MCP test below therefore drives a real engine end to end: the real
/// `decide_sealed` floor, the real `sealed:mcp-unresolved-server` rule, and
/// real `CompiledRule`s.
fn mcp_engine(
    state_dir: &std::path::Path,
    daemon_binary: &std::path::Path,
    resolved_servers: &[&str],
    rules: Vec<CompiledRule>,
) -> Arc<PolicyEngine> {
    let ctx = SealedContext {
        state_dir: state_dir.to_path_buf(),
        daemon_binary: daemon_binary.to_path_buf(),
        resolved_mcp_servers: resolved_servers.iter().map(|s| s.to_string()).collect(),
        // Equal, so `sealed_tier_shortfall` does not fire and the MCP rules
        // under test are what actually decide these tasks.
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
        home: roundhouse_policy::sealed::home_dir(),
    };
    Arc::new(
        PolicyEngine::from_rules(rules).with_sealed_ctx_provider(Arc::new(move || ctx.clone())),
    )
}

/// A config rule allowing exactly one MCP tool on one server. `tool` is the
/// server's ORIGINAL tool name, never the namespaced one — `Predicate::Mcp`
/// matches `tool` by exact string equality, which is the whole reason
/// `dispatch_mcp` must feed `admit_task` the original name.
fn allow_mcp_tool(server: &str, tool: &str) -> CompiledRule {
    CompiledRule::test_new(
        Scope::Builtin,
        Outcome::Allow,
        Predicate::mcp(ServerId(server.to_string()), Some(tool.to_string())),
    )
}

/// Builds a real `SessionMcp` wired to a `ScriptedMcpTransport` and a
/// REAL `EngineTaskSpawner` (production code, not a test double — every
/// event this executor's own internal task-spawner calls produce lands in
/// the SAME session's real event log `session_events` below can read
/// back). Returns the `SessionMcp`, the transport (to assert on
/// `call_count`), and the one tool's namespaced name `run_agent_loop`'s
/// scripted provider should ask for.
async fn build_mcp_executor(
    runner: &'static roundhouse_core::TaskRunner,
    writer: roundhouse_store::EventWriter,
    session_id: SessionId,
    policy: Arc<PolicyEngine>,
    original_tool_name: &str,
    script: Vec<ScriptedMcpResponse>,
) -> (SessionMcp, Arc<ScriptedMcpTransport>, String) {
    let tool_def = McpToolDef {
        name: original_tool_name.to_string(),
        description: "a scripted test tool".to_string(),
        input_schema: serde_json::json!({}),
    };
    let transport = Arc::new(ScriptedMcpTransport::new(vec![tool_def.clone()], script));
    let server = ServerId(FAKE_SERVER.to_string());
    let connections: Vec<(ServerId, Arc<dyn McpTransport>)> =
        vec![(server.clone(), transport.clone() as Arc<dyn McpTransport>)];

    let discovery_task = TaskId::new();
    let namespace = ToolNamespace::build(&[(
        server,
        discovery_task,
        DiscoverResult {
            protocol_version: "2026-07-28".into(),
            tools: vec![tool_def],
        },
    )])
    .unwrap();
    let namespaced_name = namespace
        .tools()
        .iter()
        .find(|t| t.original_name == original_tool_name)
        .expect("the one registered tool must be present")
        .namespaced_name
        .clone();

    let task_spawner: Arc<dyn McpTaskSpawner> =
        Arc::new(EngineTaskSpawner::new(runner, writer, session_id));
    let mcp = SessionMcp::from_parts(connections, namespace, policy, task_spawner)
        .expect("the test engine has an installed sealed-ctx provider with absolute paths");

    (mcp, transport, namespaced_name)
}

/// Everything one ordinary MCP dispatch test needs, wired the way Task 7's
/// production path will wire it: ONE `PolicyEngine` shared by the
/// `SessionActor` and the `SessionMcp` (so `admit_task` and
/// `McpExecutor::gate` judge against the same rules and the same
/// `SealedContext`), and the session told which servers actually resolved
/// via `register_mcp`.
struct McpFixture {
    actor: SessionActor,
    mcp: SessionMcp,
    transport: Arc<ScriptedMcpTransport>,
    namespaced_name: String,
    db_path: std::path::PathBuf,
    session_id: SessionId,
}

async fn mcp_fixture(
    dir: &std::path::Path,
    rules: Vec<CompiledRule>,
    original_tool_name: &str,
    script: Vec<ScriptedMcpResponse>,
) -> McpFixture {
    let state_dir = dir.join("state");
    let daemon_binary = dir.join("daemon-binary");
    let engine = mcp_engine(&state_dir, &daemon_binary, &[FAKE_SERVER], rules);
    let (actor, writer, db_path, session_id) =
        new_actor_with_engine(dir, state_dir, daemon_binary, Arc::clone(&engine)).await;
    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        engine,
        original_tool_name,
        script,
    )
    .await;
    // Without this the session's own `SealedContext.resolved_mcp_servers` is
    // empty and `sealed:mcp-unresolved-server` denies every MCP task at
    // admission — see `SessionActor::register_mcp`'s doc comment.
    actor.register_mcp(&mcp);
    McpFixture {
        actor,
        mcp,
        transport,
        namespaced_name,
        db_path,
        session_id,
    }
}

#[tokio::test]
async fn an_mcp_tool_call_is_dispatched_through_the_real_executor_and_folded_back() {
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        transport,
        namespaced_name,
        db_path,
        session_id,
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![ScriptedMcpResponse::Ok {
            content: vec![McpContentBlock::Text {
                text: "found 3 results".to_string(),
            }],
            is_error: false,
        }],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        &namespaced_name,
        serde_json::json!({ "query": "roundhouse" }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    // Fix round D, ruling W1-R80's silent-failure mode, made load-bearing
    // here: the ONLY allow rule in this engine is
    // `Predicate::Mcp { tool: Some("search") }`, matched by exact string
    // equality, and BOTH gates the call now passes (`admit_task` and
    // `McpExecutor::gate`) consult it. If `dispatch_mcp` fed `admit_task`
    // the NAMESPACED name instead of the original one, no rule would match,
    // `decide_sealed` would fall through to its no-match `Ask`, admission
    // would refuse, and this count would be 0.
    assert_eq!(
        transport.call_count(),
        1,
        "the real transport must have been called exactly once"
    );
    assert!(
        blocks.iter().any(|b| matches!(
            b,
            ContentBlock::ToolResult { is_error: false, content, .. }
                if content.iter().any(|p| p.text.contains("found 3 results"))
        )),
        "the real MCP result must come back as a non-error tool result, got {blocks:?}"
    );

    // Full S-LOG-1 lifecycle: TaskCreated -> TaskStarted -> TaskCompleted,
    // and — the property CF-3/CF-9 exist to make possible — a real
    // TaskDecided from the executor's OWN policy gate, using the SAME
    // event log this test reads back.
    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskDecided { .. })),
        "the executor's own §6.2 policy gate must have recorded a real TaskDecided"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskCompleted { .. })),
        "a completed MCP dispatch must record a real TaskCompleted"
    );
}

#[tokio::test]
async fn an_mcp_tool_call_denied_by_policy_is_recorded_and_surfaced_as_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        transport,
        namespaced_name,
        db_path,
        session_id,
    } = mcp_fixture(
        dir.path(),
        // A REAL deny rule in a REAL `PolicyEngine`, not a `FixedPolicy`
        // stand-in — `decide` short-circuits on any matching Deny.
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Deny,
            Predicate::mcp(
                ServerId(FAKE_SERVER.to_string()),
                Some("search".to_string()),
            ),
        )],
        "search",
        vec![], // never reached — the gate must refuse before the transport
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "a policy-denied call must never reach the transport"
    );
    assert!(
        blocks.iter().any(|b| matches!(
            b,
            ContentBlock::ToolResult { is_error: true, content, .. }
                if content.iter().any(|p| p.text.contains("denied"))
        )),
        "a denied MCP call must surface as an error tool result naming the denial, got {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    // Discriminating on the category, not just "some TaskFailed exists":
    // a timeout, a transport error and a panic all produce a `TaskFailed`
    // too, and only a real policy denial produces this one.
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "policy_denied"
        )),
        "a denied MCP dispatch must record a real, queryable TaskFailed categorised as a \
         policy denial, got {:?}",
        events.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn an_unresolvable_namespaced_mcp_tool_name_is_refused_without_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        transport,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    // A namespaced-SHAPED name ("__" present) that no server actually
    // registered — `resolve_tool_target` treats it as MCP-shaped by
    // construction (`tool_catalog.rs`), but `McpExecutor::resolve` (CF-3)
    // has never heard of it.
    let provider = ScriptedToolCallProvider::new("totally_unknown__tool", serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "an unresolvable namespaced name must never reach the transport"
    );
    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "an unresolvable MCP tool name must surface as an error, got {blocks:?}"
    );
}

#[tokio::test]
async fn no_mcp_host_configured_refuses_without_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, _db_path, _session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new("someserver__sometool", serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None, // no MCP host at all for this session
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "an MCP-shaped tool call with no configured host must refuse cleanly, got {blocks:?}"
    );
}

#[tokio::test]
async fn mcp_result_text_is_capped_with_a_visible_marker_when_it_exceeds_the_bound() {
    // CF-7 item 4: an untrusted server returning far more text than this
    // arm's context-bound cap must not grow this loop's context unbounded
    // — the excess is discarded with a visible marker, mirroring M2/I1's
    // own "truncation must be visible" precedent.
    let dir = tempfile::tempdir().unwrap();
    // Comfortably past MAX_MCP_RESULT_TEXT_BYTES (256 KiB) without this
    // test itself being unreasonably slow or memory-heavy.
    let huge_text = "x".repeat(400 * 1024);
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "dump")],
        "dump",
        vec![ScriptedMcpResponse::Ok {
            content: vec![McpContentBlock::Text { text: huge_text }],
            is_error: false,
        }],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let result_text = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: false,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("a non-error tool result must be present");

    assert!(
        result_text.len() < 300 * 1024,
        "the rendered result must actually be capped, got {} bytes",
        result_text.len()
    );
    assert!(
        result_text.contains("truncated"),
        "the truncation must be visible, not silent: tail = {:?}",
        &result_text[result_text.len().saturating_sub(80)..]
    );
}

#[tokio::test]
async fn mcp_image_content_is_rendered_as_a_placeholder_not_inlined_as_base64() {
    // CF-7 item 4's other half: non-text content must not be base64'd
    // straight into the model's context.
    let dir = tempfile::tempdir().unwrap();
    // A real, valid base64 payload ("not a real png" verbatim), so this
    // exercises the actual decode path in `McpExecutor::decode_content`,
    // not a pre-built ContentBlock. Hand-encoded to avoid pulling in the
    // `base64` crate as a direct dependency of this test binary just for
    // one literal.
    let fake_png_base64 = "bm90IGEgcmVhbCBwbmc=".to_string();
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "screenshot")],
        "screenshot",
        vec![ScriptedMcpResponse::Ok {
            content: vec![McpContentBlock::Image {
                media_type: "image/png".to_string(),
                data_base64: fake_png_base64,
            }],
            is_error: false,
        }],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let result_text = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: false,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("a non-error tool result must be present");

    assert!(
        result_text.contains("[image: image/png"),
        "an image block must render as a short placeholder, got {result_text:?}"
    );
    assert!(
        !result_text.contains("bm90IGEgcmVhbCBwbmc"), // the base64 payload's own prefix
        "the raw base64 image bytes must never be inlined into the model's context, got \
         {result_text:?}"
    );
}

#[tokio::test]
async fn an_mcp_elicitation_result_suspends_the_task_honestly_without_a_double_write() {
    // MRTR resume is explicitly out of this round's scope; the task must
    // still be recorded as genuinely SUSPENDED (never mischaracterized as
    // failed), and exactly once — `execute`'s own `suspend_for_elicitation`
    // path already durably writes `TaskSuspended` via the injected
    // `EngineTaskSpawner`, so this dispatch must not write a second one.
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        db_path,
        session_id,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "delete_repo")],
        "delete_repo",
        vec![ScriptedMcpResponse::InputRequired {
            input_requests: vec![InputRequest {
                id: "confirm".to_string(),
                prompt: "type the repo name to confirm deletion".to_string(),
                schema: None,
            }],
            request_state: RequestState("opaque-server-state".to_string()),
        }],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({}));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert!(
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "a suspended MCP call must surface honestly as an error result in this loop \
         (MRTR resume is out of scope), got {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    let suspended_count = events
        .iter()
        .filter(|e| matches!(&e.payload, EventPayload::TaskSuspended { .. }))
        .count();
    assert_eq!(
        suspended_count, 1,
        "exactly one TaskSuspended must be recorded — written once by execute()'s own \
         suspend_for_elicitation path, never a second time by this dispatch"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskFailed { .. })),
        "a genuine suspension must never ALSO be recorded as a TaskFailed"
    );
}

#[tokio::test]
async fn a_panicked_mcp_dispatch_records_task_failed_instead_of_leaving_the_task_dangling() {
    // CF-7 item 1: an artificially panicking spawned task, standing in for
    // the one real internal condition that can panic mid-`execute`
    // (`EngineTaskSpawner`'s append-failure panic inside
    // `suspend_for_elicitation`, which this crate cannot cleanly force from
    // outside `roundhouse-mcp` — see `resolve_mcp_join_result`'s own doc
    // comment for why it is `pub` specifically to make this test possible).
    // This proves the REAL production logic — not a re-implementation of
    // it — correctly turns a `JoinError` into a recorded `TaskFailed`
    // rather than leaving the minted task dangling at `TaskStarted`
    // forever.
    let dir = tempfile::tempdir().unwrap();
    let (_actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    // Mirrors `dispatch_mcp`'s own S-LOG-1 sequence: mint TaskCreated then
    // TaskStarted before whatever comes next, so this test's fixture is a
    // realistic "dispatch in flight" state, not a task that never existed.
    let task_id = TaskId::new();
    let created = RUNNER.record_task_created(
        session_id,
        0,
        roundhouse_core::Timestamp::from_unix_nanos(0),
        task_id,
        TaskKind::Mcp,
        None,
        roundhouse_core::Origin::Model,
        roundhouse_core::TaskInput::Json(serde_json::json!({})),
        1,
    );
    writer.append(created).await.unwrap();

    let panicking_task = tokio::spawn(async {
        panic!("simulated EventWriter append failure inside McpExecutor::execute");
    });
    let join_result: Result<roundhouse_mcp::executor::ExecutorOutcome, tokio::task::JoinError> =
        panicking_task.await;
    assert!(
        join_result.is_err(),
        "the spawned task must have actually panicked"
    );

    let result = roundhouse_engine::agent_loop::resolve_mcp_join_result(
        &writer,
        &RUNNER,
        session_id,
        task_id,
        join_result,
    )
    .await;

    assert!(
        result.is_err(),
        "a panicked dispatch must surface as an error, not silently succeed"
    );
    assert!(
        result.unwrap_err().contains("panicked"),
        "the error message should be honest about what happened"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskFailed { .. })),
        "the task must be recorded as failed, not left dangling at TaskStarted forever"
    );
}

// =======================================================================================
// Fix round D — the four ways the MCP arm was still weaker than the built-in
// arm (rulings W1-R80 / W1-R81), plus the two smaller ones.
// =======================================================================================

/// MUST 1 / finding I2 level 1 — the session-lifecycle guard.
///
/// `admit_task`'s `SessionState` allowlist is what refuses new work into a
/// session being torn down. `dispatch_mcp` never called it, so a `Cancelling`
/// session could still have a fresh MCP call started against a real server.
/// The built-in arm has had this property since Task 25; this test is the MCP
/// arm's version of it.
#[tokio::test]
async fn a_cancelling_session_refuses_a_new_mcp_dispatch_before_it_reaches_the_transport() {
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        transport,
        namespaced_name,
        db_path,
        session_id,
    } = mcp_fixture(
        dir.path(),
        // Explicitly ALLOWED by policy, so nothing but the lifecycle guard
        // can be what refuses this call — the discriminator that makes this
        // test about admission rather than about the policy gate.
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![ScriptedMcpResponse::Ok {
            content: vec![McpContentBlock::Text {
                text: "should never be reached".to_string(),
            }],
            is_error: false,
        }],
    )
    .await;

    actor
        .cancel(&RUNNER, roundhouse_core::CancelReason::User)
        .await
        .unwrap();

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "a Cancelling session must not start a new MCP call against a real server"
    );
    let refusal = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("the refusal must reach the model as an error tool result");
    assert!(
        refusal.contains("session is Cancelling"),
        "the model must be told WHY the call was refused, not just that it failed: {refusal:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "session_not_running"
        )),
        "the refused attempt must still be a real, queryable TaskFailed categorised as a \
         lifecycle refusal, got {:?}",
        events.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );
}

/// MUST 5 / finding I4 — the REAL sealed floor, on the MCP arm, end to end.
///
/// Before this round every MCP test built its executor with a permissive
/// `FixedPolicy(Allow)` `Arc<dyn Policy>` double, so nothing anywhere proved
/// the MCP gate consults the compiled-in floor at all. `SessionMcp::from_parts`
/// now takes the concrete `Arc<PolicyEngine>`, which makes that double a
/// compile error. This test proves the floor really fires here: an explicit
/// config rule ALLOWS the tool, and the call is denied anyway, because
/// `sealed:mcp-unresolved-server` matches first and config cannot override the
/// sealed floor. A `FixedPolicy(Allow)` could not produce this outcome.
#[tokio::test]
async fn the_real_sealed_floor_denies_an_mcp_call_to_an_unresolved_server_despite_an_allow_rule() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let daemon_binary = dir.path().join("daemon-binary");
    // The engine's sealed context reports NO resolved MCP servers — the
    // honest state for a server that never completed a handshake — while its
    // config rules explicitly allow the tool.
    let engine = mcp_engine(
        &state_dir,
        &daemon_binary,
        &[],
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
    );
    let (actor, writer, db_path, session_id) =
        new_actor_with_engine(dir.path(), state_dir, daemon_binary, Arc::clone(&engine)).await;
    let (mcp, transport, namespaced_name) =
        build_mcp_executor(&RUNNER, writer, session_id, engine, "search", vec![]).await;
    // Deliberately NOT calling `actor.register_mcp(&mcp)`: this session never
    // learned of a resolved server either.

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "the compiled-in sealed floor must refuse an unresolved server even though a config \
         rule allows the tool — config cannot override the floor"
    );
    let refusal = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("the denial must reach the model as an error tool result");
    assert!(
        refusal.contains("denied by sealed floor"),
        "the denial must name the sealed floor, not read as a generic failure: {refusal:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "policy_denied"
        )),
        "a sealed-floor denial must be a real, queryable TaskFailed"
    );
}

/// MUST 2 / finding I1 — an `Ask` must record a terminal, and must say
/// "approval", not "elicitation".
///
/// `gate`'s `Ask` arm records a `TaskDecided(Ask)` and returns
/// `Suspended { AwaitingApproval }` WITHOUT calling `suspend_task`, unlike
/// `suspend_for_elicitation`. `dispatch_mcp` used to append nothing for
/// either, on the (elicitation-only) belief that `execute` had already
/// written a terminal — leaving `TaskCreated -> TaskStarted ->
/// TaskDecided(Ask) -> nothing`, a task permanently in flight (S-LOG-1), and
/// telling the model it needed "an elicitation" when it needed a human.
///
/// The two gates are given deliberately different rule sets so that
/// admission allows and the executor's own gate then Asks — the one
/// configuration in which `gate`'s `Ask` arm is reachable at all now that
/// `admit_task` runs first.
#[tokio::test]
async fn an_mcp_policy_ask_records_a_terminal_and_is_reported_as_pending_approval() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let daemon_binary = dir.path().join("daemon-binary");

    let actor_engine = mcp_engine(
        &state_dir,
        &daemon_binary,
        &[FAKE_SERVER],
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
    );
    // No rule at all — `PolicyEngine::decide` returns `Ask` when nothing
    // matches (its no-match arm builds `Decision { outcome: Outcome::Ask,
    // rule: None }`), which is exactly the default path this finding is
    // about.
    let executor_engine = mcp_engine(&state_dir, &daemon_binary, &[FAKE_SERVER], vec![]);

    let (actor, writer, db_path, session_id) = new_actor_with_engine(
        dir.path(),
        state_dir,
        daemon_binary,
        Arc::clone(&actor_engine),
    )
    .await;
    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        executor_engine,
        "search",
        vec![], // never reached — the gate Asks before the transport
    )
    .await;
    actor.register_mcp(&mcp);

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "an Ask must not reach the transport"
    );

    let message = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("a pending-approval call must reach the model as an error tool result");
    assert!(
        message.contains("pending approval"),
        "the model must be told this is awaiting a human approval: {message:?}"
    );
    assert!(
        !message.contains("elicitation"),
        "a pending approval must NOT be mislabelled as an elicitation: {message:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskDecided {
                decision: roundhouse_core::PolicyDecision::Ask,
                ..
            }
        )),
        "the executor's gate must have recorded its Ask decision"
    );
    // The S-LOG-1 property this finding is about: the task reaches a terminal
    // state instead of sitting at TaskDecided(Ask) forever.
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "requires_approval"
        )),
        "an Ask must leave a real terminal event, categorised the same way the built-in arm's \
         `record_denial` categorises its own RequiresApproval, got {:?}",
        events.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );
}

/// MUST 3 level 2 / finding I2 — a mid-dispatch cancellation must actually
/// reach the MCP call.
///
/// `dispatch_builtin` passes `Some(actor.subscribe())` into
/// `execute_builtin`; `dispatch_mcp` passed no cancellation channel at all,
/// so a `cancel()` while an MCP call was in flight did nothing and the call
/// ran on to the full `MCP_CALL_TIMEOUT` (120s). The `timeout` below is the
/// discriminator: against the pre-fix code this test does not merely assert
/// something different, it does not finish.
#[tokio::test]
async fn a_session_cancelled_mid_mcp_dispatch_abandons_the_call_instead_of_waiting_out_the_timeout()
{
    let dir = tempfile::tempdir().unwrap();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        db_path,
        session_id,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![ScriptedMcpResponse::Hang(Arc::clone(&dropped))],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let loop_fut = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    );
    let canceller = async {
        // Long enough for the dispatch to be genuinely in flight inside the
        // wedged transport, short enough to keep the test fast.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        actor
            .cancel(&RUNNER, roundhouse_core::CancelReason::User)
            .await
            .unwrap();
    };

    let blocks = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (blocks, ()) = tokio::join!(loop_fut, canceller);
        blocks
    })
    .await
    .expect(
        "a cancelled session must abandon its in-flight MCP call promptly — waiting out the \
         120s MCP_CALL_TIMEOUT instead is the bug this test exists for",
    )
    .unwrap();

    assert!(
        dropped.load(Ordering::SeqCst),
        "the in-flight transport call must actually have been dropped, not merely stopped \
         being awaited"
    );
    let message = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("the abandoned call must reach the model as an error tool result");
    assert!(
        message.contains("cancelled"),
        "the model must be told the call was cancelled: {message:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    // A cancellation is not a panic — it must not be recorded as one.
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { error, .. } if error.category == "session_cancelled"
        )),
        "an abandoned dispatch must record a terminal categorised as a cancellation, not as a \
         panic, got {:?}",
        events.iter().map(|e| &e.payload).collect::<Vec<_>>()
    );
}

/// MUST 3 level 3 / finding I2 — dropping the loop must abort the detached
/// dispatch.
///
/// `tokio` does NOT abort a spawned task when its `JoinHandle` is dropped.
/// Without the `AbortOnDrop` guard, dropping `run_agent_loop`'s future during
/// session teardown left `execute()` running — still holding the session's
/// `EngineTaskSpawner` — free to append a `TaskDecided`, a `TaskSuspended`,
/// or a whole elicitation `TaskCreated` into a closing session's log.
///
/// The drop flag is the discriminator: it is set by the transport's own
/// future being dropped, which can only happen if the spawned task was really
/// aborted rather than merely abandoned.
#[tokio::test]
async fn dropping_the_agent_loop_aborts_an_in_flight_mcp_dispatch_instead_of_detaching_it() {
    let dir = tempfile::tempdir().unwrap();
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![ScriptedMcpResponse::Hang(Arc::clone(&dropped))],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    {
        let loop_fut = run_agent_loop(
            &actor,
            &RUNNER,
            &provider,
            &ctx,
            &tools,
            Some(mcp),
            empty_request(),
            AgentLoopConfig {
                max_turns: 4,
                max_tool_calls_per_turn: 10,
            },
        );
        // Drive it far enough that the dispatch is genuinely in flight, then
        // drop it — the session-teardown shape, where nothing of ours is left
        // running to observe the drop and act on it.
        let raced = tokio::time::timeout(std::time::Duration::from_millis(200), loop_fut).await;
        assert!(
            raced.is_err(),
            "the wedged transport must still have been in flight when the loop future was dropped"
        );
    }

    // Give the runtime a moment to actually run the abort.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        dropped.load(Ordering::SeqCst),
        "dropping the agent loop must abort the spawned MCP dispatch — tokio detaches a task \
         whose JoinHandle is merely dropped, leaving it free to append events into a closing \
         session"
    );
}

/// MUST 4 / finding I3 — the `--unsealed` per-task audit `Note`.
///
/// `admit_task` records a `Note` for every task when `PolicyEngine::unsealed()`
/// and fails admission CLOSED if that append fails — that is what discharges
/// the "must be recorded per-task, never silent" commitment. `McpExecutor::gate`
/// records only a `TaskDecided` and STRUCTURALLY cannot record this: it holds
/// an `Arc<dyn Policy>`, which has no `unsealed()` method. So before this
/// round, under `round daemon --unsealed`, an MCP call to a server that never
/// completed a handshake was allowed — `decide_sealed` skips every sealed rule
/// including `sealed:mcp-unresolved-server` — with NO per-task record that the
/// floor was off. Routing this arm through `admit_task` is what closes it.
#[tokio::test]
async fn an_unsealed_mcp_dispatch_records_the_per_task_audit_note_that_the_floor_was_off() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let daemon_binary = dir.path().join("daemon-binary");
    // No resolved servers anywhere and no `register_mcp` call: with the
    // sealed floor ON this is exactly the `sealed:mcp-unresolved-server`
    // denial the test above asserts. `--unsealed` skips it — and that fact
    // is what must not go unrecorded.
    let engine = Arc::new(
        PolicyEngine::from_rules(vec![allow_mcp_tool(FAKE_SERVER, "search")])
            .with_unsealed(true)
            .with_sealed_ctx_provider({
                let ctx = SealedContext {
                    state_dir: state_dir.clone(),
                    daemon_binary: daemon_binary.clone(),
                    resolved_mcp_servers: Default::default(),
                    requested_tier: Tier::Sandbox,
                    attested_tier: Tier::Sandbox,
                    home: roundhouse_policy::sealed::home_dir(),
                };
                Arc::new(move || ctx.clone())
            }),
    );
    let (actor, writer, db_path, session_id) =
        new_actor_with_engine(dir.path(), state_dir, daemon_binary, Arc::clone(&engine)).await;
    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        engine,
        "search",
        vec![ScriptedMcpResponse::Ok {
            content: vec![McpContentBlock::Text {
                text: "reached the server with the floor off".to_string(),
            }],
            is_error: false,
        }],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        1,
        "with --unsealed the floor really is off, so the call to an unresolved server goes \
         through — which is precisely why it must leave a record"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    let notes: Vec<&String> = events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::Note { text, .. } => Some(text),
            _ => None,
        })
        .collect();
    assert!(
        notes
            .iter()
            .any(|t| t.contains("sealed floor DISABLED (--unsealed)") && t.contains("kind=Mcp")),
        "the MCP task must have its own per-task unsealed audit note naming the task kind, \
         got {notes:?}"
    );
}

/// MUST 6, M1 — `retryable` must be forwarded, not hardcoded `false`.
///
/// `ExecutorOutcome::Failed` carries the executor's own judgement, and
/// `McpExecutor`'s transport-error path sets `retryable: true` (the
/// `Err(e) => ExecutorOutcome::Failed { .. }` arm of `McpExecutor::execute`,
/// categorised `executor_error`). `dispatch_mcp` matched
/// `Failed { error, .. }` and
/// passed a literal `false` to `record_task_failed`, while the timeout branch
/// two dozen lines above it explicitly built `retryable: true` — so the log
/// contradicted itself within one dispatch.
///
/// An empty script makes the scripted transport return
/// `McpError::Protocol("scripted transport script exhausted")`, which is a
/// real transport error, so `retryable: true` here is the executor's own
/// value round-tripped rather than a value this test arranged directly.
#[tokio::test]
async fn a_retryable_mcp_transport_failure_is_recorded_as_retryable_not_hardcoded_false() {
    let dir = tempfile::tempdir().unwrap();
    let McpFixture {
        actor,
        mcp,
        namespaced_name,
        db_path,
        session_id,
        ..
    } = mcp_fixture(
        dir.path(),
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
        "search",
        vec![], // exhausted script -> a real transport error
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    let failures: Vec<(&str, bool)> = events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskFailed { error, retryable } => {
                Some((error.category.as_str(), *retryable))
            }
            _ => None,
        })
        .collect();
    assert!(
        failures.contains(&("executor_error", true)),
        "the executor said this transport failure was retryable; the event log must say so \
         too, got {failures:?}"
    );
}

/// Round E, the note carried from W1-R87's review: prove **`McpExecutor::gate`'s**
/// own sealed floor, independently of `admit_task`'s.
///
/// `the_real_sealed_floor_denies_an_mcp_call_to_an_unresolved_server_despite_an_allow_rule`
/// above leaves both sealed contexts empty, so `admit_task` denies first and
/// `gate` is never reached — it proves the floor on the *admission* channel
/// only. This test inverts exactly one variable: the ACTOR's context carries
/// the server (via `register_mcp`, so admission passes), while the EXECUTOR's
/// engine is built with no resolved servers at all. The only thing left that
/// can refuse the call is `gate`'s own `decide_sealed`, and the assertion is
/// on `gate`'s message text — which is distinguishable from `AdmitError`'s.
///
/// Together the two tests show the floor is live on BOTH channels, which is
/// what the double gate being "fail-closed, not redundant" actually rests on.
#[tokio::test]
async fn the_executors_own_sealed_floor_denies_an_unresolved_server_after_admission_passes() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let daemon_binary = dir.path().join("daemon-binary");

    // Admission's channel: server resolved, tool allowed — so `admit_task`
    // returns Ok and cannot be what refuses this call.
    let actor_engine = mcp_engine(
        &state_dir,
        &daemon_binary,
        &[FAKE_SERVER],
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
    );
    // The executor's channel: the SAME allow rule, but NO resolved servers,
    // so only the compiled-in `sealed:mcp-unresolved-server` can fire.
    let executor_engine = mcp_engine(
        &state_dir,
        &daemon_binary,
        &[],
        vec![allow_mcp_tool(FAKE_SERVER, "search")],
    );

    let (actor, writer, db_path, session_id) = new_actor_with_engine(
        dir.path(),
        state_dir,
        daemon_binary,
        Arc::clone(&actor_engine),
    )
    .await;
    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        executor_engine,
        "search",
        vec![], // never reached — the gate must refuse before the transport
    )
    .await;
    actor.register_mcp(&mcp);

    let tools = actor.tool_defs().to_vec();
    let provider =
        ScriptedToolCallProvider::new(&namespaced_name, serde_json::json!({ "query": "x" }));
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        Some(mcp),
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    assert_eq!(
        transport.call_count(),
        0,
        "the executor's own sealed floor must refuse before the transport"
    );

    let refusal = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(content.iter().map(|p| p.text.clone()).collect::<String>()),
            _ => None,
        })
        .expect("the denial must reach the model as an error tool result");
    // `McpExecutor::gate`'s own text, NOT `AdmitError::Denied`'s "denied by
    // sealed floor or configured policy" — this is the discriminator that
    // says which of the two gates refused, and therefore that admission
    // really did pass.
    assert!(
        refusal.starts_with("denied by policy: mcp tool 'search' on server 'fake-server'"),
        "the refusal must be the EXECUTOR's gate talking, not admission's: {refusal:?}"
    );
    assert!(
        !refusal.contains("denied by sealed floor or configured policy"),
        "admission must have PASSED — if this is AdmitError's text the test proves nothing new: \
         {refusal:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    // Admission passing means the task really started, unlike the
    // admission-denied test above where TaskStarted is never reached.
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskStarted { .. })),
        "admission passed, so the task must have reached TaskStarted before the gate refused it"
    );
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskDecided {
                decision: roundhouse_core::PolicyDecision::Deny,
                ..
            }
        )),
        "the executor's gate must have recorded its own Deny decision"
    );
}

/// Runs one scripted `shell` tool call with the given `cwd`, and returns the
/// model-visible text of the resulting error tool result together with the
/// session's full event log. Used by the containment-refusal test below,
/// which needs to compare TWO refusals' model-visible text byte-for-byte.
async fn refused_shell_call(cwd: &str) -> (String, Vec<roundhouse_store::StoredEvent>) {
    let dir = tempfile::tempdir().unwrap();
    let (actor, _writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let tools = actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(
        "shell",
        serde_json::json!({
            "program": "./whatever.sh",
            "argv": [],
            "cwd": cwd,
        }),
    );
    let ctx = fake_ctx();

    let blocks = run_agent_loop(
        &actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .unwrap();

    let text = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolResult {
                is_error: true,
                content,
                ..
            } => Some(
                content
                    .iter()
                    .map(|p| p.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "a rejected shell cwd must surface as an error tool result, \
             got {blocks:?}"
            )
        });

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    (text, events)
}

/// Ruling W1-R131, both halves.
///
/// **The audit half:** a shell/fs containment rejection is raised by
/// `task_params_for` BEFORE `dispatch_builtin` mints its `task_id`, so
/// before this fix every such refusal returned to the model with zero
/// events in the append-only log — the same F10 asymmetry ruling W1-R81
/// closed for the MCP arm via `record_unadmitted_refusal`, left open on the
/// built-in arm.
///
/// **The disclosure half, which is the sharper one:** the rejection
/// messages were formatted verbatim into the model-visible
/// `ToolResultPart` — `"cwd {canonical:?} is outside the workspace root
/// {root:?}"` disclosed the daemon's own absolute working directory, and
/// `"cwd {raw_cwd:?} not accessible: {e}"` rendered `std::io::Error`'s text
/// for an attacker-chosen absolute path, whose ENOENT/EACCES/ENOTDIR
/// variants are distinguishable — a filesystem existence-and-permission
/// oracle over the whole host, evaluated before `admit_task` so the
/// fail-closed policy default never saw it.
///
/// The positive control that makes this test non-vacuous: two refusals for
/// GENUINELY DIFFERENT reasons (a path that does not exist at all, and a
/// real directory that exists but lies outside the workspace root) must
/// come back to the model as BYTE-IDENTICAL text. Asserting only "the text
/// contains no `os error`" would pass vacuously against any rewording.
#[tokio::test]
async fn a_shell_containment_refusal_is_audited_and_discloses_nothing_about_the_host() {
    let daemon_cwd = std::env::current_dir().unwrap();

    // Refusal 1: a path that does not exist — `canonicalize` fails ENOENT.
    let (nonexistent_text, nonexistent_events) =
        refused_shell_call("/nonexistent-roundhouse-w1r131/definitely/not/here").await;

    // Refusal 2: a real, existing directory that is simply outside the
    // workspace root — a DIFFERENT rejection branch entirely.
    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().canonicalize().unwrap();
    assert!(
        !outside_path.starts_with(&daemon_cwd),
        "this test needs a real directory outside the daemon's cwd to exercise the \
         outside-the-root branch; got {outside_path:?} under {daemon_cwd:?}"
    );
    let (outside_text, outside_events) = refused_shell_call(&outside_path.to_string_lossy()).await;

    assert_eq!(
        nonexistent_text, outside_text,
        "a nonexistent cwd and a real-but-outside-the-root cwd must be indistinguishable to \
         the model — anything else is a filesystem existence oracle"
    );

    for text in [&nonexistent_text, &outside_text] {
        assert!(
            !text.contains(&*daemon_cwd.to_string_lossy()),
            "the refusal must never disclose the daemon's own working directory: {text:?}"
        );
        assert!(
            !text.contains(&*outside_path.to_string_lossy()),
            "the refusal must never echo a canonicalized host path back to the model: {text:?}"
        );
        assert!(
            !text.contains("os error") && !text.to_lowercase().contains("no such file"),
            "the refusal must never render an io::Error — errno is the oracle: {text:?}"
        );
    }

    for (label, events) in [
        ("nonexistent", &nonexistent_events),
        ("outside-the-root", &outside_events),
    ] {
        let task_id = events
            .iter()
            .find(|e| {
                matches!(
                    &e.payload,
                    EventPayload::TaskCreated {
                        kind: TaskKind::Shell,
                        ..
                    }
                )
            })
            .and_then(|e| e.task_id)
            .unwrap_or_else(|| {
                panic!(
                    "the {label} containment refusal must be recorded as a real, queryable \
                     TaskCreated, not returned as a silent non-event"
                )
            });
        assert!(
            events.iter().any(|e| e.task_id == Some(task_id)
                && matches!(
                    &e.payload,
                    EventPayload::TaskFailed { error, .. } if error.category == "shell_cwd_rejected"
                )),
            "the {label} containment refusal must be recorded TaskFailed under its own \
             category, not left dangling at TaskCreated"
        );
        assert!(
            !events.iter().any(|e| e.task_id == Some(task_id)
                && matches!(&e.payload, EventPayload::TaskStarted { .. })),
            "a containment refusal is raised before admission — it must never reach TaskStarted"
        );
    }
}
