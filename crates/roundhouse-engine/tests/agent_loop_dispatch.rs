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
    EventPayload, OnDegrade, PolicyDecision, SessionId, SessionSpec, SessionState, TaskId,
    TaskKind, Tier,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig, AgentLoopError};
use roundhouse_engine::mcp_spawner::EngineTaskSpawner;
use roundhouse_engine::{tool_catalog, SessionActor};
use roundhouse_mcp::executor::{McpExecutor, TaskSpawner as McpTaskSpawner};
use roundhouse_mcp::namespace::ToolNamespace;
use roundhouse_mcp::transport::McpTransport;
use roundhouse_mcp::wire::{
    DiscoverResult, InputRequest, McpContentBlock, McpError, McpResult, McpResultType, McpToolDef,
    RequestState, ToolCallRequest,
};
use roundhouse_policy::engine::{
    ArgMatcher, CompiledRule, Outcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::{FsOp, Policy, PolicyInput, ServerId};
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
        match self.script.lock().unwrap().pop_front() {
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
        }
    }

    async fn shutdown(&self) -> Result<(), McpError> {
        Ok(())
    }
}

/// Test double for `roundhouse_policy::Policy` — always returns the fixed
/// decision it was built with. Mirrors `roundhouse-mcp`'s own `FixedPolicy`
/// (unreachable from here — see this section's header comment).
struct FixedPolicy(PolicyDecision);
impl Policy for FixedPolicy {
    fn decide(&self, _input: &PolicyInput) -> PolicyDecision {
        self.0
    }
}

/// Builds a real `McpExecutor` wired to a `ScriptedMcpTransport` and a
/// REAL `EngineTaskSpawner` (production code, not a test double — every
/// event this executor's own internal task-spawner calls produce lands in
/// the SAME session's real event log `session_events` below can read
/// back). Returns the executor, the transport (to assert on `call_count`),
/// and the one tool's namespaced name `run_agent_loop`'s scripted provider
/// should ask for.
async fn build_mcp_executor(
    runner: &'static roundhouse_core::TaskRunner,
    writer: roundhouse_store::EventWriter,
    session_id: SessionId,
    policy: Arc<dyn Policy>,
    original_tool_name: &str,
    script: Vec<ScriptedMcpResponse>,
) -> (Arc<McpExecutor>, Arc<ScriptedMcpTransport>, String) {
    let tool_def = McpToolDef {
        name: original_tool_name.to_string(),
        description: "a scripted test tool".to_string(),
        input_schema: serde_json::json!({}),
    };
    let transport = Arc::new(ScriptedMcpTransport::new(vec![tool_def.clone()], script));
    let server = ServerId("fake-server".to_string());
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
    let executor = Arc::new(McpExecutor::new(
        connections,
        namespace,
        policy,
        task_spawner,
    ));

    (executor, transport, namespaced_name)
}

#[tokio::test]
async fn an_mcp_tool_call_is_dispatched_through_the_real_executor_and_folded_back() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Allow)),
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
    let (actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let (mcp, transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Deny)),
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
        blocks
            .iter()
            .any(|b| matches!(b, ContentBlock::ToolResult { is_error: true, .. })),
        "a denied MCP call must surface as an error tool result, got {blocks:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events = session_events(&reopened, session_id).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskFailed { .. })),
        "a denied MCP dispatch must still record a real, queryable TaskFailed"
    );
}

#[tokio::test]
async fn an_unresolvable_namespaced_mcp_tool_name_is_refused_without_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let (actor, writer, _db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let (mcp, transport, _namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Allow)),
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
    let (actor, writer, _db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    // Comfortably past MAX_MCP_RESULT_TEXT_BYTES (256 KiB) without this
    // test itself being unreasonably slow or memory-heavy.
    let huge_text = "x".repeat(400 * 1024);
    let (mcp, _transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Allow)),
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
    let (actor, writer, _db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    // A real, valid base64 payload ("not a real png" verbatim), so this
    // exercises the actual decode path in `McpExecutor::decode_content`,
    // not a pre-built ContentBlock. Hand-encoded to avoid pulling in the
    // `base64` crate as a direct dependency of this test binary just for
    // one literal.
    let fake_png_base64 = "bm90IGEgcmVhbCBwbmc=".to_string();
    let (mcp, _transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Allow)),
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
    let (actor, writer, db_path, session_id) = new_actor(
        dir.path(),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        vec![],
    )
    .await;

    let (mcp, _transport, namespaced_name) = build_mcp_executor(
        &RUNNER,
        writer,
        session_id,
        Arc::new(FixedPolicy(PolicyDecision::Allow)),
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
