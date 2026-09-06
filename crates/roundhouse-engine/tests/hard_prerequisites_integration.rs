//! Phase 7, Task 8, Part A — the adversarial integration suite for the
//! Phase 2 "hard prerequisite" mechanisms Tasks 1-7 made reachable
//! simultaneously.
//!
//! Every case here is driven through **Task 5's real
//! [`run_agent_loop`]** — a scripted `Provider` issues a real
//! `ContentBlock::ToolUse`, which the real dispatcher resolves, the real
//! `SessionActor::admit_task` judges, and (if admitted) the real executor
//! runs. That routing is the entire point: each mechanism below already had
//! unit-level coverage inside `roundhouse-policy`/`roundhouse-sandbox` and
//! was *still* unreachable from model output in production, so a
//! unit-level call proves nothing about reachability.
//!
//! # The headline finding: three of these mechanisms are NOT reachable
//!
//! Lane W4's fixes for `Predicate::Agent`, `Predicate::Mcp { args }`,
//! `GrantScope::Directory` and the three AST walkers are all merged into
//! this branch, so the brief required their cases enabled and passing. Two
//! of the four are genuinely reachable through the real loop and pass. The
//! other two — and Phase 4's `SpawnTree` case — cannot be reached from
//! model output **at all**, for reasons that have nothing to do with W4's
//! fixes being wrong:
//!
//! - **`Predicate::Agent` / `TaskParams::Agent`**: `tool_catalog::
//!   builtin_tool_defs()` offers five tools (`read`/`write`/`edit`/`find`/
//!   `shell`) and `resolve_tool_target` resolves exactly those five plus
//!   anything containing `"__"` (MCP). There is no `agent` tool, and
//!   `roundhouse-policy`'s own `engine.rs` says of `Predicate::Agent`'s
//!   `max_tier` that it "is also unreachable today: `TaskParams::Agent`"
//!   has no construction site outside that crate.
//! - **The three AST walkers** (`shell/pipeline.rs`, `shell/opaque.rs`,
//!   `shell/classify.rs`): they take a **raw shell string**, and their
//!   entry points (`decide_shell_command`, `classify_shell`,
//!   `parse_command`) have no non-test caller anywhere in the workspace.
//!   The `shell` builtin emits `TaskParams::Shell(ParsedCommand { program,
//!   argv })` — direct exec, never an interpreter payload policy parses.
//! - **`SpawnTree::record_child` / the human-join guard**: no production
//!   caller exists (`roundhouse-bus`'s `local_bus.rs` says so of
//!   `register_human`/`mark_human` in its own source), and no tool a model
//!   can call reaches `agent_spawn`.
//!
//! Rather than `#[ignore]` those (which would hide them) or write a test
//! named for a security property it cannot exhibit (this lane's
//! most-repeated defect), each is written as a **reachability pin**: an
//! enabled test, driven through the real loop, asserting the gap that
//! actually exists. Each one flips the moment someone wires the mechanism
//! up, which is exactly when the real predicate test should be written.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use futures::stream;
use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionSpec, SessionState, TaskId, TaskKind, Tier,
    Timestamp,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig};
use roundhouse_engine::mcp_spawner::{EngineTaskSpawner, SessionMcp};
use roundhouse_engine::{tool_catalog, SessionActor};
use roundhouse_mcp::executor::TaskSpawner as McpTaskSpawner;
use roundhouse_mcp::namespace::ToolNamespace;
use roundhouse_mcp::transport::McpTransport;
use roundhouse_mcp::wire::{
    DiscoverResult, McpContentBlock, McpError, McpResult, McpResultType, McpToolDef,
    ToolCallRequest,
};
use roundhouse_policy::approval::{synthesize_grant, GrantProvenance, GrantScope};
use roundhouse_policy::engine::{
    ArgMatcher, ArgsPattern, CompiledRule, Outcome, PolicyEngine, Predicate, Scope,
};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::{FsOp, ServerId, TaskParams};
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ContentBlock,
    HttpRequest, HttpResponseStream, HttpTransport, ModelId, Params, Plan, Provider, ProviderError,
    ProviderExt, ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent,
    TokenCount, ToolChoice,
};
use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
use roundhouse_sandbox::Isolate;
use roundhouse_store::{open, session_events, spawn_writer, StoredEvent};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// `TaskRunner::bootstrap()` panics on a second call per-process and every
/// test in this binary shares one process — one shared `&'static TaskRunner`
/// for all of them, matching `agent_loop_dispatch.rs`.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

// ---------------------------------------------------------------------------
// Fixture — the same shape `agent_loop_dispatch.rs` uses, so every case here
// drives production code paths and not a test-only variant of them.
// ---------------------------------------------------------------------------

struct NoopTransport;
impl HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> BoxFut<'a, Result<HttpResponseStream, roundhouse_provider::TransportError>> {
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
/// except Seatbelt (n/a off macOS) — achieves `Tier::Sandbox`
/// deterministically and hermetically, with no real bwrap/landlock syscalls.
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

struct Fixture {
    actor: SessionActor,
    writer: roundhouse_store::EventWriter,
    db_path: std::path::PathBuf,
    session_id: SessionId,
}

async fn fixture_with_engine(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    policy: Arc<PolicyEngine>,
) -> Fixture {
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
        dir.join("daemon-binary"),
        isolate,
        handle,
        spec,
        tool_catalog::builtin_tool_defs(),
    );

    Fixture {
        actor,
        writer,
        db_path,
        session_id,
    }
}

async fn fixture(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    rules: Vec<CompiledRule>,
) -> Fixture {
    fixture_with_engine(dir, state_dir, Arc::new(PolicyEngine::from_rules(rules))).await
}

/// The scripted provider every case drives the loop with: first call
/// returns one `ToolUse` for `tool_name`/`tool_input`, every later call
/// returns a final text block.
struct ScriptedToolCallProvider {
    tool_name: String,
    tool_input: serde_json::Value,
    calls: AtomicU32,
}

impl ScriptedToolCallProvider {
    fn new(tool_name: &str, tool_input: serde_json::Value) -> Self {
        ScriptedToolCallProvider {
            tool_name: tool_name.to_string(),
            tool_input,
            calls: AtomicU32::new(0),
        }
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
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
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

/// Drives one model-issued tool call through the real loop and returns the
/// full transcript.
async fn drive(
    fx: &Fixture,
    mcp: Option<SessionMcp>,
    tool_name: &str,
    tool_input: serde_json::Value,
) -> Vec<ContentBlock> {
    let tools = fx.actor.tool_defs().to_vec();
    let provider = ScriptedToolCallProvider::new(tool_name, tool_input);
    let ctx = fake_ctx();
    run_agent_loop(
        &fx.actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        mcp,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 10,
        },
    )
    .await
    .expect("the loop itself must not error — a refused tool call is a ToolResult, not an Err")
}

async fn events_of(fx: &Fixture) -> Vec<StoredEvent> {
    let reopened = open(&fx.db_path).await.unwrap();
    session_events(&reopened, fx.session_id).await.unwrap()
}

fn tool_results(blocks: &[ContentBlock]) -> Vec<(bool, String)> {
    blocks
        .iter()
        .filter_map(|b| match b {
            ContentBlock::ToolResult {
                is_error, content, ..
            } => Some((
                *is_error,
                content
                    .iter()
                    .map(|p| p.text.clone())
                    .collect::<Vec<_>>()
                    .join(""),
            )),
            _ => None,
        })
        .collect()
}

/// A real, executable script inside a tempdir under this test binary's own
/// `std::env::current_dir()` — `tool_dispatch::resolve_shell_cwd` requires a
/// dispatched shell call's `cwd` to be component-wise inside the daemon's
/// working directory (ruling W1-R58), so an ordinary `/tmp` tempdir would be
/// rejected before ever reaching `admit_task`.
fn workspace_contained_dir() -> tempfile::TempDir {
    tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
}

#[cfg(unix)]
fn write_executable(path: &std::path::Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

/// The exact string `tool_dispatch::resolve_shell_program` produces for an
/// absolute `program` — the canonicalized *directory* joined with the
/// original final component, never the fully symlink-resolved target (that
/// distinction is the whole of ruling W1-R75). A `Predicate::Shell.program`
/// must equal this, not the raw model string.
fn resolved_program(absolute: &str) -> String {
    let p = std::path::Path::new(absolute);
    p.parent()
        .unwrap()
        .canonicalize()
        .unwrap()
        .join(p.file_name().unwrap())
        .to_string_lossy()
        .to_string()
}

// ---------------------------------------------------------------------------
// Case 1 — gh_predicate_agent (lane W4's Task 21)
// ---------------------------------------------------------------------------

/// **Reachability pin, not the predicate test the spec sketched.** W4's
/// Task 21 fixed `Predicate::Agent`'s backwards tier comparison and its own
/// `predicate_agent_tier_direction.rs` proves that fix at the
/// `PolicyEngine::decide` level. It cannot be proven through
/// `run_agent_loop`, because **a model cannot issue an `agent` tool call at
/// all**: `resolve_tool_target` knows five builtin names and "anything
/// containing `__`" (MCP), and `builtin_tool_defs()` offers no `agent`
/// tool, so `TaskParams::Agent` is never constructed on any path a model's
/// output can reach.
///
/// This test pins that gap through the real loop — a model asking for
/// `agent` at `Tier::None` gets an unknown-tool refusal, and **no `Agent`
/// task is minted at all**, so no `Predicate::Agent` is ever evaluated. The
/// two catalog assertions are the tripwire: the day someone adds an `agent`
/// tool, this test fails and the real tier-direction case gets written.
#[tokio::test]
async fn an_agent_tool_call_never_reaches_predicate_agent_because_no_agent_tool_exists_gh_predicate_agent(
) {
    assert!(
        tool_catalog::resolve_tool_target("agent").is_none(),
        "if `agent` now resolves to a dispatch target, TaskParams::Agent IS reachable from \
         model output — replace this reachability pin with the real Tier::Remote-grant / \
         Tier::None-request denial test W4's Task 21 targets"
    );
    assert!(
        !tool_catalog::builtin_tool_defs()
            .iter()
            .any(|d| d.name() == "agent"),
        "the builtin catalog gained an `agent` tool — see the assertion above"
    );

    let dir = tempfile::tempdir().unwrap();
    // A rule that WOULD fire if a `TaskParams::Agent` ever reached the
    // engine: approved at the most-isolated tier. W4's fix is what makes
    // this not also cover the `Tier::None` request the model asks for below.
    let fx = fixture(
        dir.path(),
        dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::Remote),
        )],
    )
    .await;

    let blocks = drive(
        &fx,
        None,
        "agent",
        serde_json::json!({
            "provider": "anthropic",
            "model": "claude",
            "tier_request": "None",
        }),
    )
    .await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1, "expected exactly one tool result");
    let (is_error, text) = &results[0];
    assert!(
        is_error,
        "an unresolvable tool name must be an error result"
    );
    assert!(
        text.contains("unknown tool `agent`"),
        "the refusal must name the real reason — an unresolvable tool, not a policy \
         decision — got {text:?}"
    );

    let events = events_of(&fx).await;
    assert!(
        !events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Agent,
                ..
            }
        )),
        "no Agent task may exist: nothing on the real dispatch path constructs one, so \
         Predicate::Agent is never consulted"
    );
}

// ---------------------------------------------------------------------------
// Case 2 — gh_predicate_mcp_args (lane W4's Task 22) — REACHABLE
// ---------------------------------------------------------------------------

const FAKE_SERVER: &str = "fake-server";

struct ScriptedMcpTransport {
    tools: Vec<McpToolDef>,
    calls: Mutex<Vec<ToolCallRequest>>,
}

impl ScriptedMcpTransport {
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
        Ok(McpResult {
            result_type: McpResultType::Ok,
            content: vec![McpContentBlock::Text {
                text: "the real MCP server ran".to_string(),
            }],
            is_error: false,
        })
    }
    async fn shutdown(&self) -> Result<(), McpError> {
        Ok(())
    }
}

struct McpFixture {
    fx: Fixture,
    mcp: SessionMcp,
    transport: Arc<ScriptedMcpTransport>,
    namespaced_name: String,
}

/// One `PolicyEngine` shared by the `SessionActor` and the `SessionMcp`, the
/// way `session_bootstrap::create_real_session` wires production — so
/// `admit_task` and `McpExecutor::gate` judge against the same rules and the
/// same `SealedContext`.
async fn mcp_fixture(dir: &std::path::Path, rules: Vec<CompiledRule>) -> McpFixture {
    let state_dir = dir.join("state");
    let daemon_binary = dir.join("daemon-binary");
    let ctx = SealedContext {
        state_dir: state_dir.clone(),
        daemon_binary: daemon_binary.clone(),
        resolved_mcp_servers: [FAKE_SERVER.to_string()].into_iter().collect(),
        // Equal, so `sealed_tier_shortfall` never fires and the args
        // predicate under test is what actually decides these tasks.
        requested_tier: Tier::Sandbox,
        attested_tier: Tier::Sandbox,
        home: roundhouse_policy::sealed::home_dir(),
    };
    let engine = Arc::new(
        PolicyEngine::from_rules(rules).with_sealed_ctx_provider(Arc::new(move || ctx.clone())),
    );
    let fx = fixture_with_engine(dir, state_dir, Arc::clone(&engine)).await;

    let tool_def = McpToolDef {
        name: "write_file".to_string(),
        description: "a scripted test tool".to_string(),
        input_schema: serde_json::json!({}),
    };
    let transport = Arc::new(ScriptedMcpTransport {
        tools: vec![tool_def.clone()],
        calls: Mutex::new(Vec::new()),
    });
    let server = ServerId(FAKE_SERVER.to_string());
    let connections: Vec<(ServerId, Arc<dyn McpTransport>)> =
        vec![(server.clone(), transport.clone() as Arc<dyn McpTransport>)];
    let namespace = ToolNamespace::build(&[(
        server,
        TaskId::new(),
        DiscoverResult {
            protocol_version: "2026-07-28".into(),
            tools: vec![tool_def],
        },
    )])
    .unwrap();
    let namespaced_name = namespace
        .tools()
        .iter()
        .find(|t| t.original_name == "write_file")
        .expect("the one registered tool must be present")
        .namespaced_name
        .clone();

    let task_spawner: Arc<dyn McpTaskSpawner> = Arc::new(EngineTaskSpawner::new(
        &RUNNER,
        fx.writer.clone(),
        fx.session_id,
    ));
    let mcp = SessionMcp::from_parts(connections, namespace, engine, task_spawner)
        .expect("the test engine has an installed sealed-ctx provider with absolute paths");
    // Without this the session's own `SealedContext.resolved_mcp_servers` is
    // empty and `sealed:mcp-unresolved-server` denies every MCP task at
    // admission — which would make the args assertion below vacuous.
    fx.actor.register_mcp(&mcp);

    McpFixture {
        fx,
        mcp,
        transport,
        namespaced_name,
    }
}

fn allow_write_file_with_exact_args(args: serde_json::Value) -> CompiledRule {
    CompiledRule::test_new(
        Scope::Grant,
        Outcome::Allow,
        Predicate::Mcp {
            server: ServerId(FAKE_SERVER.to_string()),
            tool: Some("write_file".to_string()),
            args: Some(ArgsPattern::Exact(args)),
        },
    )
}

/// **Lane W4's Task 22, proven reachable and proven working.** A grant
/// approved for one argument shape must not silently cover a different one
/// — through the real `run_agent_loop` -> `dispatch_mcp` -> `admit_task` ->
/// `McpExecutor::execute` path, where the model's own tool-call arguments
/// become `TaskParams::Mcp.args` verbatim (`agent_loop.rs`'s
/// `args: input.clone()`).
///
/// The real side effect asserted is the **transport call count**: a refused
/// call must never have reached the MCP server at all, which is stronger
/// than asserting an error result (an error result is also what a server
/// that ran and failed would produce).
#[tokio::test]
async fn an_mcp_grant_approved_for_one_argument_shape_does_not_auto_allow_a_different_one_gh_predicate_mcp_args(
) {
    let approved = serde_json::json!({ "path": "/tmp/approved.txt" });

    // (a) The approved argument shape still runs.
    let allowed_dir = tempfile::tempdir().unwrap();
    let allowed = mcp_fixture(
        allowed_dir.path(),
        vec![allow_write_file_with_exact_args(approved.clone())],
    )
    .await;
    let blocks = drive(
        &allowed.fx,
        Some(allowed.mcp),
        &allowed.namespaced_name,
        approved.clone(),
    )
    .await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the exact approved arguments must still dispatch, got {:?}",
        results[0].1
    );
    assert_eq!(
        allowed.transport.call_count(),
        1,
        "the approved call must actually reach the MCP server"
    );

    // (b) A different argument shape for the SAME tool must not.
    let denied_dir = tempfile::tempdir().unwrap();
    let denied = mcp_fixture(
        denied_dir.path(),
        vec![allow_write_file_with_exact_args(approved)],
    )
    .await;
    let blocks = drive(
        &denied.fx,
        Some(denied.mcp),
        &denied.namespaced_name,
        serde_json::json!({ "path": "/etc/passwd" }),
    )
    .await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].0,
        "different arguments to the same MCP tool must be refused, got {:?}",
        results[0].1
    );
    assert_eq!(
        denied.transport.call_count(),
        0,
        "a refused MCP call must never reach the server — asserting on the transport, not \
         just on the error result, is what makes this non-vacuous"
    );
    let events = events_of(&denied.fx).await;
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Mcp,
                ..
            }
        )),
        "a refused MCP call must still be a real, queryable attempt in the event log"
    );
}

// ---------------------------------------------------------------------------
// Case 3 — gh_grantscope_directory (lane W4's Task 24) — REACHABLE
// ---------------------------------------------------------------------------

/// **Lane W4's Task 24, proven reachable and proven working.** A human
/// approving a shallow ancestor directory must not produce a grant reaching
/// a sibling user's home — and here the synthesized grant is installed into
/// the very `PolicyEngine` a real `SessionActor` admits against, then
/// probed by a real model-issued `write` through `run_agent_loop`.
///
/// Real directories under a tempdir, not string paths: a `write` to a path
/// whose *parent* does not exist yields `TaskParams::Fs { canonical: Err }`,
/// which `PolicyEngine::decide` denies outright — so a non-existent probe
/// directory would make this test pass for the wrong reason (a
/// canonicalization failure, not the workspace clamp). Both probes below
/// therefore live in directories the test creates.
///
/// `synthesize_grant` itself has no production caller (approval is lane
/// W5's), so the grant is installed the way a future approval path would
/// install it; what is driven through the real loop is the **grant's own
/// security property**, which is the half W4 fixed.
#[tokio::test]
async fn a_shallow_ancestor_directory_grant_does_not_reach_a_sibling_users_home_gh_grantscope_directory(
) {
    let root = tempfile::tempdir().unwrap();
    let root_path = root.path().canonicalize().unwrap();

    // `/home/alice/project` and `/home/bob`, in miniature — the shallow
    // ancestor a human might carelessly approve is `root_path` itself.
    let boundary = root_path.join("alice/project");
    std::fs::create_dir_all(boundary.join("src")).unwrap();
    let inside = boundary.join("src/main.rs");
    std::fs::write(&inside, "fn main() {}").unwrap();

    let bob_secrets = root_path.join("bob/.ssh");
    std::fs::create_dir_all(&bob_secrets).unwrap();
    let bobs_key = bob_secrets.join("id_rsa");
    std::fs::write(&bobs_key, "BOB'S PRIVATE KEY").unwrap();

    // `CompiledRule` is deliberately not `Clone` (see this crate's own
    // `grant_rule_encapsulation` compile-fail test), so the two probes below
    // each synthesize the grant afresh — from identical inputs, via the same
    // public `synthesize_grant` -> `into_rule_for_installation` path a real
    // approval flow would use.
    let synthesize = || {
        synthesize_grant(
            &TaskParams::Fs {
                op: FsOp::Write,
                path: inside.clone(),
                canonical: Ok(inside.clone()),
            },
            GrantScope::Directory {
                path: root_path.clone(),
            },
            GrantProvenance {
                session_id: SessionId::new(),
                task_id: TaskId::new(),
                ts: Timestamp::from_unix_nanos(0),
            },
            &boundary,
        )
        .into_rule_for_installation()
        .expect("a Directory-scoped grant installs as a real rule")
    };

    // A state_dir disjoint from both probe paths, so the sealed floor's
    // `sealed:state-dir-write` rule cannot be what decides either probe.
    let state_dir = root_path.join("daemon-state");
    std::fs::create_dir_all(&state_dir).unwrap();

    // (a) The grant must NOT reach the sibling's home.
    let denied_dir = tempfile::tempdir().unwrap();
    let denied = fixture(denied_dir.path(), state_dir.clone(), vec![synthesize()]).await;
    let blocks = drive(
        &denied,
        None,
        "write",
        serde_json::json!({
            "path": bobs_key.to_string_lossy(),
            "contents": "pwned",
        }),
    )
    .await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].0,
        "a grant synthesized from a shallow ancestor must be clamped to the workspace \
         boundary and must not authorize a write into a sibling's home, got {:?}",
        results[0].1
    );
    assert_eq!(
        std::fs::read_to_string(&bobs_key).unwrap(),
        "BOB'S PRIVATE KEY",
        "the denied write must never have touched the filesystem"
    );

    // (b) ... while still covering the workspace it was clamped to — without
    // this half the test would also pass against a grant that authorizes
    // nothing at all.
    let allowed_dir = tempfile::tempdir().unwrap();
    let allowed = fixture(allowed_dir.path(), state_dir, vec![synthesize()]).await;
    let blocks = drive(
        &allowed,
        None,
        "write",
        serde_json::json!({
            "path": inside.to_string_lossy(),
            "contents": "fn main() { /* edited */ }",
        }),
    )
    .await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the clamped grant must still authorize its own workspace, got {:?}",
        results[0].1
    );
    assert_eq!(
        std::fs::read_to_string(&inside).unwrap(),
        "fn main() { /* edited */ }",
        "the allowed write must actually have run"
    );
}

// ---------------------------------------------------------------------------
// Case 4 — gh_ast_walker (lane W4's Task 26)
// ---------------------------------------------------------------------------

/// **Reachability pin, and a concrete demonstration of the gap.** W4's Task
/// 26 made all three AST walkers descend into a C-style `for ((;;))` body,
/// and `ast_walker_consistency.rs` proves that at each walker's real entry
/// point. None of those entry points is on `run_agent_loop`'s path:
/// `decide_shell_command`, `classify_shell` and `parse_command` have no
/// non-test caller in the workspace, and the `shell` builtin builds a
/// `TaskParams::Shell(ParsedCommand { program, argv })` — direct exec — so
/// policy never sees a shell *string* to walk.
///
/// So this test drives **the same command string** two ways and asserts the
/// disagreement:
/// - `pipeline::decide_shell_command`, the walkers' real entry point, says
///   `Deny` (W4's fix working).
/// - The real loop, with an `allow_interpreter: true` rule, **runs it** —
///   the `rm -rf` hidden in the loop body actually deletes the victim file,
///   because nothing on this path ever parsed the interpreter's payload.
///
/// # The second half is the FROZEN DESIGN, quoted, not a bug
///
/// `docs/architecture/03-security-and-sandboxing.md` §6.3 step 6, verbatim:
///
/// > `InterpreterProgram` nodes (`sh`, `bash`, `python`, `perl`, `awk`,
/// > `xargs`, `env`, `node`, `make`, `ssh`) are `Ask` regardless of any
/// > allowlist match, unless a rule names them with
/// > `allow_interpreter = true`. **We do not analyse the payload.**
///
/// So a walker descending into an `sh -c` payload would *contradict* the
/// frozen contract. This test asserts what the design specifies, and the
/// assertion must not be inverted to "the rm is denied" without a §13.3
/// amendment to that clause.
///
/// # The real gap, which is structural and larger
///
/// §6.3 opens: *"Model-emitted command **strings** are parsed with a real
/// shell grammar"*, and its steps 1-8 (parse -> expand -> `Opaque`
/// hard-deny -> per-node Allow -> execve each node) are the design's entire
/// shell-safety story. But `tool_catalog::ShellParams` is
/// `{ program, argv, cwd }` — **no field carries a command string**. The
/// model therefore has no way to emit one, and steps 1-8 have no
/// model-facing entry point at all.
///
/// Both halves of that path exist and both have zero production callers:
/// `shell::pipeline::decide_shell_command` (steps 1-7, the gate these
/// walkers serve) and `roundhouse_tools::execve_node` (step 8, the
/// executor). What is missing is the model-facing tool and the glue between
/// them. That is a new tool surface with real design choices, not a
/// fix-round edit — see this task's fix-round-2 report.
#[cfg(unix)]
#[tokio::test]
async fn a_c_style_arithmetic_for_loop_never_reaches_the_ast_walkers_through_the_real_loop_gh_ast_walker(
) {
    let work = workspace_contained_dir();
    let victim = work.path().join("victim.txt");
    std::fs::write(&victim, "delete me").unwrap();
    let command = format!(
        "for ((i=0; i<1; i++)); do rm -rf {}; done",
        victim.to_string_lossy()
    );

    // Half one: the walkers' own real entry point sees straight through the
    // C-style for-loop — W4's Task 26 fix, exercised as W4 exercises it.
    let walker_decision = roundhouse_policy::shell::pipeline::decide_shell_command(
        &PolicyEngine::from_rules(vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Deny,
            Predicate::program("rm"),
        )]),
        &SealedContext {
            state_dir: std::path::PathBuf::from("/tmp/state"),
            daemon_binary: std::path::PathBuf::from("/usr/libexec/roundhouse/round-daemon"),
            resolved_mcp_servers: Default::default(),
            requested_tier: Tier::Sandbox,
            attested_tier: Tier::Sandbox,
            home: roundhouse_policy::sealed::home_dir(),
        },
        &command,
        &roundhouse_policy::shell::classify::SessionEnv::default(),
    );
    assert_eq!(
        walker_decision.outcome,
        Outcome::Deny,
        "W4's Task 26 fix: the walkers must see a dangerous command hidden in a C-style \
         for-loop body"
    );
    assert!(
        victim.exists(),
        "the walker call above must be a pure decision, with no side effect"
    );

    // Half two: the same string, through the real loop. `bash -c <command>`
    // is what a model would have to write to get an interpreter to run it,
    // and the rule below is a deliberate `allow_interpreter` opt-out — the
    // ONLY way admission lets an interpreter through (§6.3 step 6). Without
    // that Allow this test would pass on the default `Ask` and prove
    // nothing, which is the failure mode it is written to avoid.
    //
    // **`/bin/bash`, not `/bin/sh` — and this is load-bearing.** A C-style
    // arithmetic `for ((...))` is bash syntax; POSIX `sh` has no such
    // construct. On a distro where `/bin/sh` is bash (this machine) the
    // payload runs and the assertion below holds; on one where `/bin/sh` is
    // dash (GitHub's `ubuntu-latest`) the interpreter rejects the string as
    // a syntax error, the `rm` never fires, the victim survives, and this
    // test fails for a reason that has nothing to do with what it pins.
    // Naming bash is also the more faithful pin, not a weaker one: `bash`
    // is in §6.3 step 6's own interpreter list, and the C-style form is
    // exactly the shape W4's walker was taught to descend into. Do NOT
    // "fix" this by rewriting the payload as POSIX-portable — that would
    // quietly exercise a different construct while still looking green.
    let sh = resolved_program("/bin/bash");
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(
        dir.path(),
        dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::Shell {
                program: sh,
                matcher: ArgMatcher::ArgvPrefix(vec![]),
                allow_interpreter: true,
            },
        )],
    )
    .await;

    let blocks = drive(
        &fx,
        None,
        "shell",
        serde_json::json!({
            "program": "/bin/bash",
            "argv": ["-c", command],
            "cwd": work.path().to_string_lossy(),
        }),
    )
    .await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the interpreter call must have been admitted (the rule opts in explicitly) — a \
         refusal here would make the assertion below vacuous, got {:?}",
        results[0].1
    );
    // This assertion FIRES when the victim still exists — i.e. when the
    // `rm` did not run — so its message must describe that, not the
    // by-design behaviour the passing case pins. (An earlier version said
    // "the `rm -rf` ... actually ran", the exact inverse of its own
    // condition; two separate readers took the passing case for a security
    // finding because of it, and it cost a wrong ruling before it was
    // caught.) The by-design fact — that nothing on `run_agent_loop`'s path
    // parses an interpreter payload, so W4's AST-walker fix is unreachable
    // from model output — is what this test's own doc comment above states,
    // and it is what a PASS here means.
    assert!(
        !victim.exists(),
        "the interpreter never executed the payload — the victim file still exists, so this \
         case never reached the behaviour it exists to pin (most likely the `program` above \
         is not a shell that accepts C-style `for ((...))`, which is bash syntax)"
    );
}

// ---------------------------------------------------------------------------
// Case 5 — gh_isolate_landlock (lane W5's Task 27 — LANDED; still blocked by CF-15)
// ---------------------------------------------------------------------------

/// A `shell` tool call the model issued must not be able to read outside its
/// session's Landlock ruleset.
///
/// # W5's Task 27 has LANDED, and this test still cannot engage — checked, not assumed
///
/// Lane W5's fix is merged into this branch and it **works**: Landlock is
/// genuinely applied to children of `Isolate::spawn`, proven by that lane's
/// own `roundhouse-sandbox/tests/isolate_landlock_enforcement.rs`, which
/// reads a genuinely-readable outside file and asserts the read fails only
/// when the wrapper is engaged.
///
/// What blocks this test is **CF-15**, unchanged by that work: built-in tool
/// execution runs **in-process and never through `Isolate::spawn` at all**.
/// Re-verified against this post-merge tree rather than carried forward —
/// every `isolate.spawn(&handle, cmd)` call site in the workspace is inside
/// `roundhouse-sandbox`'s own `tests/*.rs`, and W5's own
/// `isolate_landlock_fix_round_1.rs` says so in its own module doc comment:
/// its fixes
/// are *"latent today because `Isolate::spawn` has no production caller
/// yet."* `tool_dispatch::execute_builtin` calls `roundhouse_tools::run_shell`
/// directly, and `dispatch_builtin` records an honest
/// `IsolationAttestation { tier: Tier::None, .. }` for exactly that reason.
/// So the tier this session attested to (`Tier::Sandbox`) describes a ruleset
/// no dispatched tool call ever runs under.
///
/// The ignore reason therefore had to change: `"tracked: W5 Task 27"` is now
/// **false** — that task landed. What remains is a missing production caller
/// for `Isolate::spawn`, which belongs to whoever owns the unified
/// task-execution entry point (`SessionActor`'s own doc comments have flagged
/// its absence since Phase 1).
///
/// The Allow rule below is load-bearing: without it admission answers `Ask`,
/// the shell call never runs, the read never happens, and the test would pass
/// while proving nothing. With it, the call runs in-process and the
/// out-of-ruleset read succeeds — the failure recorded against this ignore.
#[cfg(unix)]
#[tokio::test]
#[ignore = "blocked: CF-15 — built-in tool execution runs in-process; Isolate::spawn has no \
            production caller anywhere, so W5 Task 27's landed Landlock enforcement (proven by \
            roundhouse-sandbox/tests/isolate_landlock_enforcement.rs) never applies to a \
            dispatched tool call. Needs a production Isolate::spawn caller, not a W5 fix."]
async fn a_spawned_shell_tool_call_cannot_read_outside_its_landlock_ruleset_gh_isolate_landlock() {
    let work = workspace_contained_dir();

    // A file outside anything a session ruleset would grant: created in a
    // second tempdir the session was never told about.
    let outside = tempfile::tempdir().unwrap();
    let secret = outside.path().join("outside-the-ruleset.txt");
    std::fs::write(&secret, "SECRET-OUTSIDE-THE-RULESET").unwrap();

    let script = work.path().join("exfiltrate.sh");
    write_executable(
        &script,
        &format!("#!/bin/sh\ncat {} 2>&1\n", secret.to_string_lossy()),
    );
    let canonical_script = script.canonicalize().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(
        dir.path(),
        dir.path().join("state"),
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

    let blocks = drive(
        &fx,
        None,
        "shell",
        serde_json::json!({
            "program": "./exfiltrate.sh",
            "argv": [],
            "cwd": work.path().to_string_lossy(),
        }),
    )
    .await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the shell call must have been admitted, or the assertion below is vacuous — got {:?}",
        results[0].1
    );
    assert!(
        !results[0].1.contains("SECRET-OUTSIDE-THE-RULESET"),
        "a dispatched shell tool call read a file outside its session's landlock ruleset — \
         it ran in-process rather than through Isolate::spawn (CF-15), got {:?}",
        results[0].1
    );
}

// ---------------------------------------------------------------------------
// Case 6 — agent_spawn / SpawnTree::record_child / the human-join guard
// ---------------------------------------------------------------------------

/// **Reachability pin. Stated plainly, since the spec's fallback ("file the
/// fix as an addition to lane W4's Task 32") no longer has an owning lane:**
/// Phase 4's deferred `SpawnTree::record_child` and `mark_human`/
/// `register_human` items are **not** activated by Task 5's wiring. No tool
/// a model can call reaches `roundhouse_engine::agent_spawn::agent_spawn`,
/// so no child session is ever minted through the real loop, so neither the
/// spawn tree nor the human-join guard can fire.
///
/// Driven through the real loop rather than asserted by inspection: a model
/// asking for every spawn-shaped tool name gets an unresolvable-tool
/// refusal each time, and the session's log ends with **no `Agent` task**.
#[tokio::test]
async fn agent_spawn_is_not_reachable_through_the_real_loop_so_spawn_tree_and_the_human_join_guard_never_fire(
) {
    for name in ["agent", "spawn", "agent_spawn", "task"] {
        assert!(
            tool_catalog::resolve_tool_target(name).is_none(),
            "`{name}` now resolves to a dispatch target — sub-agent spawning may have become \
             reachable from model output; replace this pin with the real SpawnTree::record_child \
             / human-join-guard test"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), dir.path().join("state"), vec![]).await;

    let blocks = drive(
        &fx,
        None,
        "agent_spawn",
        serde_json::json!({ "prompt": "do some work in a child session" }),
    )
    .await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        results[0].0 && results[0].1.contains("unknown tool `agent_spawn`"),
        "a spawn-shaped tool call must be refused as unresolvable, got {:?}",
        results[0]
    );

    let events = events_of(&fx).await;
    let kinds: Vec<TaskKind> = events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskCreated { kind, .. } => Some(kind.clone()),
            _ => None,
        })
        .collect();
    assert!(
        !kinds.contains(&TaskKind::Agent),
        "no Agent task may be minted: sub-agent spawning has no model-reachable entry point, \
         so `SpawnTree::record_child` and the human-join guard cannot have fired. Saw {kinds:?}"
    );
}
