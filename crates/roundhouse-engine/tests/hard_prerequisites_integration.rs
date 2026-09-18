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
//! # Reachability status: one mechanism is still NOT reachable
//!
//! Lane W4's fixes for `Predicate::Agent`, `Predicate::Mcp { args }`,
//! `GrantScope::Directory` and the three AST walkers are all merged into
//! this branch, so the brief required their cases enabled and passing.
//! `Predicate::Mcp { args }` (Case 2) and `GrantScope::Directory` (Case 3)
//! were reachable through the real loop from the start and pass as real
//! security tests, not pins.
//!
//! When this file was first written, three of the other mechanisms could
//! not be reached from model output at all, and each was written as a
//! **reachability pin**: an enabled test, driven through the real loop,
//! asserting the gap that actually existed, designed to fail the moment
//! someone wired the mechanism up.
//!
//! **Two of those three pins have since flipped and been replaced by the
//! real tests they were holding a place for.** Phase 8's sub-agent
//! spawn-tracking work (issue #34) added a real `agent` builtin
//! (`roundhouse_engine::tools::agent_spawn_tool`) that a model can call,
//! so:
//!
//! - **`Predicate::Agent` / `TaskParams::Agent` — REACHABLE.**
//!   `builtin_tool_defs()` now offers an `agent` tool and
//!   `resolve_tool_target` resolves it to `ToolTarget::Builtin(TaskKind::
//!   Agent)`; `dispatch_agent` builds a real `TaskParams::Agent` and puts
//!   it through the same `SessionActor::admit_task` gate every other
//!   dispatched call goes through. Case 1 below is now W4's Task 21
//!   isolation-floor test, driven end to end.
//! - **`SpawnTree::record_child` / the human-join guard — REACHABLE.**
//!   `dispatch_agent` reserves, admits and commits a real child session
//!   into the daemon-wide `SpawnTree`, and `agent_spawn` calls
//!   `TeamRegistry::join` — the function the human-join guard lives inside
//!   — on the parent's team. Case 6 below drives both through the real
//!   loop. The daemon-assembly half (one shared `TeamRegistry`, marked
//!   human at the real socket handshake) is proven in `roundhouse-daemon`'s
//!   `submit_turn_e2e.rs`, module `human_join_guard`.
//! - **The three AST walkers** (`shell/pipeline.rs`, `shell/opaque.rs`,
//!   `shell/classify.rs`) — **still NOT reachable.** They take a **raw
//!   shell string**, and their entry points (`decide_shell_command`,
//!   `classify_shell`, `parse_command`) have no non-test caller anywhere in
//!   the workspace. The `shell` builtin emits `TaskParams::Shell(
//!   ParsedCommand { program, argv })` — direct exec, never an interpreter
//!   payload policy parses. Case 4 remains a reachability pin, for the
//!   reasons its own doc comment states at length.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionSpec, SessionState, TaskId, TaskKind, TeamId, Tier,
    Timestamp,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig};
use roundhouse_engine::agent_spawn::Budget;
use roundhouse_engine::mcp_spawner::{EngineTaskSpawner, SessionMcp};
use roundhouse_engine::tools::agent_spawn_tool::{
    ChildSessionError, ChildSessionRequest, SubAgentHost,
};
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
use roundhouse_sandbox::{Attestation, Child, CommandSpec, Isolate, IsolationError, ProbeResult};
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
/// except Seatbelt (n/a off macOS) — used by the fixture to exercise the
/// production session wiring. Real-host tests skip before using it when the
/// required bwrap/Landlock facilities are unavailable.
fn available_isolate() -> BwrapLandlockIsolate {
    BwrapLandlockIsolate::test_with_probe_and_bwrap_path(
        MechanismProbeReport {
            landlock: MechanismStatus::Available,
            bwrap: MechanismStatus::Available,
            seccomp: MechanismStatus::Available,
            seatbelt: MechanismStatus::Unavailable {
                reason: "n/a".into(),
            },
        },
        "bwrap".into(),
    )
}

struct TestIsolate;

#[async_trait::async_trait]
impl Isolate for TestIsolate {
    fn declared(&self) -> Tier {
        Tier::Sandbox
    }

    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: Tier::Sandbox,
            degradations: vec![],
        }
    }

    async fn prepare(
        &self,
        _spec: &SessionSpec,
    ) -> Result<roundhouse_sandbox::Handle, IsolationError> {
        Ok(roundhouse_sandbox::Handle {
            id: "test-isolate".into(),
        })
    }

    async fn spawn(
        &self,
        _handle: &roundhouse_sandbox::Handle,
        command: CommandSpec,
    ) -> Result<Child, IsolationError> {
        let mut process = tokio::process::Command::new(&command.program);
        process
            .args(&command.argv)
            .current_dir(command.cwd.as_deref().unwrap_or("."))
            .env_clear()
            .envs(command.env)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        process.process_group(0);
        let child = process
            .spawn()
            .map_err(|err| IsolationError::Unsupported(err.to_string()))?;
        let pid = child
            .id()
            .ok_or_else(|| IsolationError::Unsupported("test child has no pid".into()))?;
        Ok(Child::from_process(pid, child))
    }

    fn attest(&self, _handle: &roundhouse_sandbox::Handle) -> Attestation {
        Attestation {
            tier: Tier::Sandbox,
            digest: "test-isolate".into(),
            net_enforced: false,
        }
    }

    async fn teardown(&self, _handle: roundhouse_sandbox::Handle) -> Result<(), IsolationError> {
        Ok(())
    }
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
    fixture_with_isolate(dir, state_dir, policy, Arc::new(TestIsolate)).await
}

async fn fixture_with_isolate(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    policy: Arc<PolicyEngine>,
    isolate: Arc<dyn Isolate>,
) -> Fixture {
    fixture_with_isolate_at_root(
        dir,
        state_dir,
        policy,
        isolate,
        std::env::current_dir().unwrap(),
    )
    .await
}

async fn fixture_with_isolate_at_root(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    policy: Arc<PolicyEngine>,
    isolate: Arc<dyn Isolate>,
    workspace_root: std::path::PathBuf,
) -> Fixture {
    let db_path = dir.join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let session_id = SessionId::new();

    let actor = SessionActor::new_with_workspace_root(
        session_id,
        writer.clone(),
        SessionState::Running,
        &RUNNER,
        policy,
        state_dir,
        dir.join("daemon-binary"),
        workspace_root,
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

async fn fixture_at_root(
    dir: &std::path::Path,
    state_dir: std::path::PathBuf,
    workspace_root: std::path::PathBuf,
    rules: Vec<CompiledRule>,
) -> Fixture {
    fixture_with_isolate_at_root(
        dir,
        state_dir,
        Arc::new(PolicyEngine::from_rules(rules)),
        Arc::new(TestIsolate),
        workspace_root,
    )
    .await
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
            Ok(ChatStream::from_events(events))
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

/// Every event recorded against the fixture's OWN session. A shorthand for
/// [`events_for`], which the sub-agent cases need because they also have to
/// read a spawned *child's* log.
async fn events_of(fx: &Fixture) -> Vec<StoredEvent> {
    events_for(fx, fx.session_id).await
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
// Sub-agent spawning — the half `roundhouse-engine` cannot supply for itself
// ---------------------------------------------------------------------------

/// A [`SubAgentHost`] over a **real** [`SpawnTree`] and a **real**
/// [`TeamRegistry`], whose `create_child_session` durably appends the child's
/// own `SessionCreated` through the fixture's real `EventWriter` — the same
/// store, and the same `TaskRunner`-minted event, the daemon's
/// `DaemonSubAgentHost::persist_session_created` writes.
///
/// Only the parts that genuinely live in `roundhouse-daemon` are absent:
/// `create_headless_session`, `SessionRegistry` and `HeadlessSession` are
/// unreachable from this crate by design (nothing may depend on
/// `roundhouse-daemon`), and the registry half is proven there instead, by
/// `sub_agent_host::tests::an_agent_tool_call_creates_a_real_registered_child_with_a_durable_parent_edge`.
/// What matters for *this* file's claims is that the child session exists as a
/// queryable lifecycle event and that the spawn tree carries the edge, and both
/// of those are real here.
struct RecordingSubAgentHost {
    tree: Arc<SpawnTree>,
    teams: TeamRegistry,
    budget: Arc<Mutex<Budget>>,
    depth: u8,
    team: Option<TeamId>,
    writer: roundhouse_store::EventWriter,
    created: Mutex<Vec<SessionId>>,
}

impl RecordingSubAgentHost {
    fn new(writer: roundhouse_store::EventWriter) -> Self {
        RecordingSubAgentHost {
            tree: Arc::new(SpawnTree::new()),
            teams: TeamRegistry::new(),
            budget: Arc::new(Mutex::new(Budget {
                remaining_tokens: 1_000,
            })),
            depth: 0,
            team: None,
            writer,
            created: Mutex::new(Vec::new()),
        }
    }

    fn created(&self) -> Vec<SessionId> {
        self.created.lock().unwrap().clone()
    }
}

fn host_now_ts() -> Timestamp {
    Timestamp::from_unix_nanos(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
    )
}

#[async_trait::async_trait]
impl SubAgentHost for RecordingSubAgentHost {
    fn spawn_tree(&self) -> &Arc<SpawnTree> {
        &self.tree
    }
    fn teams(&self) -> &TeamRegistry {
        &self.teams
    }
    fn budget(&self) -> Arc<Mutex<Budget>> {
        Arc::clone(&self.budget)
    }
    fn depth(&self) -> u8 {
        self.depth
    }
    fn team(&self) -> Option<TeamId> {
        self.team
    }
    async fn create_child_session(
        &self,
        req: ChildSessionRequest,
    ) -> Result<(), ChildSessionError> {
        let event = RUNNER.record_session_created(
            req.child,
            0, // ignored — `EventWriter::append` assigns the real per-session seq
            host_now_ts(),
            Box::new(req.spec),
            1,
        );
        self.writer
            .append(event)
            .await
            .map_err(|err| ChildSessionError {
                category: "session_created_append_failed",
                detail: err.to_string(),
            })?;
        self.created.lock().unwrap().push(req.child);
        Ok(())
    }
}

/// The `agent` tool call a model issues in the cases below. `tier_request` is
/// deliberately absent: `agent_spawn_tool::CHILD_TIER` pins every spawned
/// child at `Tier::Sandbox`, so a model cannot choose its child's isolation —
/// which is precisely what makes Case 1's floor comparison meaningful rather
/// than model-controlled.
fn agent_call_args() -> serde_json::Value {
    serde_json::json!({
        "prompt": "do some work in a child session",
        "provider": "anthropic",
        "model": "claude",
        "budget_tokens": 300,
    })
}

/// Registers `host` on the fixture's real `SessionActor`, exactly as
/// `roundhouse-daemon`'s `wire_sub_agent_host` does on the real socket path.
fn with_host(fx: &Fixture, host: Arc<RecordingSubAgentHost>) -> Arc<RecordingSubAgentHost> {
    fx.actor.register_sub_agent_host(host.clone());
    host
}

/// Every event recorded against `session` in the fixture's store — the parent's
/// own log when `session` is `fx.session_id` (see [`events_of`]), and a spawned
/// child's log otherwise.
async fn events_for(fx: &Fixture, session: SessionId) -> Vec<StoredEvent> {
    let reopened = open(&fx.db_path).await.unwrap();
    session_events(&reopened, session).await.unwrap()
}

fn created_task_kinds(events: &[StoredEvent]) -> Vec<TaskKind> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskCreated { kind, .. } => Some(kind.clone()),
            _ => None,
        })
        .collect()
}

fn failure_categories(events: &[StoredEvent]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskFailed { error, .. } => Some(error.category.to_string()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Case 1 — gh_predicate_agent (lane W4's Task 21)
//          (was a reachability pin; REACHABLE since Phase 8's `agent` tool)
// ---------------------------------------------------------------------------

/// **The real test the old reachability pin was holding a place for.** Its
/// predecessor
/// (`an_agent_tool_call_never_reaches_predicate_agent_because_no_agent_tool_exists_gh_predicate_agent`)
/// asserted that no `agent` tool existed, so `TaskParams::Agent` was never
/// constructed on any path a model's output could reach; its own failure
/// message said to replace it with *"the real Tier::Remote-grant /
/// Tier::None-request denial test W4's Task 21 targets"* the day one did.
/// Phase 8's `agent` builtin is that day, and this is that test.
///
/// W4's Task 21 turned `Predicate::Agent`'s `max_tier` from a ceiling into
/// an **isolation floor**: `matches` requires `tier_request >= max_tier`,
/// where `Tier`'s `Ord` ascends with isolation. Before that flip the
/// comparison was `<=`, so a rule approved at the *most*-isolated tier also
/// covered the *least*-isolated request. Both halves below are driven
/// through the real `run_agent_loop` -> `dispatch_agent` ->
/// `SessionActor::admit_task` path, where the model's `agent` call becomes a
/// genuine `TaskParams::Agent` that `PolicyEngine::decide` judges:
///
/// - (a) a single `Allow` at `max_tier: Tier::Remote` does **not** cover the
///   `Tier::Sandbox` a spawned child asks for, so the call falls through to
///   the engine's default `Ask` and the spawn is refused. Under the pre-flip
///   `<=` this rule would have matched and the spawn would have succeeded,
///   which is exactly what makes this half non-vacuous.
/// - (b) the same rule at `max_tier: Tier::Sandbox` **does** cover it and the
///   spawn runs — without this half the test would also pass against a
///   `Predicate::Agent` that matched nothing at all.
///
/// Both halves assert a real `TaskKind::Agent` task is minted, which is the
/// reachability claim itself: a refused spawn is still a queryable attempt,
/// and an `Agent` task existing at all is what proves `Predicate::Agent` was
/// consulted rather than skipped.
///
/// `tier_request` is **not** model-controlled — `agent_spawn_tool`'s
/// `CHILD_TIER` pins every spawned child at `Tier::Sandbox`. That is what
/// makes the floor a real security boundary here instead of a field the
/// caller can dial down.
#[tokio::test]
async fn an_agent_spawns_isolation_floor_refuses_a_request_below_the_approved_tier_gh_predicate_agent(
) {
    assert!(
        matches!(
            tool_catalog::resolve_tool_target("agent"),
            Some(tool_catalog::ToolTarget::Builtin(TaskKind::Agent))
        ),
        "`agent` must resolve to the sub-agent spawn builtin, or TaskParams::Agent is not \
         reachable from model output and this test proves nothing"
    );
    assert!(
        tool_catalog::builtin_tool_defs()
            .iter()
            .any(|d| d.name() == "agent"),
        "the builtin catalog must offer an `agent` ToolDef, or no model can ever call it"
    );

    // (a) Approved at the most-isolated tier. A `Tier::Sandbox` child request
    //     asks for LESS isolation than was approved, so the rule must not
    //     cover it.
    let denied_dir = tempfile::tempdir().unwrap();
    let denied = fixture(
        denied_dir.path(),
        denied_dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::Remote),
        )],
    )
    .await;
    let denied_host = with_host(
        &denied,
        Arc::new(RecordingSubAgentHost::new(denied.writer.clone())),
    );

    let blocks = drive(&denied, None, "agent", agent_call_args()).await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1, "expected exactly one tool result");
    assert!(
        results[0].0,
        "a Remote-approved `agent` rule must not cover a Sandbox request — under the \
         pre-Task-21 `<=` comparison it would have, got {:?}",
        results[0].1
    );

    let denied_events = events_for(&denied, denied.session_id).await;
    assert_eq!(
        created_task_kinds(&denied_events)
            .iter()
            .filter(|k| **k == TaskKind::Agent)
            .count(),
        1,
        "the refusal must be a real, queryable `agent` task: Predicate::Agent was consulted \
         and said no, which is the whole reachability claim"
    );
    assert_eq!(
        failure_categories(&denied_events),
        vec!["requires_approval".to_string()],
        "no rule covered the request, so the engine's default `Ask` decided it"
    );
    assert!(
        denied_host.created().is_empty(),
        "a policy-refused spawn must never reach the child-session step"
    );
    assert_eq!(
        denied_host.tree.direct_children(denied.session_id),
        0,
        "and must leave the parent's spawn tree exactly as it found it"
    );
    assert_eq!(denied_host.tree.reserved_children(denied.session_id), 0);

    // (b) The same rule at the tier a child actually asks for. Without this
    //     half, (a) would also pass against a predicate that matched nothing.
    let allowed_dir = tempfile::tempdir().unwrap();
    let allowed = fixture(
        allowed_dir.path(),
        allowed_dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::Sandbox),
        )],
    )
    .await;
    let allowed_host = with_host(
        &allowed,
        Arc::new(RecordingSubAgentHost::new(allowed.writer.clone())),
    );

    let blocks = drive(&allowed, None, "agent", agent_call_args()).await;
    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "a rule approved at the tier the child actually requests must admit the spawn, \
         got {:?}",
        results[0].1
    );

    let allowed_events = events_for(&allowed, allowed.session_id).await;
    assert_eq!(
        created_task_kinds(&allowed_events)
            .iter()
            .filter(|k| **k == TaskKind::Agent)
            .count(),
        1
    );
    assert!(
        failure_categories(&allowed_events).is_empty(),
        "an admitted spawn records no TaskFailed"
    );
    assert_eq!(allowed_host.created().len(), 1);
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
    let denied = fixture_at_root(
        denied_dir.path(),
        state_dir.clone(),
        root_path.clone(),
        vec![synthesize()],
    )
    .await;
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
    let allowed = fixture_at_root(
        allowed_dir.path(),
        state_dir,
        root_path.clone(),
        vec![synthesize()],
    )
    .await;
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
        roundhouse_policy::Taint::Trusted,
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
// Case 5 — gh_isolate_landlock (Phase 8 Task 7)
// ---------------------------------------------------------------------------

/// A `shell` tool call the model issued must not be able to read outside its
/// session's Landlock ruleset. The explicit admission assertion keeps a policy
/// refusal from making the confinement assertion vacuous.
#[cfg(unix)]
#[tokio::test]
async fn a_spawned_shell_tool_call_cannot_read_outside_its_landlock_ruleset_gh_isolate_landlock() {
    if !std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
    {
        eprintln!("skipping: bwrap not available on this host");
        return;
    }
    let report = roundhouse_sandbox::probe::probe_cached(&std::env::temp_dir()).await;
    if !matches!(report.landlock, MechanismStatus::Available) {
        eprintln!("skipping: Landlock is not available on this host");
        return;
    }
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
    let fx = fixture_with_isolate(
        dir.path(),
        dir.path().join("state"),
        Arc::new(PolicyEngine::from_rules(vec![CompiledRule::test_new(
            Scope::Builtin,
            Outcome::Allow,
            Predicate::Shell {
                program: canonical_script.to_string_lossy().to_string(),
                matcher: ArgMatcher::ArgvPrefix(vec![]),
                allow_interpreter: false,
            },
        )])),
        Arc::new(available_isolate()),
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
        "a dispatched shell tool call read a file outside its session's Landlock ruleset, got {:?}",
        results[0].1
    );
    assert!(
        results[0].1.contains("exit_code=Some(1)"),
        "the fixture command must have run and observed Landlock's denied read, got {:?}",
        results[0].1
    );
    let denied_output = results[0].1.to_ascii_lowercase();
    assert!(
        denied_output.contains("permission denied")
            || denied_output.contains("operation not permitted"),
        "the failed read must report a kernel permission denial, got {:?}",
        results[0].1
    );
}

// ---------------------------------------------------------------------------
// Case 6 — agent_spawn / SpawnTree::record_child / the human-join guard
//          (was a reachability pin; REACHABLE since Phase 8's `agent` tool)
// ---------------------------------------------------------------------------

/// **The real test the old reachability pin was holding a place for.** Its
/// predecessor
/// (`agent_spawn_is_not_reachable_through_the_real_loop_so_spawn_tree_and_the_human_join_guard_never_fire`)
/// asserted that no spawn-shaped tool name resolved, so
/// `roundhouse_engine::agent_spawn::agent_spawn` had no model-reachable
/// caller and neither the spawn tree nor the human-join guard could fire.
/// Phase 8's `agent` builtin made all of that false, and this is the
/// end-to-end test the pin's own failure message asked for.
///
/// Driven through the same `drive(...)` harness the pin used — a scripted
/// `Provider` issues a real `ContentBlock::ToolUse { name: "agent" }`, the
/// real dispatcher resolves it, the real `SessionActor::admit_task` judges it
/// and the real `spawn_child` sequence runs — and asserting all three things
/// the pin said could not happen:
///
/// 1. a `TaskKind::Agent` task **is** minted in the parent's log;
/// 2. a real child session exists — its own `SessionCreated`, carrying
///    `spec.parent = Some(parent)`, is durably in the store and queryable by
///    the child's id;
/// 3. the shared `SpawnTree` carries the new parent -> child edge, committed
///    rather than merely reserved.
///
/// The `SessionRegistry` half of "a real child session" — a live, running
/// actor — is `roundhouse-daemon`'s to prove, since `create_headless_session`
/// and `SessionRegistry` live there and nothing may depend on that crate;
/// `sub_agent_host::tests::an_agent_tool_call_creates_a_real_registered_child_with_a_durable_parent_edge`
/// covers it over real daemon resources.
#[tokio::test]
async fn an_agent_tool_call_mints_a_real_tracked_child_session_through_the_real_loop() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(
        dir.path(),
        dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )],
    )
    .await;
    let host = with_host(&fx, Arc::new(RecordingSubAgentHost::new(fx.writer.clone())));

    let blocks = drive(&fx, None, "agent", agent_call_args()).await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the model-issued spawn must succeed, got {:?}",
        results[0].1
    );

    // 1. The parent's own log carries exactly one `agent` task.
    let parent_events = events_for(&fx, fx.session_id).await;
    let kinds = created_task_kinds(&parent_events);
    assert_eq!(
        kinds.iter().filter(|k| **k == TaskKind::Agent).count(),
        1,
        "exactly one TaskKind::Agent task must be recorded, saw {kinds:?}"
    );
    assert!(failure_categories(&parent_events).is_empty());

    // 3. The spawn tree carries one committed edge and no dangling
    //    reservation. Read before (2) so the child's id comes from the tree
    //    itself rather than from the host's own bookkeeping.
    assert_eq!(host.tree.direct_children(fx.session_id), 1);
    assert_eq!(host.tree.reserved_children(fx.session_id), 0);
    let descendants = host.tree.descendants(fx.session_id);
    assert_eq!(descendants.len(), 1);
    let child = descendants[0];
    assert_eq!(
        host.created(),
        vec![child],
        "the session the tree committed must be the session that was created — one spawn, \
         one id, everywhere"
    );
    assert!(
        results[0].1.contains(&child.to_string()),
        "the model must be told which session it spawned, got {:?}",
        results[0].1
    );

    // 2. A real child session: its own durable `SessionCreated`, on its own
    //    log, naming its parent. This is the fact boot-time spawn-tree
    //    recovery reads (`reconcile_spawn_tree`), so asserting it here is
    //    asserting the child is recoverable, not merely remembered.
    let child_events = events_for(&fx, child).await;
    let specs: Vec<SessionSpec> = child_events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::SessionCreated { spec, .. } => Some((**spec).clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        specs.len(),
        1,
        "the child must have exactly one SessionCreated of its own"
    );
    assert_eq!(
        specs[0].parent,
        Some(fx.session_id),
        "the durable parent edge must name the spawning session"
    );
    assert_eq!(
        specs[0].requested_tier,
        Tier::Sandbox,
        "a spawned child asks for the most restrictive real tier, never the parent's"
    );

    // §7.7: the budget transfer is a debit against the parent, not a copy.
    assert_eq!(host.budget.lock().unwrap().remaining_tokens, 700);
}

/// **The human-join guard's own call site, reached through the real loop.**
/// The retired pin's second claim was that the guard *"never fires"* because
/// nothing a model could call reached `agent_spawn`. The guard itself lives
/// inside `TeamRegistry::join` (and `TeamRegistry::create_team`), and
/// `agent_spawn`'s §7.5 auto-join is the call `dispatch_agent` now makes on
/// every spawn whose parent is on a team.
///
/// This test proves that call really is on the real loop's path: a parent
/// that is a team member spawns through a model-issued `agent` call, and the
/// child lands on that team's roster as a `worker`. Every membership the
/// guard could ever reject arrives through this one call — so a passing
/// assertion here is what makes "the guard is reachable" a fact rather than
/// an inference.
///
/// The rejection half — a session marked human via the real socket handshake
/// being refused by both the `join` arm and the `create_team` arm, against
/// the one `TeamRegistry` the real daemon assembles — belongs to
/// `roundhouse-daemon`, which is where `mark_human`/`register_human` are
/// wired: see `submit_turn_e2e.rs`'s `human_join_guard` module. It cannot be
/// written here, because a freshly minted child session is never a human one.
#[tokio::test]
async fn a_spawned_childs_team_auto_join_runs_through_the_real_loop_where_the_human_guard_lives() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(
        dir.path(),
        dir.path().join("state"),
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )],
    )
    .await;

    let mut host = RecordingSubAgentHost::new(fx.writer.clone());
    // The parent creates, and is therefore the first member of, a real team.
    // `agent_spawn` refuses outright for a parent that is not a current
    // member, so without this the auto-join below would never be attempted.
    let team = host
        .teams
        .create_team(
            fx.actor.session_spec().workspace,
            "reviewers".to_string(),
            "review the diff".to_string(),
            fx.session_id,
            "lead".to_string(),
        )
        .expect("a non-human session may create a team");
    host.team = Some(team);
    let host = with_host(&fx, Arc::new(host));

    let blocks = drive(&fx, None, "agent", agent_call_args()).await;
    let results = tool_results(&blocks);
    assert!(
        !results[0].0,
        "the spawn must succeed, got {:?}",
        results[0].1
    );

    let child = host.tree.descendants(fx.session_id)[0];
    let roster = host
        .teams
        .roster(team)
        .expect("the team the parent created must still exist");
    let child_membership = roster.iter().find(|m| m.session == child).expect(
        "the spawned child must have gone through TeamRegistry::join — the exact \
                 call the human-join guard rejects for a human session",
    );
    assert_eq!(child_membership.role, "worker", "§7.5's default role");
    assert!(!child_membership.ended);
}
