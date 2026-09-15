//! Phase 8, L5 Task 3 — the `agent` tool's model-reachable spawn path.
//!
//! Proves the ordering contract `Executor::dispatch_call`
//! (`roundhouse-flow`'s `run_loop.rs`) establishes for workflow `call:`
//! children, now applied to sub-agent spawning: reserve → admit → create →
//! commit, releasing the reservation on every failure edge.
//!
//! Every test here drives the REAL loop — a scripted `Provider` returns a
//! `ContentBlock::ToolUse { name: "agent", .. }` and `run_agent_loop`
//! resolves, admits and dispatches it — rather than calling the dispatcher
//! directly, because "a model can actually reach this" is the property the
//! whole task exists to establish.
//!
//! The daemon-side half (a real `HeadlessSession`, a real registry entry, a
//! real `SessionCreated` row) is proven in `roundhouse-daemon`'s own
//! `sub_agent_host` tests; this suite supplies a recording [`FakeHost`] so
//! the ordering and the release-on-failure edges can be exercised without a
//! daemon.

use std::sync::{Arc, Mutex};

use futures::stream;
use roundhouse_bus::limits::{MAX_DEPTH, MAX_FAN_OUT};
use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{
    EventPayload, OnDegrade, SessionId, SessionSpec, SessionState, TaskKind, TeamId, Tier,
};
use roundhouse_engine::agent_loop::{run_agent_loop, AgentLoopConfig};
use roundhouse_engine::agent_spawn::Budget;
use roundhouse_engine::tool_catalog::{builtin_tool_defs, resolve_tool_target, ToolTarget};
use roundhouse_engine::tools::agent_spawn_tool::{
    ChildSessionError, ChildSessionRequest, SubAgentHost,
};
use roundhouse_engine::SessionActor;
use roundhouse_policy::engine::{CompiledRule, Outcome, PolicyEngine, Predicate, Scope};
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ContentBlock,
    HttpRequest, HttpResponseStream, HttpTransport, ModelId, Params, Plan, Provider, ProviderError,
    ReasoningRequest, RequestCtx, RequestPolicy, ResponseFormat, StreamEvent, TokenCount,
    ToolChoice, TransportError,
};
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
};
use roundhouse_store::{open, session_events, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call per process, and every
/// test in this binary shares one — the same single-instance pattern every
/// other integration suite in this crate uses.
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

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
        ext: roundhouse_provider::ProviderExt::None,
        extra: std::collections::BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// A host-independent isolate: these tests never spawn a child process, and
/// requiring bwrap would make the suite fail on hosts that lack it.
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
    async fn prepare(&self, _spec: &SessionSpec) -> Result<Handle, IsolationError> {
        Ok(Handle {
            id: "test-isolate".into(),
        })
    }
    async fn spawn(
        &self,
        _handle: &Handle,
        _command: CommandSpec,
    ) -> Result<Child, IsolationError> {
        Err(IsolationError::Unsupported(
            "the agent tool never spawns a process".into(),
        ))
    }
    fn attest(&self, _handle: &Handle) -> Attestation {
        Attestation {
            tier: Tier::Sandbox,
            digest: "test-isolate".into(),
            net_enforced: false,
        }
    }
    async fn teardown(&self, _handle: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

/// A `Provider` that asks for one `agent` tool call, then stops.
struct ScriptedAgentCall {
    input: serde_json::Value,
    calls: std::sync::atomic::AtomicU32,
}

impl Provider for ScriptedAgentCall {
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
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let args = self.input.to_string();
        Box::pin(async move {
            let events = if call == 0 {
                vec![
                    StreamEvent::BlockStart {
                        index: 0,
                        kind: BlockKind::ToolUse {
                            name: "agent".to_string(),
                            provider_id: Some("call_0".to_string()),
                        },
                    },
                    StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::ToolArgsFragment(args),
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

/// A recording [`SubAgentHost`] over a REAL [`SpawnTree`] and a real
/// [`TeamRegistry`] — only the "create the child session" step, the one thing
/// that genuinely lives in `roundhouse-daemon`, is faked.
struct FakeHost {
    tree: Arc<SpawnTree>,
    teams: TeamRegistry,
    budget: Arc<Mutex<Budget>>,
    depth: u8,
    team: Option<TeamId>,
    /// When set, `create_child_session` fails instead of recording — the
    /// step-5 failure edge.
    create_fails: bool,
    created: Mutex<Vec<CreatedChild>>,
}

/// One `create_child_session` call, as the daemon-side host would have
/// received it.
#[derive(Clone)]
struct CreatedChild {
    parent: SessionId,
    child: SessionId,
    spec: SessionSpec,
    depth: u8,
    budget: Budget,
}

impl FakeHost {
    fn new(budget_tokens: u64) -> Self {
        FakeHost {
            tree: Arc::new(SpawnTree::new()),
            teams: TeamRegistry::new(),
            budget: Arc::new(Mutex::new(Budget {
                remaining_tokens: budget_tokens,
            })),
            depth: 0,
            team: None,
            create_fails: false,
            created: Mutex::new(Vec::new()),
        }
    }

    fn created(&self) -> Vec<CreatedChild> {
        self.created.lock().unwrap().clone()
    }

    fn remaining_tokens(&self) -> u64 {
        self.budget.lock().unwrap().remaining_tokens
    }
}

#[async_trait::async_trait]
impl SubAgentHost for FakeHost {
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
        if self.create_fails {
            return Err(ChildSessionError {
                category: "session_construction_timeout",
                detail: "the fake host was told to fail".to_string(),
            });
        }
        self.created.lock().unwrap().push(CreatedChild {
            parent: req.parent,
            child: req.child,
            spec: req.spec,
            depth: req.depth,
            budget: req.child_budget,
        });
        Ok(())
    }
}

struct Fixture {
    actor: Arc<SessionActor>,
    db_path: std::path::PathBuf,
    session_id: SessionId,
    host: Arc<FakeHost>,
}

/// Builds a real `SessionActor` with `host` registered (when `Some`) and a
/// policy that allows `agent` spawns against any provider at any tier — the
/// rule an operator would write to permit sub-agents at all. Without it
/// `PolicyEngine::decide` falls through to its `Ask` default and every spawn
/// is refused before it starts, which is correct but tests nothing else.
async fn fixture(dir: &std::path::Path, host: Option<Arc<FakeHost>>) -> Fixture {
    fixture_with_rules(
        dir,
        host,
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Allow,
            Predicate::agent(None, None, Tier::None),
        )],
    )
    .await
}

async fn fixture_with_rules(
    dir: &std::path::Path,
    host: Option<Arc<FakeHost>>,
    rules: Vec<CompiledRule>,
) -> Fixture {
    let db_path = dir.join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let session_id = SessionId::new();

    let actor = Arc::new(SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        Arc::new(PolicyEngine::from_rules(rules)),
        dir.join("state"),
        dir.join("daemon-binary"),
        dir.canonicalize().unwrap(),
        isolate,
        handle,
        spec,
        builtin_tool_defs(),
    ));

    let host = host.unwrap_or_else(|| Arc::new(FakeHost::new(1_000)));
    actor.register_sub_agent_host(host.clone());

    Fixture {
        actor,
        db_path,
        session_id,
        host,
    }
}

/// Drives one real turn whose single tool call is `agent` with `args`.
async fn drive(fx: &Fixture, args: serde_json::Value) -> Vec<ContentBlock> {
    let tools = fx.actor.tool_defs().to_vec();
    let provider = ScriptedAgentCall {
        input: args,
        calls: std::sync::atomic::AtomicU32::new(0),
    };
    let ctx = fake_ctx();
    run_agent_loop(
        &fx.actor,
        &RUNNER,
        &provider,
        &ctx,
        &tools,
        None,
        empty_request(),
        AgentLoopConfig {
            max_turns: 4,
            max_tool_calls_per_turn: 4,
        },
    )
    .await
    .unwrap()
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
                    .map(|p| p.text.as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            )),
            _ => None,
        })
        .collect()
}

/// Every `TaskKind` a `TaskCreated` was recorded under, in order.
async fn created_task_kinds(fx: &Fixture) -> Vec<TaskKind> {
    let reopened = open(&fx.db_path).await.unwrap();
    session_events(&reopened, fx.session_id)
        .await
        .unwrap()
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskCreated { kind, .. } => Some(kind.clone()),
            _ => None,
        })
        .collect()
}

/// The `category` of every `TaskFailed` recorded for this session.
async fn failure_categories(fx: &Fixture) -> Vec<String> {
    let reopened = open(&fx.db_path).await.unwrap();
    session_events(&reopened, fx.session_id)
        .await
        .unwrap()
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskFailed { error, .. } => Some(error.category.to_string()),
            _ => None,
        })
        .collect()
}

fn agent_args(budget_tokens: u64) -> serde_json::Value {
    serde_json::json!({
        "prompt": "do some work in a child session",
        "provider": "anthropic",
        "budget_tokens": budget_tokens,
    })
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[test]
fn the_agent_tool_name_resolves_to_a_real_dispatch_target_and_is_offered_to_the_model() {
    assert!(
        matches!(
            resolve_tool_target("agent"),
            Some(ToolTarget::Builtin(TaskKind::Agent))
        ),
        "`agent` must resolve to the sub-agent spawn builtin"
    );
    assert!(
        builtin_tool_defs().iter().any(|d| d.name() == "agent"),
        "the builtin catalog must offer an `agent` ToolDef, or no model can ever call it"
    );
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_model_issued_agent_call_creates_a_tracked_child_session() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), None).await;

    let blocks = drive(&fx, agent_args(300)).await;

    let results = tool_results(&blocks);
    assert_eq!(results.len(), 1);
    assert!(
        !results[0].0,
        "the spawn must succeed, got {:?}",
        results[0].1
    );

    // The spawn tree gained exactly one COMMITTED direct child, and holds no
    // dangling reservation.
    assert_eq!(fx.host.tree.direct_children(fx.session_id), 1);
    assert_eq!(fx.host.tree.reserved_children(fx.session_id), 0);

    // A real child session was asked for, with the durable parent edge on its
    // own spec and the depth §7.7 admitted.
    let created = fx.host.created();
    assert_eq!(created.len(), 1);
    let child_request = &created[0];
    assert_eq!(child_request.parent, fx.session_id);
    assert_eq!(
        child_request.spec.parent,
        Some(fx.session_id),
        "the child's own SessionSpec must carry the durable parent edge"
    );
    assert_eq!(
        child_request.depth, 1,
        "a root session's child sits at depth 1"
    );
    assert!(
        results[0].1.contains(&child_request.child.to_string()),
        "the model must be told which session it spawned, got {:?}",
        results[0].1
    );

    // §7.7: the transfer is a debit, not a copy — and the transferred half
    // reaches the implementor, which is what lets the CHILD's own host start
    // from what it was actually given rather than from a fresh default.
    assert_eq!(fx.host.remaining_tokens(), 700);
    assert_eq!(child_request.budget.remaining_tokens, 300);

    // The parent's task log carries exactly one `agent` task.
    let kinds = created_task_kinds(&fx).await;
    assert_eq!(
        kinds.iter().filter(|k| **k == TaskKind::Agent).count(),
        1,
        "exactly one TaskKind::Agent task must be recorded, saw {kinds:?}"
    );
    assert!(
        failure_categories(&fx).await.is_empty(),
        "a successful spawn records no TaskFailed"
    );
}

#[tokio::test]
async fn the_committed_child_is_the_same_session_the_tree_reserved_and_the_spec_names() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), None).await;

    drive(&fx, agent_args(10)).await;

    let created = fx.host.created();
    let child_request = &created[0];
    assert_eq!(
        child_request.spec.name,
        Some(format!("agent-{}", &child_request.child.to_string()[..8])),
        "the handle, the reserved id and the persisted spec must all name ONE session"
    );
    // `descendants` reads committed edges only, so this also proves the
    // reservation was committed under the same id.
    assert_eq!(
        fx.host.tree.descendants(fx.session_id),
        vec![child_request.child]
    );
}

// ---------------------------------------------------------------------------
// Release-on-failure edges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_spawn_refused_by_the_depth_limit_releases_its_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = FakeHost::new(1_000);
    // A parent already at the deepest legal level: its child would be
    // `MAX_DEPTH + 1`, which `agent_spawn`'s `check_depth` refuses — AFTER
    // the reservation has already been taken.
    host.depth = MAX_DEPTH;
    let fx = fixture(dir.path(), Some(Arc::new(host))).await;

    let blocks = drive(&fx, agent_args(10)).await;

    let results = tool_results(&blocks);
    assert!(results[0].0, "a too-deep spawn must be refused");
    assert_eq!(
        fx.host.tree.reserved_children(fx.session_id),
        0,
        "the reservation must be released, or eight refused spawns would permanently \
         exhaust a parent that never got a child"
    );
    assert_eq!(fx.host.tree.direct_children(fx.session_id), 0);
    assert!(fx.host.created().is_empty());
    assert_eq!(
        fx.host.remaining_tokens(),
        1_000,
        "a spawn refused before the transfer leaves the budget untouched"
    );
    assert_eq!(
        failure_categories(&fx).await,
        vec!["depth_limit_exceeded".to_string()]
    );
}

#[tokio::test]
async fn a_spawn_refused_for_insufficient_budget_releases_its_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), Some(Arc::new(FakeHost::new(100)))).await;

    let blocks = drive(&fx, agent_args(300)).await;

    assert!(tool_results(&blocks)[0].0);
    assert_eq!(fx.host.tree.reserved_children(fx.session_id), 0);
    assert_eq!(fx.host.tree.direct_children(fx.session_id), 0);
    assert_eq!(fx.host.remaining_tokens(), 100);
    assert_eq!(
        failure_categories(&fx).await,
        vec!["insufficient_budget".to_string()]
    );
}

#[tokio::test]
async fn a_saturated_parent_refuses_the_ninth_spawn_without_consuming_a_slot() {
    let dir = tempfile::tempdir().unwrap();
    let host = Arc::new(FakeHost::new(10_000));
    let fx = fixture(dir.path(), Some(host)).await;

    // Eight committed children — the §7.7 ceiling — recorded directly, so
    // this test is about the ninth, not about eight full spawns.
    for _ in 0..MAX_FAN_OUT {
        fx.host.tree.record_child(fx.session_id, SessionId::new());
    }

    let blocks = drive(&fx, agent_args(10)).await;

    assert!(
        tool_results(&blocks)[0].0,
        "the ninth spawn must be refused"
    );
    assert_eq!(
        fx.host.tree.direct_children(fx.session_id),
        MAX_FAN_OUT,
        "a refused ninth spawn must not change the parent's committed children"
    );
    assert_eq!(fx.host.tree.reserved_children(fx.session_id), 0);
    assert!(fx.host.created().is_empty());
    assert_eq!(
        failure_categories(&fx).await,
        vec!["fan_out_limit_exceeded".to_string()]
    );
}

#[tokio::test]
async fn a_failed_child_creation_releases_the_reservation_and_refunds_the_transfer() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = FakeHost::new(1_000);
    host.create_fails = true;
    let fx = fixture(dir.path(), Some(Arc::new(host))).await;

    let blocks = drive(&fx, agent_args(300)).await;

    let results = tool_results(&blocks);
    assert!(results[0].0);
    assert!(
        !results[0].1.contains("fake host"),
        "the host's own failure detail must not reach the model, got {:?}",
        results[0].1
    );
    assert_eq!(
        fx.host.tree.reserved_children(fx.session_id),
        0,
        "a child that was never created must not keep holding a slot"
    );
    assert_eq!(fx.host.tree.direct_children(fx.session_id), 0);
    assert_eq!(
        fx.host.remaining_tokens(),
        1_000,
        "a child that was never created must not permanently cost the parent its tokens"
    );
    assert_eq!(
        failure_categories(&fx).await,
        vec!["session_construction_timeout".to_string()],
        "the host's own static category is what the log records"
    );
    // Still one real, queryable `agent` task: a failed spawn is an attempt.
    assert_eq!(
        created_task_kinds(&fx)
            .await
            .iter()
            .filter(|k| **k == TaskKind::Agent)
            .count(),
        1
    );
}

// ---------------------------------------------------------------------------
// Refusals before the reservation is ever taken
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_spawn_denied_by_the_parents_own_policy_never_reserves_a_slot() {
    let dir = tempfile::tempdir().unwrap();
    // A rule that denies `agent` spawns outright. `Predicate::Agent` is
    // reachable from model output for the first time because of this tool —
    // this is the test that proves it.
    let fx = fixture_with_rules(
        dir.path(),
        None,
        vec![CompiledRule::test_new(
            Scope::Project,
            Outcome::Deny,
            Predicate::agent(None, None, Tier::None),
        )],
    )
    .await;

    let blocks = drive(&fx, agent_args(10)).await;

    assert!(tool_results(&blocks)[0].0);
    assert_eq!(fx.host.tree.reserved_children(fx.session_id), 0);
    assert_eq!(fx.host.tree.direct_children(fx.session_id), 0);
    assert!(fx.host.created().is_empty());
    assert_eq!(
        failure_categories(&fx).await,
        vec!["policy_denied".to_string()]
    );
}

#[tokio::test]
async fn a_session_with_no_sub_agent_host_refuses_agent_calls_but_still_records_the_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), None).await;
    // Rebuild an actor with no host registered: the library-fixture shape,
    // and any session created before the daemon wires one.
    let db_path = dir.path().join("hostless.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let isolate: Arc<dyn Isolate> = Arc::new(TestIsolate);
    let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
    let handle = isolate.prepare(&spec).await.unwrap();
    let session_id = SessionId::new();
    let actor = Arc::new(SessionActor::new_with_workspace_root(
        session_id,
        writer,
        SessionState::Running,
        &RUNNER,
        Arc::new(PolicyEngine::from_rules(vec![])),
        dir.path().join("state"),
        dir.path().join("daemon-binary"),
        dir.path().canonicalize().unwrap(),
        isolate,
        handle,
        spec,
        builtin_tool_defs(),
    ));
    let hostless = Fixture {
        actor,
        db_path,
        session_id,
        host: fx.host,
    };

    let blocks = drive(&hostless, agent_args(10)).await;

    let results = tool_results(&blocks);
    assert!(results[0].0);
    assert!(
        results[0].1.contains("not available"),
        "the refusal must be honest about the capability being absent, got {:?}",
        results[0].1
    );
    assert_eq!(
        failure_categories(&hostless).await,
        vec!["sub_agent_host_unavailable".to_string()],
        "a refused call is still a real, queryable attempt"
    );
}

#[tokio::test]
async fn a_malformed_agent_call_is_refused_by_field_name_without_reserving_anything() {
    let dir = tempfile::tempdir().unwrap();
    let fx = fixture(dir.path(), None).await;

    let blocks = drive(
        &fx,
        serde_json::json!({ "prompt": "work", "budget_tokens": 10 }),
    )
    .await;

    let results = tool_results(&blocks);
    assert!(results[0].0);
    assert!(
        results[0].1.contains("`provider`"),
        "the model must be told which argument is wrong, got {:?}",
        results[0].1
    );
    assert_eq!(fx.host.tree.reserved_children(fx.session_id), 0);
    assert_eq!(
        failure_categories(&fx).await,
        vec!["bad_tool_arguments".to_string()]
    );
}
