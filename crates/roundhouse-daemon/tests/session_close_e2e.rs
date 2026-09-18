//! Phase 8, T19a Task 9 (plan items (a-close) and (b)): the close half of
//! session lifecycle, proven end to end through the **real** daemon — a real
//! Unix socket, a real `accept_loop`, a real `create_real_session`, and
//! `roundhouse_tui::DaemonClient::close_session` — exactly the shape
//! `submit_turn_e2e.rs` already uses for the open half. The `Daemon`
//! fixture, `wait_for_event`, and `ScriptedText/ToolCallProvider` below are
//! copied from that file rather than shared: `tests/*.rs` files are each
//! their own crate, and only `tests/common` is actually shared code.
//!
//! - `a_creator_closing_after_a_completed_turn_...`: (a-close) — a plain
//!   text turn runs to completion, the creator closes, and the durable log,
//!   the `tasks` view, and the daemon's own bookkeeping (registry entry,
//!   egress-proxy token) all agree the session is gone.
//! - `closing_while_a_shell_is_in_flight_...`: (b) — a real, in-flight shell
//!   process is killed by the close, and the sweep's `TaskCancelled`
//!   durably precedes the `SessionClosed{Cancelled}` terminator, which nothing
//!   follows.
//!
//! Neither test uses the daemon's real `BwrapLandlockIsolate`: (b) needs a
//! real OS process to kill, not real bwrap/Landlock sandboxing around it, and
//! `roundhouse-engine`'s own test suite already draws that same line (see
//! `agent_loop_dispatch.rs`'s `TestIsolate` doc comment — "the dedicated
//! hard-prerequisite suite owns real bwrap/Landlock coverage; keeping this
//! fixture host-independent prevents ordinary engine tests from failing on
//! CI hosts that do not install bwrap"). `TestIsolate` below is that same
//! fixture, copied for the identical reason.
//!
//! The break-it check (removing `SessionActor::close`'s own
//! `writer.close_session` call, confirming (a-close) and
//! `spawn_tree_boot_recovery.rs`'s cascade test both fail, then restoring it
//! byte-identically) is recorded in this lane's own report, not as a
//! committed test — the mutation itself is never landed.

mod common;

use std::sync::Arc;
use std::time::Duration;

use futures::stream;
use roundhouse_core::{
    CancelReason, EventPayload, Origin, SessionId, SessionOutcome, SessionSpec, SessionState,
    TaskKind, Tier,
};
use roundhouse_daemon::session_bootstrap::{no_policy_rules, PolicyRuleSource};
use roundhouse_policy::engine::{ArgMatcher, CompiledRule, Outcome, Predicate, Scope};
use roundhouse_proto::ClientRequest;
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ModelId, ModelInfo, Plan,
    Provider, ProviderError, RequestCtx, StreamEvent, TokenCount,
};
use roundhouse_sandbox::{
    Attestation, Child, CommandSpec, Handle, Isolate, IsolationError, ProbeResult,
};
use roundhouse_store::{fold_task, open, session_events, EventFields, StoredEvent};

/// A deterministic, host-independent child-spawning isolate for (b) — copied
/// from `roundhouse-engine`'s `agent_loop_dispatch.rs::TestIsolate` (same
/// shape, same rationale: a real OS process to kill, no real sandboxing
/// wrapper around it).
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

    async fn spawn(&self, _handle: &Handle, command: CommandSpec) -> Result<Child, IsolationError> {
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

/// A single-turn scripted `Provider` returning one final text block and no
/// tool calls. Copied from `submit_turn_e2e.rs`'s `ScriptedTextOnlyProvider`
/// (same name, same shape).
struct ScriptedTextOnlyProvider {
    text: String,
}

impl Provider for ScriptedTextOnlyProvider {
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
        let text = self.text.clone();
        Box::pin(async move {
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text(text),
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
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// A single-turn scripted `Provider` that always asks for one `ToolUse`
/// call (never a follow-up text-only turn) — (b) needs the dispatched shell
/// to stay in flight until the close cancels it, so, unlike
/// `submit_turn_e2e.rs`'s `ScriptedToolCallProvider`, this must never offer
/// a second, tool-free turn for the loop to settle into on its own.
struct ScriptedSingleShellCallProvider {
    input: serde_json::Value,
}

impl Provider for ScriptedSingleShellCallProvider {
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
        let tool_args = self.input.to_string();
        Box::pin(async move {
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::ToolUse {
                        name: "shell".to_string(),
                        provider_id: Some("call_0".to_string()),
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
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// Polls this session's real, on-disk event log until `pred` matches one of
/// its events, or the bound elapses. Copied from `submit_turn_e2e.rs`.
async fn wait_for_event(
    db_path: &std::path::Path,
    session_id: SessionId,
    what: &str,
    pred: impl Fn(&EventPayload) -> bool,
) -> Vec<StoredEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let store = open(db_path).await.unwrap();
        let events = session_events(&store, session_id).await.unwrap();
        if events.iter().any(|e| pred(&e.payload)) {
            return events;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {what} in session {session_id}'s event log; \
             saw {} events",
            events.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Polls this session's own durable event log until a `TaskCreated { kind,
/// .. }` matching `kind` has a corresponding `TaskStarted` for the SAME task
/// id, then returns that task id. Adapted from `agent_loop_dispatch.rs`'s
/// `wait_for_task_started` (same non-sleep-signal shape), returning the task
/// id rather than discarding it: (b) needs it afterward to find that exact
/// task's own `TaskCancelled` event, not just any `TaskCancelled` in the
/// swept log.
async fn wait_for_task_started(
    db_path: &std::path::Path,
    session_id: SessionId,
    kind: TaskKind,
) -> roundhouse_core::TaskId {
    let store = open(db_path).await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let events = session_events(&store, session_id).await.unwrap();
        let target_task_id = events.iter().find_map(|e| match &e.payload {
            EventPayload::TaskCreated { kind: k, .. } if *k == kind => e.task_id,
            _ => None,
        });
        if let Some(task_id) = target_task_id {
            if events.iter().any(|e| {
                e.task_id == Some(task_id) && matches!(&e.payload, EventPayload::TaskStarted { .. })
            }) {
                return task_id;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a {kind:?} TaskStarted in session {session_id}'s event log; \
             saw {:?}",
            events.iter().map(|e| &e.payload).collect::<Vec<_>>()
        );
        tokio::task::yield_now().await;
    }
}

/// Fixture: a live daemon over a real socket, driven by `provider`. Copied
/// from `submit_turn_e2e.rs`'s `Daemon`/`start_daemon*` family.
struct Daemon {
    _dir: tempfile::TempDir,
    socket_path: std::path::PathBuf,
    db_path: std::path::PathBuf,
    registry: Arc<roundhouse_daemon::session_registry::SessionRegistry>,
    resources: Arc<roundhouse_daemon::session_bootstrap::DaemonResources>,
}

async fn start_daemon(provider: Arc<dyn Provider>) -> Daemon {
    start_daemon_with_rules(provider, no_policy_rules()).await
}

async fn start_daemon_with_rules(
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
) -> Daemon {
    start_daemon_with_rules_at_root(provider, policy_rules, None, None).await
}

async fn start_daemon_with_rules_at_root(
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
    workspace_name: Option<&str>,
    workspace_root: Option<&std::path::Path>,
) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let db_path = dir.path().join("events.db");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources =
        common::resources_with_provider_and_rules(dir.path(), provider, policy_rules).await;
    if let (Some(name), Some(root)) = (workspace_name, workspace_root) {
        resources
            .workspace_registry
            .as_ref()
            .unwrap()
            .register(
                roundhouse_daemon::workspace_registry::WorkspaceRegistration::new(
                    name,
                    root.to_path_buf(),
                ),
            )
            .await
            .unwrap();
    }
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        Arc::clone(&registry),
        Arc::clone(&resources),
    ));
    Daemon {
        _dir: dir,
        socket_path,
        db_path,
        resources,
        registry,
    }
}

/// [`start_daemon_with_rules_at_root`], but over a caller-supplied
/// `isolate` — (b) needs [`TestIsolate`], not the real
/// `BwrapLandlockIsolate` `common::resources_with_provider_and_rules`
/// hardcodes, for the reason this file's own module doc comment gives.
async fn start_daemon_with_isolate_rules_at_root(
    isolate: Arc<dyn Isolate>,
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
    workspace_name: &str,
    workspace_root: &std::path::Path,
) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let db_path = dir.path().join("events.db");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::resources_with(dir.path(), isolate, provider, policy_rules).await;
    resources
        .workspace_registry
        .as_ref()
        .unwrap()
        .register(
            roundhouse_daemon::workspace_registry::WorkspaceRegistration::new(
                workspace_name,
                workspace_root.to_path_buf(),
            ),
        )
        .await
        .unwrap();
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        Arc::clone(&registry),
        Arc::clone(&resources),
    ));
    Daemon {
        _dir: dir,
        socket_path,
        db_path,
        resources,
        registry,
    }
}

/// Every task_id appearing anywhere in `events`, in first-appearance order.
fn distinct_task_ids(events: &[StoredEvent]) -> Vec<roundhouse_core::TaskId> {
    let mut ids = Vec::new();
    for event in events {
        if let Some(task_id) = event.task_id {
            if !ids.contains(&task_id) {
                ids.push(task_id);
            }
        }
    }
    ids
}

/// One row of the `tasks` materialized-cache table, read back with a raw
/// query — `roundhouse-store` exposes no typed reader for it outside the
/// crate (`tasks_view.rs` is internal), so this mirrors
/// `roundhouse-store/tests/tasks_view.rs`'s own `fetch_tasks_row` exactly.
struct TasksRow {
    kind: String,
    state: String,
}

async fn fetch_tasks_row(db_path: &std::path::Path, task_id: roundhouse_core::TaskId) -> TasksRow {
    let store = open(db_path).await.unwrap();
    let task_id_str = task_id.to_string();
    store
        .pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            conn.query_row(
                "SELECT kind, state FROM tasks WHERE task_id = ?1",
                [task_id_str],
                |row| {
                    Ok(TasksRow {
                        kind: row.get(0)?,
                        state: row.get(1)?,
                    })
                },
            )
            .unwrap()
        })
        .await
        .unwrap()
}

/// (a-close): a creator submits an ordinary text turn, waits for it to
/// complete, then closes. Every durable and in-memory signal must agree the
/// session is gone.
#[tokio::test]
async fn a_creator_closing_after_a_completed_turn_durably_closes_and_reaps_the_session() {
    let provider = Arc::new(ScriptedTextOnlyProvider {
        text: "all done".to_string(),
    });
    let daemon = start_daemon(provider).await;

    let mut creator = tokio::time::timeout(
        Duration::from_secs(5),
        roundhouse_tui::connect_create(&daemon.socket_path, "default"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id = creator.session_id();

    creator
        .send(&ClientRequest::SubmitTurn {
            session_id,
            text: "hello".to_string(),
        })
        .await
        .unwrap();

    wait_for_event(&daemon.db_path, session_id, "a completed chat task", |p| {
        matches!(
            p,
            EventPayload::TaskCreated {
                kind: TaskKind::Chat,
                ..
            }
        )
    })
    .await;
    wait_for_event(&daemon.db_path, session_id, "a completed chat task", |p| {
        matches!(p, EventPayload::TaskCompleted { .. })
    })
    .await;

    // Captured BEFORE closing: the live actor's own state watch, which the
    // reaper this call's Ack races against will eventually tear the
    // registry entry out from under — see this test's own module doc
    // comment and the brief's own instruction to grab this first.
    let actor = daemon
        .registry
        .actor(session_id)
        .expect("the session must still be registered before it is ever closed");
    let mut state_rx = actor.subscribe();

    creator
        .close_session()
        .await
        .expect("close_session must succeed: nothing was in flight, no in-flight turn either");

    // The in-memory watch must already show `Closed` — `close_session`'s Ack
    // only arrives after `SessionActor::close` has already set it, strictly
    // before the reaper's own (separately racing) teardown work begins.
    while *state_rx.borrow() != SessionState::Closed {
        state_rx
            .changed()
            .await
            .expect("the actor must not be dropped before reaching Closed");
    }

    // The durable log must agree, independently: fold_session_state over the
    // raw event log reaches the identical terminal state the live watch
    // already reached.
    let store = open(&daemon.db_path).await.unwrap();
    let events = session_events(&store, session_id).await.unwrap();
    let payloads: Vec<EventPayload> = events.iter().map(|e| e.payload.clone()).collect();
    assert_eq!(
        roundhouse_core::fold_session_state(&payloads),
        Some(SessionState::Closed),
        "fold_session_state over the durable log must agree with the live watch"
    );

    // Exactly one SessionClosed, and it is the log's own last event —
    // nothing follows the terminator.
    let closed_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|e| matches!(e.payload, EventPayload::SessionClosed { .. }))
        .collect();
    assert_eq!(
        closed_events.len(),
        1,
        "exactly one SessionClosed terminator, got {events:?}"
    );
    assert!(
        matches!(
            closed_events[0].payload,
            EventPayload::SessionClosed {
                outcome: SessionOutcome::Completed
            }
        ),
        "nothing was in flight when this session closed, so its outcome must be Completed, \
         got {:?}",
        closed_events[0].payload
    );
    let closed_seq = closed_events[0].seq();
    assert!(
        events.iter().all(|e| e.seq() <= closed_seq),
        "the SessionClosed terminator must be the log's last event, got {events:?}"
    );

    // fold_task of every task in the log must agree with its own `tasks`
    // materialized-cache row.
    for task_id in distinct_task_ids(&events) {
        let task_events: Vec<StoredEvent> = events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .cloned()
            .collect();
        let folded = fold_task(&task_events).expect("every task_id came from a TaskCreated");
        let row = fetch_tasks_row(&daemon.db_path, task_id).await;
        assert_eq!(
            format!("{:?}", folded.kind),
            row.kind,
            "fold_task's kind must agree with the tasks view for {task_id}"
        );
        assert_eq!(
            format!("{:?}", folded.state),
            row.state,
            "fold_task's state must agree with the tasks view for {task_id}"
        );
    }

    // The registry and the egress proxy must both have been cleaned up —
    // asynchronously, by `spawn_session_reaper`, which this call's Ack does
    // not itself wait for (only the durable append). `registered_count`
    // reaching zero proves the proxy deregistration ran: this daemon
    // fixture creates exactly one session, so it is the only token that
    // could ever have been registered — see that method's own doc comment.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let reaped = daemon.registry.actor(session_id).is_none()
            && daemon.resources.proxy.registered_count() == 0;
        if reaped {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for spawn_session_reaper to reap this session: registry present = \
             {}, proxy registrations = {}",
            daemon.registry.actor(session_id).is_some(),
            daemon.resources.proxy.registered_count()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// (b): a real, in-flight shell process is killed by a close, and the sweep
/// durably precedes the terminator.
///
/// The dispatched program is a small shell script rather than `sleep`
/// directly (mirroring `roundhouse-engine`'s own
/// `a_session_cancelled_shell_dispatch_is_recorded_as_task_cancelled_not_task_failed`):
/// `roundhouse-tools`' executor execs `program`/`argv` directly with no
/// shell in the loop, so writing a pid file needs a real `#!/bin/sh`
/// interpreter, and this script `exec`s into `sleep` so the pid it records
/// (its own, before the `exec`) is the one live process this session's
/// close must kill — i.e. the whole (single-member) process group, not just
/// a wrapper around it.
#[tokio::test]
async fn closing_while_a_shell_is_in_flight_kills_it_and_orders_the_sweep_before_the_terminator() {
    let workspace_dir = tempfile::tempdir().unwrap();
    let workspace_root = workspace_dir.path().canonicalize().unwrap();
    let pid_file = workspace_root.join("shell.pid");
    let script_path = workspace_root.join("long_running.sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
            pid_file.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script_path, perms).unwrap();
    }
    let canonical_script = script_path.canonicalize().unwrap();

    let policy_rules: PolicyRuleSource = {
        let program = canonical_script.to_string_lossy().to_string();
        Arc::new(move || {
            vec![CompiledRule::test_new(
                Scope::Builtin,
                Outcome::Allow,
                Predicate::Shell {
                    program: program.clone(),
                    matcher: ArgMatcher::ArgvPrefix(vec![]),
                    allow_interpreter: false,
                },
            )]
        })
    };

    let provider = Arc::new(ScriptedSingleShellCallProvider {
        input: serde_json::json!({
            "program": "./long_running.sh",
            "argv": [],
            "cwd": workspace_root.to_string_lossy(),
        }),
    });
    let daemon = start_daemon_with_isolate_rules_at_root(
        Arc::new(TestIsolate),
        provider,
        policy_rules,
        "shellws",
        &workspace_root,
    )
    .await;

    let mut creator = tokio::time::timeout(
        Duration::from_secs(5),
        roundhouse_tui::connect_create(&daemon.socket_path, "shellws"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id = creator.session_id();

    creator
        .send(&ClientRequest::SubmitTurn {
            session_id,
            text: "please run the script".to_string(),
        })
        .await
        .unwrap();

    let shell_task_id = wait_for_task_started(&daemon.db_path, session_id, TaskKind::Shell).await;

    // The script only writes its pid AFTER TaskStarted has already been
    // recorded (`run_shell_dispatch` appends `TaskStarted` once the real
    // process is spawned, before this script has necessarily reached its
    // own first line) — poll the pid file itself rather than assume it is
    // already there.
    let shell_pid: i32 = {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file) {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    break trimmed.parse().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the shell script never wrote its pid to {}",
                pid_file.display()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    assert!(
        pid_running(shell_pid),
        "the shell process must be running before this test cancels it"
    );

    creator
        .close_session()
        .await
        .expect("close_session must succeed: the sweep cancels the in-flight shell");

    // By the time close_session's Ack has arrived, `SessionActor::close`'s
    // own `wait_idle` has already resolved — which only happens once the
    // shell dispatch's `WorkGuard` has dropped, which only happens after
    // `roundhouse_tools::cancel_running_shell` has itself already confirmed
    // the whole process group is dead (`run_shell_dispatch`'s own
    // `select!`/cancellation path). No poll is needed here.
    assert!(
        !pid_running(shell_pid),
        "the shell's process group must be dead once close_session's Ack has arrived"
    );

    let store = open(&daemon.db_path).await.unwrap();
    let events = session_events(&store, session_id).await.unwrap();

    let closed_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|e| matches!(e.payload, EventPayload::SessionClosed { .. }))
        .collect();
    assert_eq!(
        closed_events.len(),
        1,
        "exactly one SessionClosed terminator, got {events:?}"
    );
    assert!(
        matches!(
            closed_events[0].payload,
            EventPayload::SessionClosed {
                outcome: SessionOutcome::Cancelled
            }
        ),
        "the shell was still in flight when this session closed, so its outcome must be \
         Cancelled, got {:?}",
        closed_events[0].payload
    );
    let closed_seq = closed_events[0].seq();
    assert!(
        events.iter().all(|e| e.seq() <= closed_seq),
        "nothing may follow the SessionClosed terminator, got {events:?}"
    );

    let shell_cancelled = events
        .iter()
        .find(|e| {
            e.task_id == Some(shell_task_id)
                && matches!(
                    e.payload,
                    EventPayload::TaskCancelled {
                        by: Origin::System,
                        reason: CancelReason::SessionClosed,
                    }
                )
        })
        .unwrap_or_else(|| {
            panic!(
                "the shell task must be recorded as TaskCancelled{{System, SessionClosed}}, got \
                 {events:?}"
            )
        });
    assert!(
        shell_cancelled.seq() < closed_seq,
        "the shell's own TaskCancelled (seq {}) must durably precede SessionClosed (seq {})",
        shell_cancelled.seq(),
        closed_seq
    );
}

/// Linux-specific liveness check via `/proc/<pid>/stat`, copied from
/// `roundhouse-tools/tests/shell_cancel.rs`. Treats a zombie (already
/// signalled to death but not yet reaped) the same as "not running" — what
/// matters here is that the process has stopped executing, not that its pid
/// slot has been fully reclaimed.
fn pid_running(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, after_comm)) = stat.rsplit_once(')') else {
        return false;
    };
    let state = after_comm.trim_start().chars().next();
    !matches!(state, None | Some('Z'))
}
