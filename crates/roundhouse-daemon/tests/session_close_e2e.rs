//! Phase 8, T19a Task 9 (plan items (a-close) and (b)): the close half of
//! session lifecycle, proven end to end through the **real** daemon — a real
//! Unix socket, a real `accept_loop`, a real `create_real_session`, and
//! `roundhouse_tui::DaemonClient::close_session` — exactly the shape
//! `submit_turn_e2e.rs` already uses for the open half. The `Daemon`
//! fixture and `ScriptedText/ToolCallProvider` below are copied from that
//! file rather than shared: `tests/*.rs` files are each their own crate,
//! and only `tests/common` is actually shared code.
//!
//! - `a_creator_closing_after_a_completed_turn_...`: (a-close) — a plain
//!   text turn runs to completion, the creator closes, and the durable log,
//!   the `tasks` view, and the daemon's own bookkeeping (registry entry,
//!   egress-proxy token) all agree the session is gone. Uses the daemon's
//!   real `BwrapLandlockIsolate` — via `start_daemon` ->
//!   `common::resources_with_provider_and_rules` -> `available_isolate()`'s
//!   non-spawning `test_with_probe` variant, which is fine here because
//!   this test never actually dispatches a shell command.
//! - `closing_while_a_shell_is_in_flight_...`: (b) — a real, in-flight shell
//!   process is killed by the close, and the sweep's `TaskCancelled`
//!   durably precedes the `SessionClosed{Cancelled}` terminator, which nothing
//!   follows. Uses a local `TestIsolate` rather than the real isolate — see
//!   that test's own doc comment for why a real bwrap-wrapped attempt was
//!   tried first and could not work for what this test checks.
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

/// Polls this session's own durable event log until a `TaskCreated { kind,
/// .. }` matching `kind` has a corresponding `TaskStarted` for the SAME task
/// id, then waits for `matches_target` to hold for some event bearing that
/// SAME task id, returning the task id once it does. Adapted from
/// `agent_loop_dispatch.rs`'s `wait_for_task_started` (same non-sleep-signal
/// shape: correlating on the specific task id this kind minted, not just
/// "any event of the right shape anywhere in the log," matters whenever a
/// session runs more than one task of different kinds concurrently — a
/// `chat`/`infer` pair alongside a dispatched tool call, in every case this
/// file uses it for).
async fn wait_for_correlated_task_event(
    db_path: &std::path::Path,
    session_id: SessionId,
    kind: TaskKind,
    what: &str,
    matches_target: impl Fn(&EventPayload) -> bool,
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
            if events
                .iter()
                .any(|e| e.task_id == Some(task_id) && matches_target(&e.payload))
            {
                return task_id;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a {kind:?} {what} in session {session_id}'s event log; \
             saw {:?}",
            events.iter().map(|e| &e.payload).collect::<Vec<_>>()
        );
        tokio::task::yield_now().await;
    }
}

/// [`wait_for_correlated_task_event`], waiting for the `kind` task's own
/// `TaskStarted`.
async fn wait_for_task_started(
    db_path: &std::path::Path,
    session_id: SessionId,
    kind: TaskKind,
) -> roundhouse_core::TaskId {
    wait_for_correlated_task_event(db_path, session_id, kind, "TaskStarted", |p| {
        matches!(p, EventPayload::TaskStarted { .. })
    })
    .await
}

/// [`wait_for_correlated_task_event`], waiting for the `kind` task's own
/// `TaskCompleted` — needed because `chat.rs`'s `run_chat_turn` appends an
/// `infer` task's completion and the `chat` task's own completion as two
/// separate durable events; waiting on "any `TaskCompleted`" risks observing
/// the `infer` task's and closing mid-turn, before the `chat` task (and the
/// turn as a whole) has actually finished.
async fn wait_for_task_completed(
    db_path: &std::path::Path,
    session_id: SessionId,
    kind: TaskKind,
) -> roundhouse_core::TaskId {
    wait_for_correlated_task_event(db_path, session_id, kind, "TaskCompleted", |p| {
        matches!(p, EventPayload::TaskCompleted { .. })
    })
    .await
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

/// A daemon fixture in the default workspace, driven by `provider`, with no
/// operator policy rules — good enough for (a-close), which never dispatches
/// a tool call that would need one. (b) needs its own workspace root and an
/// `Allow` rule for its script, so it uses
/// [`start_daemon_with_isolate_rules_at_root`] directly instead.
async fn start_daemon(provider: Arc<dyn Provider>) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let db_path = dir.path().join("events.db");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources =
        common::resources_with_provider_and_rules(dir.path(), provider, no_policy_rules()).await;
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
    use rusqlite::OptionalExtension;

    let store = open(db_path).await.unwrap();
    let task_id_str = task_id.to_string();
    let row = store
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
            .optional()
        })
        .await
        .unwrap()
        .unwrap();
    // Named explicitly rather than left to an inner `.unwrap()`: a missing
    // row inside the `interact` closure would otherwise panic there and
    // surface as an opaque `InteractError::Panic`, losing which task_id was
    // actually missing.
    row.unwrap_or_else(|| {
        panic!("no `tasks` row for task_id {task_id} — every task_id here came from a TaskCreated")
    })
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

    // Correlated on the `chat` task's own id, not "any `TaskCompleted`" —
    // `chat.rs`'s `run_chat_turn` durably completes its `infer` task
    // separately from (and before) the `chat` task itself, and closing in
    // that window would sweep the still-open `chat` task, turning this
    // test's own outcome into `Cancelled` for a reason unrelated to what it
    // means to prove. See `wait_for_task_completed`'s own doc comment.
    wait_for_task_completed(&daemon.db_path, session_id, TaskKind::Chat).await;

    // Captured BEFORE closing: the live actor's own state watch, which the
    // reaper this call's Ack races against will eventually tear the
    // registry entry out from under — see this test's own module doc
    // comment and the brief's own instruction to grab this first.
    let actor = daemon
        .registry
        .actor(session_id)
        .expect("the session must still be registered before it is ever closed");
    let mut state_rx = actor.subscribe();

    // Sanity check on the later `== 0` assertion: this session's own token
    // really is registered before the close, so that later check proves a
    // real deregistration happened rather than vacuously observing a count
    // that started at zero.
    assert_eq!(daemon.resources.proxy.registered_count(), 1);

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
            "fold_task's kind must agree with the tasks view for {task_id} — the same rendering \
             `tasks_view.rs`'s own task_kind_as_sql_str uses to populate this column"
        );

        // The state comparison is anchored to `roundhouse_core::fold_task_state`
        // (via `TaskState::as_sql_str`), not `fold_task`'s own narrower
        // `roundhouse_store::TaskState` — `fold_task_state` is the ACTUAL
        // function `tasks_view.rs::upsert_for_event` calls to populate this
        // very row, so this is a genuine "the view agrees with what wrote
        // it" check, not a coincidental match between two independently
        // named enums whose `Debug` renderings currently happen to agree
        // (and would silently stop doing so the moment either type's
        // `Suspended` grew or lost a payload).
        let payloads: Vec<EventPayload> = task_events.iter().map(|e| e.payload.clone()).collect();
        let core_state = roundhouse_core::fold_task_state(&payloads)
            .expect("every task_id came from a TaskCreated");
        assert_eq!(
            core_state.as_sql_str(),
            row.state,
            "fold_task_state's state must agree with the tasks view for {task_id}"
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
/// The dispatched script backgrounds its own `sleep 30` and records THAT
/// process's pid (`sleep 30 & echo $! > pidfile; wait`), rather than
/// recording its own pid and `exec`ing into `sleep` — a degenerate,
/// single-member group would pass unchanged even for an implementation
/// that only `kill()`s the direct child, with no process-GROUP semantics
/// at all. With a real grandchild, the assertion below is only reachable
/// through `roundhouse-sandbox`'s `Child::cancel`, whose `signal_group`
/// sends to `-pgid` (the whole group), never the direct child's own pid —
/// the same script shape `roundhouse-engine`'s own
/// `execute_builtin_shell_is_bounded_even_when_a_backgrounded_grandchild_outlives_the_direct_child`
/// uses, against `roundhouse-tools`' own cancel path
/// (`spawn_cancellable`/`cancel_running_shell`) — a sibling kill
/// implementation to `Child::cancel`/`signal_group`, not a layer beneath it.
///
/// # Why this uses `TestIsolate`, not the real `BwrapLandlockIsolate`
///
/// A real bwrap-wrapped attempt was tried first (`BwrapLandlockIsolate::
/// test_with_probe_and_bwrap_path`, which looks `bwrap` up on `PATH` rather
/// than `common::available_isolate()`'s `test_with_probe`, hardcoded to the
/// production install path `/usr/libexec/roundhouse/bwrap` — not installed
/// on an ordinary dev host, which is a real fixture-path gap but not this
/// test's own problem to fix; a fixture wired to the real binary does exist,
/// `roundhouse_daemon::test_support::available_isolate_with_real_bwrap`, but
/// its enclosing `test_support` module is `#[cfg(test)]` — it does not exist
/// at all in the library `tests/` links against, `pub(crate)` or not).
/// It genuinely cannot work for what this test checks, for a more
/// structural reason than that path gap: `bwrap` unshares the PID namespace
/// (`--unshare-all`, per `bwrap.rs`'s `spawn_under_bwrap`), so the `$!` the
/// script records is a namespace-relative pid (observed: `3`) with no path
/// from that pid file back to a host pid this test could check against
/// `/proc`. (The narrower, accurate claim: it's the pid the *script itself*
/// records that is unusable this way, not that no host-visible pid could
/// ever exist here — `Isolate::spawn` returns a `Child` whose own `pid()`
/// *is* the real host pid of the bwrap process, which is exactly what
/// `roundhouse-sandbox`'s own bwrap tests poll `/proc/{child.pid}` for; a
/// thin decorator over the real isolate could have captured that one.) More
/// fundamentally, this pid-namespace behavior means a real-bwrap run could
/// never have distinguished a process-group kill from a single-pid kill
/// anyway: without `--as-pid-1` (never passed by `spawn_under_bwrap`), bwrap
/// installs itself as the new namespace's own pid 1 (a reaper), with the
/// sandboxed script running underneath it as an ordinary descendant, not as
/// it — consistent with the observed `$! == 3` (namespace pid 1 is bwrap's
/// reaper, 2 is the script, 3 is the backgrounded `sleep`). `--die-with-parent`
/// kills that whole chain once bwrap's own host-visible process dies
/// (confirmed by hand: `kill -9` on that host pid tears down the entire
/// namespace tree only when `--die-with-parent` is passed; without it, the
/// tree survives, reparented). So a single-pid kill of the direct child
/// (the host-visible `bwrap` process itself) would have looked identical to
/// `Child::cancel`'s real group-wide kill — which is exactly the property
/// (b) exists to isolate and prove is `Child::cancel`'s own doing, not a
/// namespace side effect. So this test exercises the real
/// `Child::cancel` group-signal (`signal_group`) and its
/// `wait_for_empty_group` confirmation over a BARE spawned process
/// (`TestIsolate`, copied from `roundhouse-engine`'s own
/// `agent_loop_dispatch.rs`); it does not, and structurally cannot from
/// outside the sandbox, prove that a group-wide kill also reaches a
/// workload running inside a real bwrap wrapper — that property is
/// `roundhouse-engine`'s own `hard_prerequisites_integration.rs`-shaped
/// concern, not this lane's.
#[tokio::test]
async fn closing_while_a_shell_is_in_flight_kills_it_and_orders_the_sweep_before_the_terminator() {
    let workspace_dir = tempfile::tempdir().unwrap();
    let workspace_root = workspace_dir.path().canonicalize().unwrap();
    let pid_file = workspace_root.join("grandchild.pid");
    let script_path = workspace_root.join("long_running.sh");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nsleep 30 &\necho $! > {}\nwait\n",
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

    // The script only writes the grandchild's pid AFTER TaskStarted has
    // already been recorded (`run_isolated_shell_dispatch` appends
    // `TaskStarted` once the real process is spawned, before this script
    // has necessarily reached its own first line, let alone forked and
    // reported `$!`) — poll the pid file itself rather than assume it is
    // already there.
    let grandchild_pid: i32 = {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            if let Ok(contents) = std::fs::read_to_string(&pid_file) {
                let trimmed = contents.trim();
                if !trimmed.is_empty() {
                    break trimmed.parse().unwrap();
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the shell script never wrote its backgrounded grandchild's pid to {}",
                pid_file.display()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    assert!(
        pid_running(grandchild_pid),
        "the backgrounded grandchild must be running before this test cancels it"
    );

    creator
        .close_session()
        .await
        .expect("close_session must succeed: the sweep cancels the in-flight shell");

    // `close_session`'s Ack arriving is not, by itself, proof the grandchild
    // is dead: `SessionActor::close`'s own doc comment is explicit that
    // "`wait_idle` resolving is not a promise that every real process has
    // exited." What DOES guarantee it here is `run_isolated_shell_dispatch`'s
    // own error mapping — an unconfirmed `Child::cancel` (whose
    // `signal_group`+`wait_for_empty_group` pair is what actually proves the
    // whole process GROUP, not just the direct child, is gone) returns
    // `Err`, which that function turns into `ToolDispatchError::Isolation`,
    // not `ShellSessionCancelled` — so the `TaskCancelled{System,
    // SessionClosed}` assertion further below could not hold at all unless
    // the group-wide kill had already been confirmed. The poll below is
    // belt-and-braces, not load-bearing: `wait_for_empty_group`'s own
    // `group_is_empty` check is `kill(-pgid, 0) == ESRCH`, and a zombie
    // still answers `kill()` successfully, so that check cannot return true
    // until every member of the group — zombies included — has actually
    // been reaped. `Child::cancel` returning `Ok` therefore already implies
    // `pid_running(grandchild_pid)` is false, so this loop normally breaks
    // on its first iteration; `pid_running` treats a zombie as dead too,
    // matching `roundhouse-engine`'s own `pid_is_dead_or_zombie`.
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !pid_running(grandchild_pid) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the backgrounded grandchild (pid {grandchild_pid}) must be confirmed dead \
                 once close_session's Ack has arrived"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

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
