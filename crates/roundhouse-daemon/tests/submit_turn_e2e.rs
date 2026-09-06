//! Phase 7, Task 8, Part B — `ClientRequest::SubmitTurn` end to end through
//! the **real** daemon: a real Unix socket, a real `accept_loop`, a real
//! `create_real_session` (real store, real `PolicyEngine`, real isolation
//! probe, real redaction), and Task 5's real `run_agent_loop`. The only
//! faked thing is the provider, which is scripted so the test can decide
//! what the model "asks for".
//!
//! # The exit criterion, and the one input that is injected
//!
//! [`the_phase_exit_criterion_a_model_issued_tool_call_actually_runs_and_its_output_reaches_the_next_turn`]
//! is the phase's literal criterion and it **passes**: the tool actually
//! runs, and its real output reaches the next provider turn.
//!
//! It loads one project policy-file `Allow` rule through the same production
//! `PolicyRuleSource` factory used at daemon boot, after recording explicit
//! out-of-repository trust for that project file.
//!
//! - **What it proves:** every layer between a client frame and a real
//!   filesystem read is correctly wired — handshake, creator-only guard,
//!   spawned turn, `run_agent_loop`, `admit_task`, the real executor, and
//!   the fold back into the next provider request.
//! - **What it does NOT prove:** broad policy language support; this L0 file
//!   format intentionally permits only exact read rules.
//!
//! Nothing about the sealed floor is bypassed: `decide_sealed` still checks
//! the compiled-in floor first and can still override the injected rule.
//! [`a_creator_submitted_turn_reaches_the_real_agent_loop_and_folds_its_result_into_the_next_provider_turn`]
//! deliberately keeps `no_policy_rules()` and so exercises the real
//! production denial path alongside it.

mod common;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::stream;
use roundhouse_core::{EventPayload, SessionId, TaskKind};
use roundhouse_daemon::session_bootstrap::{
    no_policy_rules, policy_rules_from_files, PolicyRuleSource,
};
use roundhouse_policy::config::compile_policy_layers;
use roundhouse_policy::trust::{record_explicit_trust, TrustStore};
use roundhouse_proto::ClientRequest;
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId,
    ModelInfo, Plan, Provider, ProviderError, RequestCtx, StreamEvent, TokenCount,
};

/// A scripted `Provider`: the first call returns one `ToolUse` block for the
/// given tool name/input; every later call returns a final text-only block.
/// Mirrors `roundhouse-engine`'s `agent_loop_dispatch.rs::ScriptedToolCallProvider`
/// — proving the loop actually re-invokes the provider with the tool result
/// folded back in, rather than dispatching once and stopping.
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
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// Polls this session's real, on-disk event log until `pred` matches one of
/// its events, or the bound elapses.
///
/// Polls rather than sleeping a fixed interval because the turn runs in its
/// own spawned task (ruling W1-R38's shape — see `run_submitted_turn`), so
/// there is no instant the test can synchronously wait on. The bound only
/// exists so a genuine regression fails CI instead of hanging it; it is
/// never the thing being measured.
async fn wait_for_event(
    db_path: &std::path::Path,
    session_id: SessionId,
    what: &str,
    pred: impl Fn(&EventPayload) -> bool,
) -> Vec<roundhouse_store::StoredEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let store = roundhouse_store::open(db_path).await.unwrap();
        let events = roundhouse_store::session_events(&store, session_id)
            .await
            .unwrap();
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

/// Fixture: a live daemon over a real socket, driven by `provider`.
struct Daemon {
    _dir: tempfile::TempDir,
    socket_path: std::path::PathBuf,
    db_path: std::path::PathBuf,
}

async fn start_daemon(provider: Arc<dyn Provider>) -> Daemon {
    start_daemon_with_rules(provider, no_policy_rules()).await
}

/// [`start_daemon`], but with a caller-supplied [`PolicyRuleSource`] — what
/// the exit-criterion test needs, since production's [`no_policy_rules`]
/// can never answer `Allow`.
async fn start_daemon_with_rules(
    provider: Arc<dyn Provider>,
    policy_rules: PolicyRuleSource,
) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let db_path = dir.path().join("events.db");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources =
        common::resources_with_provider_and_rules(dir.path(), provider, policy_rules).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener, registry, resources,
    ));
    Daemon {
        _dir: dir,
        socket_path,
        db_path,
    }
}

/// The Part B reachability pin: a `SubmitTurn` from the **creating**
/// connection reaches Task 5's real `run_agent_loop`, the model's `ToolUse`
/// becomes a real, queryable task in this session's append-only log, and the
/// dispatch's result is folded back into the **next** provider call.
///
/// Every assertion here is about a real side effect (a row in the real
/// store, a recorded provider request), never about the absence of a panic.
#[tokio::test]
async fn a_creator_submitted_turn_reaches_the_real_agent_loop_and_folds_its_result_into_the_next_provider_turn(
) {
    let provider = Arc::new(ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": "/etc/hostname" }),
    ));
    let daemon = start_daemon(provider.clone()).await;

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
            text: "please read /etc/hostname".to_string(),
        })
        .await
        .unwrap();

    // The model's `ToolUse { name: "read" }` must produce a real `Read` task
    // in this session's own event log — the proof that the frame reached the
    // real dispatch path, not that it was merely accepted at the socket.
    let events = wait_for_event(&daemon.db_path, session_id, "a Read task", |p| {
        matches!(
            p,
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                ..
            }
        )
    })
    .await;

    // ... and that task must reach a terminal state, never be left dangling.
    // Today that terminal state is `TaskFailed` (see this file's module doc
    // comment: production sessions carry an empty rule set, so admission
    // decides `Ask` -> `RequiresApproval`). Asserted as "terminal", not as
    // "failed", so this pin keeps holding — rather than inverting — once a
    // rules source exists and the task starts completing instead.
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskFailed { .. } | EventPayload::TaskCompleted { .. }
        )),
        "the dispatched tool call must reach a terminal event, not be left half-open"
    );

    // The turn must have re-invoked the provider with the dispatch's result
    // folded in — the "and its result reached the next provider turn" half
    // of the criterion. Polled for the same reason `wait_for_event` is.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let second = loop {
        let requests = provider.requests();
        if requests.len() >= 2 {
            break requests[1].clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a second provider call; saw {}",
            requests.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    let tool_result_ids: Vec<String> = second
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            ContentBlock::ToolResult { tool_use_id, .. } => Some(tool_use_id.0.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        tool_result_ids,
        vec!["call_0".to_string()],
        "the second provider call must carry exactly the first call's tool result, \
         keyed by the same tool_use_id the model issued"
    );

    // Exactly two calls: the loop stopped when the model stopped asking for
    // tools, rather than spinning.
    assert_eq!(
        provider.requests().len(),
        2,
        "the loop must stop once the model returns no further ToolUse blocks"
    );
}

/// **Ruling W1-R37, proven rather than asserted.** An `Attach`ed connection
/// is read-only: its `SubmitTurn` must be refused, while the *creating*
/// connection's identical frame is honored.
///
/// The falsifiable delta is the attached connection's own marker text: if
/// the guard were removed, that text would appear in a provider request.
/// Ordering is established by running the creator's turn to completion
/// first — the attached connection's frame was written and flushed strictly
/// before the creator ever connected, and its connection task has been
/// scheduled by the same runtime across two full provider round-trips and
/// several store round-trips by the time this assertion runs. (Same
/// happens-after argument `multi_client_attach.rs`'s reap test makes; there
/// is no ack for a dropped frame to synchronize on, by design — `ClientEvent`
/// has no error variant.)
#[tokio::test]
async fn an_attached_connections_submit_turn_is_refused_while_the_creators_is_honored() {
    const ATTACHED_MARKER: &str = "MARKER-from-the-attached-connection";

    let provider = Arc::new(ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": "/etc/hostname" }),
    ));
    let daemon = start_daemon(provider.clone()).await;

    let mut creator = tokio::time::timeout(
        Duration::from_secs(5),
        roundhouse_tui::connect_create(&daemon.socket_path, "default"),
    )
    .await
    .expect("connect_create must not hang")
    .unwrap();
    let session_id = creator.session_id();

    let mut attached = tokio::time::timeout(
        Duration::from_secs(5),
        roundhouse_tui::connect_attach(&daemon.socket_path, session_id),
    )
    .await
    .expect("connect_attach must not hang")
    .unwrap();

    attached
        .send(&ClientRequest::SubmitTurn {
            session_id,
            text: ATTACHED_MARKER.to_string(),
        })
        .await
        .unwrap();

    creator
        .send(&ClientRequest::SubmitTurn {
            session_id,
            text: "please read /etc/hostname".to_string(),
        })
        .await
        .unwrap();

    wait_for_event(&daemon.db_path, session_id, "a Read task", |p| {
        matches!(
            p,
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                ..
            }
        )
    })
    .await;

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if provider.requests().len() >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for the creator's turn to reach its second provider call"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let requests = provider.requests();
    let attached_text_reached_the_provider = requests.iter().any(|r| {
        r.messages.iter().any(|m| {
            m.content.iter().any(|b| match b {
                ContentBlock::Text { text, .. } => text.contains(ATTACHED_MARKER),
                _ => false,
            })
        })
    });
    assert!(
        !attached_text_reached_the_provider,
        "an attached connection's SubmitTurn must never be dispatched — W1-R37 makes \
         attached connections read-only, or unauthenticated Attach becomes an \
         approval-hijack primitive"
    );
    assert_eq!(
        requests.len(),
        2,
        "only the creating connection's turn may run: two provider calls, not four"
    );
}

/// The `MAX_SUBMIT_TURN_TEXT_BYTES` bound, proven rather than left
/// decorative (CF-14's own "bound it where it is parsed" shape). An
/// oversized `SubmitTurn` from the *creating* connection — everything else
/// about it valid — must be dropped, while the very next, in-bounds frame on
/// the same connection is still honored.
///
/// Testing "still honored afterwards" is what makes this non-vacuous: a
/// version of this daemon that closed the connection on an oversized frame,
/// or that wedged, would also produce "the oversized text never reached the
/// provider".
#[tokio::test]
async fn an_oversized_submit_turn_is_dropped_without_wedging_the_connection() {
    // Deliberately just past the 64 KiB cap, built from one repeated marker
    // character so any prefix of it is still recognisable in a request.
    const OVERSIZED_MARKER: char = 'Z';
    let oversized: String = std::iter::repeat_n(OVERSIZED_MARKER, 64 * 1024 + 1).collect();

    let provider = Arc::new(ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": "/etc/hostname" }),
    ));
    let daemon = start_daemon(provider.clone()).await;

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
            text: oversized,
        })
        .await
        .unwrap();
    creator
        .send(&ClientRequest::SubmitTurn {
            session_id,
            text: "please read /etc/hostname".to_string(),
        })
        .await
        .unwrap();

    // The connection survived and the in-bounds frame ran: the dispatched
    // tool call is in the real event log.
    wait_for_event(&daemon.db_path, session_id, "a Read task", |p| {
        matches!(
            p,
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                ..
            }
        )
    })
    .await;

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if provider.requests().len() >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the in-bounds frame after an oversized one must still run to completion"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let requests = provider.requests();
    let oversized_reached_the_provider = requests.iter().any(|r| {
        r.messages.iter().any(|m| {
            m.content.iter().any(|b| match b {
                // A 1000-char run of the marker cannot occur in the
                // in-bounds turn's own text.
                ContentBlock::Text { text, .. } => {
                    text.contains(&OVERSIZED_MARKER.to_string().repeat(1000))
                }
                _ => false,
            })
        })
    });
    assert!(
        !oversized_reached_the_provider,
        "an over-length SubmitTurn must be dropped at the protocol boundary, not forwarded \
         into a real provider request"
    );
    assert_eq!(
        requests.len(),
        2,
        "exactly one turn — the in-bounds one — may have run"
    );
}

/// **The phase's literal exit criterion, met end to end** (Task 8 fix round
/// 1, rulings W1-R118/W1-R120): a model-issued tool call in a live session,
/// dispatched, **actually run**, with its real output folded back into the
/// next provider turn.
///
/// Every layer here is the production one: a real Unix socket, a real
/// `accept_loop`, a real `create_real_session` (real store, real
/// `PolicyEngine` with its real compiled-in sealed floor, real isolation
/// probe, real redaction), a real `SessionActor::admit_task`, Task 5's real
/// `run_agent_loop`, and the real `roundhouse-tools` `read` executor. The
/// only injected input is the scripted provider (so the test decides what
/// the model asks for); its Allow is loaded through the production policy
/// source from a real project file.
///
/// Nothing about the
/// sealed floor, admission, dispatch, or execution is bypassed: the rule is
/// an ordinary `Scope::Builtin` `FsPrefix{Read}` allow, exactly what an
/// operator config would compile to, and `PolicyEngine::decide_sealed`
/// still checks the compiled-in floor first and can still override it.
#[tokio::test]
async fn the_phase_exit_criterion_a_model_issued_tool_call_actually_runs_and_its_output_reaches_the_next_turn(
) {
    let fixture_dir = tempfile::tempdir().unwrap();
    let fixture_root = fixture_dir.path().canonicalize().unwrap();
    let fixture = fixture_root.join("fixture.txt");
    let fixture_contents = "the-contents-the-model-must-see";
    std::fs::write(&fixture, fixture_contents).unwrap();

    let provider = Arc::new(ScriptedToolCallProvider::new(
        "read",
        serde_json::json!({ "path": fixture.to_string_lossy() }),
    ));
    // Exercise the production rule-file loader, not an injected literal.
    // Project Allows require explicit out-of-repository trust; record that
    // operator decision here before the source mints a session-local rule.
    let policy_dir = fixture_root.join(".roundhouse");
    std::fs::create_dir(&policy_dir).unwrap();
    let policy_path = policy_dir.join("policy.toml");
    let policy_text = format!(
        "[[rule]]\nid = 'fixture-read'\noutcome = 'allow'\nread = {:?}\n",
        fixture
    );
    std::fs::write(&policy_path, &policy_text).unwrap();
    let trust_state = tempfile::tempdir().unwrap();
    let rules =
        policy_rules_from_files(Some(fixture_root.clone()), trust_state.path().to_path_buf())
            .unwrap();
    let compiled = compile_policy_layers(vec![roundhouse_config::PolicyLayer {
        scope: roundhouse_config::ConfigScope::Project,
        path: policy_path,
        contents: policy_text.clone(),
        file: roundhouse_config::PolicyFile {
            rule: vec![roundhouse_config::PolicyRule {
                id: "fixture-read".to_string(),
                outcome: roundhouse_config::PolicyRuleOutcome::Allow,
                read: fixture.clone(),
            }],
        },
    }])
    .unwrap();
    record_explicit_trust(
        &fixture_root,
        &policy_text,
        &compiled,
        &TrustStore::new(trust_state.path().to_path_buf()),
    )
    .unwrap();
    let daemon = start_daemon_with_rules(provider.clone(), rules).await;

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
            text: "please read the fixture".to_string(),
        })
        .await
        .unwrap();

    // (1) The tool ACTUALLY RAN — a real side effect in the real event log,
    // per Task 5's own pattern. `TaskCompleted` (not merely `TaskCreated`)
    // is the assertion that separates "dispatched" from "executed".
    let events = wait_for_event(&daemon.db_path, session_id, "a completed task", |p| {
        matches!(p, EventPayload::TaskCompleted { .. })
    })
    .await;
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::TaskCreated {
                kind: TaskKind::Read,
                ..
            }
        )),
        "the completed task must be the model's own Read"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(&e.payload, EventPayload::TaskFailed { .. })),
        "no task in this session may have failed"
    );

    // (2) Its result reached the NEXT provider turn — the assertion that
    // matters, since (1) alone would also hold for a turn whose result was
    // dispatched and then dropped on the floor.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let second = loop {
        let requests = provider.requests();
        if requests.len() >= 2 {
            break requests[1].clone();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for a second provider call; saw {}",
            requests.len()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };

    let tool_results: Vec<(bool, String)> = second
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
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
        .collect();

    assert_eq!(tool_results.len(), 1, "expected exactly one tool result");
    let (is_error, text) = &tool_results[0];
    assert!(
        !is_error,
        "the model-issued tool call must have actually RUN, not been refused — got the \
         error result {text:?}"
    );
    assert!(
        text.contains(fixture_contents),
        "the tool's REAL output — the fixture file's actual contents, read off disk by the \
         real roundhouse-tools executor — must be what reaches the next provider turn, \
         got {text:?}"
    );
}
