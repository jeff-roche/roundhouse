use futures::stream;
use roundhouse_core::{SessionId, TaskId, TaskRunner};
use roundhouse_engine::run_chat_turn;
use roundhouse_provider::{
    BlockDelta, BlockKind, Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId, ModelInfo,
    Params, Plan, Provider, ProviderError, ProviderExt, ReasoningRequest, RequestCtx,
    RequestPolicy, ResponseFormat, StreamEvent, TokenCount, ToolChoice,
};
use roundhouse_store::{fold_task, open, spawn_writer, StoredEvent, Task, TaskState};
use std::collections::BTreeMap;
use std::sync::Arc;

/// `TaskRunner::bootstrap()` panics if called more than once per process
/// (S-LOG-1's single-authority guarantee) — this test binary is one
/// process, and both tests below call `run_chat_turn`, so they must share
/// one bootstrapped instance rather than each trying to bootstrap its own.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

struct FakeProvider;

impl Provider for FakeProvider {
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
    ) -> roundhouse_provider::BoxFut<'a, Result<ChatStream, ProviderError>> {
        Box::pin(async move {
            let events = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("Hello".into()),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::MessageStop,
            ];
            let s = ChatStream(Box::pin(stream::iter(events)));
            Ok(s)
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async move { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> roundhouse_provider::BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async move { Ok(vec![]) })
    }
}

struct NoopTransport;
impl roundhouse_provider::HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: roundhouse_provider::HttpRequest,
    ) -> futures::future::BoxFuture<
        'a,
        Result<roundhouse_provider::HttpResponseStream, roundhouse_provider::TransportError>,
    > {
        unreachable!("FakeProvider never calls the transport directly")
    }
}

/// Reads every event row for `task_id` back out of the append-only `events`
/// table and deserializes each into a `StoredEvent` (the unsealed read-model
/// counterpart to `roundhouse_core::Event` — see `roundhouse_store::replay`),
/// so `fold_task` can be run over data that actually round-tripped through
/// storage rather than the in-memory `Event`s that were appended.
async fn load_task_events(
    store: &roundhouse_store::StorePool,
    task_id: TaskId,
) -> Vec<StoredEvent> {
    let conn = store.pool.get().await.expect("pool connection");
    let task_id_str = task_id.to_string();
    let rows: Vec<(String, i64, i64, Option<String>, String, i64)> = conn
        .interact(move |c| {
            let mut stmt = c
                .prepare(
                    "SELECT session_id, seq, ts, task_id, payload, schema_v
                     FROM events WHERE task_id = ?1 ORDER BY seq",
                )
                .expect("prepare statement");
            stmt.query_map([task_id_str], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .expect("query_map")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect rows")
        })
        .await
        .expect("interact");

    rows.into_iter()
        .map(
            |(session_id, seq, ts_nanos, task_id_opt, payload, schema_v)| StoredEvent {
                session_id: roundhouse_core::SessionId::from_uuid(
                    uuid::Uuid::parse_str(&session_id).expect("valid session_id uuid"),
                ),
                seq: u64::try_from(seq).expect("non-negative seq"),
                ts: roundhouse_core::Timestamp::from_unix_nanos(ts_nanos),
                task_id: task_id_opt.map(|s| {
                    roundhouse_core::TaskId::from_uuid(
                        uuid::Uuid::parse_str(&s).expect("valid task_id uuid"),
                    )
                }),
                payload: serde_json::from_str(&payload).expect("valid EventPayload JSON"),
                schema_v: schema_v as u16,
            },
        )
        .collect()
}

#[tokio::test]
async fn chat_turn_spawns_one_infer_child_task_and_returns_content() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let ctx = RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: "test".into(),
        credentials: None,
    };
    let session_id = SessionId::new();
    let request = ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        // Unpopulated in Phase 1 (see Task 6's deliberate-scoping note).
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    };

    let (chat_task_id, blocks) =
        run_chat_turn(&writer, &RUNNER, &FakeProvider, &ctx, session_id, request)
            .await
            .unwrap();

    assert!(matches!(&blocks[0], ContentBlock::Text { text, .. } if text == "Hello"));

    // Follow-on assertion (S-LOOP-1's "exactly one Task record per action,"
    // made concrete): query the store directly, fold both the chat and infer
    // tasks from their replayed events, and assert the parent linkage and
    // terminal state actually landed durably.
    let reopened = open(&db_path).await.unwrap();

    let conn = reopened.pool.get().await.unwrap();
    let task_ids: Vec<(Option<String>,)> = conn
        .interact(|c| {
            let mut stmt = c
                .prepare("SELECT DISTINCT task_id FROM events WHERE task_id IS NOT NULL ORDER BY task_id")
                .unwrap();
            stmt.query_map([], |row| Ok((row.get(0)?,)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .await
        .unwrap();
    assert_eq!(
        task_ids.len(),
        2,
        "exactly one chat task and one infer task, per S-LOOP-1"
    );

    let mut chat_task: Option<Task> = None;
    let mut infer_task: Option<Task> = None;
    for (task_id_str,) in task_ids {
        let task_id = TaskId::from_uuid(uuid::Uuid::parse_str(&task_id_str.unwrap()).unwrap());
        let events = load_task_events(&reopened, task_id).await;
        let task = fold_task(&events).expect("TaskCreated event present");
        match task.kind {
            roundhouse_core::TaskKind::Chat => chat_task = Some(task),
            roundhouse_core::TaskKind::Infer => infer_task = Some(task),
            other => panic!("unexpected task kind in tree: {other:?}"),
        }
    }

    let chat_task = chat_task.expect("chat task recorded");
    let infer_task = infer_task.expect("infer task recorded");

    assert_eq!(
        chat_task.id, chat_task_id,
        "run_chat_turn's returned chat_task_id must match the chat task actually recorded"
    );
    assert_eq!(
        infer_task.parent,
        Some(chat_task.id),
        "infer task must be a child of the chat task"
    );
    assert_eq!(chat_task.state, TaskState::Completed);
    assert_eq!(infer_task.state, TaskState::Completed);
}

/// Audit finding 1: a `Thinking` block must fold to `ContentBlock::Thinking`, not
/// `ContentBlock::Text`, with its signature carried through byte-for-byte — the fold
/// must never collapse it into plain text and drop the signature.
#[tokio::test]
async fn thinking_deltas_fold_to_a_thinking_block_with_signature_intact() {
    use roundhouse_engine::fold_stream_to_blocks;
    use roundhouse_provider::Signature;

    let events = vec![
        StreamEvent::BlockStart {
            index: 0,
            kind: BlockKind::Thinking,
        },
        StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Thinking {
                text: "I should check the file first.".into(),
                signature: None,
            },
        },
        StreamEvent::BlockDelta {
            index: 0,
            delta: BlockDelta::Thinking {
                text: String::new(),
                signature: Some("sig-xyz-exact".into()),
            },
        },
        StreamEvent::BlockStop { index: 0 },
        StreamEvent::MessageStop,
    ];
    let stream = ChatStream(Box::pin(stream::iter(events)));

    let blocks = fold_stream_to_blocks(stream).await;

    assert_eq!(blocks.len(), 1);
    match &blocks[0] {
        ContentBlock::Thinking {
            text,
            signature,
            redacted,
        } => {
            assert_eq!(text, "I should check the file first.");
            assert_eq!(
                signature,
                &Some(Signature("sig-xyz-exact".into())),
                "signature must survive the fold byte-for-byte"
            );
            assert!(!redacted);
        }
        other => panic!("expected ContentBlock::Thinking, got {other:?}"),
    }
}
