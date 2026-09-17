//! Phase 8 Task 19 lane B, Task 7: `run_chat_turn` (via `run_chat_turn_with_clock`) must
//! coalesce the provider's raw stream into real `TaskDelta` events for the infer task,
//! committed in order, strictly between that task's `TaskStarted` and its terminal event —
//! on both the success and failure paths. Asserts against the STORED log
//! (`roundhouse_store::session_events`), never the in-memory `Vec<ContentBlock>` alone.

use futures::StreamExt;
use roundhouse_core::{Delta, EventPayload, SessionId, TaskId, TaskRunner, Usage};
use roundhouse_engine::{run_chat_turn_with_clock, MonotonicClock};
use roundhouse_provider::{
    BlockDelta, BlockKind, Capabilities, ChatRequest, ChatStream, ContentBlock, ModelId, ModelInfo,
    Params, Plan, Provider, ProviderError, ProviderExt, ReasoningRequest, RequestCtx,
    RequestPolicy, ResponseFormat, StreamEvent, TokenCount, ToolChoice,
};
use roundhouse_store::redact::Redactor;
use roundhouse_store::{open, session_events, spawn_writer, StoredEvent};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `TaskRunner::bootstrap()` panics if called more than once per process — this test
/// binary is one process, and every test below calls `run_chat_turn_with_clock`, so they
/// must share one bootstrapped instance rather than each trying to bootstrap its own.
static RUNNER: once_cell::sync::Lazy<TaskRunner> =
    once_cell::sync::Lazy::new(TaskRunner::bootstrap);

/// A `MonotonicClock` whose `now()` only ever changes when a test calls [`Self::advance`] —
/// never on its own, and never by sleeping. A test that never calls `advance` keeps every
/// flush triggered by a real non-time rule (`BlockStop`/kind change/size/`finish`) rather than
/// by wall-clock happenstance; a test that DOES need to cross `delta_sink::FLUSH_INTERVAL`
/// (250ms) calls `advance` explicitly, at a deterministic point in the stream (see
/// `SecretStraddleAndTimeTriggerProvider`), never via a real sleep — this repo's
/// no-clock-timing-tests rule (AGENTS.md).
struct FixedClock {
    now: std::sync::Mutex<Instant>,
}

impl FixedClock {
    fn new() -> Self {
        FixedClock {
            now: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Moves this clock forward by `dur`, deterministically — never a sleep. Every later
    /// `now()` call (from any holder of a shared reference/`Arc`) observes the new value.
    fn advance(&self, dur: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += dur;
    }
}

impl MonotonicClock for FixedClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
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
        unreachable!("test providers never call the transport directly")
    }
}

fn test_ctx() -> RequestCtx {
    RequestCtx {
        trace_id: None,
        transport: Arc::new(NoopTransport),
        api_key: "test".into(),
        credentials: None,
    }
}

fn test_request() -> ChatRequest {
    ChatRequest {
        model: ModelId("claude-sonnet-5".into()),
        system: vec![],
        messages: vec![],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}

/// Streams a text block, a thinking block with a signature, and a tool-use block whose
/// arguments arrive in three fragments — exactly the brief's scripted scenario.
struct ScriptedProvider;

impl Provider for ScriptedProvider {
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
                    delta: BlockDelta::Text("Hello ".into()),
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("world".into()),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::BlockStart {
                    index: 1,
                    kind: BlockKind::Thinking,
                },
                StreamEvent::BlockDelta {
                    index: 1,
                    delta: BlockDelta::Thinking {
                        text: "pondering the question".into(),
                        signature: None,
                    },
                },
                StreamEvent::BlockDelta {
                    index: 1,
                    delta: BlockDelta::Thinking {
                        text: String::new(),
                        signature: Some("sig-xyz-exact".into()),
                    },
                },
                StreamEvent::BlockStop { index: 1 },
                StreamEvent::BlockStart {
                    index: 2,
                    kind: BlockKind::ToolUse {
                        name: "read".into(),
                        provider_id: Some("call_1".into()),
                    },
                },
                StreamEvent::BlockDelta {
                    index: 2,
                    delta: BlockDelta::ToolArgsFragment("{\"a\":".into()),
                },
                StreamEvent::BlockDelta {
                    index: 2,
                    delta: BlockDelta::ToolArgsFragment("1,\"b\":".into()),
                },
                StreamEvent::BlockDelta {
                    index: 2,
                    delta: BlockDelta::ToolArgsFragment("2}".into()),
                },
                StreamEvent::BlockStop { index: 2 },
                StreamEvent::UsageDelta {
                    input_tokens: Some(10),
                    output_tokens: Some(20),
                    cache_read_tokens: Some(0),
                },
                StreamEvent::MessageStop,
            ];
            Ok(ChatStream::from_events(events))
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

/// Streams a partial text delta, then a mid-stream `Err` item — the failure path.
struct MidStreamErrorAfterDeltasProvider;

impl Provider for MidStreamErrorAfterDeltasProvider {
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
            let results = vec![
                Ok(StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                }),
                Ok(StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("partial output".into()),
                }),
                Err(ProviderError::StreamInterrupted {
                    partial: "partial output".into(),
                }),
            ];
            Ok(ChatStream::from_results(results))
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

fn text_delta_text(delta: &Delta) -> Option<&str> {
    match delta {
        Delta::Text { text } => Some(text),
        _ => None,
    }
}

fn thinking_delta(delta: &Delta) -> Option<(&str, Option<&str>)> {
    match delta {
        Delta::Thinking { text, signature } => Some((text.as_str(), signature.as_deref())),
        _ => None,
    }
}

fn tool_args_delta(delta: &Delta) -> Option<&str> {
    match delta {
        Delta::ToolArgs { fragment } => Some(fragment),
        _ => None,
    }
}

#[tokio::test]
async fn infer_task_deltas_land_between_started_and_completed_and_match_the_folded_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let (chat_task_id, blocks) = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &ScriptedProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await
    .expect("scripted provider must not fail the turn");

    // Sanity: the returned blocks are the ones the scripted stream describes.
    let returned_text: String = blocks
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(returned_text, "Hello world");
    let returned_thinking = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::Thinking {
                text, signature, ..
            } => Some((text.clone(), signature.clone())),
            _ => None,
        })
        .expect("a Thinking block was returned");
    assert_eq!(returned_thinking.0, "pondering the question");
    assert_eq!(
        returned_thinking.1.map(|s| s.0),
        Some("sig-xyz-exact".to_string())
    );
    let returned_tool_input = blocks
        .iter()
        .find_map(|b| match b {
            ContentBlock::ToolUse { input, .. } => Some(input.clone()),
            _ => None,
        })
        .expect("a ToolUse block was returned");
    assert_eq!(returned_tool_input, serde_json::json!({"a": 1, "b": 2}));

    // Now the load-bearing assertions: against the STORED log.
    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();

    let infer_task_id: TaskId = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated {
                kind: roundhouse_core::TaskKind::Infer,
                ..
            } => e.task_id,
            _ => None,
        })
        .expect("an infer TaskCreated event was recorded");

    let infer_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|e| e.task_id == Some(infer_task_id))
        .collect();

    let started_pos = infer_events
        .iter()
        .position(|e| matches!(e.payload, EventPayload::TaskStarted { .. }))
        .expect("infer TaskStarted recorded");
    let terminal_pos = infer_events
        .iter()
        .position(|e| {
            matches!(
                e.payload,
                EventPayload::TaskCompleted { .. } | EventPayload::TaskFailed { .. }
            )
        })
        .expect("infer terminal event recorded");
    assert!(
        matches!(
            infer_events[terminal_pos].payload,
            EventPayload::TaskCompleted { .. }
        ),
        "the scripted provider must not fail the turn"
    );

    let delta_positions: Vec<usize> = infer_events
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.payload, EventPayload::TaskDelta { .. }))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !delta_positions.is_empty(),
        "the scripted stream must produce at least one TaskDelta"
    );
    for &pos in &delta_positions {
        assert!(
            pos > started_pos && pos < terminal_pos,
            "every infer TaskDelta must land strictly between TaskStarted (at {started_pos}) \
             and the terminal event (at {terminal_pos}); found one at {pos}"
        );
    }

    let deltas: Vec<&Delta> = infer_events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskDelta { delta } => Some(delta),
            _ => None,
        })
        .collect();

    let concatenated_text: String = deltas.iter().filter_map(|d| text_delta_text(d)).collect();
    assert_eq!(
        concatenated_text, "Hello world",
        "concatenated stored Text deltas must equal the returned text block"
    );

    let mut thinking_text = String::new();
    let mut thinking_signature: Option<String> = None;
    for d in &deltas {
        if let Some((text, sig)) = thinking_delta(d) {
            thinking_text.push_str(text);
            if let Some(s) = sig {
                thinking_signature = Some(s.to_string());
            }
        }
    }
    assert_eq!(
        thinking_text, "pondering the question",
        "concatenated stored Thinking text must equal the thinking block's text"
    );
    assert_eq!(
        thinking_signature.as_deref(),
        Some("sig-xyz-exact"),
        "the stored Thinking signature must equal the thinking block's signature"
    );

    let concatenated_tool_args: String = deltas.iter().filter_map(|d| tool_args_delta(d)).collect();
    assert_eq!(
        concatenated_tool_args, "{\"a\":1,\"b\":2}",
        "concatenated stored ToolArgs fragments must equal the raw JSON"
    );

    // Controller Requirement 9 (fix round 1, BLOCKING B1): the optional UsageDelta fold must
    // actually land on the infer task's TaskCompleted.usage, and must NOT leak onto the
    // parent chat task's (which carries no token usage of its own).
    let infer_usage = infer_events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCompleted { usage, .. } => Some(usage.clone()),
            _ => None,
        })
        .expect("infer TaskCompleted recorded");
    assert_eq!(
        (
            infer_usage.input_tokens,
            infer_usage.output_tokens,
            infer_usage.cache_read_tokens
        ),
        (10, 20, 0),
        "the infer task's stored usage must be the fold of the stream's UsageDelta events"
    );

    let chat_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|e| e.task_id == Some(chat_task_id))
        .collect();
    let chat_usage = chat_events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCompleted { usage, .. } => Some(usage.clone()),
            _ => None,
        })
        .expect("chat TaskCompleted recorded");
    let default_usage = Usage::default();
    assert_eq!(
        (
            chat_usage.input_tokens,
            chat_usage.output_tokens,
            chat_usage.cache_read_tokens
        ),
        (
            default_usage.input_tokens,
            default_usage.output_tokens,
            default_usage.cache_read_tokens
        ),
        "the parent chat task's own usage must stay Usage::default() -- the stream's usage \
         belongs to the infer task, not the chat task"
    );
}

#[tokio::test]
async fn infer_task_deltas_land_before_the_failed_terminal_on_the_failure_path() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let clock = FixedClock::new();
    let session_id = SessionId::new();

    let result = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &MidStreamErrorAfterDeltasProvider,
        &test_ctx(),
        session_id,
        test_request(),
        &clock,
    )
    .await;
    assert!(
        matches!(
            result,
            Err(roundhouse_engine::AgentError::Provider(
                ProviderError::StreamInterrupted { .. }
            ))
        ),
        "expected a provider failure, got {result:?}"
    );

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();

    let infer_task_id: TaskId = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated {
                kind: roundhouse_core::TaskKind::Infer,
                ..
            } => e.task_id,
            _ => None,
        })
        .expect("an infer TaskCreated event was recorded");

    let infer_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|e| e.task_id == Some(infer_task_id))
        .collect();

    let started_pos = infer_events
        .iter()
        .position(|e| matches!(e.payload, EventPayload::TaskStarted { .. }))
        .expect("infer TaskStarted recorded");
    let failed_pos = infer_events
        .iter()
        .position(|e| matches!(e.payload, EventPayload::TaskFailed { .. }))
        .expect("infer TaskFailed recorded");

    let delta_positions: Vec<usize> = infer_events
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.payload, EventPayload::TaskDelta { .. }))
        .map(|(i, _)| i)
        .collect();
    assert!(
        !delta_positions.is_empty(),
        "the partial text delta buffered before the mid-stream error must still be flushed \
         and appended (DeltaCoalescer::finish, called before the failure terminal)"
    );
    for &pos in &delta_positions {
        assert!(
            pos > started_pos && pos < failed_pos,
            "every infer TaskDelta must land strictly between TaskStarted (at {started_pos}) \
             and TaskFailed (at {failed_pos}); found one at {pos}"
        );
    }

    let concatenated_text: String = infer_events
        .iter()
        .filter_map(|e| match &e.payload {
            EventPayload::TaskDelta { delta } => text_delta_text(delta),
            _ => None,
        })
        .collect();
    assert_eq!(
        concatenated_text, "partial output",
        "the buffered partial text must reach the store even though the turn fails"
    );
}

/// Streams two Text blocks:
///
/// - Block 0: a single, over-4-KiB `BlockDelta::Text` whose registered secret sits exactly
///   where a naive `FLUSH_SIZE_THRESHOLD`-triggered non-final cut would land inside it.
/// - Block 1: two small `BlockDelta::Text` fragments ("X"s then "Y"s), with the shared
///   `FixedClock` advanced past `delta_sink::FLUSH_INTERVAL` (250ms) between them via this
///   stream's own `.then()` side effect — deterministic sequencing, never a sleep.
///
/// Both scenarios are built as a custom stream (not `ChatStream::from_events`) specifically so
/// the clock can be advanced at an exact, deterministic point between two items — proving the
/// TIME-triggered non-final flush path goes through `run_chat_turn_with_clock`'s real splitter
/// closure too, not just `delta_sink.rs`'s own unit tests (which construct `Instant`s directly
/// and never touch this crate's wiring at all).
struct SecretStraddleAndTimeTriggerProvider {
    big_text: String,
    clock: Arc<FixedClock>,
}

impl Provider for SecretStraddleAndTimeTriggerProvider {
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
        let big_text = self.big_text.clone();
        let clock = Arc::clone(&self.clock);
        Box::pin(async move {
            let events: Vec<StreamEvent> = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text(big_text),
                },
                StreamEvent::BlockStop { index: 0 },
                StreamEvent::BlockStart {
                    index: 1,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 1,
                    delta: BlockDelta::Text("X".repeat(100)),
                },
                // Index 5: the clock advances past FLUSH_INTERVAL right before this item is
                // yielded, so `run_chat_turn_with_clock` reads the advanced value when it
                // processes this delta.
                StreamEvent::BlockDelta {
                    index: 1,
                    delta: BlockDelta::Text("Y".repeat(50)),
                },
                StreamEvent::BlockStop { index: 1 },
                StreamEvent::MessageStop,
            ];
            const ADVANCE_BEFORE_INDEX: usize = 5;
            let stream =
                futures::stream::iter(events.into_iter().enumerate()).then(move |(idx, ev)| {
                    let clock = Arc::clone(&clock);
                    async move {
                        if idx == ADVANCE_BEFORE_INDEX {
                            // Mirrors delta_sink::FLUSH_INTERVAL (250ms) exactly.
                            clock.advance(Duration::from_millis(250));
                        }
                        Ok(ev)
                    }
                });
            Ok(ChatStream(Box::pin(stream)))
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

/// Fix round 1, BLOCKING B2: proves `run_chat_turn_with_clock`'s production `SplitFn` closure
/// is actually invoked with the right arguments — not just that
/// `EventWriter::redaction_split_for_coalescer` itself is correct (already covered by
/// `roundhouse-store`'s own unit tests). A swapped-argument, inverted-`final_flush`, or
/// always-zero closure would pass every other test in this file (they all stream well under
/// `BLOB_INLINE_THRESHOLD` with a clock that never advances, so `should_attempt_flush` never
/// fires and `close_pending`'s final release emits each buffer whole without ever consulting
/// the splitter) — exactly the gap Controller Requirement 1 named.
#[tokio::test]
async fn the_real_splitter_closure_is_exercised_by_both_the_size_and_time_triggers() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    let secret = "S".repeat(30);
    writer.set_redactor(Redactor::build(std::slice::from_ref(&secret)));
    let clock = Arc::new(FixedClock::new());
    let session_id = SessionId::new();

    // FLUSH_SIZE_THRESHOLD is 2048 -- position the secret (30 bytes) to straddle exactly that
    // naive cut: byte 2030..2060 straddles 2048.
    let prefix_len = 2030usize;
    let suffix_len = 3000usize;
    let big_text = format!(
        "{}{}{}",
        "a".repeat(prefix_len),
        secret,
        "b".repeat(suffix_len)
    );
    assert!(
        big_text.len() > roundhouse_core::BLOB_INLINE_THRESHOLD,
        "test premise: the block must be over 4 KiB"
    );

    let provider = SecretStraddleAndTimeTriggerProvider {
        big_text: big_text.clone(),
        clock: Arc::clone(&clock),
    };

    let (_, _blocks) = run_chat_turn_with_clock(
        &writer,
        &RUNNER,
        &provider,
        &test_ctx(),
        session_id,
        test_request(),
        &*clock,
    )
    .await
    .expect("must not fail");

    let reopened = open(&db_path).await.unwrap();
    let events: Vec<StoredEvent> = session_events(&reopened, session_id).await.unwrap();
    let infer_task_id: TaskId = events
        .iter()
        .find_map(|e| match &e.payload {
            EventPayload::TaskCreated {
                kind: roundhouse_core::TaskKind::Infer,
                ..
            } => e.task_id,
            _ => None,
        })
        .expect("an infer TaskCreated event was recorded");
    let deltas: Vec<&str> = events
        .iter()
        .filter(|e| e.task_id == Some(infer_task_id))
        .filter_map(|e| match &e.payload {
            EventPayload::TaskDelta { delta } => text_delta_text(delta),
            _ => None,
        })
        .collect();

    // Block 0's stored deltas never contain 'X'/'Y' (block 1's alphabet); block 1's never
    // contain 'a'/'b'/'S' (block 0's alphabet, or its redacted placeholder). Disjoint
    // alphabets, so this content-based split is unambiguous regardless of exact chunk counts.
    let block0: Vec<&str> = deltas
        .iter()
        .copied()
        .filter(|t| !t.contains('X') && !t.contains('Y'))
        .collect();
    let block1: Vec<&str> = deltas
        .iter()
        .copied()
        .filter(|t| t.contains('X') || t.contains('Y'))
        .collect();

    // -- Size-triggered non-final flush, real wiring, secret straddling the naive cut --
    assert!(
        block0.len() > 1,
        "an over-4-KiB block whose size alone crosses FLUSH_SIZE_THRESHOLD must produce more \
         than one stored Delta::Text if the real splitter closure is actually being called \
         with a bounded `max`; got {block0:?}"
    );
    let expected_redacted = format!(
        "{}[REDACTED]{}",
        "a".repeat(prefix_len),
        "b".repeat(suffix_len)
    );
    assert_eq!(
        block0.concat(),
        expected_redacted,
        "concatenated stored Text deltas must equal the text with the registered secret \
         redacted -- no bytes lost or reordered across the split"
    );
    for t in &block0 {
        assert!(
            !t.contains('S'),
            "a stored delta contains a raw 'S' -- the secret must have been cut across a \
             chunk boundary (a fragment, not the whole match) and so survived store-side \
             redaction unredacted: {t:?}"
        );
    }

    // -- Time-triggered non-final flush, real wiring, two small fragments --
    assert!(
        block1.len() > 1,
        "two small fragments with the clock advanced past FLUSH_INTERVAL between them must \
         produce more than one stored Delta::Text if the real splitter closure's non-final \
         (time-triggered) path is actually being exercised; got {block1:?}"
    );
    assert_eq!(
        block1.concat(),
        format!("{}{}", "X".repeat(100), "Y".repeat(50)),
        "concatenated stored deltas for the time-triggered block must equal the pushed text"
    );
}
