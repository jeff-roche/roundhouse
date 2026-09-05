//! The scripted session behind Phase 1's exit criterion: store + provider +
//! engine + tools + tui, wired together and driven once.

use std::path::PathBuf;
use std::sync::Arc;

use futures::stream;
use roundhouse_core::{Delta, EventPayload, SessionId, SessionState, TaskRunner};
use roundhouse_engine::{
    assemble_context, live_secret_values, run_chat_turn, wire_redaction_for_session, AgentError,
};
use roundhouse_proto::ClientEvent;
use roundhouse_provider::{
    BlockDelta, BlockKind, Capabilities, ChatRequest, ChatStream, ContentBlock, HttpRequest,
    HttpResponseStream, HttpTransport, Message, MessageRole, ModelId, ModelInfo, Plan, Provider,
    ProviderError, RequestCtx, StreamEvent, TokenCount, TransportError,
};
use roundhouse_store::{open, spawn_writer, StoreError};
use roundhouse_tools::{edit_file, ToolError};
use tokio::sync::mpsc;

/// Stand-in for a real concrete `Provider`. Track B's Tasks 7-10 built only
/// the pure `encode`/`decode` codec functions; Track G's Task 22 added the
/// struct that bridges them to a live `HttpTransport`
/// (`roundhouse_provider::AnthropicMessagesProvider`), which `main.rs` now
/// selects whenever `ANTHROPIC_API_KEY` is set. This fake remains the default
/// because it proves the daemon/engine/tools/tui wiring end to end without a
/// live network call, a real API key, or a bill — so the exit criterion stays
/// runnable offline and in CI, and every test in this crate is hermetic.
pub struct FakeEditProvider {
    /// The single text block this provider "generates", emitted as one delta.
    pub reply_text: String,
}

impl Provider for FakeEditProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        // All-false: this fake supports nothing beyond emitting one text block,
        // and claiming otherwise would let a future caller plan a request it
        // can't actually serve.
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
        let text = self.reply_text.clone();
        Box::pin(async move {
            // The minimal well-formed stream `fold_stream_to_blocks` accepts:
            // one text block, opened, filled, closed, then the message stop.
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

/// Paired with [`FakeEditProvider`], which never dispatches through the
/// transport — but `RequestCtx` requires one, so this fills the slot.
///
/// Returns an error rather than panicking if it is ever actually called.
/// A panic here would be a panic inside an `async` task at an I/O boundary,
/// reachable by anyone who pairs this transport with a real provider; an
/// `Err` is the same signal without taking the process down.
pub struct NoopTransport;

impl HttpTransport for NoopTransport {
    fn send<'a>(
        &'a self,
        _req: HttpRequest,
    ) -> futures::future::BoxFuture<'a, Result<HttpResponseStream, TransportError>> {
        Box::pin(async {
            Err(TransportError::Io(
                "NoopTransport cannot send requests; pair it only with FakeEditProvider".into(),
            ))
        })
    }
}

/// Everything the scripted demo session needs to run once.
pub struct DemoConfig {
    /// Filesystem path of the SQLite event log to open (created if absent).
    pub store_path: PathBuf,
    /// File the demo's one scripted tool call edits.
    pub edit_target: PathBuf,
    /// Text to find in `edit_target`; must occur exactly once (S-TOOL-3).
    pub find: String,
    /// Replacement for `find`.
    pub replace: String,
    /// Provider the chat turn streams from — [`FakeEditProvider`] in Phase 1.
    pub provider: Arc<dyn Provider>,
    /// Per-request context (trace id, transport, API key) handed to the provider.
    pub request_ctx: RequestCtx,
}

/// What one demo session produced.
#[derive(Debug)]
pub struct DemoOutcome {
    /// The session the chat/infer task pair was recorded under.
    pub session_id: SessionId,
    /// Content blocks folded out of the provider's stream.
    pub blocks: Vec<ContentBlock>,
    /// Contents of `edit_target` read back *after* the edit, so callers can
    /// assert on what actually landed on disk rather than on what was intended.
    pub edited_file: String,
}

/// Everything that can go wrong in one demo session.
#[derive(Debug, thiserror::Error)]
pub enum DemoError {
    /// Opening the event log or appending to it failed.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// The chat turn failed (provider or event-append error).
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
    /// The scripted edit failed — most often `find` not occurring exactly once.
    #[error("tool error: {0}")]
    Tool(#[from] ToolError),
    /// Reading the edited file back failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// The testable core of the Phase 1 exit criterion: open the real event
/// log, run one chat turn against `cfg.provider`, apply its one scripted
/// tool call via `roundhouse-tools`, and push a `ClientEvent` wrapping a raw
/// `EventPayload` per resulting content block to `updates` so an attached
/// `roundhouse-tui` client sees it live. Phase 7 Task 2 retired the
/// hand-rolled, daemon-pre-summarized `ServerMessage` this used to build
/// instead: the daemon now hands the TUI real `roundhouse-proto`/
/// `roundhouse-core` types and lets `Dashboard::apply` do its own
/// presentation-level reduction.
///
/// `runner` is threaded in rather than created here because
/// `TaskRunner::bootstrap()` panics on its second call per process: the sole
/// authority to mint task events belongs to the process's startup path (see
/// `roundhouse_core::TaskRunner`), so a reusable function like this one must
/// borrow it, never mint it.
///
/// Sends on `updates` are best-effort: a detached client is an ordinary
/// condition, not a failure of the session, so a closed channel is logged and
/// the session still runs to completion.
///
/// # Errors
/// Returns [`DemoError`] if the store can't be opened, the chat turn fails, the
/// scripted edit is ambiguous or matches nothing, or the edited file can't be
/// read back.
pub async fn run_demo_session(
    cfg: DemoConfig,
    runner: &TaskRunner,
    updates: mpsc::Sender<ClientEvent>,
) -> Result<DemoOutcome, DemoError> {
    let store = open(&cfg.store_path).await?;
    let writer = spawn_writer(store).await;

    // Phase 7, Task 6: install a real redactor for this session's live
    // secret values BEFORE anything is appended through `writer` — nothing
    // has appended through it yet (the very first append below is
    // `run_chat_turn`'s), so this is the earliest point at which this
    // session's writer exists at all, and there is no window in which an
    // event could reference `cfg.request_ctx.api_key` before this call
    // takes effect. This demo has no configured MCP servers, so
    // `live_secret_values` is called with an empty slice — `spawn_writer`'s
    // own default (`Redactor::build(&[])`) previously left this session's
    // provider API key completely unprotected in the persisted log.
    //
    // Fix round 1 (W1-R22 as amended by W1-R28) folded this exact call
    // into `roundhouse_engine::create_session_with_egress`, so that
    // production session-creation path can no longer forget it. This
    // demo path is NOT that path: `run_demo_session` never calls
    // `create_session_with_egress` or `create_session_isolation` at all
    // (no isolation handle, no egress proxy — this is Phase 1's hermetic
    // exit-criterion path, kept as-is for offline/CI use). This manual
    // call therefore stays — it is the ONLY redaction wiring this path
    // has, and removing it on the assumption the fold covers it would
    // silently re-expose this demo's own `api_key`. A future retirement
    // of this fake-provider path (Task 7) is where this call site goes
    // away, not before.
    wire_redaction_for_session(&writer, &live_secret_values(&cfg.request_ctx, &[]));

    let session_id = SessionId::new();
    // A real user turn, not an empty `messages` array. `FakeEditProvider`
    // ignores the request entirely, so this made no difference while the demo
    // was fake-only — but Anthropic's API rejects an empty `messages` array
    // with a 400, so once `main.rs` started selecting the live provider on the
    // presence of `ANTHROPIC_API_KEY`, an empty turn would have made the demo
    // fail for every developer who happens to have that variable exported.
    //
    // Worded to match what the demo then actually does (`edit_file` replaces
    // `cfg.find` with `cfg.replace`), so a live run's response is coherent with
    // the edit the operator watches land, rather than a non sequitur.
    let user_turn = [Message {
        role: MessageRole::User,
        content: vec![ContentBlock::Text {
            text: format!(
                "Please update the demo file at {}: replace the word \"{}\" with \"{}\". \
                 Reply with one short sentence confirming the change.",
                cfg.edit_target.display(),
                cfg.find,
                cfg.replace
            ),
            cache: None,
            citations: vec![],
        }],
    }];
    let request = assemble_context("claude-sonnet-5", "You are careful.", &[], &user_turn);

    let blocks = run_chat_turn(
        &writer,
        runner,
        cfg.provider.as_ref(),
        &cfg.request_ctx,
        session_id,
        request,
    )
    .await?;

    // A real agent loop decides which tool to call by inspecting the
    // returned `ContentBlock::ToolUse` blocks (Phase 2+ dispatch logic,
    // gated by `Policy::decide`) — this demo hard-codes the one tool call
    // to prove the wiring without that not-yet-built dispatcher.
    //
    // TODO(Phase 2): this call goes straight to `roundhouse_tools::edit_file` with
    // nothing in front of it. Per `docs/architecture/03-security-and-sandboxing.md`
    // §6.2, "Every task passes `Policy::decide` before execution" — every real tool
    // dispatcher must call `roundhouse-policy` to gate the call (Allow/Ask/Deny) and
    // `roundhouse-sandbox` to isolate it *before* an executor in `roundhouse-tools`
    // ever runs, not just here but at every call site a future dispatcher adds. This
    // demo is exempt only because its one tool call is hard-coded, not model-chosen.
    edit_file(&cfg.edit_target, &cfg.find, &cfg.replace).await?;

    for block in &blocks {
        if let ContentBlock::Text { text, .. } = block {
            send_update(
                &updates,
                ClientEvent::TaskEvent {
                    session_id,
                    task_id: None,
                    payload: Box::new(EventPayload::TaskDelta {
                        delta: Delta::Text { text: text.clone() },
                    }),
                },
            )
            .await;
        }
    }
    send_update(
        &updates,
        ClientEvent::TaskEvent {
            session_id,
            task_id: None,
            payload: Box::new(EventPayload::SessionStateChanged {
                state: SessionState::Closed,
                reason: None,
            }),
        },
    )
    .await;

    let edited_file = tokio::fs::read_to_string(&cfg.edit_target).await?;
    Ok(DemoOutcome {
        session_id,
        blocks,
        edited_file,
    })
}

/// Best-effort push to the attached client. `send` only fails when the receiver
/// is gone, which just means nobody is watching — worth a debug line, not an error.
async fn send_update(updates: &mpsc::Sender<ClientEvent>, event: ClientEvent) {
    if updates.send(event).await.is_err() {
        tracing::debug!("no attached client; dropping session update");
    }
}
