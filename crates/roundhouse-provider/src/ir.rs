use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Bare-`pub` tuple id, deliberately unlike the four private-field core ids
/// (`SessionId`/`TaskId`/`WorkspaceId`/`TeamId`) — see `RuleId`'s doc
/// comment in `roundhouse-core/src/task_meta.rs` for the rationale: this
/// names an externally-sourced value (a provider's model name string), not
/// an identity this system mints and must guard against collision.
///
/// Derives `Hash` (added 2026-08-29, Task 6) because `crate::retry` keys a
/// `HashMap<(ProviderId, ModelId), _>` — its `CircuitBreaker` and
/// `AimdSemaphore` are indexed per `(provider, model)` pair. Both wrap a
/// single `String`, which is already `Hash`, so this is additive and
/// doesn't change either type's external behavior — but removing it would
/// break `roundhouse_provider::retry`'s compile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelId(pub String);

/// See `ModelId`'s doc comment above (same rationale — a vendor name, not a
/// minted identity — and the same reason for deriving `Hash`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheBreakpoint;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Citation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaSource {
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// Bare-`pub` tuple id, deliberately unlike the four private-field core ids
/// (`SessionId`/`TaskId`/`WorkspaceId`/`TeamId`) — see `RuleId`'s doc
/// comment in `roundhouse-core/src/task_meta.rs` for the rationale: this
/// wraps whatever id string the *provider* assigned to a tool call (or one
/// this crate synthesizes for a provider that doesn't assign one — see
/// `IdOrigin` below), not an identity minted and guarded by this system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallId(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdOrigin {
    Provider,
    Synthesized,
}

/// See `ToolCallId`'s doc comment above (same rationale — an opaque,
/// provider-issued token round-tripped verbatim, not a minted identity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResultPart {
    pub text: String,
}

/// §9.3 — the narrow waist. Anthropic-shaped, ordered heterogeneous
/// content blocks: the only IR shape lossless for the hardest provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContentBlock {
    Text {
        text: String,
        cache: Option<CacheBreakpoint>,
        citations: Vec<Citation>,
    },
    Image {
        source: MediaSource,
        cache: Option<CacheBreakpoint>,
    },
    Document {
        source: MediaSource,
        title: Option<String>,
        cache: Option<CacheBreakpoint>,
    },
    ToolUse {
        id: ToolCallId,
        id_origin: IdOrigin,
        name: String,
        input: Value,
        cache: Option<CacheBreakpoint>,
    },
    ToolResult {
        tool_use_id: ToolCallId,
        content: Vec<ToolResultPart>,
        is_error: bool,
        cache: Option<CacheBreakpoint>,
    },
    Thinking {
        text: String,
        signature: Option<Signature>,
        redacted: bool,
    },
    /// Round-trips verbatim to the SAME (provider, model); dropped with a
    /// LossEvent on cross-provider handoff.
    Opaque {
        provider: ProviderId,
        kind: String,
        raw: Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBlock {
    pub text: String,
    pub cache: Option<CacheBreakpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Assistant,
}

/// Fields are private: `tool_def_from_schema` (below) is the only
/// sanctioned constructor (S-TOOL-9, §12.7) — see its doc comment for why.
/// Read access is via the accessors below; there is deliberately no public
/// way to construct or mutate a `ToolDef` with a hand-written
/// `input_schema`.
///
/// Deliberately does **not** derive `Deserialize`, unlike this struct's
/// sibling IR types: a derived impl lives inside `roundhouse-provider`
/// itself, so it has ordinary same-module access to these private fields
/// and would let `serde_json::from_str::<ToolDef>(..)` construct one with
/// an arbitrary hand-written `input_schema` — private fields only block
/// the `ToolDef { .. }` struct-literal from other crates, not trait-based
/// deserialization. That would reopen exactly the schema/type-confusion
/// gap S-TOOL-9 exists to close (see `Event`'s `Seal` doc comment in
/// `roundhouse-core` for the same class of bypass, closed the same way).
/// If a later phase needs to reconstruct a `ToolDef` from persisted or
/// wire data, that should be a narrow, reviewed function that still routes
/// through `tool_def_from_schema`-equivalent validation, not a blanket
/// derive.
#[derive(Debug, Clone, Serialize)]
pub struct ToolDef {
    name: String,
    description: String,
    input_schema: Value,
    /// `#[serde(skip)]`: this is Roundhouse-internal taint metadata, never
    /// part of a provider's tool-list payload (the Anthropic/OpenAI wire
    /// shapes this `Serialize` derives for have no such field). `Some` only
    /// for wire-sourced definitions built through [`ToolDef::from_wire_parts`]
    /// — see the field doc on why the `Provenance` rides on the def itself.
    /// `None` means repo-authored: `tool_def_from_schema`'s typed,
    /// `schemars`-generated local tools.
    #[serde(skip)]
    provenance: Option<roundhouse_core::Provenance>,
}

impl ToolDef {
    /// S-TOOL-9's boundary case (Phase 3): the narrow, reviewed construction
    /// path for *wire-sourced* tool definitions. An MCP server's
    /// `server/discover` response carries `inputSchema` JSON authored by the
    /// remote server — there is no Rust params struct to hand
    /// [`tool_def_from_schema`], and the schema is untrusted content by
    /// construction (§6.8 names tool descriptions untrusted; the schema
    /// rides alongside them). Taking the schema as a [`serde_json::Map`]
    /// makes a non-object schema unrepresentable at the type level — the
    /// same root-shape guarantee `schemars` gives [`tool_def_from_schema`] —
    /// so a caller holding a raw wire `Value` must fail closed on the
    /// non-object case itself (roundhouse-mcp's `McpHost::start` does, with
    /// a named error).
    ///
    /// `provenance` is a *required* argument, not an `Option`, and not
    /// defaulted (Phase 3 review fix, 2026-09-01): the architecture's §6.8
    /// mitigation — a session that reads untrusted content has its standing
    /// permissions downgraded to `Ask` — is engine logic that only ever
    /// holds the model-facing `Vec<ToolDef>`, so the `Untrusted` flag has to
    /// be readable from the definition itself. A constructor that let a
    /// wire-sourced def be built *without* provenance would recreate exactly
    /// the gap the flag exists to close; there is no honest provenance value
    /// to default to, so the caller must name the one it has (roundhouse-mcp
    /// stamps `Trust::Untrusted` + the discovery task's id). Nothing here
    /// certifies the schema's *content*; handling that provenance remains
    /// the engine's job.
    pub fn from_wire_parts(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: serde_json::Map<String, Value>,
        provenance: roundhouse_core::Provenance,
    ) -> Self {
        ToolDef {
            name: name.into(),
            description: description.into(),
            input_schema: Value::Object(input_schema),
            provenance: Some(provenance),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn input_schema(&self) -> &Value {
        &self.input_schema
    }

    /// The taint metadata for wire-sourced definitions
    /// ([`Self::from_wire_parts`]); `None` for repo-authored
    /// [`tool_def_from_schema`] tools. Engine trust-mitigation logic reads
    /// the flag here — see [`Self::from_wire_parts`]'s note on why
    /// provenance rides on the tool list itself.
    pub fn provenance(&self) -> Option<&roundhouse_core::Provenance> {
        self.provenance.as_ref()
    }
}

/// S-TOOL-9 (§12.7) — Phase 0 contract: a tool's `input_schema` is always
/// generated from a typed Rust params struct via `schemars`, never
/// hand-written JSON, so the schema and the type actually used to
/// deserialize arguments can never drift apart. `ShellToolParams` is Phase
/// 0's one concrete example proving the wiring end-to-end; later phases add
/// one params struct per tool (`read`, `edit`, `http`, `mcp`, ...) and call
/// `tool_def_from_schema` for each rather than hand-authoring JSON Schema.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ShellToolParams {
    pub command: String,
    pub cwd: Option<String>,
}

/// The only sanctioned way to build a `ToolDef`: `T`'s JSON Schema,
/// generated by `schemars`, converted to the plain `serde_json::Value`
/// `ToolDef.input_schema` already commits to as its wire/storage shape. No
/// executor should ever construct a `ToolDef` by hand-writing
/// `input_schema` JSON directly.
pub fn tool_def_from_schema<T: schemars::JsonSchema>(
    name: impl Into<String>,
    description: impl Into<String>,
) -> ToolDef {
    let schema = schemars::schema_for!(T);
    let input_schema =
        serde_json::to_value(&schema).expect("schemars::Schema always serializes to JSON");
    ToolDef {
        name: name.into(),
        description: description.into(),
        input_schema,
        provenance: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToolChoice {
    Auto,
    None,
    Required,
    Named(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Params {
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub max_output_tokens: Option<u32>,
    pub stop: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReasoningIntent {
    Off,
    Low,
    Medium,
    High,
    Max,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReasoningRequest {
    pub intent: Option<ReasoningIntent>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResponseFormat {
    pub json_schema: Option<Value>,
}

/// §9.6 — closed typed extension enum, one variant per provider family,
/// exhaustively matched so a new variant can't be silently ignored. Phase
/// 0 ships an empty-but-real placeholder variant; Phase 6 adds the rest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderExt {
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestPolicy {
    Error,
    Drop,
    Downgrade,
}

/// §9.3 — the narrow waist request shape.
///
/// Does not derive `Deserialize`: it carries a `Vec<ToolDef>`, and
/// `ToolDef` deliberately doesn't derive `Deserialize` either (see its doc
/// comment) — a derived impl here would just push the same bypass down
/// one field.
#[derive(Debug, Clone, Serialize)]
pub struct ChatRequest {
    pub model: ModelId,
    pub system: Vec<SystemBlock>,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolDef>,
    pub tool_choice: ToolChoice,
    pub params: Params,
    pub reasoning: ReasoningRequest,
    pub response_format: ResponseFormat,
    pub ext: ProviderExt,
    pub extra: BTreeMap<String, Value>,
    pub policy: RequestPolicy,
}

use crate::transport::HttpTransport;

/// Request context carrying the trace ID, HTTP transport, and API key.
///
/// Does not derive `Default` or `Debug` because `Arc<dyn HttpTransport>` does not implement
/// either trait — a transport must be provided explicitly at construction.
pub struct RequestCtx {
    /// Optional trace ID for request tracing.
    pub trace_id: Option<String>,
    /// HTTP transport implementation (may be real network or test cassette).
    pub transport: std::sync::Arc<dyn HttpTransport>,
    /// API key for the provider. Simplified for Phase 1; §9.9's `Secret<String>`/`CredentialProvider` lands in Phase 2.
    pub api_key: String,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub endpoint: String,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub streaming: bool,
    pub tools: bool,
    pub thinking: bool,
    pub max_breakpoints: u8,
}

#[derive(Debug, Clone, Default)]
pub struct TokenCount {
    pub tokens: u64,
}

#[derive(Debug, Clone)]
pub struct ModelInfo {
    pub id: ModelId,
    pub context_window: Option<u64>,
}

/// The real streamed-event type (§9.3: "streaming is the only path — there
/// is no non-streaming method"). Replaces Phase 0's Task 7 placeholder
/// (`#[derive(Debug, Clone, Default)] pub struct ChatStream;`) in place, per
/// that placeholder's own hand-off comment. A newtype (not a bare type
/// alias) so `ChatStream` has exactly one name and one definition site
/// across every codec's `stream_chat` impl.
pub struct ChatStream(
    pub std::pin::Pin<Box<dyn futures::Stream<Item = crate::stream_event::StreamEvent> + Send>>,
);

impl futures::Stream for ChatStream {
    type Item = crate::stream_event::StreamEvent;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx)
    }
}

/// Extended 2026-08-28 (audit follow-up, same class of fix as `RequestCtx`/
/// `ChatStream` above): the original 3 variants were enough for the
/// `Provider` trait's signature to compile, but §9.8's classification table
/// (provider error code → message regex → HTTP status default, feeding
/// directly into Phase 2's retry/fallback disposition logic) needs a real
/// error to classify *into* at the adapter boundary — that error is this
/// one, since it's what every `Provider` method already returns. Phase 2's
/// plan originally defined a second, richer `ProviderError` at
/// `roundhouse_provider::errors::ProviderError` and its own `classify()`
/// function returned *that* type — but `classify()` is meant to be called
/// from inside each adapter's error-handling path, at exactly the point an
/// adapter must produce the `ProviderError` its `Provider::stream_chat`/
/// `resolve`/`count_tokens`/`list_models` implementation returns. Two
/// competing types under the same name made that impossible without either
/// throwing away the classification right where it's useful, or forking the
/// trait's error type. Fixed by extending this one type in place instead;
/// Phase 2's `errors.rs` now imports it rather than redefining it.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ProviderError {
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("stream interrupted after first token; partial output attached")]
    StreamInterrupted { partial: String },
    /// §9.8: "capacity, not your fault" — retry with full-jitter backoff.
    #[error("provider overloaded")]
    Overloaded,
    /// §9.8: "your request rate" — shed concurrency, then retry.
    #[error("rate limited (retry_after={retry_after:?})")]
    RateLimited {
        retry_after: Option<std::time::Duration>,
    },
    /// §9.8: billing — fatal, never retry.
    #[error("quota exhausted")]
    QuotaExhausted,
    /// §9.8: 5xx / timeout family — retry, capped attempts.
    #[error("server error: {status}")]
    Server { status: u16 },
    /// §9.8: 400 (shape rejected) — fatal, never retry a request the server
    /// already rejected on shape.
    #[error("bad request ({status}): {body_snippet}")]
    BadRequest { status: u16, body_snippet: String },
    /// §9.8: 404 model — fallback to the next provider in the chain.
    #[error("model not found")]
    ModelNotFound,
    #[error("request timed out")]
    Timeout,
}
