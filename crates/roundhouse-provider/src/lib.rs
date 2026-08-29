//! The `Provider` trait, its adapters, and the capability registry: the
//! narrow-waist IR (`ChatRequest`/`ContentBlock`/`ToolDef`, §9.3) every
//! model provider is translated into and out of, so the rest of the system
//! never speaks a provider-specific wire format.
//!
//! Phase 0 ships the `Provider` trait signature and the IR types
//! (including `tool_def_from_schema`, S-TOOL-9's one sanctioned way to
//! build a `ToolDef` — its `input_schema` is always `schemars`-generated
//! from a typed Rust struct, never hand-written JSON, and `ToolDef`
//! deliberately doesn't derive `Deserialize` so that guarantee can't be
//! bypassed via `serde_json` either). Real provider adapters are Phase 6
//! work. See `docs/architecture/02-system-architecture.md` §5.2 and
//! `06-provider-abstraction.md`.
#![forbid(unsafe_code)]

mod cassette;
mod ir;
mod provider_trait;
mod stream_event;
mod transport;

pub use cassette::CassetteTransport;
pub use ir::{
    tool_def_from_schema, CacheBreakpoint, Capabilities, ChatRequest, ChatStream, Citation,
    ContentBlock, IdOrigin, MediaSource, Message, MessageRole, ModelId, ModelInfo, Params, Plan,
    ProviderError, ProviderExt, ProviderId, ReasoningIntent, ReasoningRequest, RequestCtx,
    RequestPolicy, ResponseFormat, ShellToolParams, Signature, SystemBlock, TokenCount,
    ToolCallId, ToolChoice, ToolDef, ToolResultPart,
};
pub use ir::MessageRole as Role; // compat alias — see stream_event module docs
pub use provider_trait::{BoxFut, Provider};
pub use stream_event::{BlockDelta, BlockKind, DeltaKeyer, StreamEvent};
pub use transport::{HttpRequest, HttpResponseStream, HttpTransport, TransportError};
