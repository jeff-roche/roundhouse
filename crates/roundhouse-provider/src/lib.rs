#![forbid(unsafe_code)]

mod ir;
mod provider_trait;

pub use ir::{
    tool_def_from_schema, CacheBreakpoint, Capabilities, ChatRequest, ChatStream, Citation,
    ContentBlock, IdOrigin, MediaSource, Message, MessageRole, ModelId, ModelInfo, Params, Plan,
    ProviderError, ProviderExt, ProviderId, ReasoningIntent, ReasoningRequest, RequestCtx,
    RequestPolicy, ResponseFormat, ShellToolParams, Signature, SystemBlock, TokenCount,
    ToolCallId, ToolChoice, ToolDef, ToolResultPart,
};
pub use provider_trait::{BoxFut, Provider};
