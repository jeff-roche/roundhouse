use roundhouse_provider::{
    CacheBreakpoint, ChatRequest, Message, ModelId, Params, ProviderExt, ReasoningRequest,
    RequestPolicy, ResponseFormat, SystemBlock, ToolChoice, ToolDef,
};
use std::collections::BTreeMap;

/// Renders the first three of §15.4's six canonical context layers (system prompt, tool
/// definitions, current turn — see this task's Interfaces note for the corrected full
/// six-layer order and why only one cache breakpoint is placed in Phase 1).
///
/// The fixed render order is: system prompt (layer 1 of 6, most stable) → tool
/// definitions (layer 2) → [memory / compaction summary / retained window: not
/// yet implemented, Phase 2+] → current turn (layer 6, least stable). This layer order
/// is the struct field order in the returned `ChatRequest`; there is exactly one place in the
/// codebase that decides it.
///
/// Cache breakpoints: Phase 1's IR can only express a breakpoint at one of the two
/// adjacent boundaries (system|tools and tools|turn) — `SystemBlock` and `ContentBlock`
/// carry a `cache: Option<CacheBreakpoint>` field, but `ToolDef` does not. So exactly one
/// breakpoint is placed on the system block, at the system|everything-after boundary; this
/// is the only boundary the IR can express in Phase 1. A future phase adding `ToolDef.cache`
/// and growing memory/compaction/retained-window layers would place up to `Capabilities::max_breakpoints` total.
pub fn assemble_context(
    model: &str,
    system_prompt: &str,
    tools: &[ToolDef],
    turn_messages: &[Message],
) -> ChatRequest {
    ChatRequest {
        model: ModelId(model.to_string()),
        // Fixed render order: system prompt (layer 1 of 6, most stable) -> tool
        // definitions (layer 2) -> [memory / compaction summary / retained window: not
        // yet implemented, Phase 2+] -> current turn (layer 6, least stable). Layer order
        // is the struct field order below; there is exactly one place in the codebase
        // that decides it.
        system: vec![SystemBlock { text: system_prompt.to_string(), cache: Some(CacheBreakpoint) }],
        tools: tools.to_vec(),
        messages: turn_messages.to_vec(),
        tool_choice: ToolChoice::Auto,
        params: Params::default(),
        reasoning: ReasoningRequest::default(),
        // Unpopulated in Phase 1 (see Task 6's deliberate-scoping note) — the type
        // carries them since it's frozen/shared.
        response_format: ResponseFormat::default(),
        ext: ProviderExt::None,
        extra: BTreeMap::new(),
        policy: RequestPolicy::Error,
    }
}
