use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, Message, MessageRole as Role, ReasoningIntent, ToolChoice, ToolDef,
};

/// Encode a `ChatRequest` into the Anthropic Messages API `/v1/messages` request body format.
///
/// The encoder handles all ContentBlock variants and respects cache breakpoints on both
/// system blocks and message content blocks. Thinking blocks preserve their signatures
/// when present. Reasoning depth is computed from the ReasoningIntent level and sent as
/// `output_config.effort` (see `reasoning_effort`).
pub fn encode_anthropic_messages(req: &ChatRequest) -> Value {
    let system: Vec<Value> = req
        .system
        .iter()
        .map(|s| {
            let mut v = json!({ "type": "text", "text": s.text });
            // System blocks may carry cache_control (ephemeral breakpoint).
            if s.cache.is_some() {
                v["cache_control"] = json!({ "type": "ephemeral" });
            }
            v
        })
        .collect();

    // `system` is always an array form (never a bare string) to enable per-block
    // `cache_control` — a bare-string `system` field wouldn't support breakpoints
    // on individual blocks.

    let messages: Vec<Value> = req.messages.iter().filter_map(encode_message).collect();

    let mut body = json!({
        "model": req.model,
        "system": system,
        "messages": messages,
        "max_tokens": req.params.max_output_tokens.unwrap_or(4096),
        "stream": true,
    });

    if let Some(temperature) = req.params.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(top_p) = req.params.top_p {
        body["top_p"] = json!(top_p);
    }
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            body["stop_sequences"] = json!(stop);
        }
    }
    if !req.tools.is_empty() {
        body["tools"] = Value::Array(req.tools.iter().map(encode_tool).collect());
        body["tool_choice"] = encode_tool_choice(&req.tool_choice);
    }
    // ReasoningRequest.intent is Option<ReasoningIntent> (Phase 0's real IR); Off and
    // None are equivalent for this codec's purposes.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        // Current Anthropic models (including claude-sonnet-5) reject the older
        // `{"type": "enabled", "budget_tokens": N}` shape with a 400 — `budget_tokens`
        // has been removed from the API. The current shape is `{"type": "adaptive"}`,
        // with depth controlled by `output_config.effort` instead.
        body["thinking"] = json!({ "type": "adaptive" });
        body["output_config"] = json!({ "effort": reasoning_effort(intent) });
    }

    body
}

/// Encode a tool definition for the Anthropic Messages API.
fn encode_tool(tool: &ToolDef) -> Value {
    json!({
        "name": tool.name(),
        "description": tool.description(),
        "input_schema": tool.input_schema()
    })
}

/// Encode a ToolChoice variant to Anthropic's wire format.
/// Anthropic has no equivalent to "none" so that is degraded to "auto"; a Phase 2
/// LossEvent should be generated to track this downgrade.
fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => json!({ "type": "auto" }),
        ToolChoice::None => json!({ "type": "auto" }), // Anthropic has no "none"; degraded to auto, LossEvent in Phase 2
        ToolChoice::Required => json!({ "type": "any" }),
        ToolChoice::Named(name) => json!({ "type": "tool", "name": name }),
    }
}

/// Map a ReasoningIntent to Anthropic's `output_config.effort` value.
///
/// Anthropic's current API controls adaptive-thinking depth via `output_config.effort`
/// (accepted values: `low`/`medium`/`high`/`xhigh`/`max`), not the deprecated
/// `thinking.budget_tokens`. `ReasoningIntent::Off` never reaches this function (callers
/// only invoke it when `intent != Off`); the remaining four variants map directly onto
/// their same-named effort strings, leaving `xhigh` unused since Phase 0's `ReasoningIntent`
/// has no variant between `High` and `Max`. Verified against the current Anthropic API
/// reference as of this fix (I3 in the Phase 1 final review) — double-check against live
/// docs again before relying on this mapping long-term, since the API surface can change.
fn reasoning_effort(intent: ReasoningIntent) -> &'static str {
    match intent {
        ReasoningIntent::Off => "low",
        ReasoningIntent::Low => "low",
        ReasoningIntent::Medium => "medium",
        ReasoningIntent::High => "high",
        ReasoningIntent::Max => "max",
    }
}

/// Encode a message (conversation turn) for the Anthropic Messages API.
///
/// Returns `None` if the message's content is entirely composed of blocks that are
/// filtered out in Phase 1 scope (Image, Document, Opaque), resulting in an empty
/// `content` array — Anthropic's API rejects empty content arrays. This prevents the
/// same bug class as Task 7's ToolResult-only-message fix, but reached via block filtering
/// rather than unconditional push.
fn encode_message(msg: &Message) -> Option<Value> {
    let role = match msg.role {
        Role::User => "user",
        Role::Assistant => "assistant",
    };
    let content: Vec<Value> = msg.content.iter().filter_map(encode_block).collect();
    if content.is_empty() {
        return None;
    }
    Some(json!({ "role": role, "content": content }))
}

/// Encode a ContentBlock to its Anthropic wire format.
///
/// All 7 ContentBlock variants are handled:
/// - Text: simple text blocks with optional cache breakpoint
/// - ToolUse: tool invocations with id, name, and JSON input
/// - ToolResult: results from tool executions
/// - Thinking: internal reasoning with optional signature
/// - Image/Document/Opaque: not emitted in Phase 1 (return None; a Phase 2 LossEvent covers this)
fn encode_block(block: &ContentBlock) -> Option<Value> {
    match block {
        // `citations` is ignored here — Phase 1's two codecs never populate it (see
        // Task 6's deliberate-scoping note); the field exists on the frozen type
        // regardless of whether this codec reads it.
        ContentBlock::Text { text, cache, .. } => {
            let mut v = json!({ "type": "text", "text": text });
            if cache.is_some() {
                v["cache_control"] = json!({ "type": "ephemeral" });
            }
            Some(v)
        }
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Some(json!({
            "type": "tool_use",
            "id": id,
            "name": name,
            "input": input
        })),
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => {
            // `content` is `Vec<ToolResultPart>` (Phase 0's real IR) — Anthropic's
            // tool_result content accepts an array of text blocks directly.
            let parts: Vec<Value> = content
                .iter()
                .map(|p| json!({ "type": "text", "text": p.text }))
                .collect();
            Some(json!({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": parts,
                "is_error": is_error
            }))
        }
        ContentBlock::Thinking {
            text, signature, ..
        } => {
            let mut v = json!({ "type": "thinking", "thinking": text });
            if let Some(sig) = signature {
                // The `signature` field is Anthropic's integrity mechanism for replayed thinking
                // content — the signature must be preserved verbatim when a thinking block is
                // sent back to Anthropic in a later turn, so Anthropic can verify the block
                // wasn't tampered with.
                v["signature"] = json!(sig);
            }
            Some(v)
        }
        // Phase 1 scope: Image, Document, and Opaque blocks are not emitted to Anthropic.
        // A Phase 2 LossEvent should be generated on cross-provider handoff.
        ContentBlock::Image { .. }
        | ContentBlock::Document { .. }
        | ContentBlock::Opaque { .. } => None,
    }
}
