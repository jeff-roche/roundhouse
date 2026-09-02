//! Encodes a `ChatRequest` into Cohere v2's `POST /v2/chat` request body.
//! Verified against the real, fetched Cohere API reference -- see `mod.rs`'s
//! module doc comment for the fetch record.

use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, Message, MessageRole as Role, ProviderError, ReasoningIntent,
    ToolChoice, ToolDef,
};
use crate::profile::{glob_match, ProfileReasoningError, ProviderProfile, ReasoningControl};

/// Everything that can go wrong turning a `ChatRequest` into a wire body.
/// Mirrors `google_genai::encode::EncodeError`'s structural fix: `Image`/
/// `Document`/`Opaque` blocks fail closed via this error type rather than
/// being silently dropped -- and the guard that matters is `stream_chat`'s
/// `encode(...)?` propagation (the actual production path), not only
/// `resolve`, which has zero production callers anywhere in this workspace.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("reasoning encode failed: {0}")]
    Reasoning(#[from] ProfileReasoningError),
    #[error("cohere-v2 codec does not encode {0} blocks")]
    UnencodableMedia(&'static str),
}

impl From<EncodeError> for ProviderError {
    fn from(err: EncodeError) -> Self {
        ProviderError::Unsupported(err.to_string())
    }
}

/// True if `req` contains a block anywhere in its messages that this codec
/// cannot encode -- used by `CohereV2Provider::resolve` as a cheap, I/O-free
/// pre-flight. The guarantee that actually holds on the production path is
/// `encode_message`'s `Err(EncodeError::UnencodableMedia)` return, propagated
/// through `stream_chat` -- see `EncodeError`'s doc comment.
///
/// `Thinking` is deliberately NOT in this set: Cohere v2's assistant message
/// content array documents a real `"type": "thinking"` block (verified --
/// see `mod.rs`'s fetch record), so this codec can actually round-trip a
/// prior turn's reasoning rather than failing closed on it the way
/// `google_genai`/`openai_responses` do for their own, different reasons.
pub fn contains_unencodable_media(req: &ChatRequest) -> bool {
    req.messages.iter().any(|m| {
        m.content.iter().any(|b| {
            matches!(
                b,
                ContentBlock::Image { .. }
                    | ContentBlock::Document { .. }
                    | ContentBlock::Opaque { .. }
            )
        })
    })
}

fn reasoning_control_for<'p>(
    profile: &'p ProviderProfile,
    model: &str,
) -> Option<&'p ReasoningControl> {
    profile
        .model
        .iter()
        .find(|entry| entry.match_globs.iter().any(|glob| glob_match(glob, model)))
        .and_then(|entry| entry.reasoning.as_ref())
}

/// Encodes `req` into Cohere v2's `/v2/chat` request body. Streaming is
/// always enabled (`stream: true`), matching this crate's established
/// precedent for every other codec.
pub fn encode(req: &ChatRequest, profile: &ProviderProfile) -> Result<Value, EncodeError> {
    let mut messages: Vec<Value> = Vec::new();

    if !req.system.is_empty() {
        let text: String = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        messages.push(json!({ "role": "system", "content": text }));
    }

    for msg in &req.messages {
        messages.extend(encode_message(msg)?);
    }

    let mut body = json!({
        "model": req.model.0,
        "messages": messages,
        "stream": true,
    });

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(req.tools.iter().map(encode_tool).collect());
        if let Some(tool_choice) = encode_tool_choice(&req.tool_choice) {
            body["tool_choice"] = tool_choice;
        }
    }

    // Verified request-body field names (docs.cohere.com/reference/chat):
    // `temperature`, `p` (not `top_p`), `max_tokens`, `stop_sequences`. This
    // crate's IR has no `top_k`-equivalent field on `Params`, so the
    // profile's declared `k` params-policy entry is never actually emitted
    // here -- it stays a permitted-but-unused mask entry.
    if let Some(temperature) = req.params.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(p) = req.params.top_p {
        body["p"] = json!(p);
    }
    if let Some(max_tokens) = req.params.max_output_tokens {
        body["max_tokens"] = json!(max_tokens);
    }
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            body["stop_sequences"] = json!(stop);
        }
    }

    // REALITY-CORRECTIONS §7: `ReasoningRequest.intent` is
    // `Option<ReasoningIntent>`; a missing intent means Off.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        if let Some(control) = reasoning_control_for(profile, &req.model.0) {
            let wire = control.resolve(intent)?;
            body["thinking"] = json!({ "type": wire });
        }
    }

    // REALITY-CORRECTIONS §12c: raw passthrough is profile-gated.
    if profile.defaults.allow_raw_extra {
        if let Value::Object(map) = &mut body {
            for (key, value) in &req.extra {
                map.insert(key.clone(), value.clone());
            }
        }
    }

    Ok(body)
}

fn encode_tool(tool: &ToolDef) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name(),
            "description": tool.description(),
            "parameters": tool.input_schema(),
        },
    })
}

/// Verified (docs.cohere.com/reference/chat): `tool_choice` accepts ONLY
/// `"REQUIRED"`/`"NONE"` -- there is no mechanism to force one SPECIFIC named
/// tool. `Auto` (the default) is omitted from the wire body entirely.
/// `Named` is degraded to `"REQUIRED"` (the closest honestly-expressible
/// shape: force *a* tool call) -- mirrors
/// `anthropic_messages::encode_tool_choice`'s identical, documented
/// `None -> auto` degrade precedent; a Phase 2 LossEvent should mark this
/// downgrade.
fn encode_tool_choice(choice: &ToolChoice) -> Option<Value> {
    match choice {
        ToolChoice::Auto => None,
        ToolChoice::None => Some(json!("NONE")),
        ToolChoice::Required => Some(json!("REQUIRED")),
        ToolChoice::Named(_) => Some(json!("REQUIRED")),
    }
}

/// Encodes one `Message` into zero or more Cohere v2 wire messages. A
/// `ToolResult` block always becomes its own trailing `{"role": "tool", ...}`
/// message (verified shape), regardless of `msg.role` -- mirrors
/// `openai_chat::encode_message`'s identical `tail_messages` pattern, since
/// this IR's `MessageRole` has only `User`/`Assistant`, never a `Tool`
/// variant of its own.
///
/// `Image`/`Document`/`Opaque` fail the whole encode closed (never silently
/// dropped) -- see `EncodeError`'s doc comment.
fn encode_message(msg: &Message) -> Result<Vec<Value>, EncodeError> {
    let role = match msg.role {
        Role::User => "user",
        Role::Assistant => "assistant",
    };

    let mut content_blocks: Vec<Value> = Vec::new();
    let mut has_thinking = false;
    let mut tool_calls: Vec<Value> = Vec::new();
    let mut tail_messages: Vec<Value> = Vec::new();

    for block in &msg.content {
        match block {
            ContentBlock::Text { text, .. } => {
                content_blocks.push(json!({ "type": "text", "text": text }));
            }
            // Verified: the assistant content array's real "thinking" block
            // shape is `{"type": "thinking", "thinking": "..."}` -- see
            // `mod.rs`'s fetch record.
            ContentBlock::Thinking { text, .. } => {
                has_thinking = true;
                content_blocks.push(json!({ "type": "thinking", "thinking": text }));
            }
            ContentBlock::ToolUse {
                id, name, input, ..
            } => {
                tool_calls.push(json!({
                    "id": id.0,
                    "type": "function",
                    // Cohere requires tool arguments as a JSON string, not a
                    // nested object (verified: `function.arguments` (string)).
                    "function": { "name": name, "arguments": input.to_string() },
                }));
            }
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                // `content` is `Vec<ToolResultPart>`; Cohere's tool message
                // content accepts a plain string. Verified: the tool message
                // shape has no `is_error`-equivalent field, so that flag is
                // not forwarded -- matches `openai_chat`'s identical gap for
                // the same reason (no wire field to carry it).
                let joined = content
                    .iter()
                    .map(|p| p.text.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                tail_messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id.0,
                    "content": joined,
                }));
            }
            ContentBlock::Image { .. } => return Err(EncodeError::UnencodableMedia("Image")),
            ContentBlock::Document { .. } => return Err(EncodeError::UnencodableMedia("Document")),
            ContentBlock::Opaque { .. } => return Err(EncodeError::UnencodableMedia("Opaque")),
        }
    }

    let mut out = Vec::new();
    if !content_blocks.is_empty() || !tool_calls.is_empty() {
        // `content` is sent as a plain string when the message carries only
        // `Text` blocks (the common case, and the simplest valid wire shape);
        // as a typed content-block array only when a `Thinking` block is
        // present too, since Cohere's plain-string form has no way to carry
        // a block `type` discriminator. `Value::Null` when there is no text
        // or thinking at all (a ToolUse-only assistant turn) -- mirrors
        // `openai_chat::encode_message`'s identical convention.
        let content_value = if has_thinking {
            json!(content_blocks)
        } else if content_blocks.is_empty() {
            Value::Null
        } else {
            let joined: String = content_blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("");
            json!(joined)
        };
        let mut m = json!({ "role": role, "content": content_value });
        if !tool_calls.is_empty() {
            m["tool_calls"] = json!(tool_calls);
        }
        out.push(m);
    }
    out.extend(tail_messages);
    Ok(out)
}
