use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, Message, MessageRole as Role, ReasoningIntent, ToolChoice, ToolDef,
};
use crate::profile::{glob_match, ProviderProfile};

/// Finds the `[[model]]` entry (if any) whose `match` globs match `model`,
/// and returns its `reasoning` control -- the same (provider, model) keying
/// every other codec's `reasoning_control_for` uses (mirrors
/// `cohere_v2::encode::reasoning_control_for` exactly).
fn reasoning_control_for<'p>(
    profile: &'p ProviderProfile,
    model: &str,
) -> Option<&'p crate::profile::ReasoningControl> {
    profile
        .model
        .iter()
        .find(|entry| entry.match_globs.iter().any(|glob| glob_match(glob, model)))
        .and_then(|entry| entry.reasoning.as_ref())
}

/// Encodes a `ChatRequest` into an OpenAI-compatible `/v1/chat/completions` request body.
///
/// Streaming is always enabled (`stream: true`) as per §9.3.
///
/// Fix round 1, P2: previously took only `&ChatRequest`, so a profile's
/// declared `[[model]].reasoning` (e.g. moonshot's `reasoning_effort`
/// control) was fully modeled and deserialized but never consulted --
/// dead configuration. Now looks up the matched model's `ReasoningControl`
/// the same way `cohere_v2::encode::encode` does, and forwards the resolved
/// wire value under the real, verified OpenAI-compatible top-level
/// `reasoning_effort` field (moonshot's own declared `field =
/// "/reasoning_effort"` names this same key; as with every other codec in
/// this crate, `.field`'s string is documentation, not mechanically walked
/// as a JSON pointer -- `cohere_v2`/`google_genai`/`openai_responses` all
/// hardcode their own wire path the same way).
pub fn encode_openai_chat(req: &ChatRequest, profile: &ProviderProfile) -> Value {
    let mut messages: Vec<Value> = Vec::new();

    if !req.system.is_empty() {
        let system_text = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        messages.push(json!({ "role": "system", "content": system_text }));
    }

    for msg in &req.messages {
        messages.extend(encode_message(msg));
    }

    let mut body = json!({
        "model": req.model,
        "messages": messages,
        "stream": true,
    });

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(req.tools.iter().map(encode_tool).collect());
        body["tool_choice"] = encode_tool_choice(&req.tool_choice);
    }
    if let Some(max_tokens) = req.params.max_output_tokens {
        body["max_tokens"] = json!(max_tokens);
    }
    if let Some(temperature) = req.params.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            body["stop"] = json!(stop);
        }
    }

    // REALITY-CORRECTIONS §7: `ReasoningRequest.intent` is
    // `Option<ReasoningIntent>`; a missing intent means Off. `resolve()` can
    // fail if a profile's `map`/`vocabulary` are inconsistent for this
    // intent (a profile-authoring bug, not a request-shape one); this
    // function is infallible (`-> Value`, matching its established Phase 1
    // signature and every one of its 4 call sites), so — same as an
    // unmatched model glob — an `Err` here just means no `reasoning_effort`
    // field is added, rather than propagating a new error type through
    // every caller.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        if let Some(control) = reasoning_control_for(profile, &req.model.0) {
            if let Ok(wire) = control.resolve(intent) {
                body["reasoning_effort"] = json!(wire);
            }
        }
    }

    body
}

fn encode_tool(tool: &ToolDef) -> Value {
    json!({
        "type": "function",
        "function": {
            "name": tool.name(),
            "description": tool.description(),
            "parameters": tool.input_schema(),
        }
    })
}

fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Named(name) => json!({ "type": "function", "function": { "name": name } }),
    }
}

fn encode_message(msg: &Message) -> Vec<Value> {
    let role = match msg.role {
        Role::User => "user",
        Role::Assistant => "assistant",
    };

    let mut text_parts = Vec::new();
    let mut tool_calls = Vec::new();
    let mut tail_messages = Vec::new();

    for block in &msg.content {
        match block {
            ContentBlock::Text { text, .. } => text_parts.push(text.clone()),
            ContentBlock::ToolUse {
                id, name, input, ..
            } => {
                tool_calls.push(json!({
                    "id": id,
                    "type": "function",
                    // OpenAI requires tool arguments as a JSON string, not a nested object.
                    "function": { "name": name, "arguments": input.to_string() },
                }));
            }
            ContentBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                // `content` is `Vec<ToolResultPart>` (Phase 0's real IR); OpenAI's tool
                // message content is a single string, so join the parts' text.
                let joined = content
                    .iter()
                    .map(|p| p.text.as_str())
                    .collect::<Vec<_>>()
                    .join("");
                tail_messages.push(json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id,
                    "content": joined,
                }));
            }
            // OpenAI Chat has no wire representation for thinking blocks; dropping here is
            // Phase 1 scope — the LossEvent this drop should emit is Phase 2's loss-plumbing task.
            ContentBlock::Thinking { .. } => {}
            // Image, Document, and Opaque blocks are not handled in Phase 1 scope.
            ContentBlock::Image { .. } => {}
            ContentBlock::Document { .. } => {}
            ContentBlock::Opaque { .. } => {}
        }
    }

    let mut out = Vec::new();
    // Only push the primary role message if there's actual content (text or tool calls).
    // For messages containing only ToolResult blocks, skip the primary message and let the
    // tail_messages (role: "tool") carry the content instead.
    if !text_parts.is_empty() || !tool_calls.is_empty() {
        if tool_calls.is_empty() {
            out.push(json!({ "role": role, "content": text_parts.join("") }));
        } else {
            out.push(json!({
                "role": role,
                "content": if text_parts.is_empty() { Value::Null } else { json!(text_parts.join("")) },
                "tool_calls": tool_calls,
            }));
        }
    }
    out.extend(tail_messages);
    out
}
