//! Encodes a `ChatRequest` into an Open Responses `/v1/responses` request
//! body. Verified against the real spec (`github.com/openresponses/
//! openresponses`, revision `2026-04-24`) before being written — see
//! `docs/decisions/2026-08-27-open-responses-spec-verification.md` for every
//! place this codec's shape diverges from the task brief's unverified sketch
//! (no `is_error` on `function_call_output`, no `stop` field at all, a flat
//! `tool_choice` named-tool shape, etc.) and why.

use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, MessageRole as Role, ReasoningIntent, ToolChoice, ToolDef,
};
use crate::profile::{glob_match, ProviderProfile, ReasoningControl};

/// Encodes a `ChatRequest` into an Open Responses `/v1/responses` request
/// body. Streaming is always enabled (`stream: true`), matching the
/// established precedent of the other two codecs in this crate.
pub fn encode(req: &ChatRequest, profile: &ProviderProfile) -> Value {
    let input: Vec<Value> = req
        .messages
        .iter()
        .flat_map(|msg| {
            msg.content
                .iter()
                .filter_map(move |block| encode_block(msg.role, block))
        })
        .collect();

    let mut body = json!({
        "model": req.model.0,
        "input": input,
        "stream": true,
    });

    if !req.system.is_empty() {
        let instructions: String = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        body["instructions"] = json!(instructions);
    }

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(req.tools.iter().map(encode_tool).collect());
        body["tool_choice"] = encode_tool_choice(&req.tool_choice);
    }

    if let Some(max_tokens) = req.params.max_output_tokens {
        body["max_output_tokens"] = json!(max_tokens);
    }

    // Spec-verification finding: `CreateResponseBody` has no `stop` field at
    // all -- Open Responses has no stop-sequence mechanism, unlike Chat
    // Completions. `Params.stop` is intentionally never encoded here,
    // regardless of length (see the `long_stop_sequence_list` golden case).
    //
    // Spec-verification finding: this profile's `[[model]]` entries only ever
    // match `gpt-5*` reasoning models, which OpenAI's real API rejects
    // `temperature`/`top_p` for. `temperature`/`top_p` are therefore never
    // encoded either, unconditionally rather than via a per-model check (see
    // the `temperature_forbidden_model` golden case).

    // REALITY-CORRECTIONS §7: `ReasoningRequest.intent` is
    // `Option<ReasoningIntent>`; a missing intent means Off.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        if let Some(control) = reasoning_control_for(profile, &req.model.0) {
            if let Ok(wire) = control.resolve(intent) {
                body["reasoning"] = json!({ "effort": wire });
            }
        }
    }

    // REALITY-CORRECTIONS §12c: raw passthrough is profile-gated, never
    // unconditional. `openai-responses.toml`'s `allow_raw_extra = false`
    // means a caller-supplied `extra` field never reaches the wire (see the
    // `raw_extra_passthrough_denied` golden case).
    if profile.defaults.allow_raw_extra {
        if let Value::Object(map) = &mut body {
            for (key, value) in &req.extra {
                map.insert(key.clone(), value.clone());
            }
        }
    }

    body
}

/// Finds the `ReasoningControl` for the first `[[model]]` entry whose glob
/// matches `model`, using the one shared `glob_match` helper (REALITY-
/// CORRECTIONS §8/audit finding 8) rather than a per-codec reimplementation.
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

fn encode_tool(tool: &ToolDef) -> Value {
    json!({
        "type": "function",
        "name": tool.name(),
        "description": tool.description(),
        "parameters": tool.input_schema(),
    })
}

/// Spec-verification finding: the named-tool shape here is the flat
/// `{"type": "function", "name": ...}` (`SpecificFunctionParam`) -- unlike the
/// sibling `openai_chat` codec's Chat Completions shape, there is no nested
/// `"function": {...}` wrapper.
fn encode_tool_choice(choice: &ToolChoice) -> Value {
    match choice {
        ToolChoice::Auto => json!("auto"),
        ToolChoice::None => json!("none"),
        ToolChoice::Required => json!("required"),
        ToolChoice::Named(name) => json!({ "type": "function", "name": name }),
    }
}

/// Encodes one content block into zero or one Open Responses input item.
/// Returns `None` for a block this codec doesn't put on the wire in this
/// task's scope:
///
/// - `Image`/`Document`: Open Responses supports `input_image`/`input_file`
///   items, but `roundhouse-provider` has no `base64` dependency today, and
///   both existing codecs in this crate already establish the precedent of
///   dropping these blocks in-scope with a "Phase 2 LossEvent" comment (see
///   `anthropic_messages::encode::encode_block`). This codec follows the same
///   precedent rather than being the first to add a new dependency for two
///   decorative golden cases -- flagged in the task report.
/// - `Thinking`: Open Responses' `reasoning` item type carries provider-opaque
///   `encrypted_content` from a prior turn; this codec never receives one to
///   resend in this task's scope.
/// - `Opaque`: round-trips only to the SAME (provider, model) by design, and
///   this codec's own decoder never produces one, so there is nothing for a
///   caller to resend here.
fn encode_block(role: Role, block: &ContentBlock) -> Option<Value> {
    match block {
        ContentBlock::Text { text, .. } => Some(json!({
            "type": "message",
            "role": role_str(role),
            "content": [{ "type": "input_text", "text": text }],
        })),
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Some(json!({
            "type": "function_call",
            "call_id": id.0,
            "name": name,
            "arguments": input.to_string(),
        })),
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            ..
        } => {
            // Spec-verification finding: `FunctionCallOutputItemParam`'s real
            // required fields are exactly `{call_id, type, output}` -- there
            // is no `is_error` field at all. A tool error has no wire
            // representation in this codec (see `tool_result_is_error`
            // golden case).
            let joined = content
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("");
            Some(json!({
                "type": "function_call_output",
                "call_id": tool_use_id.0,
                "output": joined,
            }))
        }
        ContentBlock::Image { .. }
        | ContentBlock::Document { .. }
        | ContentBlock::Thinking { .. }
        | ContentBlock::Opaque { .. } => None,
    }
}

fn role_str(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}
