//! Encodes a `ChatRequest` into either the Gemini Interactions API's request
//! body (default, §9.2) or the legacy `generateContent`/`streamGenerateContent`
//! body, selected by [`EndpointMode`]. Verified against the real fetched spec
//! before being written -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md`. The two
//! modes' content models genuinely diverge (Divergence 1 in that doc): there
//! is no shared `contents[].parts[]`/`encode_block` helper here the way the
//! task brief's unverified sketch assumed -- `encode_interactions` and
//! `encode_generate_content` are independent, and share only the handful of
//! things that really are mode-independent (tool metadata extraction, the
//! `EncodeError` type, the reasoning-control lookup for `GenerateContent`
//! mode).

use super::EndpointMode;
use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, MessageRole as Role, ProviderError, ReasoningIntent, ToolChoice,
    ToolDef,
};
use crate::profile::{glob_match, ProfileReasoningError, ProviderProfile, ReasoningControl};

/// Everything that can go wrong turning a `ChatRequest` into a wire body.
/// Mirrors `openai_responses::encode::EncodeError`'s structural fix
/// (fix-round-2 D1 on that codec): `Image`/`Document` blocks fail closed via
/// this error type rather than being silently dropped by returning `Ok(None)`
/// -- and the guard that matters lives on `stream_chat`'s `encode(...)?`
/// propagation (every production caller's actual path), not only on
/// `resolve`, which has zero production callers anywhere in this workspace.
///
/// Carries the offending block's kind (`"Image"` or `"Document"`) so the two
/// cases are distinguishable in the error message and golden snapshot --
/// Task 5's two golden snapshots for this were byte-identical because its
/// error message didn't distinguish them (a carried-forward review fix,
/// applied here from the start rather than after review).
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("reasoning encode failed: {0}")]
    Reasoning(#[from] ProfileReasoningError),
    #[error("google-genai codec does not encode {0} blocks")]
    UnencodableMedia(&'static str),
}

/// `stream_chat` propagates an `EncodeError` via `?` -- see
/// `openai_responses::encode`'s identical `From` impl for the same reasoning.
impl From<EncodeError> for ProviderError {
    fn from(err: EncodeError) -> Self {
        ProviderError::Unsupported(err.to_string())
    }
}

/// Encodes `req` for the given `mode`. Streaming is always enabled (matches
/// this crate's established precedent for every other codec).
pub fn encode(
    req: &ChatRequest,
    profile: &ProviderProfile,
    mode: EndpointMode,
) -> Result<Value, EncodeError> {
    match mode {
        EndpointMode::Interactions => encode_interactions(req, profile),
        EndpointMode::GenerateContent => encode_generate_content(req, profile),
    }
}

/// True if `req` contains an `Image` or `Document` block anywhere in its
/// messages -- used by `GoogleGenAiProvider::resolve` as a cheap, I/O-free
/// pre-flight. The guarantee that actually holds on the production path is
/// `encode_block`'s `Err(EncodeError::UnencodableMedia)` return, propagated
/// through `stream_chat` -- see this module's doc comment on `EncodeError`.
pub fn contains_unencodable_media(req: &ChatRequest) -> bool {
    req.messages.iter().any(|m| {
        m.content.iter().any(|b| {
            matches!(
                b,
                ContentBlock::Image { .. } | ContentBlock::Document { .. }
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

// ============================================================================
// Interactions API (default, §9.2)
// ============================================================================

/// §9.4's working bet, verified false for the content model (Divergence 1):
/// there is no `contents` field on this surface at all. `input` is a flat
/// `Step[]` (`InteractionsInput`'s `StepList` variant, verified in
/// `interactions.openapi.json`) -- one `Step` per content block, not one
/// `Content` per message the way `generateContent` groups them.
fn encode_interactions(req: &ChatRequest, profile: &ProviderProfile) -> Result<Value, EncodeError> {
    let mut input: Vec<Value> = Vec::new();
    for msg in &req.messages {
        for block in &msg.content {
            if let Some(step) = encode_interactions_step(msg.role, block)? {
                input.push(step);
            }
        }
    }

    let mut body = json!({
        "model": req.model.0,
        "input": input,
        "stream": true,
    });

    if !req.system.is_empty() {
        let text: String = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        body["system_instruction"] = json!(text);
    }

    if !req.tools.is_empty() {
        body["tools"] = Value::Array(req.tools.iter().map(encode_function_tool).collect());
        if let Some(tool_choice) = encode_interactions_tool_choice(&req.tool_choice) {
            body["generation_config"]["tool_choice"] = tool_choice;
        }
    }

    if let Some(max_tokens) = req.params.max_output_tokens {
        body["generation_config"]["max_output_tokens"] = json!(max_tokens);
    }

    // Verified real: `GenerationConfig.stop_sequences` exists on this surface
    // (Divergence 5, in this codec's favor unlike Open Responses' Task 5
    // finding of no stop-sequence mechanism at all).
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            body["generation_config"]["stop_sequences"] = json!(stop);
        }
    }

    // Divergence 3: verified that `temperature`/`top_p`/`top_k` do not exist
    // anywhere in this surface's request schema (checked the full property
    // lists of both `CreateModelInteractionParams` and `GenerationConfig`) --
    // never encoded here for any model, as a structural fact about the wire
    // schema, not a per-model policy the way OpenAI's `gpt-5*` family forbids
    // temperature alongside reasoning (Task 5's finding).

    // REALITY-CORRECTIONS §7: `ReasoningRequest.intent` is
    // `Option<ReasoningIntent>`; a missing intent means Off.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if let Some(level) = interactions_thinking_level(intent) {
        body["generation_config"]["thinking_level"] = json!(level);
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

/// Divergence 2: the Interactions API has no numeric thinking-budget field at
/// all -- only `thinking_level` (`ThinkingLevel`: `minimal|low|medium|high`,
/// verified, no `max` tier). This is a small, fixed, spec-mandated wire enum,
/// so it's hardcoded here rather than routed through the profile's
/// Budget-kind `ReasoningControl` (which targets `GenerateContent` mode's
/// `thinkingConfig.thinkingBudget` instead -- the two wire vocabularies are
/// incompatible, and `ModelEntry` has room for only one `ReasoningControl`
/// per model). Returns `None` for `Off` (field omitted entirely).
fn interactions_thinking_level(intent: ReasoningIntent) -> Option<&'static str> {
    match intent {
        ReasoningIntent::Off => None,
        ReasoningIntent::Low => Some("low"),
        ReasoningIntent::Medium => Some("medium"),
        ReasoningIntent::High | ReasoningIntent::Max => Some("high"),
    }
}

/// Encodes one content block into zero or one Interactions API `Step`.
///
/// `Ok(None)` for `Thinking`/`Opaque` -- see this module's doc comment on
/// `EncodeError` and the decision doc's Divergence 6 for why encoding a real
/// `thought` step (which needs cross-block state to attach a signature to an
/// adjacent `function_call` step correctly) is out of this task's scope.
///
/// `Err(EncodeError::UnencodableMedia(kind))` -- never `Ok(None)` -- for
/// `Image`/`Document`: this crate has no `base64` dependency (Divergence 6).
fn encode_interactions_step(
    role: Role,
    block: &ContentBlock,
) -> Result<Option<Value>, EncodeError> {
    match block {
        ContentBlock::Text { text, .. } => {
            let step_type = match role {
                Role::User => "user_input",
                Role::Assistant => "model_output",
            };
            Ok(Some(json!({
                "type": step_type,
                "content": [{ "type": "text", "text": text }],
            })))
        }
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Ok(Some(json!({
            "type": "function_call",
            "id": id.0,
            "name": name,
            "arguments": input,
        }))),
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => {
            // Divergence 5: `FunctionResultStep.is_error` is a real field on
            // this surface (unlike Open Responses' `function_call_output`,
            // Task 5's finding) -- forwarded here, not dropped.
            let joined = content
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("");
            Ok(Some(json!({
                "type": "function_result",
                "call_id": tool_use_id.0,
                "result": joined,
                "is_error": is_error,
            })))
        }
        ContentBlock::Image { .. } => Err(EncodeError::UnencodableMedia("Image")),
        ContentBlock::Document { .. } => Err(EncodeError::UnencodableMedia("Document")),
        ContentBlock::Thinking { .. } | ContentBlock::Opaque { .. } => Ok(None),
    }
}

fn encode_function_tool(tool: &ToolDef) -> Value {
    json!({
        "type": "function",
        "name": tool.name(),
        "description": tool.description(),
        "parameters": tool.input_schema(),
    })
}

/// `generation_config.tool_choice` (`ToolChoiceConfig`, verified): `{
/// "allowed_tools": { "mode": "auto"|"any"|"none"|"validated", "tools":
/// [string] } }`. `Auto` is the default and is omitted from the wire body
/// entirely rather than spelled out.
fn encode_interactions_tool_choice(choice: &ToolChoice) -> Option<Value> {
    match choice {
        ToolChoice::Auto => None,
        ToolChoice::None => Some(json!({ "allowed_tools": { "mode": "none" } })),
        ToolChoice::Required => Some(json!({ "allowed_tools": { "mode": "any" } })),
        ToolChoice::Named(name) => {
            Some(json!({ "allowed_tools": { "mode": "any", "tools": [name] } }))
        }
    }
}

// ============================================================================
// Legacy generateContent / streamGenerateContent
// ============================================================================

/// The surface the task brief's sketch actually describes correctly
/// (Divergence 1): `contents[].parts[]`, verified byte-for-byte against
/// `generate-content.md.txt`'s literal JSON-representation blocks.
fn encode_generate_content(
    req: &ChatRequest,
    profile: &ProviderProfile,
) -> Result<Value, EncodeError> {
    let mut contents: Vec<Value> = Vec::new();
    for msg in &req.messages {
        let mut parts: Vec<Value> = Vec::new();
        for block in &msg.content {
            if let Some(part) = encode_generate_content_part(block)? {
                parts.push(part);
            }
        }
        contents.push(json!({
            "role": match msg.role { Role::User => "user", Role::Assistant => "model" },
            "parts": parts,
        }));
    }

    let mut body = json!({ "contents": contents });

    if !req.system.is_empty() {
        let text: String = req
            .system
            .iter()
            .map(|s| s.text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n");
        body["systemInstruction"] = json!({ "parts": [{ "text": text }] });
    }

    if !req.tools.is_empty() {
        // Verified: legacy `tools[]` wraps every function declaration inside
        // ONE `Tool` object's `functionDeclarations` array -- not a flat
        // per-tool array the way the Interactions API's `tools[]` is.
        body["tools"] = json!([{
            "functionDeclarations": req.tools.iter().map(|t| json!({
                "name": t.name(),
                "description": t.description(),
                "parameters": t.input_schema(),
            })).collect::<Vec<_>>(),
        }]);
        if let Some(tool_config) = encode_generate_content_tool_config(&req.tool_choice) {
            body["toolConfig"] = tool_config;
        }
    }

    if let Some(max_tokens) = req.params.max_output_tokens {
        body["generationConfig"]["maxOutputTokens"] = json!(max_tokens);
    }
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            body["generationConfig"]["stopSequences"] = json!(stop);
        }
    }
    // Divergence 3: unlike Interactions mode, this surface's
    // `GenerationConfig` genuinely has `temperature`/`topP` (verified), with
    // no documented exclusion against `thinkingConfig` -- forwarded
    // unconditionally, matching the real schema.
    if let Some(temperature) = req.params.temperature {
        body["generationConfig"]["temperature"] = json!(temperature);
    }
    if let Some(top_p) = req.params.top_p {
        body["generationConfig"]["topP"] = json!(top_p);
    }

    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        if let Some(control) = reasoning_control_for(profile, &req.model.0) {
            let budget: i64 = control.resolve(intent)?.parse().unwrap_or(0);
            body["generationConfig"]["thinkingConfig"]["thinkingBudget"] = json!(budget);
        }
    }

    if profile.defaults.allow_raw_extra {
        if let Value::Object(map) = &mut body {
            for (key, value) in &req.extra {
                map.insert(key.clone(), value.clone());
            }
        }
    }

    Ok(body)
}

/// Encodes one content block into zero or one legacy `Part`. Same
/// `Ok(None)`/`Err` split as `encode_interactions_step` -- see its doc
/// comment.
///
/// Known, documented gap: `FunctionResponse.name` is marked required by the
/// fetched schema, but `ContentBlock::ToolResult` carries no tool-name field
/// in this crate's IR (only `tool_use_id`) -- omitted here rather than
/// invented. Flagged in the task report.
fn encode_generate_content_part(block: &ContentBlock) -> Result<Option<Value>, EncodeError> {
    match block {
        ContentBlock::Text { text, .. } => Ok(Some(json!({ "text": text }))),
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Ok(Some(json!({
            "functionCall": { "id": id.0, "name": name, "args": input },
        }))),
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => {
            let joined = content
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("");
            // Verified: `FunctionResponse.response` is an arbitrary object;
            // "if the function call failed to execute, the response can have
            // an `error` key" per the fetched doc's own note -- `output` for
            // the success case is this codec's own convention (callers may
            // use any key).
            let response = if *is_error {
                json!({ "error": joined })
            } else {
                json!({ "output": joined })
            };
            Ok(Some(json!({
                "functionResponse": { "id": tool_use_id.0, "response": response },
            })))
        }
        ContentBlock::Image { .. } => Err(EncodeError::UnencodableMedia("Image")),
        ContentBlock::Document { .. } => Err(EncodeError::UnencodableMedia("Document")),
        ContentBlock::Thinking { .. } | ContentBlock::Opaque { .. } => Ok(None),
    }
}

/// `toolConfig.functionCallingConfig` (verified via code samples in
/// `generate-content.md.txt`): `{ "mode": "AUTO"|"ANY"|"NONE",
/// "allowedFunctionNames": [string] }`.
fn encode_generate_content_tool_config(choice: &ToolChoice) -> Option<Value> {
    match choice {
        ToolChoice::Auto => None,
        ToolChoice::None => Some(json!({ "functionCallingConfig": { "mode": "NONE" } })),
        ToolChoice::Required => Some(json!({ "functionCallingConfig": { "mode": "ANY" } })),
        ToolChoice::Named(name) => Some(json!({
            "functionCallingConfig": { "mode": "ANY", "allowedFunctionNames": [name] },
        })),
    }
}
