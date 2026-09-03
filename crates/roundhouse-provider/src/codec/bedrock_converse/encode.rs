//! Encodes a `ChatRequest` into a Bedrock `Converse`/`ConverseStream` request
//! body. Field names verified against the real fetched AWS API Reference --
//! see this module's parent `mod.rs` doc comment for the fetch record.

use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, MessageRole as Role, ProviderError, ReasoningIntent, ToolChoice,
    ToolDef,
};
use crate::profile::{glob_match, ProviderProfile};

/// Everything that can go wrong turning a `ChatRequest` into a wire body.
/// Mirrors `google_genai`/`openai_responses`' `EncodeError` structure
/// (fix-round-2 D1 lesson on those codecs, applied here from the start):
/// content this codec cannot encode fails closed via a typed error
/// propagated through `stream_chat`'s `encode(...)?` -- the production path
/// every real caller takes -- not only through `resolve`, which has zero
/// production callers anywhere in this workspace.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("reasoning requested but no reasoning control declared in profile for this model")]
    ReasoningUnsupported,
    #[error("bedrock-converse codec does not encode {0} blocks")]
    UnencodableMedia(&'static str),
    /// Verified real divergence (see this codec's `mod.rs` doc comment,
    /// point 1): Bedrock's `ToolChoice` union has exactly `auto`/`any`/`tool`
    /// members -- there is no way to tell the model "do not call any tool."
    #[error(
        "bedrock-converse toolConfig has no mechanism to forbid tool use \
         (ToolChoice::None has no member in the real ToolChoice union: only auto/any/tool exist)"
    )]
    ToolChoiceNoneUnsupported,
}

impl From<EncodeError> for ProviderError {
    fn from(err: EncodeError) -> Self {
        ProviderError::Unsupported(err.to_string())
    }
}

/// Infallible wrapper for golden-snapshot fixtures, which never exercise the
/// `Unsupported` path -- mirrors the task brief's own `encode`/`try_encode`
/// split exactly (this codec's golden test file calls `encode` directly
/// inside `insta::assert_json_snapshot!`, with no `Result` to unwrap at the
/// call site).
pub fn encode(req: &ChatRequest, profile: &ProviderProfile) -> Value {
    try_encode(req, profile).expect("golden-snapshot fixtures never exercise the Unsupported path")
}

/// Encodes `req` for the Bedrock Converse wire format, as a `ProviderError`
/// directly -- this is the production path `stream_chat` propagates via `?`
/// (REALITY-CORRECTIONS §13b item 5: the guard that matters is the one on
/// this path, not `resolve`, which has zero production callers anywhere in
/// this workspace). Streaming is always assumed by the caller
/// (`ConverseStream`, not `Converse` -- this crate's established precedent
/// of always encoding for the streaming variant).
pub fn try_encode(req: &ChatRequest, profile: &ProviderProfile) -> Result<Value, ProviderError> {
    build(req, profile).map_err(ProviderError::from)
}

fn build(req: &ChatRequest, profile: &ProviderProfile) -> Result<Value, EncodeError> {
    // REALITY-CORRECTIONS §7: `ReasoningRequest.intent` is
    // `Option<ReasoningIntent>`; a missing intent means Off. Audit finding 7
    // (echoed in the task brief): bare `Intent`, never a second `Option`
    // wrapping it once defaulted.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        let has_control = profile.model.iter().any(|m| {
            m.match_globs.iter().any(|g| glob_match(g, &req.model.0)) && m.reasoning.is_some()
        });
        if !has_control {
            return Err(EncodeError::ReasoningUnsupported);
        }
        // No declared model in this profile actually carries a reasoning
        // control (see `mod.rs`'s module doc comment and the profile TOML's
        // own comment) -- there is therefore no verified per-model
        // `additionalModelRequestFields` wire mapping to apply here. If a
        // future model entry adds one, this branch is where it would be
        // threaded through; fabricating an unverified field name now would
        // be exactly the kind of "looks right but isn't a real spec value"
        // mistake REALITY-CORRECTIONS §13b warns against.
    }

    let messages: Vec<Value> = req
        .messages
        .iter()
        .map(|m| {
            let content: Result<Vec<Value>, EncodeError> =
                m.content.iter().map(encode_block).collect();
            Ok(json!({
                "role": role_str(m.role),
                "content": content?,
            }))
        })
        .collect::<Result<_, EncodeError>>()?;

    let mut body = json!({ "messages": messages });

    if !req.system.is_empty() {
        body["system"] = json!(req
            .system
            .iter()
            .map(|s| json!({ "text": s.text }))
            .collect::<Vec<_>>());
    }

    if !req.tools.is_empty() {
        body["toolConfig"] = json!({
            "tools": req.tools.iter().map(encode_tool).collect::<Vec<_>>(),
        });
        if let Some(tool_choice) = encode_tool_choice(&req.tool_choice)? {
            body["toolConfig"]["toolChoice"] = tool_choice;
        }
    }

    let mut inference_config = serde_json::Map::new();
    if let Some(t) = req.params.temperature {
        inference_config.insert("temperature".into(), json!(t));
    }
    if let Some(p) = req.params.top_p {
        inference_config.insert("topP".into(), json!(p));
    }
    if let Some(mt) = req.params.max_output_tokens {
        inference_config.insert("maxTokens".into(), json!(mt));
    }
    if let Some(stop) = &req.params.stop {
        if !stop.is_empty() {
            inference_config.insert("stopSequences".into(), json!(stop));
        }
    }
    if !inference_config.is_empty() {
        body["inferenceConfig"] = Value::Object(inference_config);
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

fn role_str(role: Role) -> &'static str {
    match role {
        Role::User => "user",
        Role::Assistant => "assistant",
    }
}

/// Encodes one content block into a Bedrock `ContentBlock`. Every
/// unencodable kind returns `Err(EncodeError::UnencodableMedia(kind))`,
/// naming which kind -- never a silent `Ok(None)` drop (REALITY-CORRECTIONS
/// §13b item 5).
///
/// `Image`/`Document`: this crate has no `base64` dependency, matching the
/// sibling codecs' established precedent. `Thinking`: Bedrock's
/// `reasoningContent` block requires the exact prior signature to be
/// round-tripped for multi-step continuation on models that support it (the
/// same class of requirement Gemini's `thought_signature` has), and this
/// profile's only declared model has no reasoning capability to round-trip
/// into in the first place -- failing closed is the honest choice here, not
/// a silently-dropped reasoning trace. `Opaque`: round-trips only to the
/// same (provider, model) it came from; this codec has no encoder for it.
fn encode_block(block: &ContentBlock) -> Result<Value, EncodeError> {
    match block {
        ContentBlock::Text { text, .. } => Ok(json!({ "text": text })),
        ContentBlock::ToolUse {
            id, name, input, ..
        } => Ok(json!({
            "toolUse": { "toolUseId": id.0, "name": name, "input": input }
        })),
        ContentBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } => Ok(json!({
            "toolResult": {
                "toolUseId": tool_use_id.0,
                "content": content.iter().map(|p| json!({ "text": p.text })).collect::<Vec<_>>(),
                "status": if *is_error { "error" } else { "success" },
            }
        })),
        ContentBlock::Image { .. } => Err(EncodeError::UnencodableMedia("Image")),
        ContentBlock::Document { .. } => Err(EncodeError::UnencodableMedia("Document")),
        ContentBlock::Thinking { .. } => Err(EncodeError::UnencodableMedia("Thinking")),
        ContentBlock::Opaque { .. } => Err(EncodeError::UnencodableMedia("Opaque")),
    }
}

/// `toolConfig.tools[].toolSpec` (verified `ToolSpecification`: `name`,
/// `description`, `inputSchema`) wrapping `ToolInputSchema`'s one real
/// member, `json` (verified `API_runtime_ToolInputSchema.html`: a one-member
/// union).
fn encode_tool(tool: &ToolDef) -> Value {
    json!({
        "toolSpec": {
            "name": tool.name(),
            "description": tool.description(),
            "inputSchema": { "json": tool.input_schema() },
        }
    })
}

/// `toolConfig.toolChoice` (verified `ToolChoice` union: `auto` | `any` |
/// `tool`). `Auto` is the documented default and is omitted from the wire
/// body entirely (`Ok(None)`), matching this crate's established precedent
/// for every codec's "auto" case. `ToolChoice::None` has no real member to
/// encode into -- see this module's `EncodeError::ToolChoiceNoneUnsupported`
/// doc comment.
fn encode_tool_choice(choice: &ToolChoice) -> Result<Option<Value>, EncodeError> {
    match choice {
        ToolChoice::Auto => Ok(None),
        ToolChoice::None => Err(EncodeError::ToolChoiceNoneUnsupported),
        ToolChoice::Required => Ok(Some(json!({ "any": {} }))),
        ToolChoice::Named(name) => Ok(Some(json!({ "tool": { "name": name } }))),
    }
}
