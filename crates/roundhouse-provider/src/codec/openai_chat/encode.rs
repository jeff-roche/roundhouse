use serde_json::{json, Value};

use crate::ir::{
    ChatRequest, ContentBlock, Message, MessageRole as Role, ReasoningIntent, ToolChoice, ToolDef,
};
use crate::profile::{glob_match, ProviderProfile, WireValue};

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

/// Fix round 2: `ReasoningControl.field` is a genuine RFC 6901 JSON pointer,
/// not a hardcoded-wire-path hint. Hardcoding a single top-level key (this
/// codec's fix-round-1 approach) is indistinguishable from honoring the
/// pointer ONLY for a codec that serves one provider with one wire shape
/// (`cohere_v2`, `google_genai`, `openai_responses` all do this safely,
/// because each has exactly one reasoning wire shape). `openai-chat` is
/// different in kind: it is the SHARED codec behind ~18 providers, and
/// their declared `field`s genuinely diverge -- moonshot/deepseek use flat
/// `/reasoning_effort`, Z.ai's `glm-*` models use nested `/thinking/type`,
/// Qwen uses flat `/enable_thinking`. A hardcoded key produces the wrong
/// wire shape (or the wrong key entirely) for any profile whose `field`
/// isn't `/reasoning_effort`.
///
/// Walks `pointer` (leading `/`, `~1`-escaped `/` and `~0`-escaped `~` per
/// RFC 6901; no array-index segments are needed by any profile in this
/// crate), creating intermediate JSON objects as needed, and sets `value`
/// at the final segment. `/thinking/type` against an otherwise-populated
/// `body` therefore inserts a NEW `body.thinking` object rather than
/// requiring one to already exist.
///
/// Fix round 3, Q2/Q4: a code-reviewer harness demonstrated the original
/// (fix round 2) version of this function would silently CLOBBER an
/// existing non-object value it descended through mid-pointer (e.g.
/// `/messages/0` replacing the entire `messages` array with `{"0": ...}`),
/// because it unconditionally replaced any non-object intermediate rather
/// than treating that as a collision. `build.rs`'s
/// `validate_openai_chat_reasoning_field` now rejects the specific,
/// statically-visible case of this (a `field` whose FIRST segment names a
/// reserved top-level key) at compile time, but that check cannot see a
/// collision deeper than the first segment — this function is the second,
/// unconditional line of defense: descending through anything that is
/// neither `Null` (a fresh slot) nor an existing `Object` is now a hard
/// `panic!`, in both debug and release builds, never a silent overwrite.
/// Fix round 2's `debug_assert!` on a missing leading `/` is folded into
/// the same unconditional-panic posture for the identical reason (Q4): a
/// debug-panics/release-silently-no-ops split is the worst of both worlds.
fn set_json_pointer(root: &mut Value, pointer: &str, value: Value) {
    let stripped = pointer.strip_prefix('/').unwrap_or_else(|| {
        panic!(
            "ReasoningControl.field {pointer:?} is not a valid JSON pointer (must start with \
             '/') -- build.rs's validate_openai_chat_reasoning_field should have rejected this \
             profile at compile time"
        )
    });
    let segments: Vec<String> = stripped
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect();
    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        match current {
            Value::Null => *current = Value::Object(serde_json::Map::new()),
            Value::Object(_) => {}
            other => panic!(
                "reasoning field pointer {pointer:?} tried to write through an existing \
                 non-object value ({other:?}) at path segment {segment:?} -- writing here \
                 would silently overwrite it instead of adding a new field. \
                 build.rs's validate_openai_chat_reasoning_field should have rejected a field \
                 pointer whose first segment collides with a reserved top-level wire key; if \
                 this fires, RESERVED_REASONING_FIELD_KEYS itself needs updating"
            ),
        }
        let map = current
            .as_object_mut()
            .expect("normalized to an object, or already one, just above");
        if i + 1 == segments.len() {
            map.insert(segment.clone(), value);
            return;
        }
        current = map.entry(segment.clone()).or_insert(Value::Null);
    }
}

/// Encodes a `ChatRequest` into an OpenAI-compatible `/v1/chat/completions` request body.
///
/// Streaming is always enabled (`stream: true`) as per §9.3.
///
/// Fix round 1, P2: previously took only `&ChatRequest`, so a profile's
/// declared `[[model]].reasoning` (e.g. moonshot's `reasoning_effort`
/// control) was fully modeled and deserialized but never consulted -- dead
/// configuration. Now looks up the matched model's `ReasoningControl` the
/// same way `cohere_v2::encode::encode` does.
///
/// Fix round 2: the resolved wire value is written at `control.field`,
/// walked as a genuine RFC 6901 JSON pointer (see [`set_json_pointer`]) --
/// NOT hardcoded under a fixed key the way fix round 1 did. Unlike
/// `cohere_v2`/`google_genai`/`openai_responses` (each serving one provider
/// with one reasoning wire shape, where a hardcoded key is indistinguishable
/// from honoring the pointer), `openai-chat` is the shared codec behind
/// ~18 providers whose `field`s genuinely diverge in both key name and
/// nesting depth (moonshot/deepseek: flat `/reasoning_effort`; Z.ai:
/// nested `/thinking/type`; Qwen: flat `/enable_thinking`).
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
    // unmatched model glob — an `Err` here just means no reasoning field is
    // written at all (whatever `control.field` names), rather than
    // propagating a new error type through every caller.
    let intent = req.reasoning.intent.unwrap_or(ReasoningIntent::Off);
    if intent != ReasoningIntent::Off {
        if let Some(control) = reasoning_control_for(profile, &req.model.0) {
            // Fix round 7, K6: `resolve_wire_value` (not bare `resolve`)
            // types the wire value per the profile's declared `value_type` --
            // `/reasoning_effort`-style controls (the default, `value_type =
            // "string"`) still emit exactly the JSON string they always have;
            // Qwen's `value_type = "bool"` now emits a genuine JSON boolean
            // instead of the string `"true"`, matching what DashScope
            // documents `enable_thinking` as.
            if let Ok(value) = control.resolve_wire_value(intent) {
                set_json_pointer(&mut body, &control.field, wire_value_to_json(value));
            }
        }
    }

    body
}

/// Converts a profile-typed [`WireValue`] into the `serde_json::Value` it
/// belongs on the wire as. Kept here (not in `profile::reasoning`, which is
/// mirrored dependency-free into `build.rs`'s own compilation unit) since
/// JSON encoding is this codec's concern, not the profile schema's.
fn wire_value_to_json(value: WireValue) -> Value {
    match value {
        WireValue::String(s) => Value::String(s),
        WireValue::Bool(b) => Value::Bool(b),
        WireValue::Number(n) => json!(n),
    }
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

#[cfg(test)]
mod set_json_pointer_tests {
    use super::set_json_pointer;
    use serde_json::json;

    #[test]
    fn flat_pointer_sets_a_top_level_key() {
        let mut body = json!({ "model": "m" });
        set_json_pointer(&mut body, "/enable_thinking", json!("true"));
        assert_eq!(body, json!({ "model": "m", "enable_thinking": "true" }));
    }

    #[test]
    fn nested_pointer_creates_the_intermediate_object() {
        let mut body = json!({ "model": "m" });
        set_json_pointer(&mut body, "/thinking/type", json!("deep"));
        assert_eq!(
            body,
            json!({ "model": "m", "thinking": { "type": "deep" } })
        );
    }

    #[test]
    fn nested_pointer_merges_into_an_already_existing_sibling_key() {
        let mut body = json!({ "thinking": { "budget": 100 } });
        set_json_pointer(&mut body, "/thinking/type", json!("deep"));
        assert_eq!(
            body,
            json!({ "thinking": { "budget": 100, "type": "deep" } })
        );
    }

    #[test]
    fn tilde_and_slash_escapes_are_decoded_per_rfc_6901() {
        let mut body = json!({});
        set_json_pointer(&mut body, "/a~1b~0c", json!(1));
        assert_eq!(body, json!({ "a/b~c": 1 }));
    }

    /// Fix round 3, Q4: a pointer with no leading `/` is not valid RFC 6901
    /// and must panic unconditionally (not the fix-round-2 `debug_assert!`,
    /// which was a silent no-op in release builds).
    #[test]
    #[should_panic(expected = "not a valid JSON pointer")]
    fn a_pointer_missing_the_leading_slash_panics() {
        let mut body = json!({});
        set_json_pointer(&mut body, "no_leading_slash", json!("x"));
    }

    /// Fix round 3, Q2: the exact shape a code-reviewer harness
    /// demonstrated silently clobbers real request data against the
    /// fix-round-2 implementation -- `/messages/0` descending through an
    /// EXISTING array (not a fresh `Null` slot) must hard-error, never
    /// replace the whole array with `{"0": ...}`.
    #[test]
    #[should_panic(expected = "existing non-object value")]
    fn a_pointer_descending_through_an_existing_non_object_value_panics() {
        let mut body = json!({ "messages": [1, 2, 3] });
        set_json_pointer(&mut body, "/messages/0", json!("clobbered"));
    }

    /// Same collision, one level deeper -- proves the check applies at
    /// every intermediate segment, not just the first.
    #[test]
    #[should_panic(expected = "existing non-object value")]
    fn a_deeper_pointer_descending_through_an_existing_non_object_value_panics() {
        let mut body = json!({ "thinking": { "type": "already a string, not nested further" } });
        set_json_pointer(&mut body, "/thinking/type/nested", json!("x"));
    }
}
