//! Fix round 3, Q2/Q4: validates that a `[[model]].reasoning.field` JSON
//! pointer (`ReasoningControl.field`, walked at encode time by
//! `set_json_pointer` in `encode.rs`) is well-formed and does not collide
//! with one of `encode_openai_chat`'s own top-level wire keys. A
//! code-reviewer harness demonstrated that without this check, a profile
//! declaring `field = "/model"`, `"/stream"`, or `"/messages/0"` would
//! silently clobber that field at encode time -- exactly the class of "a
//! typo in a quirk profile" §9.5 promises turns into a BUILD error, not a
//! production data-corruption bug.
//!
//! Deliberately dependency-free (only `std::path::Path` and `&str`, no
//! `crate::ir`/`crate::profile` types) so `build.rs` can `#[path]`-mount
//! this exact file -- a build script cannot depend on the crate it builds
//! (see `build.rs`'s own module doc comment for why `schema.rs`/
//! `reasoning.rs` are mirrored the same way) -- while the real crate calls
//! the SAME function through its normal `pub` surface. One implementation,
//! not two kept in sync by hand.

use std::path::Path;

/// `encode_openai_chat`'s own top-level wire keys (see `encode.rs`) -- a
/// reasoning `field` pointer whose first segment names one of these would
/// silently overwrite that key instead of adding a new one.
pub const RESERVED_REASONING_FIELD_KEYS: &[&str] =
    &["model", "messages", "stream", "tools", "tool_choice"];

/// Panics — a BUILD error when called from `build.rs`'s `main`, per §9.5
/// ("a typo in a quirk profile is a BUILD error, not a production 400") —
/// if `field` is not a valid JSON pointer (missing its required leading
/// `/`) or if its first path segment collides with one of
/// [`RESERVED_REASONING_FIELD_KEYS`].
///
/// This is the first, cheaper line of defense: it can only see a pointer's
/// FIRST segment statically. `encode.rs`'s `set_json_pointer` still
/// hard-errors at encode time on a traversal collision this check cannot
/// see (a deeply nested collision past the first segment) — defense in
/// depth, not a redundant duplicate.
pub fn validate_openai_chat_reasoning_field(profile_path: &Path, field: &str) {
    let Some(stripped) = field.strip_prefix('/') else {
        panic!(
            "profile {profile_path:?} declares a [[model]].reasoning.field {field:?} that is \
             not a valid JSON pointer (must start with '/') — this is the §9.5 guarantee that \
             a typo in a quirk profile is a BUILD error, not a production panic"
        );
    };
    let first_segment = stripped.split('/').next().unwrap_or("");
    if RESERVED_REASONING_FIELD_KEYS.contains(&first_segment) {
        panic!(
            "profile {profile_path:?} declares a [[model]].reasoning.field {field:?} whose \
             first path segment {first_segment:?} collides with one of encode_openai_chat's own \
             top-level wire keys ({RESERVED_REASONING_FIELD_KEYS:?}) — writing a reasoning \
             value there would silently clobber that field instead of adding a new one. This \
             is the §9.5 guarantee that a typo in a quirk profile is a BUILD error, not a \
             production data-corruption bug"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::validate_openai_chat_reasoning_field;
    use std::path::Path;

    fn p() -> &'static Path {
        Path::new("profiles/test-fixture.toml")
    }

    #[test]
    fn accepts_the_real_shipped_moonshot_flat_field() {
        validate_openai_chat_reasoning_field(p(), "/reasoning_effort");
    }

    #[test]
    fn accepts_the_real_task_11_zai_nested_field() {
        validate_openai_chat_reasoning_field(p(), "/thinking/type");
    }

    #[test]
    fn accepts_the_real_task_12_qwen_flat_field() {
        validate_openai_chat_reasoning_field(p(), "/enable_thinking");
    }

    #[test]
    #[should_panic(expected = "not a valid JSON pointer")]
    fn rejects_a_field_missing_the_leading_slash() {
        validate_openai_chat_reasoning_field(p(), "reasoning_effort");
    }

    #[test]
    #[should_panic(expected = "\"model\"")]
    fn rejects_a_field_colliding_with_the_reserved_model_key() {
        validate_openai_chat_reasoning_field(p(), "/model");
    }

    #[test]
    #[should_panic(expected = "\"stream\"")]
    fn rejects_a_field_colliding_with_the_reserved_stream_key() {
        validate_openai_chat_reasoning_field(p(), "/stream");
    }

    #[test]
    #[should_panic(expected = "\"tools\"")]
    fn rejects_a_field_colliding_with_the_reserved_tools_key() {
        validate_openai_chat_reasoning_field(p(), "/tools");
    }

    #[test]
    #[should_panic(expected = "\"tool_choice\"")]
    fn rejects_a_field_colliding_with_the_reserved_tool_choice_key() {
        validate_openai_chat_reasoning_field(p(), "/tool_choice");
    }

    /// The exact shape a code-reviewer harness demonstrated actually
    /// clobbers the request's messages array: a nested pointer whose FIRST
    /// segment (not the whole pointer) is the reserved key.
    #[test]
    #[should_panic(expected = "\"messages\"")]
    fn rejects_a_nested_field_whose_first_segment_collides_with_the_reserved_messages_key() {
        validate_openai_chat_reasoning_field(p(), "/messages/0");
    }
}
