//! Structural tripwire (mirrors `google_genai_wire_literal_tripwire.rs`/
//! `openai_responses_event_type_tripwire.rs`, applying their fix-round
//! hardenings from the start rather than after a review finds the gap --
//! REALITY-CORRECTIONS §13b): every wire-string literal `decode.rs`/
//! `encode.rs` match on, and every error code `bedrock-converse.toml`
//! declares, must be a real value from the fetched AWS API Reference's
//! authoritative field/union-member documentation, not a name that merely
//! *looks* right.
//!
//! Six vendored lists under `testdata/`, each extracted mechanically from a
//! specific, individually fetched `API_runtime_<Name>.html` page (see each
//! list's own header comment for its exact source URL and fetch date) --
//! never from this file's or the codec's own prose:
//! - `bedrock_converse_2026_event_types.txt` -- `ConverseStreamOutput`'s 6
//!   real `:event-type` values.
//! - `bedrock_converse_2026_exception_types.txt` -- the full 10-shape
//!   exception set across `Converse`/`ConverseStream`'s documented errors.
//! - `bedrock_converse_2026_content_block_kinds.txt` -- the full 12-member
//!   `ContentBlock` union (request/response).
//! - `bedrock_converse_2026_content_block_start_kinds.txt` -- the full
//!   3-member `ContentBlockStart` union.
//! - `bedrock_converse_2026_content_block_delta_kinds.txt` -- the full
//!   6-member `ContentBlockDelta` union.
//! - `bedrock_converse_2026_reasoning_content_delta_kinds.txt` -- the full
//!   3-member `ReasoningContentBlockDelta` union.
//! - `bedrock_converse_2026_tool_choice_kinds.txt` -- the full 3-member
//!   `ToolChoice` union.
//!
//! Each scan also asserts a count floor (not just non-empty), so a scanner
//! that only catches one match arm out of several doesn't pass vacuously.

use std::fs;
use std::path::Path;

fn decode_rs_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/bedrock_converse/decode.rs"),
    )
    .expect("src/codec/bedrock_converse/decode.rs must exist")
}

fn encode_rs_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/bedrock_converse/encode.rs"),
    )
    .expect("src/codec/bedrock_converse/encode.rs must exist")
}

fn vendored_list(file_name: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(file_name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

fn is_top_level_fn_start(line: &str) -> bool {
    line.starts_with("fn ")
        || line.starts_with("pub fn ")
        || line.starts_with("async fn ")
        || line.starts_with("pub async fn ")
}

/// Extracts one top-level function's source text by name (mirrors
/// `google_genai_wire_literal_tripwire.rs`'s identical helper).
fn function_body<'a>(src: &'a str, fn_name: &str) -> &'a str {
    let needle_variants = [
        format!("\nfn {fn_name}("),
        format!("\npub fn {fn_name}("),
        format!("\nasync fn {fn_name}("),
        format!("\npub async fn {fn_name}("),
    ];
    let start = needle_variants
        .iter()
        .find_map(|needle| src.find(needle.as_str()).map(|pos| pos + 1))
        .unwrap_or_else(|| panic!("function `{fn_name}` not found in the scanned source"));

    let after_start = &src[start..];
    let mut end = after_start.len();
    let first_newline = after_start.find('\n').unwrap_or(after_start.len());
    let mut search_from = first_newline + 1;
    for line in after_start[search_from..].lines() {
        if is_top_level_fn_start(line) {
            end = search_from;
            break;
        }
        search_from += line.len() + 1;
    }
    &after_start[..end]
}

/// Extracts a top-level `const` item's initializer text by name (for
/// `KNOWN_EXCEPTION_SHAPES`, which is a `const`, not a `fn`).
///
/// Deliberately searches for the terminating `];` starting AFTER `= [`, not
/// for the first bare `;` after the `const` keyword: a fixed-size array
/// type annotation (`[&str; 5]`) itself contains a `;`, which would
/// otherwise truncate the scanned text before the array's own contents ever
/// appear -- caught empirically (this returned an empty body until fixed).
fn const_body<'a>(src: &'a str, const_name: &str) -> &'a str {
    let needle = format!("const {const_name}");
    let start = src
        .find(&needle)
        .unwrap_or_else(|| panic!("const `{const_name}` not found in the scanned source"));
    let after_start = &src[start..];
    let assign_pos = after_start.find("= [").unwrap_or_else(|| {
        panic!("const `{const_name}` is not an array literal (`= [...]`) -- update this scanner")
    });
    let after_assign = &after_start[assign_pos..];
    let end = after_assign
        .find("];")
        .unwrap_or_else(|| panic!("const `{const_name}`'s array literal has no terminating `];`"));
    &after_assign[..end]
}

/// Scans `text` for every double-quoted string literal used as a `match`
/// pattern, including or-patterns on one line (fix-round-2 D3 hardening,
/// applied from the start -- see `google_genai_wire_literal_tripwire.rs`'s
/// identical function for the rationale). Comment lines are skipped.
fn match_arm_literals(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut literals: Vec<(String, usize)> = Vec::new();
        let mut search_from = 0usize;
        while let Some(rel_start) = line[search_from..].find('"') {
            let start = search_from + rel_start;
            let after_quote = &line[start + 1..];
            let Some(rel_end) = after_quote.find('"') else {
                break;
            };
            let literal = after_quote[..rel_end].to_string();
            let end = start + 1 + rel_end + 1;
            literals.push((literal, end));
            search_from = end;
        }
        let Some((_, last_end)) = literals.last() else {
            continue;
        };
        if line[*last_end..].trim_start().starts_with("=>") {
            for (literal, _) in literals {
                if !found.iter().any(|f| f == &literal) {
                    found.push(literal);
                }
            }
        }
    }
    found
}

/// Every bare double-quoted string literal in `text` (skipping comment
/// lines, format-interpolated strings containing `{`, and the empty
/// string). Used for `const` array bodies and for scanning field-access
/// literals (`.get("text")`, `.pointer("/a/b")`) that aren't `match` arms.
fn all_string_literals(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        // `UnencodableMedia("Image")` etc. name this codec's own Rust
        // `ContentBlock` variant, not a Bedrock wire value -- same exclusion
        // `google_genai_wire_literal_tripwire.rs` uses for the identical shape.
        if line.trim_start().starts_with("//") || line.contains("UnencodableMedia") {
            continue;
        }
        let mut rest = line;
        while let Some(start) = rest.find('"') {
            let after_quote = &rest[start + 1..];
            let Some(end) = after_quote.find('"') else {
                break;
            };
            let literal = &after_quote[..end];
            rest = &after_quote[end + 1..];
            if literal.is_empty() || literal.contains('{') {
                continue;
            }
            if !found.iter().any(|f| f == literal) {
                found.push(literal.to_string());
            }
        }
    }
    found
}

/// Splits every `.pointer("/a/b")`-shaped literal into its non-empty
/// `/`-separated segments (mirrors `google_genai_wire_literal_tripwire.rs`'s
/// `legacy_wire_literals` treatment of the same shape) and leaves every
/// other literal (a plain `.get("key")` literal, or a `match`/array literal)
/// untouched.
fn expand_pointer_paths(literals: Vec<String>) -> Vec<String> {
    let mut found = Vec::new();
    for literal in literals {
        if let Some(path) = literal.strip_prefix('/') {
            for segment in path.split('/') {
                if !segment.is_empty() && !found.iter().any(|f| f == segment) {
                    found.push(segment.to_string());
                }
            }
        } else if !found.iter().any(|f| f == &literal) {
            found.push(literal);
        }
    }
    found
}

#[test]
fn every_matched_event_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("bedrock_converse_2026_event_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_event"));

    assert!(
        matched.len() >= 6,
        "sanity/count-floor check failed: expected at least 6 event-type literals in \
         decode_event (this decoder recognizes all 6 real event types), found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_event matches on event-type literal(s) that are not in the vendored spec's \
         real ConverseStreamOutput event_type values: {unknown:?}"
    );
}

#[test]
fn every_recognized_exception_shape_is_a_real_spec_value() {
    let vendored = vendored_list("bedrock_converse_2026_exception_types.txt");
    let src = decode_rs_source();
    let matched = all_string_literals(const_body(&src, "KNOWN_EXCEPTION_SHAPES"));

    assert!(
        matched.len() >= 5,
        "sanity/count-floor check failed: expected at least 5 exception-shape literals in \
         KNOWN_EXCEPTION_SHAPES (the 5 real in-band ConverseStreamOutput exception members), \
         found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "KNOWN_EXCEPTION_SHAPES declares exception-shape literal(s) that are not in the \
         vendored spec's full documented exception set: {unknown:?}"
    );
}

#[test]
fn profile_error_table_keys_are_real_bedrock_exception_shapes() {
    let vendored = vendored_list("bedrock_converse_2026_exception_types.txt");
    let toml_src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/bedrock-converse.toml"),
    )
    .expect("profiles/bedrock-converse.toml must exist");
    let parsed: toml::Value = toml::from_str(&toml_src).expect("profile TOML must parse");
    let errors = parsed
        .get("errors")
        .and_then(|e| e.as_table())
        .expect("profile must declare an [errors] table");

    assert!(
        errors.len() >= 3,
        "sanity/count-floor check failed: expected at least 3 declared error codes, found {}: {:?}",
        errors.len(),
        errors.keys().collect::<Vec<_>>()
    );

    let unknown: Vec<&String> = errors.keys().filter(|k| !vendored.contains(k)).collect();
    assert!(
        unknown.is_empty(),
        "bedrock-converse.toml's [errors] table declares code(s) that are not among the \
         real, fetched exception shape names: {unknown:?}"
    );
}

#[test]
fn every_matched_content_block_delta_literal_is_a_real_spec_enum_value() {
    let mut vendored = vendored_list("bedrock_converse_2026_content_block_delta_kinds.txt");
    vendored.extend(vendored_list(
        "bedrock_converse_2026_reasoning_content_delta_kinds.txt",
    ));
    let src = decode_rs_source();
    let matched = expand_pointer_paths(all_string_literals(function_body(
        &src,
        "decode_content_block_delta",
    )));

    assert!(
        matched.len() >= 4,
        "sanity/count-floor check failed: expected at least 4 delta-kind/field literals in \
         decode_content_block_delta (text, toolUse, input, reasoningContent, text, signature), \
         found {}: {matched:?}",
        matched.len()
    );

    // `delta`/`contentBlockIndex` are this event's own envelope field names,
    // and `input` is `ToolUseBlockDelta`'s own field name -- none are
    // `ContentBlockDelta`/`ReasoningContentBlockDelta` union members --
    // excluded from the spec-membership check the same way
    // `google_genai_wire_literal_tripwire.rs` excludes purely-numeric
    // pointer segments.
    let envelope_fields = ["delta", "contentBlockIndex", "input"];
    let unknown: Vec<&String> = matched
        .iter()
        .filter(|m| !envelope_fields.contains(&m.as_str()) && !vendored.contains(m))
        .collect();
    assert!(
        unknown.is_empty(),
        "decode_content_block_delta references literal(s) that are not in the vendored \
         ContentBlockDelta/ReasoningContentBlockDelta union: {unknown:?}"
    );
}

#[test]
fn every_matched_content_block_start_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("bedrock_converse_2026_content_block_start_kinds.txt");
    let src = decode_rs_source();
    let matched = expand_pointer_paths(all_string_literals(function_body(
        &src,
        "decode_content_block_start",
    )));

    assert!(
        matched.len() >= 3,
        "sanity/count-floor check failed: expected at least 3 literals in \
         decode_content_block_start (start, toolUse, name/toolUseId field reads at minimum), \
         found {}: {matched:?}",
        matched.len()
    );

    // `start`/`name`/`toolUseId`: the event's own envelope field name and
    // `ToolUseBlockStart`'s own field names, not `ContentBlockStart` union
    // member names -- excluded from the union-membership check.
    let non_union_fields = ["start", "name", "toolUseId"];
    let unknown: Vec<&String> = matched
        .iter()
        .filter(|m| !non_union_fields.contains(&m.as_str()) && !vendored.contains(m))
        .collect();
    assert!(
        unknown.is_empty(),
        "decode_content_block_start references literal(s) that are not in the vendored \
         ContentBlockStart union: {unknown:?}"
    );
}

#[test]
fn every_encoded_content_block_kind_is_a_real_spec_enum_value() {
    let vendored = vendored_list("bedrock_converse_2026_content_block_kinds.txt");
    let src = encode_rs_source();
    let matched = all_string_literals(function_body(&src, "encode_block"));

    assert!(
        matched.len() >= 3,
        "sanity/count-floor check failed: expected at least 3 encoded content-block-kind \
         literals in encode_block (text, toolUse, toolResult), found {}: {matched:?}",
        matched.len()
    );

    // `toolUseId`/`input`/`name`/`content`/`status`: `ToolUseBlock`'s and
    // `ToolResultBlock`'s own nested field names, and `error`/`success`:
    // `ToolResultBlock.status`'s own enum values -- none are top-level
    // `ContentBlock` union member names -- excluded from the
    // union-membership check.
    let nested_fields = [
        "toolUseId",
        "input",
        "name",
        "content",
        "status",
        "error",
        "success",
    ];
    let unknown: Vec<&String> = matched
        .iter()
        .filter(|m| !nested_fields.contains(&m.as_str()) && !vendored.contains(m))
        .collect();
    assert!(
        unknown.is_empty(),
        "encode_block emits content-block-kind literal(s) that are not in the vendored \
         ContentBlock union: {unknown:?}"
    );
}

#[test]
fn every_encoded_tool_choice_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("bedrock_converse_2026_tool_choice_kinds.txt");
    let src = encode_rs_source();
    let matched = all_string_literals(function_body(&src, "encode_tool_choice"));

    assert!(
        matched.len() >= 2,
        "sanity/count-floor check failed: expected at least 2 tool-choice literals in \
         encode_tool_choice (any, tool), found {}: {matched:?}",
        matched.len()
    );

    // `name`: `SpecificToolChoice`'s own field name, not a `ToolChoice`
    // union member -- excluded from the union-membership check.
    let unknown: Vec<&String> = matched
        .iter()
        .filter(|m| m.as_str() != "name" && !vendored.contains(m))
        .collect();
    assert!(
        unknown.is_empty(),
        "encode_tool_choice emits tool-choice literal(s) that are not in the vendored \
         ToolChoice union: {unknown:?}"
    );
}
