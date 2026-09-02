//! Structural tripwire (mirrors `openai_responses_event_type_tripwire.rs`,
//! including its fix-round-2 D3 hardenings applied here from the start): every
//! wire-string literal `decode.rs` matches on, and every error code
//! `google-genai.toml` declares, must be a real value from the fetched spec's
//! authoritative discriminator (`const`/`enum`), not a name that merely
//! *looks* right -- REALITY-CORRECTIONS §13b's C1 lesson from Task 5, applied
//! from the start rather than after a review found it.
//!
//! Four vendored lists, each extracted mechanically from
//! `interactions.openapi.json`'s `components.schemas` (never from prose) or
//! from the dedicated Interactions API error-code reference page -- see
//! `docs/decisions/2026-08-27-google-genai-spec-verification.md`:
//! - `google_genai_interactions_2026_event_types.txt` -- `InteractionSseEvent`
//!   oneOf's `event_type` consts.
//! - `google_genai_interactions_2026_step_types.txt` -- `Step` oneOf's `type`
//!   consts.
//! - `google_genai_interactions_2026_step_delta_types.txt` -- `StepDeltaData`
//!   oneOf's `type` consts.
//! - `google_genai_interactions_2026_error_codes.txt` -- the Interactions API
//!   error-code reference page's full documented table.
//!
//! Each scan also asserts a **count floor** (not just non-empty), per the
//! brief's carried-forward hardening note: a scanner that only catches one
//! match arm out of several would otherwise pass "vacuously enough" to hide
//! a regression in the scan itself.
//!
//! Fix-round-1 F4 adds a fifth vendored list,
//! `google_genai_generate_content_2026_wire_literals.txt`, covering the
//! legacy `generateContent`/`streamGenerateContent` surface -- the original
//! version of this file scanned only the Interactions-mode functions, so
//! every legacy literal (`candidates`, `finishReason`, `STOP`,
//! `promptFeedback`/`blockReason`, `functionCall`/`args`, `usageMetadata`,
//! `functionDeclarations`, `toolConfig`, `stopSequences`, `thinkingConfig`,
//! ...) was outside its reach.

use std::fs;
use std::path::Path;

fn decode_rs_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/google_genai/decode.rs"),
    )
    .expect("src/codec/google_genai/decode.rs must exist")
}

fn encode_rs_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/google_genai/encode.rs"),
    )
    .expect("src/codec/google_genai/encode.rs must exist")
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

/// True for a top-level (column-0) function-definition line -- same boundary
/// marker `openai_responses_event_type_tripwire.rs` uses.
fn is_top_level_fn_start(line: &str) -> bool {
    line.starts_with("fn ")
        || line.starts_with("pub fn ")
        || line.starts_with("async fn ")
        || line.starts_with("pub async fn ")
}

/// Extracts one top-level function's source text by name. Panics if not
/// found -- a scan that silently found nothing would be worse than none.
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

/// Scans `text` for every double-quoted string literal used as a `match`
/// pattern, INCLUDING or-patterns on one line (`"a" | "b" => ...`) -- a line
/// counts if, after its LAST quoted literal, the remainder (modulo
/// whitespace) starts with `=>`; every literal on that line is then counted,
/// not just the last one. This is the fix-round-2 D3 hardening the sibling
/// codec's tripwire needed only after review found the gap
/// (`openai_responses_event_type_tripwire.rs`'s doc comment: "an or-pattern
/// ... is silently excluded" by a scanner that only checks the literal
/// immediately followed by `=>`); applied here from the start, since this
/// decoder's own `"interaction.created" | "interaction.status_update" => {}`
/// arm is exactly that shape. Comment lines are skipped.
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

/// Scans `text` for every `<ident> == "literal"` string-equality comparison
/// (this decoder's `interaction.completed` status check uses this shape, not
/// a `match`, since it also needs an early-return on the failure branches).
/// Comment lines are skipped.
fn equality_literals(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut rest = line;
        while let Some(start) = rest.find("== \"") {
            let after_quote = &rest[start + 3..][1..];
            let Some(end) = after_quote.find('"') else {
                break;
            };
            let literal = &after_quote[..end];
            if !found.iter().any(|f| f == literal) {
                found.push(literal.to_string());
            }
            rest = &after_quote[end + 1..];
        }
    }
    found
}

/// Fix-round-1 F4: scans `text` for every wire-relevant string literal on
/// the legacy `generateContent` surface -- broader than `match_arm_literals`
/// (that codec's field-name literals appear via `.get("key")` and
/// `.pointer("/a/b")` calls and `json!({"key": ...})` object keys, not
/// `match` patterns). Collects:
/// - every plain quoted literal, AND
/// - for a `.pointer("/a/b/c")`-shaped literal, each non-numeric `/`-
///   separated segment (so `"/promptFeedback/blockReason"` yields
///   `promptFeedback` and `blockReason` separately).
///
/// Excludes: comment lines; any line mentioning `UnencodableMedia` (this
/// codec's own internal block-kind names -- `"Image"`/`"Document"`/
/// `"Thinking"`/`"Opaque"` -- are Rust-side error labels, not wire literals);
/// any literal containing `{` (an interpolated format string, e.g.
/// `"block-{next_block_slot}"` or an error message, not a bare wire value);
/// the structural `"\n\n"` text-join separator; and the bare empty string
/// (a default fallback, not itself a value to verify).
fn legacy_wire_literals(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
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
            if literal.is_empty() || literal.contains('{') || literal == r"\n\n" {
                continue;
            }
            if let Some(path) = literal.strip_prefix('/') {
                for segment in path.split('/') {
                    if segment.is_empty() || segment.chars().all(|c| c.is_ascii_digit()) {
                        continue;
                    }
                    if !found.iter().any(|f| f == segment) {
                        found.push(segment.to_string());
                    }
                }
            } else if !found.iter().any(|f| f == literal) {
                found.push(literal.to_string());
            }
        }
    }
    found
}

#[test]
fn every_legacy_generate_content_wire_literal_is_a_real_spec_value() {
    let vendored = vendored_list("google_genai_generate_content_2026_wire_literals.txt");
    let encode_src = encode_rs_source();
    let decode_src = decode_rs_source();

    let mut matched: Vec<String> = Vec::new();
    let scan_targets: &[(&str, &str)] = &[
        (encode_src.as_str(), "encode_generate_content"),
        (encode_src.as_str(), "encode_generate_content_part"),
        (encode_src.as_str(), "encode_generate_content_tool_config"),
        (decode_src.as_str(), "decode_generate_content_stream"),
        (decode_src.as_str(), "decode_generate_content_usage"),
    ];
    for (src, fn_name) in scan_targets {
        for literal in legacy_wire_literals(function_body(src, fn_name)) {
            if !matched.contains(&literal) {
                matched.push(literal);
            }
        }
    }

    assert!(
        matched.len() >= 25,
        "sanity/count-floor check failed: expected at least 25 distinct wire \
         literals across the legacy generateContent encode/decode functions, \
         found {}: {matched:?} -- the scan itself may be broken",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "the legacy generateContent/streamGenerateContent encode/decode functions \
         reference literal(s) that are not in the vendored spec list: {unknown:?} \
         -- fix-round-1 F4: this surface previously had no tripwire at all"
    );
}

#[test]
fn every_matched_event_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("google_genai_interactions_2026_event_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_interactions_stream"));

    assert!(
        matched.len() >= 7,
        "sanity/count-floor check failed: expected at least 7 event-type \
         literals in decode_interactions_stream (this decoder recognizes all \
         7 real event types), found {}: {matched:?} -- the scan itself may be \
         broken",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_interactions_stream matches on event-type literal(s) that are \
         not in the vendored spec's real event_type values: {unknown:?}"
    );
}

#[test]
fn every_matched_step_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("google_genai_interactions_2026_step_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_step_start"));

    assert!(
        matched.len() >= 3,
        "sanity/count-floor check failed: expected at least 3 step-type \
         literals in decode_step_start (model_output, function_call, \
         thought), found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_step_start matches on step-type literal(s) that are not in \
         the vendored spec's real Step.type values: {unknown:?}"
    );
}

#[test]
fn every_matched_step_delta_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("google_genai_interactions_2026_step_delta_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_step_delta"));

    assert!(
        matched.len() >= 4,
        "sanity/count-floor check failed: expected at least 4 delta-type \
         literals in decode_step_delta (text, arguments_delta, \
         thought_signature, thought_summary), found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_step_delta matches on delta-type literal(s) that are not in \
         the vendored spec's real StepDeltaData.type values: {unknown:?}"
    );
}

#[test]
fn every_compared_interaction_status_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("google_genai_interactions_2026_status_values.txt");
    let src = decode_rs_source();
    let matched = equality_literals(function_body(&src, "decode_interactions_stream"));

    assert!(
        matched.len() >= 2,
        "sanity/count-floor check failed: expected at least 2 status \
         literals compared in decode_interactions_stream (\"completed\", \
         \"requires_action\"), found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_interactions_stream compares against interaction-status \
         literal(s) that are not in the vendored spec's real \
         InteractionSseEventInteraction.status enum values: {unknown:?}"
    );
}

#[test]
fn profile_error_table_keys_are_real_interactions_api_error_codes() {
    let vendored = vendored_list("google_genai_interactions_2026_error_codes.txt");
    let toml_src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/google-genai.toml"),
    )
    .expect("profiles/google-genai.toml must exist");
    let parsed: toml::Value = toml::from_str(&toml_src).expect("profile TOML must parse");
    let errors = parsed
        .get("errors")
        .and_then(|e| e.as_table())
        .expect("profile must declare an [errors] table");

    assert!(
        errors.len() >= 3,
        "sanity/count-floor check failed: expected at least 3 declared error \
         codes, found {}: {:?}",
        errors.len(),
        errors.keys().collect::<Vec<_>>()
    );

    // Fix-round-1 F10: the vendored list now covers all three of the fetched
    // error-codes page's documented tables (35 codes total: "Standard API
    // error codes", "Generation blocked codes", "Generation error codes"),
    // not just the 18-entry "Standard" table this profile happens to use
    // today -- so a future, legitimate `[errors.safety]`-style entry (a real
    // code from either of the other two tables) is not wrongly rejected as
    // "not a real spec value."
    let unknown: Vec<&String> = errors.keys().filter(|k| !vendored.contains(k)).collect();
    assert!(
        unknown.is_empty(),
        "google-genai.toml's [errors] table declares code(s) that are not among \
         the 35 codes documented across all three tables of the Interactions API \
         error-code reference page: {unknown:?} -- this is exactly the class of \
         bug Task 5's C1 found (a literal that looks right but isn't a real spec \
         value): the classic UPPER_SNAKE google.rpc.Code vocabulary (e.g. \
         RESOURCE_EXHAUSTED) is the WRONG one for this surface -- see the \
         decision doc's Divergence 4."
    );
}
