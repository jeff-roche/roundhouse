//! Structural tripwire (mirrors `google_genai_wire_literal_tripwire.rs` and
//! `bedrock_converse_wire_literal_tripwire.rs`): every wire-string literal
//! `decode.rs` matches on must be a real value from the fetched Cohere API
//! reference, not a name that merely *looks* right -- REALITY-CORRECTIONS
//! §13b's binding lesson, which names this task ("6, 7, 8") explicitly even
//! though the task brief itself calls this codec "Not spec-gated."
//!
//! Three vendored lists, each extracted mechanically from the real, fetched
//! Cohere API reference pages (see `src/codec/cohere_v2/mod.rs`'s module doc
//! comment for the exact URLs and fetch date):
//! - `cohere_v2_2026_event_types.txt` -- the 11 real SSE event `type` values
//!   (`https://docs.cohere.com/reference/chat-stream`).
//! - `cohere_v2_2026_content_block_types.txt` -- the assistant content
//!   array's 2 real block `type` values (`https://docs.cohere.com/reference/chat`).
//! - `cohere_v2_2026_finish_reason_values.txt` -- the 6 real `finish_reason`
//!   enum values (`https://docs.cohere.com/reference/chat`).
//!
//! Each scan also asserts a count floor (not just non-empty), per this
//! project's carried-forward hardening note: a scanner that only catches one
//! match arm out of several would otherwise pass "vacuously enough" to hide a
//! regression in the scan itself.

use std::fs;
use std::path::Path;

fn decode_rs_source() -> String {
    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/cohere_v2/decode.rs"))
        .expect("src/codec/cohere_v2/decode.rs must exist")
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
/// marker `google_genai_wire_literal_tripwire.rs` uses.
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
/// not just the last one. Mirrors `google_genai_wire_literal_tripwire.rs`'s
/// identical fix-round-2 D3 hardening, applied here from the start since this
/// decoder's own `"content-end" | "tool-call-end" => ...` and
/// `"citation-start" | "citation-end" => ...` arms are exactly that shape.
/// Comment lines are skipped.
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
                // The bare empty string is this decoder's own sentinel for
                // "no finish_reason was present at all" (`decode_message_end`'s
                // `"" => ...` arm) -- an absence, not a wire enum value, so it
                // has nothing to be verified against.
                if literal.is_empty() {
                    continue;
                }
                if !found.iter().any(|f| f == &literal) {
                    found.push(literal);
                }
            }
        }
    }
    found
}

#[test]
fn every_matched_event_type_literal_is_a_real_spec_value() {
    let vendored = vendored_list("cohere_v2_2026_event_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_cohere_v2_stream"));

    assert!(
        matched.len() >= 11,
        "sanity/count-floor check failed: expected all 11 real event-type \
         literals to appear in decode_cohere_v2_stream's match, found {}: \
         {matched:?} -- the scan itself may be broken",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_cohere_v2_stream matches on event-type literal(s) that are not \
         in the vendored, fetched spec's real event_type values: {unknown:?}"
    );
}

#[test]
fn every_matched_content_block_type_literal_is_a_real_spec_value() {
    let vendored = vendored_list("cohere_v2_2026_content_block_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_content_start"));

    assert!(
        matched.len() >= 2,
        "sanity/count-floor check failed: expected both real content-block-type \
         literals (text, thinking) in decode_content_start, found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_content_start matches on content-block-type literal(s) that are \
         not in the vendored, fetched spec's real values: {unknown:?}"
    );
}

#[test]
fn every_matched_finish_reason_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("cohere_v2_2026_finish_reason_values.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_message_end"));

    assert!(
        matched.len() >= 6,
        "sanity/count-floor check failed: expected all 6 real finish_reason \
         values enumerated explicitly in decode_message_end, found {}: {matched:?}",
        matched.len()
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_message_end matches on finish_reason literal(s) that are not in \
         the vendored, fetched spec's real enum values: {unknown:?}"
    );
}
