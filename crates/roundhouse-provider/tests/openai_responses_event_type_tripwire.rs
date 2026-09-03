//! Fix-round-1 C1's structural tripwire: every event-type string literal
//! `codec::openai_responses::decode` matches an SSE frame's `type` field
//! against must be a real, spec-declared `type` enum value -- not merely the
//! name of a schema that exists somewhere in the document.
//!
//! That distinction is exactly what let C1 through: the Step 0 spec-
//! verification gate confirmed that schema *names* like
//! `ResponseReasoningSummaryDeltaStreamingEvent` existed in
//! `components.schemas`, but not that the literal string the decoder matches
//! on (`"response.reasoning_summary.delta"`) was the schema's authoritative
//! `enum`/`default` value rather than its separate, stale prose
//! `description` field (which really does say
//! "always `response.reasoning_summary.delta`" -- the real `enum`/`default`
//! say `"response.reasoning_summary_text.delta"`). A self-consistent
//! hallucination (the decoder and the hand-authored cassette agreeing on the
//! same wrong string) passed every other test in the suite.
//!
//! `testdata/open_responses_2026-04-24_event_types.txt` is the vendored,
//! mechanically-extracted fix: every `components.schemas` entry ending
//! `StreamingEvent`'s `type.enum`/`type.default` value, read directly from
//! the fetched spec JSON, never from a schema's `description`.
//!
//! **Fix-round-2 D3, two hardenings on the same tripwire:**
//!
//! 1. The first version of this test collected literals by prefiltering on
//!    `starts_with("response.") || literal == "error"` BEFORE checking
//!    membership -- so a literal that is wrong in a way that *also* isn't
//!    prefixed `response.` (a typo like `"resp.completed"`, or a stray
//!    `"response_completed"`) would be silently excluded from the check
//!    entirely rather than flagged as unknown. That's a filter failing open
//!    on exactly the property it exists to verify. This version instead
//!    scopes the scan to the two functions that actually dispatch on
//!    `event_type` (`decode_stream_event`, `terminal_failure`) and collects
//!    EVERY `"literal" =>` match-arm pattern found there, with no prefix
//!    filter at all -- membership in the vendored list is required
//!    unconditionally.
//! 2. Extended to `decode_output_item_added`'s item-type match
//!    (`"message"`/`"function_call"`/`"reasoning"`, matched against
//!    `item.type`) against a second vendored list,
//!    `testdata/open_responses_2026-04-24_item_types.txt` -- a wrong value
//!    there is the *identical* C1 failure mode (a block kind that silently
//!    fails to open) and had exactly the same "verified the schema exists,
//!    never checked whether the matched string is right" gap.

use std::fs;
use std::path::Path;

fn decode_rs_source() -> String {
    fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/openai_responses/decode.rs"),
    )
    .expect("src/codec/openai_responses/decode.rs must exist")
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

/// True for a top-level (column-0) function-definition line, covering every
/// `fn`/`pub fn`/`async fn`/`pub async fn` shape `decode.rs` actually uses.
/// Used only as a boundary marker to bound one function's body text within
/// the whole-file source -- this file has no nested functions, so column-0
/// placement is a reliable signal.
fn is_top_level_fn_start(line: &str) -> bool {
    line.starts_with("fn ")
        || line.starts_with("pub fn ")
        || line.starts_with("async fn ")
        || line.starts_with("pub async fn ")
}

/// Extracts one top-level function's source text (its signature line through
/// the line before the next top-level function definition, or end of file),
/// by name. Panics if `fn_name` isn't found -- a scan that silently found
/// nothing would be worse than no scan at all.
fn function_body<'a>(src: &'a str, fn_name: &str) -> &'a str {
    let needle_variants = [
        format!("\nfn {fn_name}("),
        format!("\npub fn {fn_name}("),
        format!("\nasync fn {fn_name}("),
        format!("\npub async fn {fn_name}("),
    ];
    let start = needle_variants
        .iter()
        .find_map(|needle| src.find(needle.as_str()).map(|pos| pos + 1)) // +1 skips the leading \n
        .unwrap_or_else(|| panic!("function `{fn_name}` not found in decode.rs"));

    let after_start = &src[start..];
    let mut end = after_start.len();
    // Find the next top-level fn-start line AFTER this function's own
    // signature line, so the signature line itself (which obviously starts
    // with "fn"/"pub fn") never terminates the scan immediately.
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

/// Scans `text` for every double-quoted string literal that is actually used
/// as a `match` pattern (immediately followed, modulo whitespace, by `=>`) --
/// the same text-scanning approach this crate already uses elsewhere (e.g.
/// `tests/no_raw_event_mutation.rs`'s scan for raw `UPDATE`/`DELETE` SQL).
/// Comment lines (`//`, `///`, `//!`) are skipped entirely, so a doc comment
/// merely *mentioning* a literal (this file's own doc comment does, to
/// explain the bug) can never be mistaken for code matching on it. No prefix
/// filter is applied -- fix-round-2 D3 -- every match-arm literal found is
/// required to be in the caller's vendored list. A literal is only counted
/// once even if it appears in more than one arm.
fn match_arm_literals(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut rest = line;
        while let Some(start) = rest.find('"') {
            let after_quote = &rest[start + 1..];
            let Some(end) = after_quote.find('"') else {
                break;
            };
            let literal = &after_quote[..end];
            let after_literal = after_quote[end + 1..].trim_start();
            if after_literal.starts_with("=>") && !found.iter().any(|f| f == literal) {
                found.push(literal.to_string());
            }
            rest = &after_quote[end + 1..];
        }
    }
    found
}

#[test]
fn every_matched_event_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("open_responses_2026-04-24_event_types.txt");
    let src = decode_rs_source();

    // Both functions that dispatch on `event_type`: the main event switch
    // and the terminal-failure recognizer.
    let mut matched = match_arm_literals(function_body(&src, "decode_stream_event"));
    matched.extend(match_arm_literals(function_body(&src, "terminal_failure")));

    assert!(
        !matched.is_empty(),
        "sanity check failed: found zero event-type literals in decode.rs -- the scan \
         itself is broken (or decode.rs no longer matches on any event type), so this \
         test would otherwise pass vacuously"
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode.rs matches on event-type literal(s) that are not in the vendored \
         2026-04-24 spec's real `type` enum/default values: {unknown:?} -- this is \
         exactly the class of bug fix-round-1 C1 found (a literal that matches the \
         spec's stale prose `description` rather than its authoritative `enum`/\
         `default`). Re-check testdata/open_responses_2026-04-24_event_types.txt \
         against the real fetched spec before assuming this list is wrong instead \
         of decode.rs."
    );
}

/// Fix-round-2 D3: `decode_output_item_added` matches `item.type` (not
/// `event_type`) to decide the block kind -- a wrong value there is the
/// identical C1 failure mode (block never opens) and had the identical
/// "schema exists, value never checked" gap.
#[test]
fn every_matched_item_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_list("open_responses_2026-04-24_item_types.txt");
    let src = decode_rs_source();
    let matched = match_arm_literals(function_body(&src, "decode_output_item_added"));

    assert!(
        !matched.is_empty(),
        "sanity check failed: found zero item-type literals in decode_output_item_added -- \
         the scan itself is broken, so this test would otherwise pass vacuously"
    );

    let unknown: Vec<&String> = matched.iter().filter(|m| !vendored.contains(m)).collect();
    assert!(
        unknown.is_empty(),
        "decode_output_item_added matches on item-type literal(s) that are not in the \
         vendored 2026-04-24 spec's real ItemField union: {unknown:?}"
    );
}
