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
//! the fetched spec JSON, never from a schema's `description`. This test
//! scans `decode.rs`'s own source text for the string literals it matches
//! `payload["type"]` against and asserts every one of them is a member of
//! that vendored list.

use std::fs;
use std::path::Path;

fn vendored_event_types() -> Vec<String> {
    include_str!("../testdata/open_responses_2026-04-24_event_types.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect()
}

/// Scans `decode.rs`'s source text for every double-quoted string literal
/// that is actually used as a `match` pattern (immediately followed, modulo
/// whitespace, by `=>`) -- the same text-scanning approach this crate
/// already uses elsewhere (e.g. `tests/no_raw_event_mutation.rs`'s scan for
/// raw `UPDATE`/`DELETE` SQL). Comment lines (`//`, `///`, `//!`) are skipped
/// entirely, so a doc comment merely *mentioning* an event-type string (this
/// file's own doc comment does, to explain the bug) can never be mistaken
/// for code matching on it. Restricting to the `"literal" =>` shape (rather
/// than any quoted string starting with `response.`) also excludes this
/// file's fallback error *messages* (e.g. `"response.failed with no error
/// detail..."`, used as a `.unwrap_or(...)` argument, not a match pattern)
/// and this file's own unit tests, which describe events in prose without
/// ever matching on them. A literal is only counted once even if it appears
/// in more than one arm.
fn matched_event_type_literals() -> Vec<String> {
    let src = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/openai_responses/decode.rs"),
    )
    .expect("src/codec/openai_responses/decode.rs must exist");

    let mut found: Vec<String> = Vec::new();
    for line in src.lines() {
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
            if after_literal.starts_with("=>")
                && (literal.starts_with("response.") || literal == "error")
                && !found.iter().any(|f| f == literal)
            {
                found.push(literal.to_string());
            }
            rest = &after_quote[end + 1..];
        }
    }
    found
}

#[test]
fn every_matched_event_type_literal_is_a_real_spec_enum_value() {
    let vendored = vendored_event_types();
    let matched = matched_event_type_literals();

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
