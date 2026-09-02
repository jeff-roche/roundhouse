//! Fix-round-1 follow-up (found while fixing C2, not itself in that review):
//! `sse_stream::SseStream` silently drops the LAST SSE frame in a body
//! unless it is followed by a blank-line terminator (`"\n\n"`/`"\r\n\r\n"`) --
//! confirmed empirically, and at the library source
//! (`sse-stream-0.2.5/src/stream.rs:361`, whose own comment says "When data
//! stream terminated without empty line, we should discard last incomplate
//! message").
//!
//! Every `.cassette` file in `openai_responses/`'s original commit put its
//! most important frame LAST: `response.completed` (carrying the usage
//! figure and the terminal signal) for the four success-path cassettes, and
//! `response.failed`/`response.incomplete`/`error` for the fix-round-1 C2
//! cassettes -- and none of them had a trailing blank line. The four
//! original cassettes still passed every check (`check_usage_invariants`'
//! `input_tokens >= cache_read_tokens` degenerately holds at `0 >= 0` when
//! the usage event never actually decodes), so the conformance suite was
//! green while silently never exercising the one frame that mattered most --
//! the same class of self-consistent hallucination as C1's decoder/cassette
//! pair sharing one wrong string, just here it was the harness and the
//! cassette bytes sharing one wrong assumption about a third-party library.
//!
//! **Fix-round-2 D2**: the first version of this test only walked
//! `testdata/cassettes/openai_responses/`. The reviewer swept the whole
//! crate and found `testdata/cassettes/moonshot/text.cassette` has the exact
//! same defect, live and uncovered. "Each later task remembers to copy this
//! guard into its own cassette directory" is precisely the discipline that
//! fails at scale -- eleven more tasks author cassettes in sibling
//! directories under `testdata/cassettes/`, so this walks that whole tree
//! recursively instead of one subdirectory, and will cover every cassette
//! any of them add without needing its own copy of this test.
//!
//! **Task 6 fix-round-1, F5 (the carried-forward M2 hardening)**: two gaps
//! in the walk/detection logic itself, both closed here:
//!
//! 1. `walkdir::WalkDir`'s errors (a broken symlink, a permission failure)
//!    were silently discarded via `.filter_map(Result::ok)` -- a directory
//!    the walk can't fully read would make this test quietly check FEWER
//!    cassettes than exist, passing "green" over an incomplete scan. Now a
//!    walk error panics with the path, the same posture as every other
//!    "care doesn't survive eleven repetitions, a test does" guard in this
//!    crate.
//! 2. SSE detection previously relied solely on a `text/event-stream`
//!    content-type header line -- but `CassetteTransport::from_file` does
//!    not require that header to replay a body as SSE (a codec's decoder
//!    decides how to parse the body, not the cassette format), so a future
//!    cassette authored without one would be SSE-replayed by its codec's
//!    `SseStream::from_bytes_stream` in real tests but silently SKIPPED by
//!    this guard. Detection now ALSO sniffs the body itself for the
//!    structural signature of SSE framing (a line starting with `data:`),
//!    so a cassette is treated as SSE if either signal says so.
use std::fs;
use std::path::{Path, PathBuf};

fn cassettes_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes")
}

/// Splits a `.cassette` file's bytes into (status/header block, body),
/// mirroring `CassetteTransport::from_file`'s own separator search (the
/// first `"\n\n"` or `"\r\n\r\n"`).
fn split_header_and_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        return (&raw[..pos], &raw[pos + 4..]);
    }
    let pos = raw
        .windows(2)
        .position(|w| w == b"\n\n")
        .expect("cassette must have a header/body separator");
    (&raw[..pos], &raw[pos + 2..])
}

/// True if `body` structurally looks like an SSE stream -- at least one line
/// (after lossy UTF-8 decoding, which is fine for a structural sniff) starts
/// with `data:`. Independent of any header, matching how a codec's own
/// decoder actually decides to parse a response body.
fn looks_like_sse(body: &[u8]) -> bool {
    String::from_utf8_lossy(body)
        .lines()
        .any(|line| line.trim_start().starts_with("data:"))
}

#[test]
fn every_sse_cassette_ends_with_a_blank_line_terminator() {
    let mut missing_terminator = Vec::new();
    let mut checked = 0usize;

    for entry in walkdir::WalkDir::new(cassettes_root()) {
        let entry = entry.unwrap_or_else(|e| {
            panic!(
                "walkdir failed while scanning {}: {e} -- a directory this test can't fully \
                 read means it would otherwise check fewer cassettes than exist and pass \
                 green over an incomplete scan",
                cassettes_root().display()
            )
        });
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("cassette") {
            continue;
        }
        let raw = fs::read(path).expect("cassette must be readable");
        let (header, body) = split_header_and_body(&raw);
        let header_text = String::from_utf8_lossy(header);
        let header_says_sse = header_text
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("text/event-stream"));
        // Fix-round-1 F5: OR the header signal with a body sniff, since
        // `CassetteTransport::from_file` doesn't require the header at all.
        if !header_says_sse && !looks_like_sse(body) {
            continue; // e.g. error_429/error_500: plain JSON/HTML bodies, not SSE.
        }
        checked += 1;
        let ends_with_blank_line = body.ends_with(b"\n\n") || body.ends_with(b"\r\n\r\n");
        if !ends_with_blank_line {
            missing_terminator.push(
                path.strip_prefix(cassettes_root())
                    .unwrap_or(path)
                    .to_string_lossy()
                    .to_string(),
            );
        }
    }

    assert!(
        checked > 0,
        "sanity check failed: found zero SSE-typed cassettes under {} -- the walk itself is \
         broken, so this test would otherwise pass vacuously",
        cassettes_root().display()
    );
    assert!(
        missing_terminator.is_empty(),
        "these SSE cassettes are missing a trailing blank-line terminator, which makes \
         `sse_stream` silently drop their LAST frame: {missing_terminator:?}"
    );
}

#[cfg(test)]
mod looks_like_sse_tests {
    use super::looks_like_sse;

    #[test]
    fn detects_sse_from_the_body_alone_with_no_header() {
        assert!(looks_like_sse(b"data: {\"hello\":\"world\"}\n\n"));
    }

    #[test]
    fn a_plain_json_body_is_not_sse() {
        assert!(!looks_like_sse(
            b"{\"error\":{\"type\":\"rate_limit_exceeded\"}}"
        ));
    }

    #[test]
    fn a_plain_html_body_is_not_sse() {
        assert!(!looks_like_sse(
            b"<html><body>502 Bad Gateway</body></html>"
        ));
    }
}
