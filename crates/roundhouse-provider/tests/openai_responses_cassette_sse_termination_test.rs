//! Fix-round-1 follow-up (found while fixing C2, not itself in the review):
//! `sse_stream::SseStream` silently drops the LAST SSE frame in a body
//! unless it is followed by a blank-line terminator (`"\n\n"`/`"\r\n\r\n"`) --
//! confirmed empirically (see this task's report) by counting frames off a
//! `CassetteTransport`-replayed body with and without a trailing blank line.
//!
//! Every `.cassette` file in this codec's original commit put its most
//! important frame LAST: `response.completed` (carrying the usage figure and
//! the terminal signal) for the four success-path cassettes, and
//! `response.failed`/`response.incomplete`/`error` for the fix-round-1 C2
//! cassettes -- and none of them had a trailing blank line. The four
//! original cassettes still passed every check (`check_usage_invariants`'
//! `input_tokens >= cache_read_tokens` degenerately holds at `0 >= 0` when
//! the usage event never actually decodes), so the conformance suite was
//! green while silently never exercising the one frame that mattered most --
//! the same class of self-consistent hallucination fix-round-1 C1 found in
//! the decoder's event-type string, just in the cassette bytes instead. The
//! three new C2 cassettes failed loudly instead, because their whole point
//! was to prove the dropped frame *is* detected -- which is what surfaced
//! this.
//!
//! This test is the structural fix: every SSE-typed cassette under
//! `testdata/cassettes/openai_responses/` must end with a blank-line
//! terminator, so this class of bug fails a test instead of silently
//! degrading a cassette to "replays everything except its last event."
use std::fs;
use std::path::Path;

fn cassettes_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/openai_responses")
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

#[test]
fn every_sse_cassette_ends_with_a_blank_line_terminator() {
    let mut missing_terminator = Vec::new();

    for entry in fs::read_dir(cassettes_dir()).expect("cassettes dir must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("cassette") {
            continue;
        }
        let raw = fs::read(&path).expect("cassette must be readable");
        let (header, body) = split_header_and_body(&raw);
        let header_text = String::from_utf8_lossy(header);
        let is_sse = header_text
            .lines()
            .any(|line| line.to_ascii_lowercase().contains("text/event-stream"));
        if !is_sse {
            continue; // error_429/error_500: plain JSON/HTML bodies, not SSE.
        }
        let ends_with_blank_line = body.ends_with(b"\n\n") || body.ends_with(b"\r\n\r\n");
        if !ends_with_blank_line {
            missing_terminator.push(path.file_name().unwrap().to_string_lossy().to_string());
        }
    }

    assert!(
        missing_terminator.is_empty(),
        "these SSE cassettes are missing a trailing blank-line terminator, which makes \
         `sse_stream` silently drop their LAST frame: {missing_terminator:?}"
    );
}
