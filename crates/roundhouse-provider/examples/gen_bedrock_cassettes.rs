//! Regenerates `testdata/cassettes/bedrock_converse/*.cassette`.
//!
//! **Cassette provenance** (task report requirement): every eventstream
//! frame's binary bytes below -- the 12-byte prelude, every header's
//! length-prefixed encoding, both CRC32 checksums -- are produced by
//! `aws_smithy_eventstream::frame::write_message_to`, the SAME published AWS
//! crate (pinned version `aws-smithy-eventstream` 0.60.21) this codec's
//! `EventStreamDecoder` uses to decode them. Only the JSON payload content is
//! authored by hand, and every field name/shape in it was individually
//! fetched and verified against the real AWS Bedrock API Reference -- see
//! `src/codec/bedrock_converse/mod.rs`'s module doc comment for the fetch
//! record. This is not a hand-computed-CRC, self-consistent-with-its-own-
//! decoder fixture (REALITY-CORRECTIONS §13b item 3's warning) -- the framing
//! half is produced by AWS's own library, independently of this codec.
//!
//! Run with: `cargo run --example gen_bedrock_cassettes -p roundhouse-provider`

use aws_smithy_eventstream::frame::write_message_to;
use aws_smithy_types::event_stream::{Header, HeaderValue, Message};
use serde_json::{json, Value};
use std::path::PathBuf;

fn event_message(event_type: &str, payload: &Value) -> Message {
    Message::new(serde_json::to_vec(payload).expect("payload must serialize"))
        .add_header(Header::new(
            ":message-type",
            HeaderValue::String("event".into()),
        ))
        .add_header(Header::new(
            ":event-type",
            HeaderValue::String(event_type.to_string().into()),
        ))
        .add_header(Header::new(
            ":content-type",
            HeaderValue::String("application/json".into()),
        ))
}

fn exception_message(exception_type: &str, payload: &Value) -> Message {
    Message::new(serde_json::to_vec(payload).expect("payload must serialize"))
        .add_header(Header::new(
            ":message-type",
            HeaderValue::String("exception".into()),
        ))
        .add_header(Header::new(
            ":exception-type",
            HeaderValue::String(exception_type.to_string().into()),
        ))
        .add_header(Header::new(
            ":content-type",
            HeaderValue::String("application/json".into()),
        ))
}

fn encode_all(messages: &[Message]) -> Vec<u8> {
    let mut body = Vec::new();
    for message in messages {
        write_message_to(message, &mut body).expect("a well-formed Message always encodes");
    }
    body
}

fn write_eventstream_cassette(name: &str, messages: &[Message]) {
    let body = encode_all(messages);
    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(b"200\n");
    file.extend_from_slice(b"content-type: application/vnd.amazon.eventstream\n");
    file.extend_from_slice(b"\n");
    file.extend_from_slice(&body);
    write_cassette_file(name, &file);
}

fn write_http_error_cassette(name: &str, status: u16, exception_type: &str, message: &str) {
    let body = serde_json::to_vec(&json!({ "message": message })).expect("must serialize");
    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(format!("{status}\n").as_bytes());
    file.extend_from_slice(b"content-type: application/json\n");
    file.extend_from_slice(format!("x-amzn-errortype: {exception_type}\n").as_bytes());
    file.extend_from_slice(b"\n");
    file.extend_from_slice(&body);
    write_cassette_file(name, &file);
}

/// `error_500` deliberately has NO `x-amzn-errortype` header and a
/// non-JSON HTML body -- simulating a gateway/outage response that never
/// reached Bedrock's own error-formatting code at all (matches
/// `openai_responses`' `error_500.cassette` precedent: "never `?` on JSON
/// parsing in the error path").
fn write_html_error_cassette(name: &str, status: u16) {
    let mut file: Vec<u8> = Vec::new();
    file.extend_from_slice(format!("{status}\n").as_bytes());
    file.extend_from_slice(b"content-type: text/html\n");
    file.extend_from_slice(b"\n");
    file.extend_from_slice(b"<html><body>502 Bad Gateway</body></html>");
    write_cassette_file(name, &file);
}

fn write_cassette_file(name: &str, contents: &[u8]) {
    let dir: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/cassettes/bedrock_converse");
    std::fs::create_dir_all(&dir).expect("cassette dir must be creatable");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("cassette file must be writable");
    println!("wrote {} ({} bytes)", path.display(), contents.len());
}

fn main() {
    // text.cassette: a single text block with NO contentBlockStart at all
    // (verified divergence -- text has no ContentBlockStart union member),
    // exercising the implicit-open path.
    write_eventstream_cassette(
        "text.cassette",
        &[
            event_message("messageStart", &json!({ "role": "assistant" })),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "text": "4" } }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "text": "." } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 0 })),
            event_message("messageStop", &json!({ "stopReason": "end_turn" })),
            event_message(
                "metadata",
                &json!({
                    "usage": {
                        "inputTokens": 9,
                        "outputTokens": 3,
                        "totalTokens": 12,
                        "cacheReadInputTokens": 0,
                        "cacheWriteInputTokens": 0,
                    },
                    "metrics": { "latencyMs": 320 },
                }),
            ),
        ],
    );

    // tools.cassette: one forced tool call.
    write_eventstream_cassette(
        "tools.cassette",
        &[
            event_message("messageStart", &json!({ "role": "assistant" })),
            event_message(
                "contentBlockStart",
                &json!({
                    "contentBlockIndex": 0,
                    "start": { "toolUse": { "toolUseId": "tooluse_abc123", "name": "get_weather" } },
                }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "toolUse": { "input": "{\"location\":" } } }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "toolUse": { "input": "\"Tokyo\"}" } } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 0 })),
            event_message("messageStop", &json!({ "stopReason": "tool_use" })),
            event_message(
                "metadata",
                &json!({ "usage": { "inputTokens": 40, "outputTokens": 15, "totalTokens": 55 } }),
            ),
        ],
    );

    // parallel_tools.cassette: two tool calls in the same response.
    write_eventstream_cassette(
        "parallel_tools.cassette",
        &[
            event_message("messageStart", &json!({ "role": "assistant" })),
            event_message(
                "contentBlockStart",
                &json!({
                    "contentBlockIndex": 0,
                    "start": { "toolUse": { "toolUseId": "tooluse_weather1", "name": "get_weather" } },
                }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "toolUse": { "input": "{\"location\":\"Tokyo\"}" } } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 0 })),
            event_message(
                "contentBlockStart",
                &json!({
                    "contentBlockIndex": 1,
                    "start": { "toolUse": { "toolUseId": "tooluse_time1", "name": "get_time" } },
                }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 1, "delta": { "toolUse": { "input": "{\"location\":\"Tokyo\"}" } } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 1 })),
            event_message("messageStop", &json!({ "stopReason": "tool_use" })),
            event_message(
                "metadata",
                &json!({ "usage": { "inputTokens": 55, "outputTokens": 30, "totalTokens": 85 } }),
            ),
        ],
    );

    // reasoning.cassette: a reasoningContent block (text + signature, no
    // contentBlockStart -- same implicit-open divergence as text), followed
    // by a separate visible text block. Usage carries a nonzero
    // `cacheReadInputTokens` so the `input_tokens >= cache_read_tokens`
    // invariant is genuinely exercised, not vacuously true at zero
    // (REALITY-CORRECTIONS §13b item 6).
    write_eventstream_cassette(
        "reasoning.cassette",
        &[
            event_message("messageStart", &json!({ "role": "assistant" })),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "reasoningContent": { "text": "Let me think. " } } }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "reasoningContent": { "text": "2+2=4." } } }),
            ),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "reasoningContent": { "signature": "sig-abc123" } } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 0 })),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 1, "delta": { "text": "The answer is 4." } }),
            ),
            event_message("contentBlockStop", &json!({ "contentBlockIndex": 1 })),
            event_message("messageStop", &json!({ "stopReason": "end_turn" })),
            event_message(
                "metadata",
                &json!({
                    "usage": {
                        "inputTokens": 40,
                        "outputTokens": 25,
                        "totalTokens": 75,
                        "cacheReadInputTokens": 10,
                        "cacheWriteInputTokens": 0,
                    },
                }),
            ),
        ],
    );

    // Bonus (beyond the required minimum): a real in-band eventstream
    // exception frame arriving mid-generation, after some content already
    // streamed -- proves no MessageStop is fabricated despite partial
    // output, and that a modeled exception surfaces as an error rather than
    // being silently skipped.
    write_eventstream_cassette(
        "exception_throttling.cassette",
        &[
            event_message("messageStart", &json!({ "role": "assistant" })),
            event_message(
                "contentBlockDelta",
                &json!({ "contentBlockIndex": 0, "delta": { "text": "Partial output before " } }),
            ),
            exception_message(
                "ThrottlingException",
                &json!({ "message": "Too many tokens per second, please wait." }),
            ),
        ],
    );

    // error_429.cassette / error_500.cassette: plain HTTP-level errors (the
    // request never even reached a 200 + eventstream body), matching
    // `openai_responses`' identical two-cassette precedent.
    write_http_error_cassette(
        "error_429.cassette",
        429,
        "ThrottlingException",
        "Too many requests, please wait before retrying.",
    );
    write_html_error_cassette("error_500.cassette", 500);

    println!("done.");
}
