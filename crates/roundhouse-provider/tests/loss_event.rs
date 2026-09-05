//! Phase 7 Task 13b integration coverage: `LossEvent` actually reaches the
//! two named emit sites (`openai-responses`'s `response.incomplete`,
//! `bedrock-converse`'s `messageStop.stopReason`), exercised through each
//! codec's real decode function rather than a hand-built `LossEvent` value.
//!
//! **Ruling R4**: the plan's original sketch specced
//! `record_loss(writer: &EventWriter, ..)`, which cannot be built here
//! (`roundhouse-store` already depends on `roundhouse-provider`; the reverse
//! would be a dependency cycle -- see `crates/roundhouse-provider/src/loss_event.rs`'s
//! module doc). These tests call each codec's pure decode function directly
//! and assert on the `LossEvent` it returns in-band, per R4, rather than
//! going through any `EventWriter`/store plumbing.

use roundhouse_provider::codec::bedrock_converse::decode::decode_bedrock_converse_stream;
use roundhouse_provider::codec::openai_responses::decode::decode_openai_responses_stream;
use roundhouse_provider::loss_event::LossKind;
use roundhouse_provider::{CassetteTransport, HttpRequest, HttpTransport};

/// The scenario the original task text's Step 1 named directly: an operator
/// must be able to tell a `max_output_tokens` truncation apart from content
/// filtering, instead of both collapsing into the same opaque
/// `BadRequest{200,""}` `response.incomplete` produced before this task.
#[tokio::test]
async fn an_openai_responses_incomplete_stream_names_the_real_reason_not_a_blank_bad_request() {
    let sse_body = concat!(
        "data: {\"type\":\"response.incomplete\",\"sequence_number\":1,",
        "\"response\":{\"id\":\"resp_1\",\"status\":\"incomplete\",",
        "\"incomplete_details\":{\"reason\":\"max_output_tokens\"}}}\n\n",
    );
    let transport = CassetteTransport {
        status: 200,
        headers: vec![],
        body: sse_body.as_bytes().to_vec(),
        chunk_size: 0,
    };
    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/responses".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();

    // `StreamEvent` derives no `Debug` (REALITY-CORRECTIONS §14c), so this
    // is asserted by matching rather than `.expect_err`.
    let failure = match decode_openai_responses_stream(resp.body).await {
        Ok(_) => panic!("response.incomplete must not decode as a silent success"),
        Err(failure) => failure,
    };

    let loss = failure
        .loss
        .expect("response.incomplete must carry a LossEvent naming the real reason");
    assert_eq!(
        loss.kind,
        LossKind::TruncatedAtMaxTokens,
        "an operator must be able to tell truncation-at-max-tokens apart from content \
         filtering -- the whole point of this task"
    );
    // Fix round 1, K1: `description` is sanitized (truncated +
    // `{:?}`-escaped) before it lands in the `LossEvent`, even for a
    // known-safe short literal like this one.
    assert_eq!(loss.description, "\"max_output_tokens\"");
}

/// The other named reason value: `content_filter` must map to a distinct
/// `LossKind`, not the same tag as a `max_output_tokens` truncation.
#[tokio::test]
async fn an_openai_responses_incomplete_stream_distinguishes_content_filter_from_truncation() {
    let sse_body = concat!(
        "data: {\"type\":\"response.incomplete\",\"sequence_number\":1,",
        "\"response\":{\"id\":\"resp_1\",\"status\":\"incomplete\",",
        "\"incomplete_details\":{\"reason\":\"content_filter\"}}}\n\n",
    );
    let transport = CassetteTransport {
        status: 200,
        headers: vec![],
        body: sse_body.as_bytes().to_vec(),
        chunk_size: 0,
    };
    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://api.openai.com/v1/responses".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();

    let failure = match decode_openai_responses_stream(resp.body).await {
        Ok(_) => panic!("response.incomplete must not decode as a silent success"),
        Err(failure) => failure,
    };
    let loss = failure.loss.expect("content_filter must carry a LossEvent");
    assert_eq!(loss.kind, LossKind::ContentFiltered);
}

/// `bedrock-converse`'s `messageStop.stopReason` was, before this task,
/// never read at all -- `guardrail_intervened` and `content_filtered` both
/// produced an identical bare `MessageStop`, indistinguishable from
/// `end_turn`. This proves the fix through the real decode function (not
/// just the module's own inline unit tests, which build frames the same
/// way -- this is the crate-external, black-box confirmation that the
/// `LossEvent` return value is actually reachable from outside the module).
#[tokio::test]
async fn a_bedrock_converse_guardrail_intervened_stop_is_a_distinct_loss_event() {
    use aws_smithy_eventstream::frame::write_message_to;
    use aws_smithy_types::event_stream::{Header, HeaderValue, Message};

    let message = Message::new(
        serde_json::to_vec(&serde_json::json!({ "stopReason": "guardrail_intervened" })).unwrap(),
    )
    .add_header(Header::new(
        ":message-type",
        HeaderValue::String("event".into()),
    ))
    .add_header(Header::new(
        ":event-type",
        HeaderValue::String("messageStop".into()),
    ));
    let mut raw = Vec::new();
    write_message_to(&message, &mut raw).unwrap();

    let (events, losses) =
        decode_bedrock_converse_stream(futures::stream::iter(vec![Ok(bytes::Bytes::from(raw))]))
            .await
            .expect("a real, observed messageStop is a successful decode, not an error");

    assert!(events
        .iter()
        .any(|e| matches!(e, roundhouse_provider::StreamEvent::MessageStop)));
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].kind, LossKind::GuardrailIntervened);
    assert_eq!(losses[0].description, "guardrail_intervened");
}
