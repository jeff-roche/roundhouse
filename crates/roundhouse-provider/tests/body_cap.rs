//! Phase 7 Task 15: every codec's `provider.rs` used to hand-roll an
//! unbounded `while let Some(chunk) = body.next().await { out.extend_from_slice(&chunk) }`
//! loop when collecting a non-success HTTP response body for `errors::classify`
//! -- no byte cap, so a malicious or merely broken peer streaming an
//! arbitrarily large body could make this process buffer without bound.
//! `body_cap::collect_body_capped` replaces all seven such loops with one
//! shared, capped implementation.

use bytes::Bytes;
use futures::stream;

#[tokio::test]
async fn a_response_body_exceeding_the_cap_errors_without_buffering_the_whole_thing() {
    // 200 MiB total, well past the 64 MiB cap -- if this test completes
    // quickly and without exhausting memory, the implementation is truly
    // rejecting at the moment the running total exceeds the cap, not
    // buffering the whole stream first and checking afterward.
    let huge = stream::iter((0..200).map(|_| Ok(Bytes::from(vec![0u8; 1024 * 1024]))));
    let result = roundhouse_provider::body_cap::collect_body_capped(huge, 64 * 1024 * 1024).await;
    assert!(
        matches!(
            result,
            Err(roundhouse_provider::TransportError::ResponseTooLarge { .. })
        ),
        "expected ResponseTooLarge, got {result:?}"
    );
}

#[tokio::test]
async fn a_response_body_under_the_cap_is_collected_in_full() {
    let chunks = stream::iter(vec![
        Ok::<_, roundhouse_provider::TransportError>(Bytes::from_static(b"hello, ")),
        Ok(Bytes::from_static(b"world")),
    ]);
    let result = roundhouse_provider::body_cap::collect_body_capped(chunks, 1024)
        .await
        .unwrap();
    assert_eq!(result, b"hello, world");
}

#[tokio::test]
async fn a_body_exactly_at_the_cap_is_not_rejected() {
    let chunks = stream::iter(vec![Ok::<_, roundhouse_provider::TransportError>(
        Bytes::from(vec![1u8; 16]),
    )]);
    let result = roundhouse_provider::body_cap::collect_body_capped(chunks, 16)
        .await
        .unwrap();
    assert_eq!(result.len(), 16);
}

#[tokio::test]
async fn a_chunk_error_mid_stream_is_ignored_matching_prior_per_codec_behavior() {
    // The per-codec loops this replaces silently dropped `Err` chunks
    // (`if let Ok(chunk) = chunk`) because this collection only ever runs on
    // the error-classification path -- best-effort diagnostic text, not a
    // success-path decode. Preserve that behavior exactly.
    let chunks = stream::iter(vec![
        Ok(Bytes::from_static(b"partial")),
        Err(roundhouse_provider::TransportError::Io("boom".into())),
        Ok(Bytes::from_static(b"-body")),
    ]);
    let result = roundhouse_provider::body_cap::collect_body_capped(chunks, 1024)
        .await
        .unwrap();
    assert_eq!(result, b"partial-body");
}
