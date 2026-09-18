//! Task 31 (Phase 5, Subsystem D2): the SSE endpoint's request-shape checks —
//! the ones that are answered before `stream_session_events` ever reaches a
//! store: an unparsable path segment, a malformed or hostile `Last-Event-ID`,
//! a cursor naming a session other than the URL's, and the cursor codec's own
//! round trip.
//!
//! **Phase 8 Task 21 (Decision 1) retired the rest of this file.** Every test
//! that used to live here exercising `SseHub`'s in-memory ring — replay on
//! reconnect, resync on a lag past the ring, per-session isolation of the
//! fan-out, the ring's own byte/entry accounting — pinned behaviour that no
//! longer exists: the store itself now serves as the replay history, with
//! nothing evicted and no separate hub state. `tests/sse_store_stream.rs` is
//! where the store-backed behaviour (catch-up, replay across a disconnect,
//! resync on a cursor ahead of the head) is pinned instead.
//!
//! Every request here is rejected before the handler ever looks at
//! `AppState::store`, so `AppState::default()` (`store: None`) is what every
//! test in this file builds its router over — the same convention
//! `tests/interaction.rs`'s pre-store-check tests already use.

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use roundhouse_core::SessionId;
use roundhouse_web::lan_auth::BindConfig;
use roundhouse_web::sse::{format_event_id, parse_last_event_id, Cursor};
use roundhouse_web::{build_router, AppState};
use tower::ServiceExt;

fn events_uri(session_id: SessionId) -> String {
    format!("/api/sessions/{session_id}/events")
}

/// The header is passed as **bytes**, not `&str`, so a test can send a value
/// that is a legal HTTP header but not valid ASCII text — the `to_str()`
/// rejection path in the handler. (A NUL, `\r` or `\n` cannot be tested this
/// way: `HeaderValue` refuses to hold them, so `axum`'s documented `Event::id`
/// panic on a NUL is unreachable from the wire even before this module
/// declines to echo the header.)
fn sse_request(uri: &str, last_event_id: Option<&[u8]>) -> Request<Body> {
    // An `/api` request that does not address the bind is `403` before it
    // reaches any handler (ruling P93 §A), and an in-process `oneshot` sets
    // no `Host` of its own. These routers are loopback-bound, so this is the
    // name they answer to; `tests/host_guard.rs` asserts the refusal itself.
    let mut builder = Request::builder().uri(uri).header("Host", "127.0.0.1");
    if let Some(id) = last_event_id {
        builder = builder.header(
            "Last-Event-ID",
            HeaderValue::from_bytes(id).expect("test header value is a legal HTTP header"),
        );
    }
    builder.body(Body::empty()).expect("request builds")
}

struct Probed {
    status: StatusCode,
    headers: HeaderMap,
}

/// Drives the real router with a store-less state. Every test in this file
/// is rejected before the store would ever be reached, so there is nothing to
/// wire one up for.
async fn probe(uri: &str, last_event_id: Option<&[u8]>) -> Probed {
    let response = build_router(AppState::default(), &BindConfig::loopback())
        .oneshot(sse_request(uri, last_event_id))
        .await
        .expect("router is infallible");
    Probed {
        status: response.status(),
        headers: response.headers().clone(),
    }
}

/// A malformed cursor is a client that cannot be resumed correctly. Answering
/// it with a stream from the beginning would silently replay events the
/// client already has, which is exactly the crash-recovery bug §11.3's cursor
/// exists to prevent.
///
/// **Mutation killed:** `parse_last_event_id(raw).unwrap_or_default()` or any
/// `.ok()`-and-ignore — the status becomes 200 with a `text/event-stream`
/// body.
#[tokio::test]
async fn a_malformed_last_event_id_is_rejected_rather_than_silently_streaming_from_the_start() {
    let session = SessionId::new();
    let malformed = [
        "not-a-cursor".to_owned(),
        String::new(),
        ":".to_owned(),
        ":7".to_owned(),
        "1234:".to_owned(),
        "not-a-uuid:7".to_owned(),
        session.to_string(),
        // A valid session id with a seq that is not a bare decimal integer.
        // `u64::from_str` accepts a leading `+`; the wire format does not, or
        // `<uuid>:+7` would be a second spelling of `<uuid>:7`.
        format!("{session}:+7"),
        format!("{session}:-1"),
        format!("{session}:seven"),
        format!("{session}: 7"),
        format!("{session}:18446744073709551616"), // u64::MAX + 1
        format!("{session}:0:0"),
    ];

    for raw in malformed {
        let probed = probe(&events_uri(session), Some(raw.as_bytes())).await;
        assert_eq!(
            probed.status,
            StatusCode::BAD_REQUEST,
            "{raw:?} is not a cursor and must be rejected, not defaulted"
        );
        assert!(
            probed
                .headers
                .get(CONTENT_TYPE)
                .is_none_or(|value| value != "text/event-stream"),
            "{raw:?} must not open an event stream"
        );
    }
}

/// The cursor carries a session id, and the URL carries one too. If they
/// disagree the request is incoherent — honouring either one silently gives
/// the client a stream it did not ask for.
///
/// **Mutation killed:** dropping the `cursor.session_id == session` check —
/// the status becomes 200 (or, with no store attached, 503 rather than 400).
#[tokio::test]
async fn cursor_for_another_session_is_400() {
    let mine = SessionId::new();
    let theirs = SessionId::new();
    let foreign = format_event_id(&Cursor {
        session_id: theirs,
        seq: 3,
    });

    let probed = probe(&events_uri(mine), Some(foreign.as_bytes())).await;

    assert_eq!(probed.status, StatusCode::BAD_REQUEST);
}

/// `Last-Event-ID` is a client-controlled request header and `axum`'s
/// `Event::id` **panics** on a NUL and its `field` writer panics on `\r` or
/// `\n`. A panic inside a request handler is a denial of service, so nothing
/// may route the raw header into a response frame.
///
/// **Mutation killed:** echoing the raw header into `Event::id`, or
/// `.expect()`ing the parse — either turns these into a panicking handler
/// (`oneshot` surfaces it as a panic, failing the test) instead of a 400.
#[tokio::test]
async fn a_hostile_last_event_id_is_rejected_without_panicking_the_handler() {
    let session = SessionId::new();
    let hostile: Vec<Vec<u8>> = vec![
        b"%00".to_vec(),
        b"\t".to_vec(),
        // Legal header bytes, not valid ASCII text: the `to_str()` rejection
        // path. A handler using `to_str().unwrap()` panics here.
        vec![0x80, b':', b'1'],
        format!("{session}:0\u{fffd}").into_bytes(),
        // Longer than any id this server emits, and long enough that a naive
        // numeric parse would overflow rather than fail.
        format!("{session}:{}", "9".repeat(4096)).into_bytes(),
        b"A".repeat(8192),
        // `Uuid::parse_str` accepts the URN form, which contains colons.
        // Splitting the cursor on the LAST colon would accept this as a second
        // spelling of `<uuid>:5`.
        format!("urn:uuid:{}:5", session.as_uuid()).into_bytes(),
        format!("{{{session}}}:5:5").into_bytes(),
    ];

    for raw in hostile {
        let probed = probe(&events_uri(session), Some(&raw)).await;
        assert_eq!(
            probed.status,
            StatusCode::BAD_REQUEST,
            "{:?} must be rejected, and must not panic the handler",
            String::from_utf8_lossy(&raw)
        );
    }
}

/// The API subtree and the SPA fallback must not blur into each other. An
/// `/api/...` path with no route is a 404, not the `index.html` shell: a
/// client that mistypes an endpoint has to see the mistake, not a 200 with a
/// page of HTML that fails later as an opaque JSON parse error.
///
/// **Mutation killed:** changing the status `roundhouse_web`'s `api_not_found`
/// answers with — every path here is now that fallback's, so its `404` is
/// exactly what this asserts.
#[tokio::test]
async fn an_api_path_with_no_route_is_a_404_rather_than_the_spa_shell() {
    for path in [
        "/api",
        "/api/sessions",
        "/api/nope",
        "/api/sessions/whatever/events/extra",
    ] {
        let probed = probe(path, None).await;
        assert_eq!(
            probed.status,
            StatusCode::NOT_FOUND,
            "{path} matches no API route and is not a §11.1 client route"
        );
        assert!(
            probed
                .headers
                .get(CONTENT_TYPE)
                .is_none_or(|value| value != "text/html"),
            "{path} must not be answered with the app shell"
        );
    }
}

/// The path segment is a session id, not an arbitrary string. Accepting one
/// that is not a UUID would produce a stream that can never match any
/// published event — a silently empty subscription rather than an error.
///
/// **Mutation killed:** falling back to `SessionId::new()` or ignoring the
/// path parse error — the status becomes something other than 400 (or, with
/// no store attached, a 503 that never checked the path at all).
#[tokio::test]
async fn a_path_session_id_that_is_not_a_uuid_is_rejected() {
    // Reaches the handler, which rejects it: the exact status is this module's
    // to get right, so it is asserted exactly.
    let probed = probe("/api/sessions/not-a-uuid/events", None).await;
    assert_eq!(
        probed.status,
        StatusCode::BAD_REQUEST,
        "an unparsable session id must be refused by the handler"
    );

    // An empty segment never reaches the handler at all — `matchit` does not
    // match it, so the answer comes from the asset fallback. What this module
    // owes here is only that no stream opens; the status is another layer's
    // decision and asserting it would pin behaviour this file does not own.
    let probed = probe("/api/sessions//events", None).await;
    assert_ne!(
        probed.status,
        StatusCode::OK,
        "an empty session segment names no session and must not open a stream"
    );
}

// ── the cursor functions on their own ────────────────────────────────────

/// The wire format is this task's decision (§11.3 mandates that
/// `Last-Event-ID` *carries* the `(session_id, seq)` cursor; it prescribes no
/// encoding), so the encoding is pinned here explicitly rather than only via
/// a round trip. A round-trip-only test passes for `"{seq}:{session_id}"`,
/// for a base64 blob, or for anything else self-consistent — including an
/// encoding that silently changed under a client already holding old ids.
#[test]
fn an_event_id_is_the_session_uuid_a_colon_and_the_decimal_seq() {
    let session_id = SessionId::new();
    let cursor = Cursor {
        session_id,
        seq: 4217,
    };

    assert_eq!(
        format_event_id(&cursor),
        format!("{}:4217", session_id.as_uuid()),
    );
    assert_eq!(parse_last_event_id(&format_event_id(&cursor)), Ok(cursor));
}

#[test]
fn a_cursor_round_trips_through_the_boundary_seq_values() {
    let session_id = SessionId::new();
    for seq in [0, 1, u64::MAX] {
        let cursor = Cursor { session_id, seq };
        assert_eq!(
            parse_last_event_id(&format_event_id(&cursor)),
            Ok(cursor),
            "seq {seq} must survive the round trip"
        );
    }
}
