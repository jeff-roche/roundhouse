//! Task 31 (Phase 5, Subsystem D2): the SSE endpoint and the `Last-Event-ID`
//! <-> `(session_id, seq)` cursor mapping.
//!
//! **Every test that matters here drives the real `axum::Router`** through
//! `build_router` + `ServiceExt::oneshot`, with a real `Last-Event-ID` request
//! header, and asserts on the **frames the endpoint emitted** — their `id:`,
//! `event:` and `data:` fields. A pair of tests that only round-tripped
//! `format_event_id` through `parse_last_event_id` and rejected `"garbage"`
//! would pass for any implementation that never read the header at all, which
//! is the defect this file is written against.
//!
//! Each endpoint test names, in its doc comment, the mutation it kills. The
//! report for this task carries the same list with the observed failure for
//! each one, so "this test can fail" is a measurement rather than a claim.

use std::time::Duration;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use roundhouse_core::{Delta, EventPayload, SessionId};
use roundhouse_proto::ClientEvent;
use roundhouse_web::sse::{format_event_id, parse_last_event_id, Cursor, SessionUpdate, SseHub};
use roundhouse_web::{build_router, AppState};
use tower::ServiceExt;

// ── SSE frame parsing ────────────────────────────────────────────────────
//
// `axum` writes each field as `name: value\n` and terminates a frame with a
// blank line, so a frame is a `\n\n`-separated block. Parsing the body back
// into fields is what lets these tests assert on the `id:` the endpoint chose
// rather than on a status code.

#[derive(Debug, Default, PartialEq, Eq)]
struct Frame {
    id: Option<String>,
    event: Option<String>,
    data: Option<String>,
}

fn parse_frames(body: &str) -> Vec<Frame> {
    body.split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut frame = Frame::default();
            for line in block.lines() {
                if let Some(rest) = line.strip_prefix("id: ") {
                    frame.id = Some(rest.to_owned());
                } else if let Some(rest) = line.strip_prefix("event: ") {
                    frame.event = Some(rest.to_owned());
                } else if let Some(rest) = line.strip_prefix("data: ") {
                    frame.data = Some(rest.to_owned());
                }
            }
            frame
        })
        .collect()
}

fn frame_ids(body: &str) -> Vec<String> {
    parse_frames(body)
        .into_iter()
        .filter_map(|frame| frame.id)
        .collect()
}

/// The `data:` payloads as parsed JSON values. Parsed rather than compared as
/// text: ruling P29 — `serde_json`'s object key order is not stable across the
/// workspace, so any assertion over `to_string()` output is a trap.
fn frame_payloads(body: &str) -> Vec<serde_json::Value> {
    parse_frames(body)
        .into_iter()
        .filter_map(|frame| frame.data)
        .map(|data| serde_json::from_str(&data).expect("each data: field is one JSON document"))
        .collect()
}

// ── harness ──────────────────────────────────────────────────────────────

fn text_event(session_id: SessionId, seq: u64, text: &str) -> SessionUpdate {
    SessionUpdate {
        session_id,
        seq,
        event: ClientEvent::TaskEvent {
            session_id,
            task_id: None,
            payload: Box::new(EventPayload::TaskDelta {
                delta: Delta::Text {
                    text: text.to_owned(),
                },
            }),
        },
    }
}

fn events_uri(session_id: SessionId) -> String {
    format!("/api/sessions/{session_id}/events")
}

/// Publishes, asserting the endpoint is actually subscribed.
///
/// Without this the whole file is vacuous in one direction: if the handler
/// never subscribed, every publish would reach nobody, every body would be
/// empty, and a suite asserting "the other session's events are absent" would
/// pass for a stream that emits nothing at all.
fn publish(hub: &SseHub, update: SessionUpdate) {
    assert_eq!(
        hub.publish(update),
        1,
        "the SSE handler must be subscribed before the test publishes"
    );
}

struct Streamed {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

/// Drives the real router end to end.
///
/// Ordering is load-bearing: the request is dispatched **first**, because the
/// handler is what subscribes to the hub; then `publish` runs; then the last
/// `SseHub` handle is dropped, which closes the broadcast channel so the
/// stream terminates and the body can be collected. Without that drop an SSE
/// body never ends.
///
/// The header is passed as **bytes**, not `&str`, so a test can send a value
/// that is a legal HTTP header but not valid ASCII text — the `to_str()`
/// rejection path in the handler. (A NUL, `\r` or `\n` cannot be tested this
/// way: `HeaderValue` refuses to hold them, so `axum`'s documented `Event::id`
/// panic on a NUL is unreachable from the wire even before this module
/// declines to echo the header.)
async fn stream(
    hub: SseHub,
    uri: &str,
    last_event_id: Option<&[u8]>,
    publish: impl FnOnce(&SseHub),
) -> Streamed {
    let mut builder = Request::builder().uri(uri);
    if let Some(id) = last_event_id {
        builder = builder.header(
            "Last-Event-ID",
            HeaderValue::from_bytes(id).expect("test header value is a legal HTTP header"),
        );
    }
    let request = builder.body(Body::empty()).expect("request builds");

    let response = build_router(AppState { sse: hub.clone() })
        .oneshot(request)
        .await
        .expect("router is infallible");

    let status = response.status();
    let headers = response.headers().clone();

    publish(&hub);
    // The router's own clone was dropped when `oneshot`'s temporary went out
    // of scope above; this is the last sender.
    drop(hub);

    // A bug that leaves a sender alive would hang here rather than fail, so
    // the wait is bounded and reported as a failure instead.
    let body = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 64 * 1024),
    )
    .await
    .expect("the SSE stream must terminate once every sender is dropped")
    .expect("body fits in 64 KiB");

    Streamed {
        status,
        headers,
        body: String::from_utf8(body.to_vec()).expect("SSE bodies are UTF-8"),
    }
}

// ── the endpoint ─────────────────────────────────────────────────────────

/// With no `Last-Event-ID`, the client has seen nothing and must receive
/// everything — **including `seq` 0**. `roundhouse-store`'s writer allocates
/// the first seq as `COALESCE(MAX(seq), -1) + 1`, so 0 is a real event and
/// any "0 means no cursor" sentinel silently eats it.
///
/// **Mutation killed:** making the absent-header resume point `1` instead of
/// `0` (the shape a `seq`-as-sentinel implementation has). The `:0` frame
/// disappears and both assertions below fail.
#[tokio::test]
async fn an_absent_last_event_id_streams_from_seq_zero_rather_than_treating_zero_as_a_sentinel() {
    let hub = SseHub::new();
    let session = SessionId::new();

    let streamed = stream(hub, &events_uri(session), None, |hub| {
        for (seq, text) in [(0, "zeroth"), (1, "first")] {
            publish(hub, text_event(session, seq, text));
        }
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert_eq!(
        streamed.headers.get(CONTENT_TYPE).expect("content type"),
        "text/event-stream",
        "the SSE route must be reached, not the asset router's SPA fallback"
    );
    assert_eq!(
        frame_ids(&streamed.body),
        vec![format!("{session}:0"), format!("{session}:1"),],
        "seq 0 is a real event, not the absence of a cursor"
    );
}

/// The point of the whole task: `Last-Event-ID` names the last event the
/// client **received**, so the stream resumes at `seq + 1`.
///
/// **Mutations killed:** (a) not reading the header at all — the `:0` and
/// `:1` frames reappear; (b) resuming at `cursor.seq` instead of
/// `cursor.seq + 1` — the `:1` frame is replayed. Both change `frame_ids`.
#[tokio::test]
async fn a_last_event_id_resumes_after_the_cursor_rather_than_replaying_or_ignoring_it() {
    let hub = SseHub::new();
    let session = SessionId::new();
    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 1,
    });

    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |hub| {
            for (seq, text) in [(0, "zeroth"), (1, "first"), (2, "second"), (3, "third")] {
                publish(hub, text_event(session, seq, text));
            }
        },
    )
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert_eq!(
        frame_ids(&streamed.body),
        vec![format!("{session}:2"), format!("{session}:3")],
        "the client already has seq 0 and 1; the stream resumes at seq 2"
    );

    // The payloads, not just the ids: an implementation that emitted the
    // right ids against the wrong events would pass an id-only assertion.
    let expected: Vec<serde_json::Value> = [(2, "second"), (3, "third")]
        .into_iter()
        .map(|(seq, text)| {
            serde_json::to_value(text_event(session, seq, text).event).expect("serializes")
        })
        .collect();
    assert_eq!(frame_payloads(&streamed.body), expected);
}

/// The `id:` on each frame is generated from that frame's own cursor, and it
/// is what a browser sends back as `Last-Event-ID` — so it must be exactly
/// what `parse_last_event_id` accepts, and it must never be an echo of the
/// request header (`axum`'s `Event::id` asserts on its contents; a
/// client-controlled value there is a panic in a request handler).
///
/// **Mutation killed:** emitting the incoming `Last-Event-ID` as every
/// frame's `id:` — the parsed seq would then be 1 for both frames instead of
/// 2 and 3.
#[tokio::test]
async fn every_emitted_event_id_is_the_generated_cursor_for_its_own_event() {
    let hub = SseHub::new();
    let session = SessionId::new();
    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 1,
    });

    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |hub| {
            for seq in 0..4 {
                publish(hub, text_event(session, seq, "delta"));
            }
        },
    )
    .await;

    let parsed: Vec<Cursor> = frame_ids(&streamed.body)
        .iter()
        .map(|id| parse_last_event_id(id).expect("an emitted id must parse as a cursor"))
        .collect();

    assert_eq!(
        parsed,
        vec![
            Cursor {
                session_id: session,
                seq: 2
            },
            Cursor {
                session_id: session,
                seq: 3
            },
        ],
    );
}

/// The stream is per-session. A hub is one process-wide broadcast, so without
/// a session filter every client would receive every session's events.
///
/// **Mutation killed:** dropping the `update.session_id == session` check —
/// the other session's three frames appear in the body.
#[tokio::test]
async fn another_sessions_events_never_appear_in_this_sessions_stream() {
    let hub = SseHub::new();
    let mine = SessionId::new();
    let theirs = SessionId::new();

    let streamed = stream(hub, &events_uri(mine), None, |hub| {
        for seq in 0..3 {
            publish(hub, text_event(theirs, seq, "not mine"));
            publish(hub, text_event(mine, seq, "mine"));
        }
    })
    .await;

    assert_eq!(
        frame_ids(&streamed.body),
        vec![
            format!("{mine}:0"),
            format!("{mine}:1"),
            format!("{mine}:2"),
        ],
    );
    assert!(
        !streamed.body.contains(&theirs.to_string()),
        "no trace of another session may reach this stream; body was:\n{}",
        streamed.body
    );
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
        let streamed = stream(
            SseHub::new(),
            &events_uri(session),
            Some(raw.as_bytes()),
            |_| {},
        )
        .await;
        assert_eq!(
            streamed.status,
            StatusCode::BAD_REQUEST,
            "{raw:?} is not a cursor and must be rejected, not defaulted"
        );
        assert!(
            streamed
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
/// the status becomes 200.
#[tokio::test]
async fn a_last_event_id_naming_a_different_session_is_rejected() {
    let mine = SessionId::new();
    let theirs = SessionId::new();
    let foreign = format_event_id(&Cursor {
        session_id: theirs,
        seq: 3,
    });

    let streamed = stream(
        SseHub::new(),
        &events_uri(mine),
        Some(foreign.as_bytes()),
        |_| {},
    )
    .await;

    assert_eq!(streamed.status, StatusCode::BAD_REQUEST);
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
        let streamed = stream(SseHub::new(), &events_uri(session), Some(&raw), |_| {}).await;
        assert_eq!(
            streamed.status,
            StatusCode::BAD_REQUEST,
            "{:?} must be rejected, and must not panic the handler",
            String::from_utf8_lossy(&raw)
        );
    }
}

/// §11.3: a client whose cursor predates what the daemon still holds is told
/// `resync_required` and refetches a snapshot. The broadcast buffer
/// overflowing is the same class of failure — the stream cannot produce the
/// events the client is missing — so it gets the same answer. Continuing
/// silently would hand the client a gap it has no way to detect.
///
/// **Mutation killed:** `Err(RecvError::Lagged(_)) => continue`, the shape
/// this endpoint was drafted with. The body then contains only the surviving
/// frames and no `resync_required` frame at all.
#[tokio::test]
async fn a_subscriber_that_falls_behind_is_told_resync_required_rather_than_handed_a_silent_gap() {
    let hub = SseHub::with_capacity(2);
    let session = SessionId::new();

    let streamed = stream(hub, &events_uri(session), None, |hub| {
        for seq in 0..5 {
            publish(hub, text_event(session, seq, "delta"));
        }
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);

    let frames = parse_frames(&streamed.body);
    let last = frames
        .last()
        .expect("the stream emitted at least one frame");
    assert_eq!(
        last.event.as_deref(),
        Some("resync_required"),
        "falling behind must terminate the stream with §11.3's resync signal; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        last.id, None,
        "the resync frame carries no cursor: a browser would otherwise resume from it \
         as if it were a real event"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            last.data
                .as_deref()
                .expect("the resync frame states how much was lost")
        )
        .expect("JSON"),
        serde_json::json!({ "dropped_events": 3 }),
    );
    assert_eq!(
        frames.len(),
        1,
        "the resync frame is terminal: nothing is emitted after it. Body was:\n{}",
        streamed.body
    );
}

/// The API subtree and the SPA fallback must not blur into each other. An
/// `/api/...` path with no route is a 404, not the `index.html` shell: a
/// client that mistypes an endpoint has to see the mistake, not a 200 with a
/// page of HTML that fails later as an opaque JSON parse error.
///
/// **Mutation killed:** nesting the SSE router at `/` instead of `/api`, or
/// widening `assets::is_client_route` to treat `/api/...` as a client route —
/// the status becomes 200 with the shell's `text/html`.
#[tokio::test]
async fn an_api_path_with_no_route_is_a_404_rather_than_the_spa_shell() {
    for path in [
        "/api",
        "/api/sessions",
        "/api/nope",
        "/api/sessions/whatever/events/extra",
    ] {
        let streamed = stream(SseHub::new(), path, None, |_| {}).await;
        assert_eq!(
            streamed.status,
            StatusCode::NOT_FOUND,
            "{path} matches no API route and is not a §11.1 client route"
        );
        assert!(
            streamed
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
/// path parse error — the status becomes 200.
#[tokio::test]
async fn a_path_session_id_that_is_not_a_uuid_is_rejected() {
    for path in ["/api/sessions/not-a-uuid/events", "/api/sessions//events"] {
        let streamed = stream(SseHub::new(), path, None, |_| {}).await;
        assert_ne!(
            streamed.status,
            StatusCode::OK,
            "{path} names no session and must not open a stream"
        );
    }
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
