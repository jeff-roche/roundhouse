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
//! Per ruling P81 the sweep is re-run against the file as it ships — a table
//! measured against a different revision of the suite invites a reader to
//! discount it — and a mutation that fails to compile, panics at router
//! construction, or kills every test is a broken build rather than evidence.

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

/// Publishes for another session **without** asserting the receiver count.
///
/// Deliberate, and the reason is measured rather than assumed: under the
/// mutation that reverts the hub to one process-global channel, the count is 1,
/// so a strict helper aborts the test *there* — and the assertions about what
/// reached the body, which are the point of
/// `another_sessions_events_never_appear_in_this_sessions_stream`, never run. A
/// leak would then be reported as a receiver-count mismatch rather than as the
/// leak it is. The count property is asserted where it can be reached, at the
/// end of `a_burst_on_another_session_does_not_lag_this_sessions_stream`.
fn publish_ignoring_receiver_count(hub: &SseHub, update: SessionUpdate) {
    let _ = hub.publish(update);
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
/// `SseHub` handle is dropped. The hub owns the map that owns every session's
/// sender, so that drop closes the channels and every stream ends, letting the
/// body be collected. Without it an SSE body never ends — which is also why
/// `SessionSubscription` holds only a `Weak` back-reference to that map: a
/// strong one would keep its own sender alive and the close would never
/// arrive.
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
    // of scope above; this is the last hub handle.
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

/// The stream is per-session, and after this task's fix round that is the
/// hub's **map key**, not a filter: an update for another session has no
/// channel to reach this subscriber through.
///
/// **Mutation killed:** the pre-fix shape — one process-global
/// `broadcast::Sender` for every session, *and* `Filter::accepts`'s
/// `update.session_id == self.session_id` check removed. The other session's
/// three frames interleave into the body, measured.
///
/// **Stated honestly as a two-part mutation.** Neither half kills this test
/// alone, and both were run: removing only the filter check leaves it green
/// (the map key already routes), and making the channel global while keeping
/// the filter leaves it green too (the filter catches what the key no longer
/// does). That is precisely what "belt and braces" means in `Filter`'s doc
/// comment — one of the two is redundant at any time, but which one is
/// redundant is a property of the hub, not of the filter. The report's sweep
/// records all three measurements.
#[tokio::test]
async fn another_sessions_events_never_appear_in_this_sessions_stream() {
    let hub = SseHub::new();
    let mine = SessionId::new();
    let theirs = SessionId::new();

    let streamed = stream(hub, &events_uri(mine), None, |hub| {
        for seq in 0..3 {
            publish_ignoring_receiver_count(hub, text_event(theirs, seq, "not mine"));
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

/// The reason the hub is keyed by session rather than filtered per connection.
///
/// A burst on one session must not cost an **idle** session its stream. Under a
/// single process-global channel, every session's traffic passes through every
/// connection's receiver slot, so this session — which has produced one event —
/// would be pushed past the buffer by another session's five and be told
/// `resync_required` having missed nothing of its own. Worse, the
/// `dropped_events` count it would be handed is a measure of *the other
/// session's* traffic.
///
/// **Mutation killed:** replacing the per-session map with one shared
/// `broadcast::Sender` (the pre-fix shape), whether or not `Filter`'s session
/// check is kept — the filter runs after the buffer has already overrun. The
/// body becomes a single `resync_required` frame carrying a count of events
/// this client was never entitled to know about, instead of the one frame this
/// session actually produced.
///
/// The receiver counts are collected during the publish and asserted **after**
/// the body, deliberately: asserting them inline would abort the test at the
/// first flood publish under that mutation, and the body assertions — which are
/// what actually show the coupling — would never run.
#[tokio::test]
async fn a_burst_on_another_session_does_not_lag_this_sessions_stream() {
    // Two slots, so five events on the other session would overrun a shared
    // buffer several times over.
    let hub = SseHub::with_capacity(2);
    let mine = SessionId::new();
    let theirs = SessionId::new();
    let mut receiver_counts = Vec::new();

    let streamed = stream(hub, &events_uri(mine), None, |hub| {
        for seq in 0..5 {
            receiver_counts.push(hub.publish(text_event(theirs, seq, "flood")));
        }
        receiver_counts.push(hub.publish(text_event(mine, 0, "mine")));
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    let frames = parse_frames(&streamed.body);
    assert!(
        frames.iter().all(|frame| frame.event.is_none()),
        "an idle session's stream must carry no resync_required; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        frame_ids(&streamed.body),
        vec![format!("{mine}:0")],
        "this session produced exactly one event and must receive exactly it"
    );
    assert_eq!(
        receiver_counts,
        vec![0, 0, 0, 0, 0, 1],
        "the other session has no open stream, so its five updates must reach nobody; \
         only this session's single update has a receiver"
    );
}

/// The map entry is dropped with its last reader.
///
/// `GET /api/sessions/{any-uuid}/events` creates a channel for whatever session
/// id it is given, and the id need not name a session that exists. If the
/// entries outlived their subscribers, a client could grow the map by one entry
/// per request, indefinitely.
///
/// **Mutation killed:** deleting `impl Drop for SessionSubscription` (or
/// weakening its `receiver_count() <= 1` to `== 0`, which never holds while the
/// dropping receiver still counts itself). The final assertion sees 1.
#[tokio::test]
async fn a_sessions_channel_is_dropped_with_its_last_subscriber() {
    let hub = SseHub::new();
    let session = SessionId::new();
    assert_eq!(hub.tracked_sessions(), 0, "a fresh hub tracks nothing");

    {
        let _first = hub.subscribe(session);
        assert_eq!(hub.tracked_sessions(), 1);

        let _second = hub.subscribe(session);
        assert_eq!(
            hub.tracked_sessions(),
            1,
            "two streams on one session share one channel"
        );

        let _other = hub.subscribe(SessionId::new());
        assert_eq!(
            hub.tracked_sessions(),
            2,
            "a second session, a second entry"
        );
    }

    assert_eq!(
        hub.tracked_sessions(),
        0,
        "every entry must go when its last subscriber does: the session id in the \
         URL is client-chosen and need not exist"
    );
}

/// `SessionUpdate.session_id` routes the update and stamps the cursor; the
/// `ClientEvent::TaskEvent` inside it carries a session id of its own. If they
/// disagree, the wrapper is not describing its payload — and a publisher that
/// built the wrapper from a subscription key rather than from the payload would
/// deliver one session's event into another session's stream, labelled with
/// that stream's cursor. Neither side could see it.
///
/// So the disagreement ends the stream loudly instead.
///
/// **Mutation killed:** removing the equality check in `encode` — the frame is
/// emitted as a normal event with `id: <mine>:0`, carrying a payload whose own
/// `session_id` is another session's, and both assertions below fail.
#[tokio::test]
async fn an_update_whose_payload_names_another_session_ends_the_stream_with_stream_error() {
    let hub = SseHub::new();
    let mine = SessionId::new();
    let theirs = SessionId::new();

    let streamed = stream(hub, &events_uri(mine), None, |hub| {
        // Routed to `mine` — this stream's own key — but describing `theirs`.
        let mut mislabelled = text_event(theirs, 0, "not mine");
        mislabelled.session_id = mine;
        publish(hub, mislabelled);
        publish(hub, text_event(mine, 1, "never reached"));
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    let frames = parse_frames(&streamed.body);
    assert_eq!(
        frames.len(),
        1,
        "the stream_error frame is terminal; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        frames[0].event.as_deref(),
        Some("stream_error"),
        "a mismatched routing key must not be emitted as a normal frame; body was:\n{}",
        streamed.body
    );
    assert_eq!(frames[0].id, None, "a failed frame carries no resume point");
    assert!(
        !streamed.body.contains(&theirs.to_string()),
        "the error must not name the session the client was not entitled to; body was:\n{}",
        streamed.body
    );
}

/// The API subtree and the SPA fallback must not blur into each other. An
/// `/api/...` path with no route is a 404, not the `index.html` shell: a
/// client that mistypes an endpoint has to see the mistake, not a 200 with a
/// page of HTML that fails later as an opaque JSON parse error.
///
/// **Mutation killed:** widening `assets::is_client_route` to treat `/api/...`
/// as a client route — the status becomes 200 with the shell's `text/html`.
/// (Nesting the SSE router at `/` is *not* a usable mutation: `axum` panics in
/// `build_router` itself — "Nesting at the root is no longer supported. Use
/// merge instead." — taking 12 of the 15 tests down at once, measured. That is
/// a broken build, not a killed mutant. Ruling P81: a mutation counts only if
/// it leaves the suite runnable and kills a proper subset.)
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
    // Reaches the handler, which rejects it: the exact status is this module's
    // to get right, so it is asserted exactly.
    let streamed = stream(
        SseHub::new(),
        "/api/sessions/not-a-uuid/events",
        None,
        |_| {},
    )
    .await;
    assert_eq!(
        streamed.status,
        StatusCode::BAD_REQUEST,
        "an unparsable session id must be refused by the handler"
    );

    // An empty segment never reaches the handler at all — `matchit` does not
    // match it, so the answer comes from the asset fallback. What this module
    // owes here is only that no stream opens; the status is another layer's
    // decision and asserting it would pin behaviour this file does not own.
    let streamed = stream(SseHub::new(), "/api/sessions//events", None, |_| {}).await;
    assert_ne!(
        streamed.status,
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
