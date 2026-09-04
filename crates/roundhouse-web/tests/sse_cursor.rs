//! Task 31 (Phase 5, Subsystem D2): the SSE endpoint and the `Last-Event-ID`
//! <-> `(session_id, seq)` cursor mapping. Task 32 (D3) added §11.3's ring —
//! what the cursor is answered *with* — to the same file rather than a second
//! one, because the ring is inside the hub and every test of it is a test of
//! this endpoint: same harness, same router, same frames.
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
use roundhouse_web::lan_auth::BindConfig;
use roundhouse_web::sse::{
    format_event_id, parse_last_event_id, Cursor, Retention, SessionUpdate, SseHub,
};
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

/// A runaway-body valve for `to_bytes`, not an assertion: no test's meaning
/// depends on it, and every test that cares about how much was emitted asserts
/// on the frames instead.
///
/// It has to sit above the largest body any test here collects, which is
/// `the_default_retention_recovers_a_full_live_queue_of_realistic_events` —
/// 65 events of 4096 characters, **measured at ~280 KiB** of frames.
const MAX_COLLECTED_BODY: usize = 2 * 1024 * 1024;

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

    // Task 33 added the bind argument. Loopback: these are cursor tests, and
    // the loopback bind is the one that puts no gate in front of the stream.
    let response = build_router(AppState { sse: hub.clone() }, &BindConfig::loopback())
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
        axum::body::to_bytes(response.into_body(), MAX_COLLECTED_BODY),
    )
    .await
    .expect("the SSE stream must terminate once every sender is dropped")
    .expect("body fits in MAX_COLLECTED_BODY");

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

/// A gap the ring **cannot** cover is the one thing §11.3 answers with
/// `resync_required`, and this is the live-stream half of it: a subscriber
/// bumped out of the live queue whose missing events have also fallen off the
/// ring's tail. Continuing silently would hand the client a gap it has no way
/// to detect.
///
/// The retention here is the degenerate one the constructor still allows —
/// `live_queue == ring_events` — which gives a recovery band of exactly zero:
/// every value the queue drops is one the ring has already evicted. That is
/// what makes this the unrecoverable case rather than
/// `a_subscriber_bumped_out_of_the_live_queue_recovers_the_gap_from_the_ring`.
///
/// **Mutations killed:** (a) `Err(RecvError::Lagged(_)) => continue` — the
/// body then holds only the surviving frames and no `resync_required` at all;
/// (b) treating an exhausted ring as "no tail, nothing missed" and going live
/// — same silent gap.
#[tokio::test]
async fn a_lag_the_ring_cannot_cover_is_told_resync_required_rather_than_handed_a_silent_gap() {
    let hub = SseHub::with_retention(Retention {
        live_queue: 2,
        ring_events: 2,
        ..Retention::default()
    });
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
        "falling behind past the ring must terminate the stream with §11.3's resync signal; \
         body was:\n{}",
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
                .expect("the resync frame states what it could not deliver")
        )
        .expect("JSON"),
        // The client has seen nothing, so it still needs seq 0; the ring holds
        // only the last two of the five published, so its tail is seq 3.
        serde_json::json!({ "resume_from": 0, "oldest_retained": 3 }),
    );
    assert_eq!(
        frames.len(),
        1,
        "the resync frame is terminal: nothing is emitted after it. Body was:\n{}",
        streamed.body
    );
}

// ── §11.3's ring: replay on reconnect, resync only on a tail miss ─────────
//
// Task 32 (Phase 5, Subsystem D3). These four tests are the ones D2 could not
// write: they publish **before** the connection exists and assert on what the
// reconnecting client is handed. Each holds a second subscription (`_keeper`)
// for the same session, because a session's channel — and now its ring — lives
// exactly as long as its last subscriber. That is the eviction rule, not an
// accident of the harness; the residual it leaves is named in `sse.rs`.

/// The point of the whole task, and the thing the endpoint could not do
/// before it: a client that reconnects with a cursor still inside the ring is
/// **replayed the gap**, not merely joined to the live stream.
///
/// Nothing is published after the request here. Every frame in the body was
/// published before the connection existed, so a hub that only fans out live
/// updates produces an empty body.
///
/// **Mutations killed:** (a) dropping the replay and going straight live (the
/// D2 shape) — the body is empty; (b) replaying the whole ring instead of the
/// suffix from the cursor — `:0` and `:1` reappear, which is the duplicate
/// delivery the cursor exists to prevent; (c) replaying with the payloads
/// mismatched against their ids — the second assertion fails.
#[tokio::test]
async fn a_reconnecting_client_is_replayed_the_gap_the_ring_still_holds() {
    let hub = SseHub::new();
    let session = SessionId::new();
    // A second stream on the same session, holding the channel and its ring
    // open across the reconnect this test is about.
    let _keeper = hub.subscribe(session);

    for (seq, text) in [
        (0, "zeroth"),
        (1, "first"),
        (2, "second"),
        (3, "third"),
        (4, "fourth"),
    ] {
        publish(&hub, text_event(session, seq, text));
    }

    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 1,
    });
    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |_| {},
    )
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert_eq!(
        frame_ids(&streamed.body),
        vec![
            format!("{session}:2"),
            format!("{session}:3"),
            format!("{session}:4"),
        ],
        "the client has seq 0 and 1; the ring still holds 2, 3 and 4 and must replay exactly \
         those. Body was:\n{}",
        streamed.body
    );

    let expected: Vec<serde_json::Value> = [(2, "second"), (3, "third"), (4, "fourth")]
        .into_iter()
        .map(|(seq, text)| {
            serde_json::to_value(text_event(session, seq, text).event).expect("serializes")
        })
        .collect();
    assert_eq!(frame_payloads(&streamed.body), expected);
}

/// §11.3's own words: *"or if the cursor is older than the ring's tail, emits
/// `resync_required` and the client refetches a snapshot."* This is that
/// check, at reconnect time, which is the only place §11.3 describes it.
///
/// **Mutations killed:** (a) replaying whatever the ring happens to hold and
/// calling it the gap — the body becomes frames `:6`..`:9`, silently skipping
/// seq 1 through 5; (b) comparing the cursor against the ring's *newest* seq
/// rather than its oldest — every reconnect then resyncs, and
/// `a_reconnecting_client_is_replayed_the_gap_the_ring_still_holds` fails
/// alongside this one, which is how the pair pins the boundary from both
/// sides.
#[tokio::test]
async fn a_cursor_older_than_the_rings_tail_is_told_resync_required_rather_than_a_partial_replay() {
    let hub = SseHub::with_retention(Retention {
        live_queue: 1,
        ring_events: 4,
        ..Retention::default()
    });
    let session = SessionId::new();
    let _keeper = hub.subscribe(session);

    for seq in 0..10 {
        publish(&hub, text_event(session, seq, "delta"));
    }

    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 0,
    });
    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |_| {},
    )
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    let frames = parse_frames(&streamed.body);
    assert_eq!(
        frames.len(),
        1,
        "a tail miss is one terminal frame and nothing else; body was:\n{}",
        streamed.body
    );
    assert_eq!(frames[0].event.as_deref(), Some("resync_required"));
    assert_eq!(frames[0].id, None);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            frames[0].data.as_deref().expect("a stated payload")
        )
        .expect("JSON"),
        // The client holds seq 0, so it needs seq 1; the ring holds the last
        // four of the ten published, so its tail is seq 6.
        serde_json::json!({ "resume_from": 1, "oldest_retained": 6 }),
    );
}

/// A subscriber bumped out of the live queue is **recoverable**, not doomed.
///
/// D2 had to answer `Lagged` with a terminal `resync_required` because it held
/// no history. The ring is that history, so falling behind the live queue is
/// now a gap the server can fill — and `resync_required` goes back to naming
/// the single condition §11.3 names.
///
/// The five events are published while nothing polls the response body, so the
/// two-slot live queue is overrun by three; the sixteen-entry ring still holds
/// every one of them.
///
/// **Mutations killed:** (a) the D2 shape, `Lagged` => terminal
/// `resync_required` — the body becomes one resync frame and no events;
/// (b) recovering from the ring but not filtering what the live channel then
/// re-delivers — seq 3 and 4 are emitted twice, which the exact `frame_ids`
/// comparison catches.
#[tokio::test]
async fn a_subscriber_bumped_out_of_the_live_queue_recovers_the_gap_from_the_ring() {
    let hub = SseHub::with_retention(Retention {
        live_queue: 2,
        ring_events: 16,
        ..Retention::default()
    });
    let session = SessionId::new();

    let streamed = stream(hub, &events_uri(session), None, |hub| {
        for seq in 0..5 {
            publish(hub, text_event(session, seq, "delta"));
        }
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert!(
        parse_frames(&streamed.body)
            .iter()
            .all(|frame| frame.event.is_none()),
        "a gap the ring covers is not a resync; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        frame_ids(&streamed.body),
        (0..5)
            .map(|seq| format!("{session}:{seq}"))
            .collect::<Vec<_>>(),
        "every event the live queue dropped is still in the ring and must be delivered \
         exactly once. Body was:\n{}",
        streamed.body
    );
}

/// The ring is bounded by **bytes as well as entries**, because
/// `ring_events` alone bounds nothing that matters: `EventPayload` has
/// unbounded inline variants, so 4096 entries is 4096 x whatever the publisher
/// sent — and the endpoint that creates a session's ring takes an arbitrary
/// UUID with no authentication.
///
/// Both halves run the same three 4 KiB events past the same entry bound (64,
/// far more than three) and differ only in `ring_bytes`. Under the 1 KiB
/// budget each event on its own exceeds the whole budget, so the ring is left
/// holding exactly the newest one — never nothing, because an empty ring has
/// no tail to miss and would send the client live with a silent gap.
///
/// **Mutations killed:** (a) dropping the byte bound (or checking it before
/// the push instead of after) — the first half replays all three events
/// instead of resyncing; (b) evicting the newest rather than the oldest, or
/// evicting down to empty — the first half's `oldest_retained` is wrong, or
/// there is no resync frame at all; (c) applying the byte bound
/// unconditionally — the second half, which is the control, loses events it
/// has room for.
#[tokio::test]
async fn the_rings_byte_bound_evicts_where_its_entry_bound_would_not() {
    let big = "x".repeat(4096);
    let session = SessionId::new();
    let no_cursor: Option<&[u8]> = None;

    let hub = SseHub::with_retention(Retention {
        live_queue: 1,
        ring_events: 64,
        ring_bytes: 1024,
    });
    let _keeper = hub.subscribe(session);
    for seq in 0..3 {
        publish(&hub, text_event(session, seq, &big));
    }
    let streamed = stream(hub, &events_uri(session), no_cursor, |_| {}).await;

    let frames = parse_frames(&streamed.body);
    assert_eq!(
        frames.len(),
        1,
        "three events of 4 KiB do not fit a 1 KiB ring; body was {} bytes",
        streamed.body.len()
    );
    assert_eq!(frames[0].event.as_deref(), Some("resync_required"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            frames[0].data.as_deref().expect("a stated payload")
        )
        .expect("JSON"),
        // Each event alone is over budget, so the ring retains the newest and
        // nothing else — rather than nothing at all, which would have no tail
        // to miss.
        serde_json::json!({ "resume_from": 0, "oldest_retained": 2 }),
    );

    // The control: the same events, the same entry bound, a byte budget that
    // fits them. Without this, "always resync" would pass the half above.
    let hub = SseHub::with_retention(Retention {
        live_queue: 1,
        ring_events: 64,
        ring_bytes: 1024 * 1024,
    });
    let _keeper = hub.subscribe(session);
    for seq in 0..3 {
        publish(&hub, text_event(session, seq, &big));
    }
    let streamed = stream(hub, &events_uri(session), no_cursor, |_| {}).await;

    assert_eq!(
        frame_ids(&streamed.body),
        (0..3)
            .map(|seq| format!("{session}:{seq}"))
            .collect::<Vec<_>>(),
        "12 KiB of events fit a 1 MiB ring and must all be replayed"
    );
}

/// A gap that opened while **nobody was subscribed** is signalled, not jumped.
///
/// This is the one case the ring cannot see. A session with no subscriber has
/// no entry, so `publish` is a no-op and retains nothing — there is no tail for
/// a cursor to be older than. `Ring::replay_since` therefore answers an empty
/// ring with "nothing missed", correctly, and the discontinuity is caught one
/// layer later: the first delivered event whose seq is past what this
/// connection still owes the client.
///
/// Without that check the client is handed a **silent gap**: status 200, no
/// `resync_required`, a body containing only seq 5, and a `Last-Event-ID` that
/// jumps `:1` -> `:5` with nothing in the protocol saying seq 2, 3 and 4 ever
/// existed.
///
/// **Mutations killed:** (a) removing the `update.seq > self.filter.resume_from`
/// arm from `Connection::deliver` — the body becomes a single ordinary frame
/// with `id: <session>:5` and no `event:` field, which is the silent jump
/// itself; (b) answering an empty ring with `resync_required` instead (rejected
/// as ruling P83's mutation M7) — that fires on a *first* connection to a fresh
/// entry too, and
/// `an_absent_last_event_id_streams_from_seq_zero_rather_than_treating_zero_as_a_sentinel`
/// fails alongside this one, which is how the pair pins "only a real
/// discontinuity resyncs".
#[tokio::test]
async fn a_gap_opened_while_nobody_was_subscribed_is_a_resync_rather_than_a_silent_jump() {
    let hub = SseHub::new();
    let session = SessionId::new();

    // The first tab sees seq 0 and 1, then closes. Being the session's last
    // subscriber, it takes the entry — channel and ring — with it.
    {
        let _tab = hub.subscribe(session);
        for (seq, text) in [(0, "zeroth"), (1, "first")] {
            publish(&hub, text_event(session, seq, text));
        }
    }
    assert_eq!(
        hub.tracked_sessions(),
        0,
        "the closed tab was the last subscriber, so the ring went with it"
    );

    // The daemon keeps appending while no stream is open. With no entry there
    // is nothing to publish into: these reach nobody and are retained nowhere.
    for seq in 2..5 {
        assert_eq!(
            hub.publish(text_event(session, seq, "nobody was listening")),
            0,
            "a session with no subscriber has neither a channel nor a ring"
        );
    }

    // The tab reopens at the last cursor it actually saw, and the next event
    // the daemon appends arrives on the new stream.
    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 1,
    });
    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |hub| publish(hub, text_event(session, 5, "after the gap")),
    )
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    let frames = parse_frames(&streamed.body);
    assert_eq!(
        frames.len(),
        1,
        "the resync is terminal, and seq 5 is not delivered as though nothing were \
         missing; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        frames[0].event.as_deref(),
        Some("resync_required"),
        "seq 5 arriving where seq 2 was owed is a gap, not an ordinary frame; body was:\n{}",
        streamed.body
    );
    assert_eq!(frames[0].id, None);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            frames[0].data.as_deref().expect("a stated payload")
        )
        .expect("JSON"),
        // The client holds seq 1, so it still needs seq 2; the oldest the
        // server can offer is the seq 5 that just arrived.
        serde_json::json!({ "resume_from": 2, "oldest_retained": 5 }),
    );
}

/// A client that resynced and caught up is **not** resynced again, even though
/// its session's ring is empty.
///
/// The pair to the test above, and the reason the check is on a seq
/// discontinuity rather than on "the ring is empty". A client that took the
/// resync, refetched a snapshot through seq 25 and reconnected at `:25` is owed
/// seq 26 — so seq 26 arriving is continuity, not a gap, and it must be
/// delivered as an ordinary frame. Otherwise every recovered client resyncs
/// forever.
///
/// **Mutation killed:** answering an empty ring with `resync_required` (ruling
/// P83's M7) — the body becomes one `resync_required` frame instead of the two
/// ordinary frames asserted here.
#[tokio::test]
async fn a_client_that_reconnects_exactly_where_it_left_off_is_not_resynced_by_an_empty_ring() {
    let hub = SseHub::new();
    let session = SessionId::new();

    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: 25,
    });
    let streamed = stream(
        hub,
        &events_uri(session),
        Some(resume_from.as_bytes()),
        |hub| {
            for (seq, text) in [(26, "next"), (27, "and the one after")] {
                publish(hub, text_event(session, seq, text));
            }
        },
    )
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert!(
        parse_frames(&streamed.body)
            .iter()
            .all(|frame| frame.event.is_none()),
        "seq 26 is exactly what a client holding seq 25 is owed; body was:\n{}",
        streamed.body
    );
    assert_eq!(
        frame_ids(&streamed.body),
        vec![format!("{session}:26"), format!("{session}:27")],
    );
}

/// The recovery band has to hold **at the retention that actually ships**.
///
/// `live_queue <= ring_events` is asserted in `SseHub::with_retention`, but it
/// constrains only the entry dimension: `ring_bytes` can shrink the ring below
/// `live_queue` entries with nothing noticing. At the first defaults it did —
/// `1 MiB / 256` left 4 KiB per event against a 4305-byte measured one — so a
/// receiver bumped by a full live queue of realistic events could not be
/// recovered from the ring at all, and the whole recovery path was dead for
/// `SseHub::new()`.
///
/// So this test takes `Retention::default()` **verbatim** and derives its own
/// size from it: one more event than the live queue holds, which bumps the
/// receiver by construction, each carrying a 4096-character `Delta::Text` —
/// the same payload size `sse.rs`'s own byte-accounting unit test measures at
/// 4305 bytes retained. Every one of them must come back.
///
/// **Mutation killed:** `live_queue: 256` (the first default). `published`
/// becomes 257, the ring's byte bound evicts the oldest 14 entries at
/// 257 x 4305 = 1,106,385 bytes against a 1 MiB budget, and the body becomes a
/// single `resync_required` frame carrying
/// `{"resume_from": 0, "oldest_retained": 14}` instead of 65 event frames.
/// Measured, not reasoned. Nothing else in the suite changes, because every
/// other test that pins a lag boundary sets `live_queue` explicitly.
#[tokio::test]
async fn the_default_retention_recovers_a_full_live_queue_of_realistic_events() {
    let published = Retention::default().live_queue + 1;
    let realistic = "x".repeat(4096);
    let hub = SseHub::new();
    let session = SessionId::new();

    let streamed = stream(hub, &events_uri(session), None, |hub| {
        for seq in 0..published as u64 {
            publish(hub, text_event(session, seq, &realistic));
        }
    })
    .await;

    assert_eq!(streamed.status, StatusCode::OK);
    assert!(
        parse_frames(&streamed.body)
            .iter()
            .all(|frame| frame.event.is_none()),
        "the shipped hub must recover its own live queue from its own ring; \
         body was {} bytes and began:\n{}",
        streamed.body.len(),
        &streamed.body[..streamed.body.len().min(512)],
    );
    assert_eq!(
        frame_ids(&streamed.body),
        (0..published as u64)
            .map(|seq| format!("{session}:{seq}"))
            .collect::<Vec<_>>(),
        "every event the default live queue dropped must still be in the default ring"
    );
}

/// The reason the hub is keyed by session rather than filtered per connection.
///
/// A burst on one session must not cost an **idle** session its stream. Under a
/// single process-global channel, every session's traffic passes through every
/// connection's receiver slot, so this session — which has produced one event —
/// would be pushed past the buffer by another session's five, and would then
/// have to recover a gap it did not cause from a ring another session's traffic
/// also occupies.
///
/// **Mutation killed:** replacing the per-session map with one shared entry —
/// one `broadcast::Sender` *and one ring* — for every session (the pre-fix
/// shape), whether or not `Filter`'s session check is kept.
///
/// **What kills it is the `receiver_counts` assertion, and only that one.**
/// Measured under the filter-kept half of that mutation: the sole failure is
/// `receiver_counts` at `[1, 1, 1, 1, 1, 1]` against `[0, 0, 0, 0, 0, 1]` —
/// every publish reached this stream, which is the coupling itself. Both body
/// assertions **pass**: the body is exactly `["<mine>:0"]` with no
/// `resync_required` frame. (The explanation, which is a reading of the code
/// rather than a second measurement: the burst does still bump this connection
/// out of the shared live queue, but the now-shared *ring* covers the lag and
/// `Filter` discards the five replayed updates that name another session.)
///
/// (D2's version of this comment said the body became a single
/// `resync_required` frame carrying a `dropped_events` count of another
/// session's traffic. That was true before the ring and is not true now: the
/// ring recovers the lag, and no count is reported at all.)
///
/// The counts are still collected during the publish and asserted **after** the
/// body rather than inline, because an inline assertion would abort at the
/// first flood publish and the body assertions would never run — they are what
/// shows *how* the mutation manifests, even though they no longer fail.
#[tokio::test]
async fn a_burst_on_another_session_does_not_lag_this_sessions_stream() {
    // Two slots, so five events on the other session would overrun a shared
    // buffer several times over.
    let hub = SseHub::with_retention(Retention {
        live_queue: 2,
        ..Retention::default()
    });
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
