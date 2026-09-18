//! Phase 8 Task 21 (Task 5), Decision 1: the store-backed half of the SSE
//! endpoint — everything that needs a real `roundhouse_store::StorePool` and
//! a real writer, which `tests/sse_cursor.rs`'s request-shape checks do not.
//!
//! Every test here drives the real `axum::Router` through `build_router` +
//! `ServiceExt::oneshot`, against a real, on-disk `roundhouse_store::open`
//! database and a real `roundhouse_store::spawn_writer`, and asserts on the
//! frames the endpoint actually emitted — their `id:`, `event:` and `data:`
//! fields — never on the writer's own return values in isolation. Per this
//! lane's no-clock-timing-tests rule, ordering between "the request is open"
//! and "an event commits" is driven by `oneshot` returning (a real response,
//! headers already sent) before any event is appended, never by a `sleep`.
//! Every `tokio::time::timeout` used is a failure bound only — a hang becomes
//! a failed test, not the thing being asserted.

use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderValue, Request, StatusCode};
use futures_util::StreamExt;
use roundhouse_core::{EventPayload, NoteLevel, SessionId, TaskRunner, Timestamp};
use roundhouse_proto::ClientEvent;
use roundhouse_store::{open, spawn_writer, EventWriter, StorePool};
use roundhouse_web::lan_auth::BindConfig;
use roundhouse_web::sse::{format_event_id, Cursor};
use roundhouse_web::{build_router, AppState, BoundedStore};
use tower::ServiceExt;

/// `Event` (Phase 0, frozen) can only be minted via `TaskRunner`, and
/// `TaskRunner::bootstrap` panics if called twice in one process (S-LOG-1) —
/// so, like `roundhouse-store`'s own `tests/follow.rs`, this is one `Lazy`
/// shared by every test in this file rather than one per test.
static RUNNER: std::sync::LazyLock<TaskRunner> = std::sync::LazyLock::new(TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

async fn open_store(dir: &std::path::Path) -> StorePool {
    open(&dir.join("events.db")).await.expect("store opens")
}

/// Appends one `Note` event and returns its real, writer-assigned `seq` — the
/// `seq` argument on `record_note` is a placeholder `Event` requires but the
/// writer overwrites with `COALESCE(MAX(seq), -1) + 1` for the session.
async fn append_note(writer: &EventWriter, session_id: SessionId, text: &str) -> u64 {
    writer
        .append(RUNNER.record_note(
            session_id,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            text.to_owned(),
            1,
        ))
        .await
        .expect("append succeeds")
}

/// The `ClientEvent` a `data:` field must decode to for a `Note` appended by
/// [`append_note`] with the same `text` — built independently of the
/// production `encode` function, from the same `record_note` shape, so a test
/// comparing against it is comparing against the payload's own definition
/// rather than against whatever `encode` happens to produce.
fn expected_event(session_id: SessionId, text: &str) -> ClientEvent {
    ClientEvent::TaskEvent {
        session_id,
        task_id: None,
        payload: Box::new(EventPayload::Note {
            level: NoteLevel::Info,
            text: text.to_owned(),
        }),
    }
}

fn events_uri(session_id: SessionId) -> String {
    format!("/api/sessions/{session_id}/events")
}

fn sse_request(uri: &str, last_event_id: Option<&str>) -> Request<Body> {
    // Task 34's fix round added the rebinding check (ruling P93 §A): an `/api`
    // request that does not address the bind is `403` before it reaches any
    // handler, and an in-process `oneshot` sets no `Host` of its own. These
    // routers are loopback-bound, so this is the name they answer to.
    let mut builder = Request::builder().uri(uri).header("Host", "127.0.0.1");
    if let Some(id) = last_event_id {
        builder = builder.header(
            "Last-Event-ID",
            HeaderValue::from_str(id).expect("test cursor is a legal header value"),
        );
    }
    builder.body(Body::empty()).expect("request builds")
}

fn sse_state(store: &StorePool) -> AppState {
    AppState {
        store: Some(BoundedStore::new(store.clone())),
        ..AppState::default()
    }
}

async fn open_stream(
    store: &StorePool,
    uri: &str,
    last_event_id: Option<&str>,
) -> axum::response::Response {
    build_router(sse_state(store), &BindConfig::loopback())
        .oneshot(sse_request(uri, last_event_id))
        .await
        .expect("router is infallible")
}

// ── SSE frame parsing ────────────────────────────────────────────────────
//
// `axum` writes each field as `name: value\n` and terminates a frame with a
// blank line, so a frame is a `\n\n`-separated block.

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
/// text: `serde_json`'s object key order is not stable across the workspace,
/// so any assertion over `to_string()` output is a trap.
fn frame_payloads(body: &str) -> Vec<serde_json::Value> {
    parse_frames(body)
        .into_iter()
        .filter_map(|frame| frame.data)
        .map(|data| serde_json::from_str(&data).expect("each data: field is one JSON document"))
        .collect()
}

/// Reads chunks off an **open, potentially never-ending** stream until
/// `frames` complete `\n\n`-terminated blocks have arrived, then returns
/// without waiting for the stream to end — a `SessionFollower`-backed stream
/// only ends on client disconnect or a store error, so waiting for EOF here
/// would hang forever on the happy path. Bounded by a timeout that fails the
/// test rather than hanging it.
async fn read_frames(response: axum::response::Response, frames: usize) -> (StatusCode, String) {
    let status = response.status();
    let mut chunks = response.into_body().into_data_stream();
    let mut body = String::new();
    while body.matches("\n\n").count() < frames {
        let chunk = tokio::time::timeout(Duration::from_secs(10), chunks.next())
            .await
            .expect("the endpoint must emit the frames this connection waits for")
            .expect("the stream must not end before it has emitted them")
            .expect("body chunks are readable");
        body.push_str(std::str::from_utf8(&chunk).expect("SSE bodies are UTF-8"));
    }
    (status, body)
}

/// Reads a stream that is expected to end **on its own** — the terminal
/// `resync_required` path, which is the only case in this file where the
/// server closes the body rather than the client.
async fn read_to_end(response: axum::response::Response) -> (StatusCode, String) {
    let status = response.status();
    let body = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 1024 * 1024),
    )
    .await
    .expect("a terminal resync stream must end on its own")
    .expect("body readable");
    (
        status,
        String::from_utf8(body.to_vec()).expect("SSE bodies are UTF-8"),
    )
}

// ── the tests ────────────────────────────────────────────────────────────

/// The point of Decision 1: events committed **after** the stream opens are
/// caught by the follower's `CommitFeed` wake and streamed with cursor ids
/// matching their real, store-assigned `seq` — with no ring, no hub, and no
/// publish call anywhere in the path.
#[tokio::test]
async fn sse_streams_committed_events_with_cursor_ids() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = open_store(dir.path()).await;
    let writer = spawn_writer(store.clone()).await;
    let session = SessionId::new();

    let response = open_stream(&store, &events_uri(session), None).await;
    assert_eq!(response.status(), StatusCode::OK);

    let seq0 = append_note(&writer, session, "zeroth").await;
    let seq1 = append_note(&writer, session, "first").await;

    let (status, body) = read_frames(response, 2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        frame_ids(&body),
        vec![format!("{session}:{seq0}"), format!("{session}:{seq1}")],
    );
    assert_eq!(
        frame_payloads(&body),
        vec![
            serde_json::to_value(expected_event(session, "zeroth")).expect("serializes"),
            serde_json::to_value(expected_event(session, "first")).expect("serializes"),
        ],
    );
}

/// `Last-Event-ID` names the last event the client **received**, so the
/// stream resumes strictly after it — the client-visible contract Decision 1
/// keeps unchanged even though the mechanism underneath (a store catch-up
/// rather than a ring replay) is new.
#[tokio::test]
async fn last_event_id_resumes_at_seq_plus_one() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = open_store(dir.path()).await;
    let writer = spawn_writer(store.clone()).await;
    let session = SessionId::new();

    let mut seqs = Vec::new();
    for text in ["zeroth", "first", "second", "third"] {
        seqs.push(append_note(&writer, session, text).await);
    }

    let resume_from = format_event_id(&Cursor {
        session_id: session,
        seq: seqs[1],
    });
    let response = open_stream(&store, &events_uri(session), Some(&resume_from)).await;

    let (status, body) = read_frames(response, 2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        frame_ids(&body),
        vec![
            format!("{session}:{}", seqs[2]),
            format!("{session}:{}", seqs[3]),
        ],
        "the client already has seq {} and {}; the stream resumes after it",
        seqs[0],
        seqs[1],
    );
    assert_eq!(
        frame_payloads(&body),
        vec![
            serde_json::to_value(expected_event(session, "second")).expect("serializes"),
            serde_json::to_value(expected_event(session, "third")).expect("serializes"),
        ],
    );
}

/// Old residual 5 (`sse.rs`'s pre-Task-21 module docs): the in-memory ring
/// only retained history for a session that was **already being watched**, so
/// events committed while nobody had a stream open were replayed to nobody
/// and lost from the ring forever. The store has no such window: it keeps
/// every committed event whether or not a stream was ever open, so a client
/// that connects for the first time long after the fact is still replayed
/// everything from its cursor.
///
/// RED-verified (see the task report): starting the follower at the current
/// head instead of at the requested cursor turns this into the exact old
/// failure — the body comes back empty instead of holding all three events —
/// while `sse_streams_committed_events_with_cursor_ids` above still passes,
/// since it never has any events committed before it connects.
#[tokio::test]
async fn events_committed_while_nobody_watched_are_replayed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = open_store(dir.path()).await;
    let writer = spawn_writer(store.clone()).await;
    let session = SessionId::new();

    // Committed with no stream open at all — there is no hub, so there is no
    // entry for this session to have been retained in even in principle.
    let mut seqs = Vec::new();
    for text in ["zeroth", "first", "second"] {
        seqs.push(append_note(&writer, session, text).await);
    }

    let response = open_stream(&store, &events_uri(session), None).await;
    let (status, body) = read_frames(response, 3).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        frame_ids(&body),
        seqs.iter()
            .map(|seq| format!("{session}:{seq}"))
            .collect::<Vec<_>>(),
        "every event committed before the connection existed must still be replayed; body \
         was:\n{body}",
    );
}

/// §11.3's `resync_required`, narrowed by Decision 1 to the one case a store
/// cannot itself answer: the client's cursor names a seq the session has not
/// produced yet. Covers both shapes of "ahead of the head" the route checks:
/// a session with some history whose cursor overshoots it, and a session with
/// none at all.
#[tokio::test]
async fn cursor_ahead_of_head_gets_resync_required() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = open_store(dir.path()).await;
    let writer = spawn_writer(store.clone()).await;
    let session = SessionId::new();

    let seq0 = append_note(&writer, session, "zeroth").await;
    let seq1 = append_note(&writer, session, "first").await;
    assert_eq!(seq1, seq0 + 1, "seqs are dense per session");

    let ahead = format_event_id(&Cursor {
        session_id: session,
        seq: seq1 + 5,
    });
    let response = open_stream(&store, &events_uri(session), Some(&ahead)).await;
    let (status, body) = read_to_end(response).await;

    assert_eq!(status, StatusCode::OK);
    let frames = parse_frames(&body);
    assert_eq!(
        frames.len(),
        1,
        "a tail-miss resync is one terminal frame and nothing else; body was:\n{body}",
    );
    assert_eq!(frames[0].event.as_deref(), Some("resync_required"));
    assert_eq!(
        frames[0].id, None,
        "the resync frame carries no cursor: a browser would otherwise resume from it as \
         though it were a real event",
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            frames[0]
                .data
                .as_deref()
                .expect("the resync frame states what it could not deliver")
        )
        .expect("JSON"),
        serde_json::json!({ "resume_from": seq1 + 6, "oldest_retained": seq1 + 1 }),
    );

    // The other shape of "ahead of the head": a session with no events at all,
    // so `head` is `None` rather than merely smaller than the cursor.
    let empty_session = SessionId::new();
    let cursor = format_event_id(&Cursor {
        session_id: empty_session,
        seq: 0,
    });
    let response = open_stream(&store, &events_uri(empty_session), Some(&cursor)).await;
    let (status, body) = read_to_end(response).await;

    assert_eq!(status, StatusCode::OK);
    let frames = parse_frames(&body);
    assert_eq!(frames.len(), 1, "body was:\n{body}");
    assert_eq!(frames[0].event.as_deref(), Some("resync_required"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            frames[0]
                .data
                .as_deref()
                .expect("the resync frame states what it could not deliver")
        )
        .expect("JSON"),
        serde_json::json!({ "resume_from": 1, "oldest_retained": 0 }),
        "a session with no events has no head, so nothing has been retained yet",
    );
}
