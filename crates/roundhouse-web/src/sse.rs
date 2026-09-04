//! The server→client SSE stream and the `Last-Event-ID` cursor it round-trips.
//!
//! §11.3 (`docs/architecture/08-ui-design.md:112-119`) mandates four things,
//! and it is worth separating them from what this module *decides*, because
//! only the first list is frozen design:
//!
//! **Mandated by §11.3:** SSE server→client rather than WebSocket; SSE's
//! `Last-Event-ID` carrying the `(session_id, seq)` cursor already required
//! for crash recovery; a ring buffer of the last 4096 events **per session in
//! the daemon**, replayed on reconnect; and `resync_required` when the
//! client's cursor is older than the ring's tail.
//!
//! **Decided here, not quoted from anywhere** (§11.3 prescribes no encoding
//! and no URL):
//!
//! 1. **The wire format is `"<session-uuid>:<decimal-seq>"`.** One opaque
//!    string, so it survives a browser `EventSource`'s native reconnect with
//!    no client-side parsing. See [`format_event_id`].
//! 2. **The route is `GET /api/sessions/{session_id}/events`.** §11.1's route
//!    table covers the browser's client-side views only; no document names an
//!    API path. `/api` is where [`crate::build_router`] nests it, ahead of the
//!    asset fallback.
//! 3. **`Last-Event-ID` names the last event the client *received*, so the
//!    stream resumes at `seq + 1`.** `roundhouse-store` allocates the first
//!    seq of a session as `COALESCE(MAX(seq), -1) + 1` (`writer.rs:171`) —
//!    **seq 0 is a real event**, so "0 means no cursor" would be a bug. An
//!    absent header resumes from 0; a present one resumes strictly after it.
//! 4. **A malformed or foreign cursor is a `400`, never a silent restart.**
//!    Streaming from the beginning would replay events the client already
//!    holds, which is the failure the cursor exists to prevent.
//!
//! # What this module is *not*
//!
//! It is **not** §11.3's ring buffer. [`SseHub`] is a `tokio::sync::broadcast`
//! fan-out: a subscriber sees what is published after it subscribes and
//! nothing before, so a reconnecting client's gap is **not** replayed here.
//! The ring buffer, and replay from a cursor that predates the live stream,
//! belong to the Subsystem D task that owns resync. This module's obligation
//! is narrower and it meets it: it never hands a client a gap it cannot see.
//! See [`SseHub`] on lag handling.
//!
//! # Residual: nothing publishes into the hub yet
//!
//! [`SseHub::publish`] has **no caller in this workspace**. There is no
//! pub/sub in `roundhouse-store`, nothing in `roundhouse-daemon` links
//! `roundhouse-web` yet, and no Subsystem D task specifies the writer. Until
//! one does, a real deployment's stream would open, stay open, and emit
//! nothing but keep-alive comments. The endpoint is tested by publishing into
//! the hub directly from `tests/sse_cursor.rs`, which is exactly the seam a
//! future writer fills — but that is a test calling it, not the daemon.

use std::convert::Infallible;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::stream::Stream;
use roundhouse_core::SessionId;
use roundhouse_proto::ClientEvent;
use thiserror::Error;
use tokio::sync::broadcast;
use uuid::Uuid;

/// The `(session_id, seq)` pair §11.3 requires `Last-Event-ID` to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    pub session_id: SessionId,
    pub seq: u64,
}

/// Why a `Last-Event-ID` was refused.
///
/// Each `Display` string is a fixed sentence with **no interpolation of the
/// offending header**. `Last-Event-ID` is client-controlled, these strings go
/// into a response body, and echoing untrusted input back is a habit worth not
/// having even where (as here, `text/plain`) it is inert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CursorError {
    /// The header held bytes outside visible ASCII. Not produced by
    /// [`parse_last_event_id`], which takes a `&str`; produced by the handler,
    /// which gets a `HeaderValue` and must decode it first.
    #[error("Last-Event-ID must be visible ASCII")]
    NotAsciiText,
    #[error("Last-Event-ID must be '<session-uuid>:<seq>'")]
    NotTwoFields,
    #[error("Last-Event-ID's session id is not a UUID")]
    SessionIdNotAUuid,
    #[error("Last-Event-ID's seq is not a decimal u64")]
    SeqNotADecimalU64,
}

/// Formats a cursor as the `id:` field of an SSE frame.
///
/// The encoding — session UUID, `:`, decimal seq — is this module's decision;
/// see the module docs. It is generated from the server's own `(SessionId,
/// u64)` and therefore contains only hex digits, hyphens, one colon and
/// decimal digits. That matters: `axum`'s `Event::id` **panics** if the value
/// contains a NUL, and `Event`'s field writer panics on `\r` or `\n`. Nothing
/// in this module puts a client-supplied string into an `Event`.
pub fn format_event_id(cursor: &Cursor) -> String {
    format!("{}:{}", cursor.session_id, cursor.seq)
}

/// Parses a `Last-Event-ID` header value back into a [`Cursor`].
///
/// Splits on the **first** colon, not the last. `Uuid::parse_str` accepts the
/// URN form `urn:uuid:<hex>`, which contains colons; splitting from the right
/// would let `urn:uuid:<hex>:7` through as a second spelling of the same
/// cursor. Splitting from the left gives `("urn", "uuid:<hex>:7")`, whose seq
/// field is not a decimal integer, so it is rejected.
///
/// The seq field is required to be **bare ASCII digits**. `u64::from_str`
/// accepts a leading `+`, which would make `<uuid>:+7` a second spelling of
/// `<uuid>:7`; one encoding in, one encoding out.
///
/// `SessionId` has no `FromStr` — Phase 0's private `newtype_id!` macro
/// generates only `new`/`from_uuid`/`as_uuid`/`Display`/`Default` — so the
/// `Uuid` is parsed directly and handed to `SessionId::from_uuid`.
pub fn parse_last_event_id(header: &str) -> Result<Cursor, CursorError> {
    let (session_part, seq_part) = header.split_once(':').ok_or(CursorError::NotTwoFields)?;

    let session_id = SessionId::from_uuid(
        Uuid::parse_str(session_part).map_err(|_| CursorError::SessionIdNotAUuid)?,
    );

    if seq_part.is_empty() || !seq_part.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CursorError::SeqNotADecimalU64);
    }
    let seq: u64 = seq_part
        .parse()
        .map_err(|_| CursorError::SeqNotADecimalU64)?;

    Ok(Cursor { session_id, seq })
}

/// One appended event, addressed by the cursor a client resumes from.
///
/// The payload is a `roundhouse_proto::ClientEvent` — the same wire type the
/// TUI receives over the Unix socket, so §11.3's "one resync contract, two
/// transports" is one type rather than two shapes to keep in step.
/// `ClientEvent` has no `seq` field of its own, so the cursor travels beside
/// it here and in the SSE `id:` field rather than inside the payload.
#[derive(Debug, Clone)]
pub struct SessionUpdate {
    pub session_id: SessionId,
    pub seq: u64,
    pub event: ClientEvent,
}

/// Fan-out buffer capacity for [`SseHub::new`].
///
/// Matched to §11.3's per-session ring size so that, for a stream following a
/// single session, this buffer is not the tighter of the two limits. It is
/// **not** that ring: it holds no history a new subscriber can read, and it is
/// shared across every session and every connection, so concurrently active
/// sessions share these slots rather than getting 4096 each.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 4096;

/// Process-wide fan-out of appended events to every open SSE connection.
///
/// Cloning gives another handle to the same channel. The channel closes when
/// the last handle is dropped, which ends every stream reading from it.
///
/// # Falling behind is not silent
///
/// A `tokio::sync::broadcast` receiver that falls further behind than the
/// buffer gets `RecvError::Lagged(n)` and then resumes from the oldest
/// retained value — the messages in between are gone. Continuing past that
/// would hand the client a gap with no marker in the stream, which is the
/// opposite of §11.3's contract. So this module answers `Lagged` the way
/// §11.3 answers a cursor older than the ring's tail: it emits a terminal
/// `resync_required` frame naming how many events were dropped, and ends the
/// stream. The client refetches a snapshot rather than reconnecting from a
/// cursor whose successor no longer exists.
///
/// The `resync_required` frame deliberately carries **no `id:`**. A browser
/// `EventSource` remembers the last id it saw and replays it on reconnect; an
/// id here would be resumed from as though it were a real event.
#[derive(Clone, Debug)]
pub struct SseHub {
    tx: broadcast::Sender<SessionUpdate>,
}

impl SseHub {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BROADCAST_CAPACITY)
    }

    /// Panics if `capacity` is zero (`tokio::sync::broadcast::channel`'s own
    /// assertion). Capacity is rounded up to a power of two by `tokio`.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Publishes `update` to every open stream, returning how many received
    /// it. **Zero is normal, not an error**: no browser has to be connected
    /// for the daemon to be appending events.
    pub fn publish(&self, update: SessionUpdate) -> usize {
        self.tx.send(update).unwrap_or(0)
    }

    /// A receiver seeing every update published **after** this call. Nothing
    /// earlier: this is a fan-out, not a replay log.
    pub fn subscribe(&self) -> broadcast::Receiver<SessionUpdate> {
        self.tx.subscribe()
    }
}

impl Default for SseHub {
    fn default() -> Self {
        Self::new()
    }
}

/// The `http` crate has no constant for this header. Written lowercase by
/// convention; `HeaderMap` lookup is case-insensitive, which
/// `tests/sse_cursor.rs` exercises by sending the mixed-case spelling a
/// browser sends.
const LAST_EVENT_ID: &str = "last-event-id";

/// The SSE routes, to be nested under `/api` by [`crate::build_router`].
pub fn router() -> Router<crate::AppState> {
    Router::new().route("/sessions/{session_id}/events", get(stream_session_events))
}

/// `GET /api/sessions/{session_id}/events` — one session's event stream,
/// resumed from the `Last-Event-ID` header when the client sends one.
///
/// Returns `Response` rather than `Sse<_>` because the two rejection paths
/// (an unparsable path segment, an unusable cursor) are `400`s, and a handler
/// that can only return an `Sse` has nowhere to put them. Rejecting is the
/// point: a stream opened from the wrong resume point looks identical to a
/// working one.
async fn stream_session_events(
    State(state): State<crate::AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(uuid) = Uuid::parse_str(&session_id) else {
        return (StatusCode::BAD_REQUEST, "session id is not a UUID\n").into_response();
    };
    let session_id = SessionId::from_uuid(uuid);

    let resume_from = match headers.get(LAST_EVENT_ID) {
        // No cursor: the client has seen nothing, so it gets everything from
        // seq 0. Not "from the next event published" and not "from seq 1".
        None => 0,
        Some(raw) => {
            // A header carrying bytes outside visible ASCII cannot be one of
            // our own ids, which are hex, hyphens, a colon and digits.
            let Ok(raw) = raw.to_str() else {
                return cursor_rejected(CursorError::NotAsciiText);
            };
            let cursor = match parse_last_event_id(raw) {
                Ok(cursor) => cursor,
                Err(error) => return cursor_rejected(error),
            };
            if cursor.session_id != session_id {
                return (
                    StatusCode::BAD_REQUEST,
                    "Last-Event-ID names a different session than the URL\n",
                )
                    .into_response();
            }
            // At `u64::MAX` this re-delivers that one event instead of
            // advancing. `seq` is allocated into a SQLite `INTEGER` (i64), so
            // it cannot reach `u64::MAX`; the saturating form is here so the
            // arithmetic has no panicking edge at all rather than because the
            // edge is reachable.
            cursor.seq.saturating_add(1)
        }
    };

    Sse::new(session_stream(
        state.sse.subscribe(),
        Filter {
            session_id,
            resume_from,
        },
    ))
    .keep_alive(KeepAlive::default())
    .into_response()
}

fn cursor_rejected(error: CursorError) -> Response {
    (StatusCode::BAD_REQUEST, format!("{error}\n")).into_response()
}

/// Which updates one connection wants: its session, from its resume point on.
#[derive(Debug, Clone, Copy)]
struct Filter {
    session_id: SessionId,
    resume_from: u64,
}

impl Filter {
    fn accepts(&self, update: &SessionUpdate) -> bool {
        update.session_id == self.session_id && update.seq >= self.resume_from
    }
}

enum StreamState {
    Live {
        rx: broadcast::Receiver<SessionUpdate>,
        filter: Filter,
    },
    Done,
}

/// The stream of SSE frames for one connection.
///
/// Built with `futures_util::stream::unfold` rather than a `stream!` macro:
/// this crate is `#![forbid(unsafe_code)]`, which cannot be overridden
/// locally, so a generator macro that expands `unsafe` into it is a hard
/// compile error rather than a lint to allow.
fn session_stream(
    rx: broadcast::Receiver<SessionUpdate>,
    filter: Filter,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    futures_util::stream::unfold(StreamState::Live { rx, filter }, |state| async move {
        match state {
            StreamState::Done => None,
            StreamState::Live { mut rx, filter } => loop {
                match rx.recv().await {
                    Ok(update) => {
                        if !filter.accepts(&update) {
                            continue;
                        }
                        return Some(match encode(&update) {
                            Encoded::Frame(event) => (Ok(event), StreamState::Live { rx, filter }),
                            Encoded::Terminal(event) => (Ok(event), StreamState::Done),
                        });
                    }
                    Err(broadcast::error::RecvError::Lagged(dropped)) => {
                        return Some((Ok(resync_required(dropped)), StreamState::Done));
                    }
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            },
        }
    })
}

enum Encoded {
    Frame(Event),
    /// A frame after which the stream must stop.
    Terminal(Event),
}

fn encode(update: &SessionUpdate) -> Encoded {
    let cursor = Cursor {
        session_id: update.session_id,
        seq: update.seq,
    };
    match serde_json::to_string(&update.event) {
        Ok(json) => Encoded::Frame(Event::default().id(format_event_id(&cursor)).data(json)),
        // No `ClientEvent` value is known to reach this arm, and no test
        // exercises it — every variant is plain data over `String`, `Bytes`
        // and enums. It exists because the alternatives are worse in a way
        // this task is specifically about: `unwrap` is a panic in a request
        // handler, and skipping the event is a silent gap. Ending the stream
        // with a named frame is the same answer lag gets, for the same
        // reason.
        Err(error) => Encoded::Terminal(
            Event::default()
                .event("stream_error")
                .data(serde_json::json!({ "error": error.to_string() }).to_string()),
        ),
    }
}

/// §11.3's `resync_required`, emitted when this stream cannot produce the
/// events the client is missing. Carries no `id:` — see [`SseHub`].
fn resync_required(dropped: u64) -> Event {
    Event::default()
        .event("resync_required")
        .data(serde_json::json!({ "dropped_events": dropped }).to_string())
}
