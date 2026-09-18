//! The server→client SSE stream and the `Last-Event-ID` cursor it round-trips.
//!
//! §11.3 (`docs/architecture/08-ui-design.md:112-119`) mandates four things:
//! SSE server→client rather than WebSocket; SSE's `Last-Event-ID` carrying the
//! `(session_id, seq)` cursor already required for crash recovery; a replay of
//! history on reconnect; and `resync_required` when a client's cursor cannot
//! be honoured. Its own text describes a bounded in-memory ring as the replay
//! mechanism; **Decision 1 (Phase 8 Task 21, T5) amends that**: the store
//! itself now serves as the replay history, in place of the ring, since it
//! already keeps every committed event and a bounded second copy of the same
//! data bought nothing this route needed. `resync_required` survives, but
//! narrowed to the one case a store cannot answer by simply reading further
//! back: a cursor naming a seq the session has not produced yet.
//!
//! # The design, in one paragraph
//!
//! [`stream_session_events`] parses the path segment and the `Last-Event-ID`
//! header into a session id and an optional [`Cursor`] (400 on either being
//! unusable, or on the cursor naming a different session than the URL — both
//! unchanged from before this task). It then builds a
//! [`roundhouse_store::SessionFollower`] over [`crate::BoundedPageSource`] —
//! this crate's [`roundhouse_store::PageSource`] impl, permit-bounded the same
//! way every other `/api` handler's store reach is (see that type's own doc
//! comment) — starting from the cursor's seq, or from the beginning if there
//! was none. [`session_stream`] then drives the follower forever: catch up
//! from the store, then wait on its `CommitFeed` for the next commit, re-read,
//! repeat — until the client disconnects, the follower hits a store error, or
//! (the one case checked up front, before the follower is ever built) the
//! cursor is ahead of the session's head.
//!
//! # What this module is *not*
//!
//! It is **not** a redaction boundary. [`encode`] serialises a
//! [`roundhouse_store::StoredEvent`]'s payload verbatim, with no filtering of
//! any kind — a secret that reaches the `events` table this way is a secret
//! this module streams to a browser. Per this task's own constraints, the
//! published payload is always the stored row, and the writer that appended
//! it is what owns redacting it before that append; this module reads back
//! only what already passed that gate.
//!
//! It is **not an authentication or authorization boundary either**, and the
//! two notes belong together because the second one decides how much the
//! first one costs. `stream_session_events` performs no authentication and no
//! authorization: it parses the path segment as a UUID, checks the cursor
//! names the same session, and starts following. **The session id in the URL
//! is a name, not a capability** — knowing one is sufficient to open its
//! stream, and [`parse_last_event_id`]'s own note already says the cursor
//! carries no authority. **`roundhouse-daemon`'s `main.rs` is the task that
//! binds a listener to this endpoint, and its decision is: none, on the
//! loopback bind.** Per §11.3, "loopback-only remains what you get with no
//! configuration" — the same posture [`crate::lan_auth`] documents for the
//! whole `/api` surface — so this endpoint is reachable, unauthenticated, by
//! every local uid, not only the peercred-checked uid the Unix socket admits.
//! See [`crate::lan_auth`]'s own module docs for the cost this now has, stated
//! there rather than assumed away: a caller who learns a session UUID is
//! replayed its whole committed history, not merely events from the moment it
//! connected — the store keeps everything, and nothing here bounds how far
//! back a reconnect may reach.
//!
//! # Open residual: this module's `400`s are the `/api` namespace's only
//! plain-text error bodies
//!
//! [`crate::api_error`] states that every error under `/api` is
//! `{"error": …}`, and every other route holds it. This one predates that
//! function, and its rejection paths — `stream_session_events`'s unparsable
//! path segment and its "names a different session" cursor, plus
//! `cursor_rejected` for every [`CursorError`] — still answer plain text, so a
//! client doing `res.json()` on a refused stream open gets a parse error where
//! a reason belongs. **Whoever next touches this module converts them**;
//! [`crate::api_error`] carries the site list and what the change costs.

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
use roundhouse_store::{PageSource, SessionFollower, StoredEvent};
use thiserror::Error;
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
///
/// # Residual: the UUID field is lenient about spelling
///
/// `Uuid::parse_str` also accepts the simple (32 bare hex digits) and braced
/// (`{...}`) forms, so `{<uuid>}:5` parses to the same cursor as `<uuid>:5`
/// even though [`format_event_id`] emits only the hyphenated form. (The URN
/// form is rejected, as a side effect of splitting on the first colon.) This is
/// a parsing leniency, not an authorisation surface — **the cursor carries no
/// authority today**; it is a resume point, checked against the session in the
/// URL. It is named rather than tightened because a tighter rule would benefit
/// nobody at this stage. **If a later task ever makes the cursor
/// authenticated** — signed, or trusted to name a session the caller may read —
/// multiple spellings of one id become a canonicalisation bug, and this is the
/// line to change.
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
/// Returns `Response` rather than `Sse<_>` because several rejection paths
/// (an unparsable path segment, an unusable cursor, no store attached) are
/// plain HTTP responses, and a handler that can only return an `Sse` has
/// nowhere to put them. Rejecting is the point: a stream opened from the
/// wrong resume point looks identical to a working one.
async fn stream_session_events(
    State(state): State<crate::AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Ok(uuid) = Uuid::parse_str(&session_id) else {
        return (StatusCode::BAD_REQUEST, "session id is not a UUID\n").into_response();
    };
    let session_id = SessionId::from_uuid(uuid);

    let cursor: Option<Cursor> = match headers.get(LAST_EVENT_ID) {
        // No cursor: the client has seen nothing, so it gets everything from
        // seq 0 and there is nothing for it to be "ahead of the head" about.
        None => None,
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
            Some(cursor)
        }
    };

    let Some(store) = state.store.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            crate::api_error("no store is attached to this server"),
        )
            .into_response();
    };
    let source = crate::BoundedPageSource::new(store.clone(), state.api_pool_permits.clone());

    // The head is read only when there is a cursor to check it against: with
    // no `Last-Event-ID` there is no "ahead of the head" question to ask, and
    // skipping the read is one fewer permit taken on the common path.
    let start = match cursor {
        Some(cursor) => {
            let head = match source.head(session_id).await {
                Ok(head) => head,
                Err(_error) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        crate::api_error("this session's event stream failed to read the store"),
                    )
                        .into_response();
                }
            };
            if head.is_none_or(|head| cursor.seq > head) {
                StreamState::Resync {
                    resume_from: cursor.seq.saturating_add(1),
                    head,
                }
            } else {
                StreamState::Open(SessionFollower::new(
                    source,
                    store.commit_feed(),
                    session_id,
                    Some(cursor.seq),
                ))
            }
        }
        None => StreamState::Open(SessionFollower::new(
            source,
            store.commit_feed(),
            session_id,
            None,
        )),
    };

    Sse::new(session_stream(start))
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn cursor_rejected(error: CursorError) -> Response {
    (StatusCode::BAD_REQUEST, format!("{error}\n")).into_response()
}

/// One SSE connection's state machine: following the store, or already
/// decided on a terminal `resync_required`.
enum StreamState {
    Open(SessionFollower<crate::BoundedPageSource>),
    /// A tail miss found before the stream opened: one frame, then done.
    Resync {
        resume_from: u64,
        head: Option<u64>,
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
    start: StreamState,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    futures_util::stream::unfold(start, |state| async move {
        match state {
            StreamState::Done => None,
            StreamState::Resync { resume_from, head } => {
                Some((Ok(resync_required(resume_from, head)), StreamState::Done))
            }
            // Cancel-safe (`SessionFollower::next`'s own doc comment): losing
            // a race against a client disconnect at this `.await` neither
            // loses a committed event nor advances the follower's cursor past
            // one it never handed back.
            StreamState::Open(mut follower) => match follower.next().await {
                Ok(event) => Some(match encode(event) {
                    Encoded::Frame(frame) => (Ok(frame), StreamState::Open(follower)),
                    Encoded::Terminal(frame) => (Ok(frame), StreamState::Done),
                }),
                // The follower's own doc comment on `check_seq_follows_cursor`
                // is the one case besides a store I/O failure that reaches
                // here: a debug build would already have panicked on it, so
                // in a release build this is either a transient store fault
                // (pool exhaustion, a busy connection past its retry budget)
                // or a genuine gap in the event-sourcing invariant. Neither
                // detail is safe to hand a client — see `refusal_to_store_error`
                // in `bounded.rs` for why the crate's convention is silence
                // over detail here — so this ends the stream with the same
                // generic terminal frame a serialisation failure gets.
                Err(_error) => Some((
                    Ok(stream_error("this session's event stream failed")),
                    StreamState::Done,
                )),
            },
        }
    })
}

enum Encoded {
    Frame(Event),
    /// A frame after which the stream must stop.
    Terminal(Event),
}

/// One stored event as an SSE frame — or a terminal `stream_error` if it
/// cannot be one honestly.
///
/// Takes `event` by value: [`SessionFollower::next`] hands back an owned
/// [`StoredEvent`], and this is its only consumer, so there is nothing to
/// borrow it from. Unlike the pre-store-backed version of this module, there
/// is no cross-check that the payload's own session id agrees with the
/// routing key: `event.session_id` **is** what [`roundhouse_store::events_after`]
/// filtered `WHERE session_id = ?` on, so the two cannot disagree short of a
/// bug in that query.
fn encode(event: StoredEvent) -> Encoded {
    let cursor = Cursor {
        session_id: event.session_id,
        seq: event.seq,
    };
    // Decision 6: the SSE `data:` payload stays `ClientEvent::TaskEvent`, with
    // no `seq` of its own — the cursor already travels in the frame's `id:`
    // field — so the shipped frontend bundle needs no rebuild.
    let client_event = ClientEvent::TaskEvent {
        session_id: event.session_id,
        task_id: event.task_id,
        payload: Box::new(event.payload),
    };
    match serde_json::to_string(&client_event) {
        Ok(json) => Encoded::Frame(Event::default().id(format_event_id(&cursor)).data(json)),
        // No `ClientEvent` value is known to reach this arm, and no test
        // exercises it — every variant is plain data over `String`, `Bytes`
        // and enums. It exists because the alternatives are worse in a way
        // this module is specifically about: `unwrap` is a panic in a request
        // handler, and skipping the event is a silent gap. Ending the stream
        // with a named frame is the same answer a store failure gets.
        Err(error) => Encoded::Terminal(stream_error(&error.to_string())),
    }
}

/// A terminal frame saying the stream stopped because it could not emit the
/// event it was given.
///
/// Carries no `id:` — see [`resync_required`]'s note, which applies for the
/// same reason. `message` is placed inside a JSON string, so a newline in it
/// (a `serde_json` error message can contain one) is escaped rather than
/// terminating the frame early; `axum`'s `Event::data` would otherwise assert.
fn stream_error(message: &str) -> Event {
    Event::default()
        .event("stream_error")
        .data(serde_json::json!({ "error": message }).to_string())
}

/// §11.3's `resync_required`, narrowed by Decision 1 to the one condition a
/// store-backed replay cannot itself answer: **the client's cursor names a
/// seq the session has not produced yet** — `head` is `None` (no events at
/// all) or the cursor's seq is strictly greater than `head`. Checked once, in
/// [`stream_session_events`], before a [`SessionFollower`] is ever built; the
/// follower itself does not validate this (see its own doc comment).
///
/// Every other resync condition the pre-store version of this module had —
/// a subscriber lagging past a bounded ring, a gap opened while nobody was
/// watching — no longer exists: the store keeps every committed event
/// forever, so "behind" is answered by simply reading further back, and there
/// is no window in which an event exists but was not retained anywhere.
///
/// The payload keeps the wire shape the shipped frontend bundle already
/// validates (`resume_from`/`oldest_retained`, both numbers — see
/// `frontend/src/api.ts`'s `isResyncRequired`), so this still arrives as a
/// recognised `resync_required` rather than falling back to the generic
/// `stream_error` treatment. **`oldest_retained` carries a new meaning under
/// the new name**, since there is no ring to have a tail: it is the next seq
/// the store could actually serve if asked — `head + 1`, or `0` for a session
/// with no events at all. The frontend only checks that both fields are
/// numbers and renders the same terminal state either way (`SessionView.tsx`),
/// so this rename is invisible to it.
///
/// Carries no `id:`. A browser `EventSource` remembers the last id it saw and
/// replays it as `Last-Event-ID` on reconnect; an id here would be resumed
/// from as though it were a real event.
fn resync_required(resume_from: u64, head: Option<u64>) -> Event {
    Event::default().event("resync_required").data(
        serde_json::json!({
            "resume_from": resume_from,
            "oldest_retained": head.map_or(0, |head| head + 1),
        })
        .to_string(),
    )
}
