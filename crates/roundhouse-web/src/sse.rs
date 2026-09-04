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
//! It is also **not** a redaction boundary. `encode` serialises the
//! `ClientEvent` it is handed verbatim, with no filtering of any kind, so
//! Phase 2's `roundhouse-secrets` guarantee has to already hold **at the
//! publish site**: a secret that reaches [`SseHub::publish`] is a secret this
//! module streams to a browser. The writer named in residual 1 below owns that,
//! and this note is here so it is not discovered afterwards.
//!
//! # Residuals — named here, not solved here
//!
//! **1. Nothing publishes into the hub yet.** [`SseHub::publish`] has **no
//! caller in this workspace**. There is no pub/sub in `roundhouse-store`,
//! nothing in `roundhouse-daemon` links `roundhouse-web` yet, and no Subsystem
//! D task specifies the writer. Until one does, a real deployment's stream
//! would open, stay open, and emit nothing but keep-alive comments. The
//! endpoint is tested by publishing into the hub directly from
//! `tests/sse_cursor.rs`, which is exactly the seam a future writer fills —
//! but that is a test calling it, not the daemon.
//!
//! **2. The hub's memory cost is `capacity × event size`, not `capacity`.**
//! `tokio::sync::broadcast` frees a slot's value only once **every** subscriber
//! has consumed it, so one stalled client can hold up to
//! [`DEFAULT_BROADCAST_CAPACITY`] whole [`SessionUpdate`]s resident. That
//! matters because `EventPayload` has unbounded inline variants —
//! `TaskCompleted { output: TaskOutput::Text(String) }`,
//! `TaskOutput::Json(serde_json::Value)`, `Note { text }` — none of which this
//! module truncates. **A publisher of large task output should prefer
//! `TaskOutput::Blob`**, which is a `BlobRef` rather than the bytes. Neither
//! the per-update size nor the resident total has been measured here (P18);
//! what is stated is the multiplication, not a bound.
//!
//! **3. Three resume boundaries are indistinguishable from a working idle
//! stream.** All three open a `200` that emits only keep-alives: a cursor at
//! `u64::MAX` (nothing can follow it), a cursor *ahead* of anything the session
//! has produced, and a cursor for a session that has no events — or does not
//! exist. This endpoint cannot tell any of them from a live session that
//! happens to be quiet, because separating them needs a read of the store's
//! high-water seq, which this task does not do. **Owner: whichever Subsystem D
//! task gives this crate store access** — the same one that owns resync.
//!
//! **4. `roundhouse-store`'s `session_events` is unbounded** — `SELECT ...
//! ORDER BY seq ASC` with no `WHERE seq > ?` and no `LIMIT`. A
//! resume-from-cursor that reads history out of the store (rather than off the
//! live broadcast, as this endpoint does) needs a new accessor or a
//! read-then-filter over the whole log. This endpoint does not read the store
//! at all; recorded for the task that does.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

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

/// Fan-out buffer capacity, **per session**, for [`SseHub::new`].
///
/// Each session gets its own `tokio::sync::broadcast` channel of this size, so
/// this number matches §11.3's per-session ring of 4096 events: a stream
/// following one session is limited by the same figure the design already
/// names, and a busy session cannot consume an idle one's slots.
///
/// It is still **not** that ring. It holds no history a new subscriber can
/// read — matching the size is about not being the tighter of the two limits,
/// not about being the same mechanism.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 4096;

/// The channels, one per session with at least one live subscriber.
type Senders = HashMap<SessionId, broadcast::Sender<SessionUpdate>>;

/// Fan-out of appended events to open SSE connections, **keyed by session**.
///
/// Cloning gives another handle to the same map, so every request handler — and
/// the publisher residual 1 calls for, once it exists — shares one hub. The map
/// is owned by the hub: dropping the last handle drops every sender with it,
/// which is what ends the streams reading from them.
///
/// # Why per session, rather than one channel filtered per connection
///
/// A single process-global channel makes every session's traffic pass through
/// every connection's receiver slot, and two things follow that a filter
/// cannot undo, because by the time the filter runs the damage is done:
///
/// - **Availability coupling.** A burst on session B pushes an *idle* session
///   A's subscriber past the buffer, so A's stream ends in `resync_required`
///   having produced no events of its own. With several tabs open, one busy
///   session resyncs all of them at once.
/// - **A cross-session side channel.** `RecvError::Lagged(n)` counts the
///   messages *this receiver* skipped **across all sessions**, and
///   `resync_required` reports that count to the client — so a client watching
///   one session could infer the traffic volume of others.
///
/// Keying the map by session makes cross-session delivery structurally
/// impossible rather than one `==` away, gives each session its own capacity,
/// and makes the lag count honest: it counts only this session's events.
///
/// An entry exists only while some subscriber holds it. [`SessionSubscription`]
/// removes its session's entry on drop once it is the last reader, so a client
/// requesting a stream for an arbitrary UUID leaves nothing behind.
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
#[derive(Clone, Debug)]
pub struct SseHub {
    capacity: usize,
    senders: Arc<Mutex<Senders>>,
}

impl SseHub {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_BROADCAST_CAPACITY)
    }

    /// # Panics
    ///
    /// If `capacity` is zero — the assertion is here, in a constructor called
    /// at start-up, rather than being left to `broadcast::channel`'s own
    /// assertion inside a lazily-created channel, where it would be a panic in
    /// a request handler. Capacity is rounded up to a power of two by `tokio`.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity > 0, "SseHub capacity must be greater than zero");
        Self {
            capacity,
            senders: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A poisoned lock is recovered from rather than propagated. The guarded
    /// value is a plain map of channel handles with no invariant a panic could
    /// break halfway, and the alternative — every later request panicking on a
    /// poisoned mutex — turns one unrelated panic into a permanent outage of
    /// the endpoint.
    fn lock_senders(&self) -> MutexGuard<'_, Senders> {
        self.senders.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes `update` to the open streams **for its own session**,
    /// returning how many received it. `update.session_id` is the sole routing
    /// authority; no other session's subscribers can be reached from here.
    ///
    /// **Zero is normal, not an error**: no browser has to be connected for the
    /// daemon to be appending events, and a session with no subscriber has no
    /// channel at all.
    pub fn publish(&self, update: SessionUpdate) -> usize {
        // The sender is cloned out and the lock released before sending, so no
        // other session's subscribe/unsubscribe waits on this send — and so the
        // dropped-value destructors a full ring runs do not run under the lock.
        let sender = self.lock_senders().get(&update.session_id).cloned();
        match sender {
            Some(tx) => tx.send(update).unwrap_or(0),
            None => 0,
        }
    }

    /// How many sessions currently have a channel — i.e. have at least one open
    /// stream.
    ///
    /// Public so that the map's cleanup is *observable* rather than merely
    /// asserted in a comment: without it, "the entry is removed when the last
    /// subscriber drops" is untestable from outside, and an endpoint reachable
    /// with an arbitrary UUID leaking one map entry per request is exactly the
    /// kind of growth that is easy to introduce and impossible to notice. It is
    /// also the natural gauge for a future `/metrics`.
    pub fn tracked_sessions(&self) -> usize {
        self.lock_senders().len()
    }

    /// A subscription seeing every update published for `session_id` **after**
    /// this call. Nothing earlier: this is a fan-out, not a replay log. Nothing
    /// from another session either: that is the map key, not a filter.
    pub fn subscribe(&self, session_id: SessionId) -> SessionSubscription {
        let rx = self
            .lock_senders()
            .entry(session_id)
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .subscribe();
        SessionSubscription {
            session_id,
            rx,
            senders: Arc::downgrade(&self.senders),
        }
    }
}

impl Default for SseHub {
    fn default() -> Self {
        Self::new()
    }
}

/// One connection's view of one session's updates, and the janitor for that
/// session's map entry.
///
/// The back-reference to the map is **weak**, deliberately. The map owns every
/// `Sender`, so a strong reference here would keep this session's sender alive
/// for as long as its own reader lives — and a `broadcast` channel signals
/// `Closed` only when its last *sender* drops. A subscription holding its own
/// sender alive can therefore never observe the close, and dropping every
/// [`SseHub`] handle would no longer end the streams reading from it. Weak
/// keeps the ownership one-directional: hub owns map owns senders; a
/// subscription that outlives the hub simply finds nothing to clean up.
#[derive(Debug)]
pub struct SessionSubscription {
    session_id: SessionId,
    rx: broadcast::Receiver<SessionUpdate>,
    senders: Weak<Mutex<Senders>>,
}

impl SessionSubscription {
    /// The next update for this session, or why there will not be one. See
    /// [`SseHub`] on `Lagged`.
    pub async fn recv(&mut self) -> Result<SessionUpdate, broadcast::error::RecvError> {
        self.rx.recv().await
    }
}

impl Drop for SessionSubscription {
    /// Removes the session's channel once its last reader goes away, so the
    /// map does not accumulate an entry per session ever streamed — including
    /// the arbitrary UUIDs an unauthenticated client can ask for.
    ///
    /// `Drop::drop` runs **before** this struct's fields are dropped, so
    /// `self.rx` still counts itself: `<= 1` means "nobody but me". The check
    /// and the removal happen under the same guard `SseHub::subscribe` takes,
    /// so a subscription racing this one either increments the count before the
    /// check (and the entry stays) or creates a fresh entry after the removal.
    ///
    /// If the last [`SseHub`] handle is already gone the map is gone with it,
    /// there is nothing to prune, and the upgrade returning `None` is the
    /// normal shutdown path rather than an error.
    fn drop(&mut self) {
        let Some(senders) = self.senders.upgrade() else {
            return;
        };
        let mut senders = senders.lock().unwrap_or_else(PoisonError::into_inner);
        if let Entry::Occupied(entry) = senders.entry(self.session_id) {
            if entry.get().receiver_count() <= 1 {
                entry.remove();
            }
        }
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
        state.sse.subscribe(session_id),
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

/// Which updates one connection wants: from its resume point on.
///
/// The `session_id` check is **belt and braces, not the mechanism**. Routing is
/// [`SseHub`]'s map key, so a subscription for session A cannot be handed
/// session B's update in the first place; this check is what would catch a
/// future hub that reintroduced a shared channel, and it costs one comparison
/// per event. `resume_from` is the part that does real work here — it is
/// per-connection state the hub knows nothing about.
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
        rx: SessionSubscription,
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
///
/// The dependency is `futures-util`, not the `futures` facade that six other
/// crates in this workspace use — the only place in the workspace that departs
/// from that convention, so it is worth a sentence. `futures` is a re-export
/// shell over `futures-core`/`-util`/`-executor`/`-channel`/`-sink`/`-io`/
/// `-task`; this crate wants exactly one combinator (`unfold`) from one of
/// them. Both are already in `Cargo.lock` at 0.3.34 via `axum` and via those
/// six crates, so neither choice adds a package to the workspace — the
/// difference is what *this* crate's graph pulls in and compiles against.
/// Anything here that grows to need the facade's breadth should switch to it,
/// and say so.
fn session_stream(
    rx: SessionSubscription,
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

/// One update as an SSE frame — or a terminal `stream_error` if it cannot be
/// one honestly.
///
/// # The routing key must agree with the payload
///
/// [`SessionUpdate::session_id`] is the sole routing authority: it is
/// [`SseHub`]'s map key and it is what goes into the `id:` a client resumes
/// from. `ClientEvent::TaskEvent` carries a `session_id` of its **own**, and
/// nothing upstream forces the two to match. A future publisher that built the
/// wrapper from a subscription key or a loop variable rather than from the
/// payload would route one session's event into another session's stream *and*
/// label it with that stream's cursor — invisible to the client, which sees a
/// coherent frame, and invisible to the server, which sees a successful send.
///
/// So the disagreement is checked here, on the only path out, and answered the
/// way a serialisation failure is: a named terminal frame. It turns a silent
/// cross-session leak into a loud stream failure. The message names no session
/// id, because the client is not entitled to the one it was not supposed to
/// receive.
fn encode(update: &SessionUpdate) -> Encoded {
    if let ClientEvent::TaskEvent { session_id, .. } = &update.event {
        if *session_id != update.session_id {
            return Encoded::Terminal(stream_error(
                "event payload names a different session than the update carrying it",
            ));
        }
    }

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

/// §11.3's `resync_required`, emitted when this stream cannot produce the
/// events the client is missing. `dropped` counts **this session's** events
/// only, because the channel it was lost from carries only this session.
///
/// Carries no `id:`. A browser `EventSource` remembers the last id it saw and
/// replays it as `Last-Event-ID` on reconnect; an id here would be resumed from
/// as though it were a real event.
///
/// **The client must `close()` the `EventSource` on this frame.** A stock
/// `EventSource` reconnects on its own when the server ends the stream, and
/// because this module holds no history the reconnection resumes from the same
/// cursor, into the same gap — and gets **no** second `resync_required`, since
/// the fresh subscriber is not lagging. The signal is delivered exactly once;
/// a client that ignores it is quietly left with the gap this frame exists to
/// prevent. That is a client-side obligation this endpoint cannot enforce.
fn resync_required(dropped: u64) -> Event {
    Event::default()
        .event("resync_required")
        .data(serde_json::json!({ "dropped_events": dropped }).to_string())
}
