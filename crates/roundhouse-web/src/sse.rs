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
//! # The ring, and the one thing `resync_required` means
//!
//! §11.3's ring buffer lives **inside** [`SseHub`], in the same per-session map
//! entry as that session's live fan-out channel — not beside it. That is what
//! lets the two compose rather than duplicate:
//!
//! - A reconnecting client's cursor is answered from the ring
//!   ([`SessionSubscription::replay_since`]): the gap is **replayed**, which is
//!   what §11.3 mandates and what a fan-out on its own cannot do.
//! - A subscriber bumped out of the live queue (`broadcast::RecvError::Lagged`)
//!   re-reads the same ring and carries on. Falling behind is recoverable, not
//!   terminal.
//! - **`resync_required` has exactly one producer**, the `resync_required`
//!   frame builder, emitted for exactly one condition — *the events the client
//!   still needs are older than the oldest the server can offer*. That is
//!   §11.3's *"the cursor is older than the ring's tail"* wherever the ring has
//!   a tail, and `Connection::deliver`'s seq discontinuity where it does not.
//!   One event name, one payload shape. D2 emitted it for `Lagged` as well,
//!   with a different payload, because it had no ring to recover from; it now
//!   has one.
//!
//! What the ring does **not** do is outlive its session's subscribers: the map
//! entry is pruned with the last one (residual 5). Which is why the third path
//! exists: a session that stopped being watched has an empty ring, so a gap
//! opened while nobody was subscribed has no tail to be older than, and is
//! caught at delivery instead.
//!
//! # What this module is *not*
//!
//! It is **not** a redaction boundary. `encode` serialises the
//! `ClientEvent` it is handed verbatim, with no filtering of any kind, so
//! Phase 2's `roundhouse-secrets` guarantee has to already hold **at the
//! publish site**: a secret that reaches [`SseHub::publish`] is a secret this
//! module streams to a browser. The writer named in residual 1 below owns that,
//! and this note is here so it is not discovered afterwards.
//!
//! It is **not an authentication or authorization boundary either**, and the
//! two notes belong together because the second one decides how much the first
//! one costs. `stream_session_events` performs no authentication and no
//! authorization: it parses the path segment as a UUID, checks the cursor names
//! the same session, and subscribes. **The session id in the URL is a name, not
//! a capability** — knowing one is sufficient to open its stream, and
//! [`parse_last_event_id`]'s own note already says the cursor carries no
//! authority. The task that binds a listener to this endpoint — the same one
//! residual 1 names — owns authn/authz, and until it exists this crate has no
//! caller identity to check anything against.
//!
//! **What the ring changes about that is the blast radius, not the defect.**
//! Before it, a caller who learned a session UUID received only events
//! published from that moment on. Now the same caller is replayed up to
//! [`Retention::ring_events`] entries / [`Retention::ring_bytes`] of that
//! session's **history** — which, since this module serialises verbatim, may
//! include anything unredacted the publish site let through. An unauthenticated
//! read yields history, not only future events. The mitigation that is actually
//! in place is narrow and worth stating exactly: history exists only while the
//! session is *already being watched* (residual 5), because a session with no
//! subscriber has no ring.
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
//! **2. The hub's memory cost is `entries × event size`, and only the ring's
//! share of it is bounded.** `EventPayload` has unbounded inline variants —
//! `TaskCompleted { output: TaskOutput::Text(String) }`,
//! `TaskOutput::Json(serde_json::Value)`, `Note { text }` — none of which this
//! module truncates, and the ring retains them **unconditionally from the first
//! publish**, where the live queue only retains while a subscriber is behind.
//! D3 narrows this rather than closing it. What it does: every update is shared
//! as one `Arc` between the ring and every live queue slot, so the fan-out is
//! reference counts rather than copies, and [`Retention::ring_bytes`] bounds
//! **the ring** by serialised bytes as well as entries (stated exactly on
//! `Ring::push`, including the one case that exceeds the budget by
//! construction). What it does **not** do: bound the broadcast, which retains
//! up to [`Retention::live_queue`] payloads for a stalled client outside that
//! accounting — so the per-session worst case is
//! `live_queue · E + max(ring_bytes, E)`, not `ring_bytes`.
//! [`Retention::ring_bytes`] carries the arithmetic and names the two things
//! that would close it: a maximum event size at the publish site (or a
//! publisher that uses `TaskOutput::Blob`, a `BlobRef` rather than the bytes),
//! and a refactor to a single retainer. Neither is done here, and real event
//! sizes remain unsampled (P18) — nothing publishes into the hub yet — so the
//! byte budget is a ceiling that was chosen, not one measured against a
//! workload.
//!
//! **3. Three resume boundaries are indistinguishable from a working idle
//! stream.** All three open a `200` that emits only keep-alives: a cursor at
//! `u64::MAX` (nothing can follow it), a cursor *ahead* of anything the session
//! has produced, and a cursor for a session that has no events — or does not
//! exist. D3 narrows this but does not close it: a cursor *behind* the ring's
//! tail is now a `resync_required` rather than a silent idle. A cursor ahead of
//! the ring is still indistinguishable from a quiet session, because separating
//! them needs a read of the store's high-water seq, which this crate cannot do.
//! **Owner: whichever Subsystem D task gives this crate store access.**
//!
//! **4. `roundhouse-store`'s `session_events` is unbounded** — `SELECT ...
//! ORDER BY seq ASC` with no `WHERE seq > ?` and no `LIMIT`. A
//! resume-from-cursor that reads history out of the store (rather than out of
//! the ring, as this endpoint does) needs a new accessor or a read-then-filter
//! over the whole log. This endpoint does not read the store at all; recorded
//! for the task that does.
//!
//! **The converse of residual 3 must be qualified, not carried forward.** D2
//! could say this endpoint was no existence oracle, because every outcome
//! looked like an idle stream. That is no longer true in one direction: a
//! `resync_required` at connect time tells an unauthenticated caller, in a
//! single request, that the named session **is being watched right now and has
//! produced at least `oldest_retained` events** — a live session distinguished
//! from "nothing here", plus a lower bound on its traffic. The frame's payload
//! is not the problem and is not changed: `{resume_from, oldest_retained}` is
//! exactly what a client needs, both numbers are this session's own, and the
//! alternative — a gap with no marker — is worse. It is the **authn gap named
//! above** that makes it a disclosure, and it is recorded here so the next
//! reader does not repeat D2's unqualified claim.
//!
//! **5. The ring lives exactly as long as its session's last subscriber.** The
//! map entry — channel and ring together — is created on the first subscribe
//! and pruned when the last subscription drops, because an endpoint reachable
//! with an arbitrary UUID and no authentication must not let a caller retain
//! bytes by naming sessions. So a client that reconnects *after* its own last
//! stream closed finds an empty ring and is taken live from its cursor.
//! **Nothing was buffered while nobody was subscribed** — [`SseHub::publish`]
//! with no entry is a no-op — so the ring is not losing history it held; what
//! it cannot do is replay events the daemon appended while no stream was open.
//! Serving those needs the store (residual 4), and the same task owns both.
//! Until then the honest boundary is: **the ring replays a gap in a session
//! that stayed watched, not a gap in one that did not.**
//!
//! What it does do for the unwatched case is **say so**. That gap has no tail
//! to be older than — the ring is empty — so `Ring::replay_since` cannot see
//! it; `Connection::deliver` catches it at the first event that skips past
//! what the client is owed, and answers with the same `resync_required`. The
//! client refetches a snapshot instead of silently jumping its `Last-Event-ID`
//! across the missing range.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::io::{self, Write};
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

/// How much one session's channel keeps, and for how long.
///
/// # Why one type rather than two constants
///
/// The live queue and the ring are two limits that **must move together**: a
/// live queue deeper than the ring makes a lagging subscriber unrecoverable by
/// construction, because every value the queue drops is one the ring has
/// already evicted. Two independent `pub const`s with nothing tying them are
/// the shape in which that relation gets broken silently, so the relation is
/// asserted where the numbers are chosen — see [`SseHub::with_retention`],
/// which is also where the half of it an assertion **cannot** reach is stated:
/// `ring_bytes` is a second way to shrink the ring below `live_queue`, and it
/// depends on an event size no constructor knows.
///
/// # Where §11.3's 4096 lives
///
/// **On the ring, not on the live queue.** D2 sized the broadcast channel at
/// 4096 to match §11.3's per-session ring *while explicitly stating it was not
/// that ring*. The ring now exists, so the figure moves to it and the live
/// queue shrinks to what it actually is: a hand-off buffer between the
/// publisher and one connection's task. Retaining 4096 in both would be 8192
/// retained references per session for one design requirement.
#[derive(Debug, Clone, Copy)]
pub struct Retention {
    /// `tokio::sync::broadcast` capacity, per session: how far a connection's
    /// task may fall behind the publisher before its receiver is bumped and
    /// the gap has to be recovered from the ring.
    ///
    /// **64, and this number is a policy choice rather than a measurement**
    /// (P18): no workload has been observed to establish how far a real
    /// subscriber falls behind. What is load-bearing is only that it is well
    /// below `ring_events` **and** that `ring_bytes / live_queue` leaves room
    /// for a realistic event, because that quotient — not `ring_events` — is
    /// what actually decides whether a bumped receiver can be recovered. See
    /// [`SseHub::with_retention`], where the relation is asserted as far as it
    /// can be. `tokio` rounds the capacity up to a power of two, so a power of
    /// two is what is written here.
    ///
    /// # Why 64 rather than 256
    ///
    /// 256 was the first choice, and it fails at this type's own defaults. The
    /// derived headroom was `1 MiB / 256 = 4 KiB per event`, and a 4096-char
    /// `Delta::Text` measures **4305 bytes** retained
    /// (`a_retained_updates_size_is_its_serialised_payload_plus_the_fixed_wrapper`)
    /// — over budget. A receiver that lagged by a full live queue of events
    /// that size could not be recovered from the ring at all: the byte bound
    /// had already evicted them. The recovery path this module is built around
    /// was dead for the shipped hub, which
    /// `the_default_retention_recovers_a_full_live_queue_of_realistic_events`
    /// now pins.
    ///
    /// 64 puts the headroom at **16 KiB per event**, ~3.8x the measured 4305.
    ///
    /// **The same change bounds something else**, which is why it is one
    /// constant and not two: a `tokio::sync::broadcast` slot holds its value
    /// until every receiver live at send time consumes it, so a stalled client
    /// retains up to `live_queue` payloads outside the ring's accounting. That
    /// worst case falls from `256·E` to `64·E`. The recovery band and the
    /// broadcast's retention are two views of this number; see
    /// [`Retention::ring_bytes`] for the whole memory picture.
    pub live_queue: usize,
    /// §11.3's "ring buffer of the last 4096 events per session", in entries.
    pub ring_events: usize,
    /// The ring's **second** bound, in bytes of serialised payload.
    ///
    /// `ring_events` alone bounds the entry count, not the memory:
    /// `EventPayload` has unbounded inline variants (`TaskOutput::Text`,
    /// `TaskOutput::Json`, `Note { text }`), so 4096 entries is 4096 x
    /// *whatever the publisher sent*. A single 4 MiB `TaskOutput::Json` at
    /// 4096 entries is ~16 GiB per session, and the endpoint that creates a
    /// session's entry takes an arbitrary UUID with no authentication.
    ///
    /// **1 MiB, also a policy ceiling rather than a measurement** (P18): it is
    /// 256 bytes per entry at §11.3's full 4096. Real event sizes in this
    /// workspace have not been sampled — nothing publishes into the hub yet
    /// (residual 1) — so there is nothing to sample.
    ///
    /// The bound is enforced **after** the push, and never leaves the ring
    /// empty (see `Ring::push`). The consequence is deliberate and worth
    /// naming — a session whose events are large keeps **fewer** than
    /// `ring_events`, so a reconnecting client is more likely to be told
    /// `resync_required`. That is §11.3's own answer to a tail miss, and it is
    /// a visible signal rather than a silent gap.
    ///
    /// # What this bound does **not** cover
    ///
    /// It bounds **the ring**, not the session. Every update is one `Arc`
    /// shared between the ring and every live queue slot, which makes the
    /// fan-out reference counts rather than copies — but sharing means the
    /// ceiling is set by the **larger** retainer, and only one of the two is
    /// byte-bounded. `tokio::sync::broadcast` holds a slot's value until every
    /// receiver live at send time has consumed it, so a stalled client keeps up
    /// to [`Retention::live_queue`] payloads alive, and the ring's byte
    /// eviction can drop those same entries while the broadcast still holds
    /// them — putting them outside this figure's accounting entirely.
    ///
    /// So, per session, with `E` the largest published event:
    ///
    /// ```text
    /// worst case  ~=  live_queue * E  +  max(ring_bytes, E)
    /// ```
    ///
    /// At the defaults that is `64 * E + max(1 MiB, E)`. It reduces to
    /// "~1 MiB per session" only while `E <= ring_bytes / live_queue`, which at
    /// the defaults is 16 KiB — chosen against a measured 4305-byte event
    /// (see [`Retention::live_queue`]), and **not** a bound anything enforces.
    /// A single 4 MiB `TaskOutput::Json` makes it ~260 MiB for one session.
    ///
    /// # Two residuals, unowned
    ///
    /// Both are named here rather than in a ledger because neither is solved,
    /// and the sentence above is only true within them:
    ///
    /// **A. Nothing caps `E`.** The bound that would make the arithmetic above
    /// collapse to a constant is a **maximum event size at the publish site** —
    /// reject or truncate an oversized update before it reaches
    /// [`SseHub::publish`] — or a publisher that uses `TaskOutput::Blob`, which
    /// carries a `BlobRef` rather than the bytes. This module cannot impose
    /// either: it has no publisher (residual 1), and declining an update here
    /// would put a hole in the ring (see `Ring::push`). **Owner: whichever
    /// Subsystem D task writes the publisher.**
    ///
    /// **B. The end state is one retainer, not two.** Make the ring the sole
    /// holder of payloads and let the broadcast carry only a wake-up — a `u64`
    /// seq, or `()` — with `Connection::next` reading the payload back out of
    /// the ring by seq. Every byte then lives in the one bounded structure, the
    /// worst case really is `max(ring_bytes, E)`, and `Lagged` stops being an
    /// interesting event at all, because the ring already answers it. That is a
    /// refactor of this module's two-structure design, not a correction to it;
    /// it is named as the target so the next change to this file starts there.
    pub ring_bytes: usize,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            live_queue: 64,
            ring_events: 4096,
            ring_bytes: 1024 * 1024,
        }
    }
}

/// The per-session state, one entry per session with at least one live
/// subscriber.
type Sessions = HashMap<SessionId, SessionChannel>;

/// One session's live fan-out and the §11.3 ring behind it.
///
/// Cloneable because [`SseHub::publish`] takes both out of the map and releases
/// the map lock before using either: a publish for one session must not hold up
/// a subscribe for another. Both fields are handles to shared state, so the
/// clone is two atomic increments, not a copy of anything retained.
#[derive(Clone, Debug)]
struct SessionChannel {
    tx: broadcast::Sender<Arc<SessionUpdate>>,
    /// **Strong, unlike [`SessionSubscription`]'s back-reference to the map.**
    /// That one is `Weak` because of the *sender*: a subscription that kept its
    /// own sender alive could never observe `Closed`. A ring holds no sender,
    /// so a subscription that keeps one alive past the pruning of its map entry
    /// keeps alive only the bytes it is about to drop with itself.
    ring: Arc<Mutex<Ring>>,
}

/// §11.3's per-session ring: *"a ring buffer of the last 4096 events per
/// session"*, held so a reconnecting client's gap can be replayed.
///
/// Holds a **contiguous suffix** of what was published for its session — that
/// is the invariant the whole replay path rests on. A hole anywhere in it would
/// turn a replay into a silent gap, which is the one failure mode this module
/// is written against, so eviction is only ever from the front and a value is
/// never declined at the back (see [`Ring::push`]).
#[derive(Debug)]
struct Ring {
    retained: VecDeque<Retained>,
    /// The sum of `Retained::bytes`, maintained incrementally rather than
    /// recomputed: a push must not walk the ring.
    bytes: usize,
    events_limit: usize,
    bytes_limit: usize,
}

/// One retained update and what it was measured to cost.
///
/// The size is stored rather than recomputed on eviction because the two must
/// be the *same* number — a size that measured differently the second time
/// would drift `Ring::bytes` away from what the ring holds, in a direction
/// nothing would notice until the budget stopped being enforced.
#[derive(Debug)]
struct Retained {
    update: Arc<SessionUpdate>,
    bytes: usize,
}

impl Ring {
    fn new(retention: &Retention) -> Self {
        Self {
            retained: VecDeque::new(),
            bytes: 0,
            events_limit: retention.ring_events,
            bytes_limit: retention.ring_bytes,
        }
    }

    /// Appends `update` and evicts from the front until the ring is inside both
    /// bounds — **or holds exactly one entry**.
    ///
    /// # What is bounded, exactly
    ///
    /// After any push, `self.bytes <= bytes_limit` **unless the ring holds a
    /// single entry**, in which case it is that entry's size, whatever that is.
    /// So the retained total is bounded by `max(bytes_limit, the largest single
    /// update published)` and the entry count by `max(events_limit, 1)`. Both
    /// halves are asserted in this module's unit tests against measured sizes.
    ///
    /// The exception is deliberate: an update too large for the whole budget
    /// has to be retained anyway, because the alternative — declining it —
    /// leaves a hole in the middle of a buffer whose contract is that it holds
    /// a contiguous suffix, and a client replaying across that hole would be
    /// handed a gap with nothing marking it. Retaining it alone means the next
    /// reconnect gets `resync_required`, which is a signal the client can act
    /// on.
    ///
    /// One push can evict many entries — an update larger than the entire budget
    /// evicts every other one — but never more than the ring holds, and each entry
    /// is evicted at most once, so the eviction loop cannot outrun the pushes that
    /// fed it.
    ///
    /// `bytes` is taken as an argument rather than measured here, so that
    /// [`retained_bytes`] — which walks the whole serialised payload — runs
    /// **outside** the ring's lock. Under the lock it would cost one full
    /// serialisation pass per publish while every other publisher for that
    /// session waits, and [`SseHub::publish`] deliberately holds that lock
    /// across the send as well. The caller must pass `retained_bytes(&update)`
    /// for the same update; the value is then stored rather than recomputed on
    /// eviction, so both ends of the accounting are the same number (see
    /// [`Retained`]).
    fn push(&mut self, update: Arc<SessionUpdate>, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.retained.push_back(Retained { update, bytes });

        while self.retained.len() > 1
            && (self.retained.len() > self.events_limit || self.bytes > self.bytes_limit)
        {
            let evicted = self
                .retained
                .pop_front()
                .expect("the loop condition holds only while the ring has two or more entries");
            self.bytes = self.bytes.saturating_sub(evicted.bytes);
        }
    }

    /// §11.3's reconnect decision, in the module's one cursor convention:
    /// `resume_from` is the **next seq the client still needs**, inclusive —
    /// the same value [`Filter::resume_from`] carries and the same value the
    /// handler derives from `Last-Event-ID`. There is no second convention and
    /// no `-1` bridge to underflow at the absent-header case, where
    /// `resume_from` is 0 and **seq 0 is a real event**.
    ///
    /// An **empty** ring is [`Replay::Events`] with nothing in it, not a tail
    /// miss: a ring with no tail cannot have a cursor older than its tail.
    /// Answering `resync_required` there would resync every first connection to
    /// a freshly created entry, which is every connection this endpoint has
    /// ever served.
    ///
    /// # The tail-miss branch is a short-circuit, not the sole guarantor
    ///
    /// Stated because the mutation sweep measured it: deleting the
    /// `resume_from < oldest_retained` branch below and replaying whatever the
    /// ring holds kills **no integration test**, because
    /// [`Connection::deliver`] then sees the first replayed event skip past
    /// `resume_from` and produces `Next::Resync` with the identical two
    /// numbers. The two checks are one condition observed at two places.
    ///
    /// The branch stays for two reasons that are not correctness: it answers
    /// before the stream opens, so the subscription is dropped immediately
    /// rather than one poll later; and it avoids materialising a `Vec` of the
    /// whole ring — up to [`Retention::ring_bytes`] of `Arc` clones — on the
    /// way to discarding it. Its contract is therefore pinned at this level, by
    /// `a_cursor_below_the_rings_tail_is_a_tail_miss_rather_than_a_partial_replay`,
    /// rather than through the endpoint.
    fn replay_since(&self, resume_from: u64) -> Replay {
        let Some(oldest) = self.retained.front() else {
            return Replay::Events(Vec::new());
        };
        let oldest_retained = oldest.update.seq;
        if resume_from < oldest_retained {
            return Replay::ResyncRequired {
                resume_from,
                oldest_retained,
            };
        }
        Replay::Events(
            self.retained
                .iter()
                .filter(|entry| entry.update.seq >= resume_from)
                .map(|entry| Arc::clone(&entry.update))
                .collect(),
        )
    }
}

/// What one retained update is charged against [`Retention::ring_bytes`]: the
/// bytes its payload **serialises to**, plus the fixed-size wrapper.
///
/// This is not the heap the value occupies, and the relation between the two
/// has not been measured (P18). The serialised length is used because it is
/// exact, needs no allocation to compute (see [`ByteCounter`]), and is the
/// figure that bounds what this endpoint can be made to *send* — which is the
/// quantity an unauthenticated caller can inflate.
///
/// A payload that fails to serialise is charged what was written before the
/// failure. That is not a reachable arm for any `ClientEvent` today (see
/// [`encode`]), and it is a size, not a decision: the update is retained
/// either way, and the stream that reaches it ends with a `stream_error`.
fn retained_bytes(update: &SessionUpdate) -> usize {
    let mut counter = ByteCounter::default();
    let _ = serde_json::to_writer(&mut counter, &update.event);
    std::mem::size_of::<SessionUpdate>() + counter.0
}

/// An `io::Write` that keeps the length and discards the bytes, so a payload
/// can be measured without being serialised into a buffer first — which for a
/// 4 MiB `TaskOutput::Json` would mean allocating 4 MiB to decide whether to
/// keep it.
#[derive(Debug, Default)]
struct ByteCounter(usize);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What a subscriber is owed from the ring before it goes live.
///
/// Returned by [`SessionSubscription::replay_since`] on both paths that can
/// need history — a reconnect, and a subscriber bumped out of the live queue —
/// so that §11.3's tail-miss test is written once and answered identically
/// whichever way it is reached.
#[derive(Debug)]
pub enum Replay {
    /// The ring covers the cursor. These are the retained updates from it
    /// onwards, oldest first, and may be empty.
    Events(Vec<Arc<SessionUpdate>>),
    /// §11.3: *"the cursor is older than the ring's tail"* — the events the
    /// client is missing are gone, so it must refetch a snapshot.
    ResyncRequired {
        /// The next seq the client still needs.
        resume_from: u64,
        /// The oldest seq the ring still holds. Always greater than
        /// `resume_from`; the difference is how many events were lost.
        oldest_retained: u64,
    },
}

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
///   A's subscriber past the buffer. A then has to recover a gap it did not
///   cause — from a ring that also holds B's events, so B's traffic decides
///   whether A's own is still there. With several tabs open, one busy session
///   degrades all of them at once.
/// - **Cross-session delivery, one `==` away.** Every session's payload would
///   physically reach every connection's receiver, with a `Filter` comparison
///   the only thing between it and the wire.
///
/// Keying the map by session makes cross-session delivery structurally
/// impossible rather than one `==` away, and gives each session its own
/// capacity — its own live queue and its own ring, so neither one's occupancy
/// is a function of another session's traffic.
///
/// (D2 also argued this from `RecvError::Lagged(n)`, which counts what a
/// receiver skipped **across all sessions** and which D2's `resync_required`
/// reported to the client as `dropped_events`. That half no longer applies:
/// the count is not reported and `_dropped` is unused — the resync payload is
/// two of this session's own seqs. The two reasons above are the ones that
/// survive.)
///
/// An entry exists only while some subscriber holds it. [`SessionSubscription`]
/// removes its session's entry on drop once it is the last reader, so a client
/// requesting a stream for an arbitrary UUID leaves nothing behind.
///
/// # Falling behind is not silent, and no longer terminal
///
/// A `tokio::sync::broadcast` receiver that falls further behind than
/// [`Retention::live_queue`] gets `RecvError::Lagged(n)` and then resumes from
/// the oldest value still in the queue — the messages in between are gone from
/// *the queue*. Continuing past that would hand the client a gap with no marker
/// in the stream, which is the opposite of §11.3's contract.
///
/// They are not gone from the **ring**, which is why the two limits are one
/// [`Retention`]: the connection re-reads the missing range with
/// [`SessionSubscription::replay_since`] and carries on. Only when the ring has
/// evicted them too — a gap wider than the ring, or a session whose events are
/// large enough to exhaust its byte budget — is the answer §11.3's
/// `resync_required`, which is then the same tail-miss condition, from the same
/// producer, with the same payload as a reconnect that arrives too late.
#[derive(Clone, Debug)]
pub struct SseHub {
    retention: Retention,
    sessions: Arc<Mutex<Sessions>>,
}

impl SseHub {
    pub fn new() -> Self {
        Self::with_retention(Retention::default())
    }

    /// # Panics
    ///
    /// If any limit is zero, or if `live_queue` (rounded up to a power of two,
    /// as `tokio` rounds it) exceeds `ring_events`.
    ///
    /// The assertions are here, in a constructor called at start-up, rather
    /// than left to `broadcast::channel`'s own assertion inside a lazily
    /// created channel, where they would be a panic in a request handler.
    ///
    /// # The recovery band, and the half of it this assertion cannot reach
    ///
    /// The ordering assertion is the whole reason [`Retention`] is one type:
    /// every value the live queue drops should still be in the ring, or a
    /// lagging subscriber is unrecoverable by construction and the recovery
    /// path is dead code that looks alive. Equality is permitted and gives a
    /// recovery band of exactly zero — the default is 64x apart.
    ///
    /// **But `live_queue <= ring_events` constrains only the *entry*
    /// dimension.** The ring has a second bound, [`Retention::ring_bytes`],
    /// which can shrink it below `live_queue` entries with nothing here
    /// noticing — and it did, at this type's own first defaults, where
    /// `1 MiB / 256` left 4 KiB per event against a measured 4305-byte one.
    /// So, precisely:
    ///
    /// - The **entry** bound preserves the band, and is asserted below.
    /// - The **byte** bound can shrink it, and is *not* asserted, because
    ///   whether it does depends on the size of events this hub has not seen.
    /// - The derived headroom is **`ring_bytes / live_queue`** — 16 KiB at the
    ///   defaults — and that is the number a reader should check against their
    ///   own workload, not `ring_events`.
    ///
    /// Nothing here can check the second bullet, since it needs an event size.
    /// `the_default_retention_recovers_a_full_live_queue_of_realistic_events`
    /// checks it for the configuration that actually ships.
    pub fn with_retention(retention: Retention) -> Self {
        let Retention {
            live_queue,
            ring_events,
            ring_bytes,
        } = retention;
        assert!(
            live_queue > 0,
            "SseHub live_queue must be greater than zero"
        );
        assert!(
            ring_events > 0,
            "SseHub ring_events must be greater than zero"
        );
        assert!(
            ring_bytes > 0,
            "SseHub ring_bytes must be greater than zero"
        );
        assert!(
            live_queue
                .checked_next_power_of_two()
                .is_some_and(|rounded| rounded <= ring_events),
            "SseHub live_queue ({live_queue}, which tokio rounds up to a power of two) must not \
             exceed ring_events ({ring_events}), or a lagging subscriber cannot be recovered from \
             the ring by entry count alone — the byte bound can still shrink the band below it, \
             which is not checkable here"
        );
        Self {
            retention,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// A poisoned lock is recovered from rather than propagated. The guarded
    /// value is a plain map of handles with no invariant a panic could break
    /// halfway, and the alternative — every later request panicking on a
    /// poisoned mutex — turns one unrelated panic into a permanent outage of
    /// the endpoint. The same reasoning covers a session's [`Ring`]: a panic
    /// mid-`push` could leave `bytes` disagreeing with what is retained, which
    /// costs at worst a ring that evicts a little early or late, against an
    /// endpoint that answers nothing at all.
    fn lock_sessions(&self) -> MutexGuard<'_, Sessions> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Publishes `update` to the open streams **for its own session**, and
    /// retains it in that session's ring, returning how many streams received
    /// it live. `update.session_id` is the sole routing authority; no other
    /// session's subscribers or ring can be reached from here.
    ///
    /// **Zero is normal, not an error**: no browser has to be connected for the
    /// daemon to be appending events. Zero is also *nothing retained* — a
    /// session with no subscriber has no entry, so it has no ring either
    /// (residual 5).
    ///
    /// # Why the send happens under the ring's lock
    ///
    /// The map lock is released first, so no other session's subscribe or
    /// unsubscribe waits on this send. The session's own ring lock is then held
    /// **across** the push and the send, so that the order values enter the ring
    /// and the order they enter the live queue cannot disagree. If they could, a
    /// replay that ended at seq M could be followed by a live value below M,
    /// which the connection's filter discards as a duplicate — losing an event,
    /// rather than merely reordering one. The cost is that two publishes for
    /// the *same* session serialise; publishes for different sessions do not.
    ///
    /// (This supersedes D2's reason for releasing the lock before sending —
    /// keeping dropped-value destructors out of it. The ring's own eviction
    /// runs destructors under this lock regardless, and correctness of ordering
    /// is worth more than where a `Drop` runs.)
    ///
    /// Since that lock is held across two operations, what runs **inside** it is
    /// kept to the two: `retained_bytes` walks the whole serialised payload,
    /// so it is measured here, before the lock, and handed to `Ring::push`. A
    /// publish for a session with N connections would otherwise cost one full
    /// serialisation pass for the ring plus N for the frames, with the first of
    /// them blocking every other publisher for that session.
    pub fn publish(&self, update: SessionUpdate) -> usize {
        let Some(channel) = self.session_channel(update.session_id) else {
            return 0;
        };
        // One allocation, shared by the ring and by every live queue slot: the
        // fan-out is reference counts, not copies of the payload.
        let update = Arc::new(update);
        let bytes = retained_bytes(&update);
        let mut ring = channel.ring.lock().unwrap_or_else(PoisonError::into_inner);
        ring.push(Arc::clone(&update), bytes);
        channel.tx.send(update).unwrap_or(0)
    }

    fn session_channel(&self, session_id: SessionId) -> Option<SessionChannel> {
        self.lock_sessions().get(&session_id).cloned()
    }

    /// How many sessions currently have an entry — i.e. have at least one open
    /// stream.
    ///
    /// Public so that the map's cleanup is *observable* rather than merely
    /// asserted in a comment: without it, "the entry is removed when the last
    /// subscriber drops" is untestable from outside, and an endpoint reachable
    /// with an arbitrary UUID leaking one map entry per request is exactly the
    /// kind of growth that is easy to introduce and impossible to notice. Each
    /// entry now carries a ring, so what it gauges is bytes and not only slots.
    /// It is also the natural gauge for a future `/metrics`.
    pub fn tracked_sessions(&self) -> usize {
        self.lock_sessions().len()
    }

    /// A subscription to `session_id`'s live updates, creating the session's
    /// entry — channel and ring — if this is its first subscriber.
    ///
    /// Sees every update published **after** this call, and nothing earlier:
    /// history is [`SessionSubscription::replay_since`]'s job, deliberately
    /// separate so that the ring is read once, by the caller that knows the
    /// cursor. Nothing from another session either: that is the map key, not a
    /// filter.
    pub fn subscribe(&self, session_id: SessionId) -> SessionSubscription {
        let mut sessions = self.lock_sessions();
        let channel = sessions
            .entry(session_id)
            .or_insert_with(|| SessionChannel {
                tx: broadcast::channel(self.retention.live_queue).0,
                ring: Arc::new(Mutex::new(Ring::new(&self.retention))),
            });
        // Subscribing under the map lock, rather than after cloning the entry
        // out, is what stops a concurrent last-subscriber drop from pruning the
        // entry between the lookup and the subscribe — which would leave this
        // receiver attached to a sender no publisher can reach.
        let subscription = SessionSubscription {
            session_id,
            rx: channel.tx.subscribe(),
            ring: Arc::clone(&channel.ring),
            sessions: Arc::downgrade(&self.sessions),
        };
        drop(sessions);
        subscription
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
    rx: broadcast::Receiver<Arc<SessionUpdate>>,
    /// This session's ring. Held strongly — see [`SessionChannel::ring`] — so
    /// that a lag can be recovered from it even in the window where the hub is
    /// shutting down and the map is already gone.
    ring: Arc<Mutex<Ring>>,
    sessions: Weak<Mutex<Sessions>>,
}

impl SessionSubscription {
    /// The next update for this session, or why there will not be one. See
    /// [`SseHub`] on `Lagged`.
    pub async fn recv(&mut self) -> Result<Arc<SessionUpdate>, broadcast::error::RecvError> {
        self.rx.recv().await
    }

    /// What this session's ring still holds from `resume_from` on — the next
    /// seq the client needs, inclusive — or §11.3's tail miss.
    ///
    /// The one entry point to the ring, used by **both** paths that can need
    /// history: the reconnect, before the stream goes live, and a subscriber
    /// bumped out of the live queue. One reader, one cursor convention, one
    /// tail-miss test.
    ///
    /// Reading the ring here is *not* atomic with [`SseHub::subscribe`]: an
    /// update published in between is both replayed and delivered live. That is
    /// deliberate rather than tolerated — the connection's filter discards a
    /// duplicate below
    /// its resume point, which is the same mechanism the lag path relies on, so
    /// there is one dedup rule exercised by both instead of a lock ordering
    /// that exists only to avoid it.
    pub fn replay_since(&self, resume_from: u64) -> Replay {
        self.ring
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .replay_since(resume_from)
    }
}

impl Drop for SessionSubscription {
    /// Removes the session's entry — channel **and ring** — once its last
    /// reader goes away, so the map does not accumulate an entry per session
    /// ever streamed, including the arbitrary UUIDs an unauthenticated client
    /// can ask for. With a ring in the entry that is no longer only a map slot
    /// but everything the ring retained, which is the eviction path a
    /// free-standing ring would have had to grow for itself.
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
        let Some(sessions) = self.sessions.upgrade() else {
            return;
        };
        let mut sessions = sessions.lock().unwrap_or_else(PoisonError::into_inner);
        if let Entry::Occupied(entry) = sessions.entry(self.session_id) {
            if entry.get().tx.receiver_count() <= 1 {
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

    // Subscribe first, then read the ring: the other order leaves a window in
    // which an update is in neither — published after the ring was read and
    // before the receiver existed — which is the silent gap this endpoint is
    // written against. This order can only produce the opposite, a duplicate,
    // which `Filter` discards.
    let subscription = state.sse.subscribe(session_id);
    let replay = subscription.replay_since(resume_from);

    Sse::new(session_stream(
        subscription,
        Filter {
            session_id,
            resume_from,
        },
        replay,
    ))
    .keep_alive(KeepAlive::default())
    .into_response()
}

fn cursor_rejected(error: CursorError) -> Response {
    (StatusCode::BAD_REQUEST, format!("{error}\n")).into_response()
}

/// Which updates one connection still wants: from its resume point on.
///
/// The `session_id` check is **belt and braces, not the mechanism**. Routing is
/// [`SseHub`]'s map key, so a subscription for session A cannot be handed
/// session B's update in the first place; this check is what would catch a
/// future hub that reintroduced a shared channel, and it costs one comparison
/// per event. `resume_from` is the part that does real work here — it is
/// per-connection state the hub knows nothing about.
///
/// # `resume_from` advances, and what that costs
///
/// It starts at the cursor the request arrived with and moves to `seq + 1` as
/// each event is emitted, so it means one thing throughout: **the next seq this
/// connection still owes the client**. That is what makes both recovery paths
/// expressible — a replay is "everything from `resume_from`" whether it is
/// asked for at reconnect or after a lag — and it is what discards the
/// duplicates a replay overlapping the live queue produces.
///
/// The cost is that a value **below** what has already been emitted is dropped
/// rather than delivered late. Ring order and live-queue order cannot disagree
/// ([`SseHub::publish`] holds one lock across both), so this can only bite a
/// publisher that allocates seqs out of order — which `roundhouse-store`'s
/// single monotonic allocator (`COALESCE(MAX(seq), -1) + 1`, `writer.rs:171`)
/// does not. Recorded because it is a real constraint on the publisher
/// residual 1 calls for, and it is invisible from the client side.
///
/// # The publisher's contract, in full — both clauses
///
/// Together with [`Connection::deliver`]'s gap check, this module requires two
/// things of whatever eventually publishes into the hub:
///
/// 1. **Seqs are allocated in order, per session.** Out-of-order allocation
///    loses an event here, silently (above).
/// 2. **Every allocated seq is published into the hub.** A publisher that
///    forwarded only some event kinds would leave holes, and every hole is a
///    `resync_required` at [`Connection::deliver`] — a client that resyncs
///    forever rather than one that misses events, but unusable either way.
///
/// Both are invisible from the client side, and neither is enforceable from
/// this crate, which has no publisher to check (residual 1).
#[derive(Debug, Clone, Copy)]
struct Filter {
    session_id: SessionId,
    resume_from: u64,
}

impl Filter {
    fn accepts(&self, update: &SessionUpdate) -> bool {
        update.session_id == self.session_id && update.seq >= self.resume_from
    }

    /// Records that `seq` has been emitted.
    ///
    /// `saturating_add` for the same reason the handler uses it on the incoming
    /// cursor: `seq` is ultimately client-influenced (a resumed stream's first
    /// emitted seq comes from `Last-Event-ID`), `cargo test` is a debug build,
    /// and an overflow here would be a panic inside a live request handler. At
    /// `u64::MAX` the connection stops advancing, which re-delivers only an
    /// event that seq can never be followed by.
    fn advance_past(&mut self, seq: u64) {
        self.resume_from = seq.saturating_add(1);
    }
}

/// One connection: its live receiver, its filter, and whatever the ring has
/// handed it that is not yet on the wire.
struct Connection {
    rx: SessionSubscription,
    filter: Filter,
    /// Replayed updates awaiting emission, oldest first. Drained ahead of the
    /// live receiver, so history reaches the client before anything that
    /// follows it.
    pending: VecDeque<Arc<SessionUpdate>>,
}

/// What a connection has next.
enum Next {
    Update(Arc<SessionUpdate>),
    /// The events the client still needs are older than the oldest the server
    /// can offer — §11.3's tail miss, or the delivery-time discontinuity
    /// [`Connection::deliver`] describes, which is the same condition where the
    /// ring is empty and so has no tail to compare against. Terminal.
    Resync {
        resume_from: u64,
        oldest_retained: u64,
    },
    /// Every sender is gone.
    Closed,
}

impl Connection {
    /// Emit `update`, discard it as one this connection does not want, or
    /// report the gap it reveals.
    ///
    /// # The gap check, and why it is here rather than at the ring
    ///
    /// `resume_from` is *the next seq this connection still owes the client*.
    /// An accepted update whose seq is **greater** than it means every seq in
    /// between was never delivered — the client's next `Last-Event-ID` would
    /// jump the gap with nothing in the stream marking it, which is precisely
    /// what the [`SseHub`] docs call *"the opposite of §11.3's contract"*.
    ///
    /// Checking it **at delivery** rather than at the ring is what makes the
    /// check total. [`Ring::replay_since`] can only compare a cursor against
    /// what the ring *holds*; it cannot see a gap opened by events that were
    /// published while nobody was subscribed, because those left no trace
    /// anywhere ([`SseHub::publish`] with no entry is a no-op — residual 5). A
    /// client whose tab closed, whose session's entry was therefore pruned, and
    /// which reconnects after the daemon appended more events, finds an **empty
    /// ring** — no tail, so no tail miss — and would otherwise be taken live at
    /// the next event with the intervening ones silently gone. Here that
    /// arrives as the same `resync_required` a tail miss produces, from the same
    /// two numbers, because it is the same condition generalised: *the events
    /// the client still needs are older than the oldest the server can offer.*
    /// The same check also covers a byte eviction that outran a live cursor
    /// mid-stream, which no ring-side test can reach.
    ///
    /// It does **not** resync a client that has simply caught up: a client that
    /// resynced, snapshotted at seq 26 and reconnected at `resume_from = 27`
    /// receives seq 27 as an ordinary frame even though the ring is empty,
    /// because 27 is not greater than 27. Only an actual discontinuity fires.
    ///
    /// # What it costs: a tightened contract on the publisher
    ///
    /// The publisher's obligation grows from *"seqs are allocated in order per
    /// session"* to **"...and every allocated seq is published into the hub"**.
    /// A publisher that filtered event kinds — forwarding `TaskCompleted` but
    /// not `TaskDelta`, say — would leave holes in the seq sequence and this
    /// check would fire on every one of them, resyncing the client constantly.
    /// It belongs beside [`Filter`]'s existing constraint on seq *ordering*,
    /// and both clauses are stated together there. It is the price of detecting
    /// a gap the server cannot otherwise see.
    fn deliver(&mut self, update: Arc<SessionUpdate>) -> Option<Next> {
        if !self.filter.accepts(&update) {
            return None;
        }
        if update.seq > self.filter.resume_from {
            return Some(Next::Resync {
                resume_from: self.filter.resume_from,
                oldest_retained: update.seq,
            });
        }
        self.filter.advance_past(update.seq);
        Some(Next::Update(update))
    }

    /// The next thing to emit, having already dealt with everything that is not
    /// one: duplicates, another session's updates, and a lag the ring can cover.
    ///
    /// The loop cannot spin: each iteration either returns, drains one pending
    /// update, or awaits the receiver — and a second `Lagged` requires further
    /// publishes, since `tokio` reports a receiver's lag once and then resumes
    /// it at the oldest value the queue still holds.
    async fn next(&mut self) -> Next {
        loop {
            if let Some(update) = self.pending.pop_front() {
                match self.deliver(update) {
                    Some(next) => return next,
                    None => continue,
                }
            }

            match self.rx.recv().await {
                Ok(update) => match self.deliver(update) {
                    Some(next) => return next,
                    None => continue,
                },
                // Bumped out of the live queue. The missing range is
                // everything from this connection's resume point on, and the
                // ring is asked for exactly that — the same question a
                // reconnect asks, so it gets the same answer. `dropped` is not
                // used: it counts what this *receiver* skipped, which is not
                // the same as what the client is missing once a replay is in
                // flight, and reporting two different numbers under one name is
                // the shape this task exists to remove.
                Err(broadcast::error::RecvError::Lagged(_dropped)) => {
                    match self.rx.replay_since(self.filter.resume_from) {
                        Replay::Events(events) => self.pending.extend(events),
                        Replay::ResyncRequired {
                            resume_from,
                            oldest_retained,
                        } => {
                            return Next::Resync {
                                resume_from,
                                oldest_retained,
                            }
                        }
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return Next::Closed,
            }
        }
    }
}

enum StreamState {
    Open(Connection),
    /// A tail miss found before the stream opened: one frame, then done.
    Resync {
        resume_from: u64,
        oldest_retained: u64,
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
    replay: Replay,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    let start = match replay {
        Replay::Events(events) => StreamState::Open(Connection {
            rx,
            filter,
            pending: events.into(),
        }),
        // The subscription is dropped with `rx` here rather than held for a
        // stream that will emit one frame and stop — which is also what returns
        // the session's map entry if this was its only reader.
        Replay::ResyncRequired {
            resume_from,
            oldest_retained,
        } => StreamState::Resync {
            resume_from,
            oldest_retained,
        },
    };

    futures_util::stream::unfold(start, |state| async move {
        match state {
            StreamState::Done => None,
            StreamState::Resync {
                resume_from,
                oldest_retained,
            } => Some((
                Ok(resync_required(resume_from, oldest_retained)),
                StreamState::Done,
            )),
            StreamState::Open(mut connection) => match connection.next().await {
                Next::Update(update) => Some(match encode(&update) {
                    Encoded::Frame(event) => (Ok(event), StreamState::Open(connection)),
                    Encoded::Terminal(event) => (Ok(event), StreamState::Done),
                }),
                Next::Resync {
                    resume_from,
                    oldest_retained,
                } => Some((
                    Ok(resync_required(resume_from, oldest_retained)),
                    StreamState::Done,
                )),
                Next::Closed => None,
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

/// §11.3's `resync_required`, and **the only place it is produced**.
///
/// One condition reaches it — *the events the client still needs are older than
/// the oldest the server can offer* — which is §11.3's *"the cursor is older
/// than the ring's tail"* wherever a tail exists, and
/// [`Connection::deliver`]'s seq discontinuity where one does not. Three paths
/// discover it: a reconnect whose cursor arrives too late, a subscriber whose
/// lag outran the ring (both via [`Ring::replay_since`]), and a delivered
/// update that skips ahead of what this connection still owes. All three land
/// here with the same two numbers and the same payload shape. D2 also emitted
/// this name for `Lagged`, with a `{"dropped_events": n}` payload, because it
/// had no ring to recover from; keeping both would have been one client-visible
/// signal with two meanings and two shapes.
///
/// The payload states the two ends of the gap. How many events were lost is
/// `oldest_retained - resume_from`, and it is **not** a third field: a second
/// spelling of one number is a second thing to keep in step. Both are this
/// session's own seqs, which the client is entitled to — no other session's
/// traffic is observable through them, which is why the hub is keyed by session.
///
/// Carries no `id:`. A browser `EventSource` remembers the last id it saw and
/// replays it as `Last-Event-ID` on reconnect; an id here would be resumed from
/// as though it were a real event.
///
/// **The client must `close()` the `EventSource` on this frame** and refetch a
/// snapshot. A stock `EventSource` otherwise reconnects on its own, and — since
/// the events are gone from the ring, which is what this frame says — resumes
/// from the same cursor into the same tail miss. It would at least get this
/// frame again rather than a silent gap, for as long as the session's entry
/// outlives the reconnect; that is a weaker guarantee than a client that
/// closes, and it is a client-side obligation this endpoint cannot enforce.
fn resync_required(resume_from: u64, oldest_retained: u64) -> Event {
    Event::default().event("resync_required").data(
        serde_json::json!({
            "resume_from": resume_from,
            "oldest_retained": oldest_retained,
        })
        .to_string(),
    )
}

/// The [`Ring`]'s accounting, measured rather than argued.
///
/// `tests/sse_cursor.rs` drives the ring through the real endpoint, which is
/// where its *behaviour* is pinned. What cannot be reached from out there is
/// the number [`Retention::ring_bytes`] is compared against: these tests assert
/// what [`retained_bytes`] actually returns for a payload of a known size, and
/// what the ring's running total actually is after a sequence of pushes. Ruling
/// P18 — a bound is only stated here because it is measured here.
#[cfg(test)]
mod tests {
    use roundhouse_core::{Delta, EventPayload};

    use super::*;

    fn update(session_id: SessionId, seq: u64, text: &str) -> Arc<SessionUpdate> {
        Arc::new(SessionUpdate {
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
        })
    }

    fn ring(events_limit: usize, bytes_limit: usize) -> Ring {
        Ring::new(&Retention {
            live_queue: 1,
            ring_events: events_limit,
            ring_bytes: bytes_limit,
        })
    }

    /// `Ring::push` takes the size as an argument so that measuring it happens
    /// outside the ring's lock (see [`SseHub::publish`]). These tests are the
    /// only other caller, and they must pair the same two values the publisher
    /// does — hence one helper rather than the measurement repeated per push.
    fn push(ring: &mut Ring, update: Arc<SessionUpdate>) {
        let bytes = retained_bytes(&update);
        ring.push(update, bytes);
    }

    /// The byte counter counts what a serialiser would write, byte for byte —
    /// so the budget is compared against the payload's real serialised size and
    /// not against a guess at it.
    #[test]
    fn a_retained_updates_size_is_its_serialised_payload_plus_the_fixed_wrapper() {
        let session_id = SessionId::new();
        let payload = "x".repeat(4096);
        let update = update(session_id, 0, &payload);

        let serialised = serde_json::to_string(&update.event).expect("serialises");
        assert_eq!(
            retained_bytes(&update),
            std::mem::size_of::<SessionUpdate>() + serialised.len(),
        );
        // And the payload dominates that total, which is the whole reason a
        // count of entries does not bound the memory: 4096 bytes of text
        // against a wrapper measured here at well under 200.
        assert!(
            serialised.len() > 4096 && std::mem::size_of::<SessionUpdate>() < 200,
            "measured: payload {} bytes, wrapper {} bytes",
            serialised.len(),
            std::mem::size_of::<SessionUpdate>(),
        );
    }

    /// The running total tracks exactly what is retained — including across
    /// eviction, where a drifting total would stop enforcing the budget in a
    /// direction nothing else observes.
    #[test]
    fn the_rings_byte_total_is_the_sum_of_what_it_still_holds() {
        let session_id = SessionId::new();
        let one = retained_bytes(&update(session_id, 0, "delta"));

        let mut ring = ring(3, usize::MAX);
        for seq in 0..3 {
            push(&mut ring, update(session_id, seq, "delta"));
        }
        assert_eq!(ring.retained.len(), 3);
        assert_eq!(ring.bytes, one * 3, "three equal-sized updates");

        // Past the entry bound: the oldest goes, and its bytes go with it.
        push(&mut ring, update(session_id, 3, "delta"));
        assert_eq!(ring.retained.len(), 3);
        assert_eq!(ring.bytes, one * 3);
        assert_eq!(
            ring.retained.front().expect("non-empty").update.seq,
            1,
            "eviction is from the front, so the ring stays a contiguous suffix"
        );
    }

    /// The byte bound is what actually holds when the entry bound is generous,
    /// which is the case §11.3's 4096 leaves open.
    #[test]
    fn the_byte_bound_holds_where_the_entry_bound_is_generous() {
        let session_id = SessionId::new();
        let payload = "x".repeat(1000);
        let one = retained_bytes(&update(session_id, 0, &payload));
        let budget = one * 3;

        let mut ring = ring(4096, budget);
        for seq in 0..10 {
            push(&mut ring, update(session_id, seq, &payload));
        }

        assert_eq!(
            ring.retained.len(),
            3,
            "a {budget}-byte budget holds three {one}-byte updates, not 4096 of them",
        );
        assert!(
            ring.bytes <= budget,
            "measured {} bytes against a {budget}-byte budget",
            ring.bytes,
        );
        assert_eq!(ring.retained.front().expect("non-empty").update.seq, 7);
    }

    /// The one case that exceeds the budget, stated as an exception because it
    /// is one: a hole in the ring would be a silent gap, so an oversized update
    /// is retained alone rather than declined.
    #[test]
    fn an_update_larger_than_the_whole_budget_is_retained_alone_rather_than_dropped() {
        let session_id = SessionId::new();
        let payload = "x".repeat(4096);
        let mut ring = ring(4096, 1024);

        for seq in 0..3 {
            push(&mut ring, update(session_id, seq, &payload));
        }

        assert_eq!(ring.retained.len(), 1, "never evicted down to nothing");
        assert_eq!(ring.retained.front().expect("non-empty").update.seq, 2);
        assert!(
            ring.bytes > 1024,
            "the exception is real and measured: {} bytes retained against a 1024-byte budget",
            ring.bytes,
        );
    }

    /// §11.3's tail miss, pinned at the ring's own level.
    ///
    /// It is tested here rather than only through the endpoint because deleting
    /// the branch kills nothing out there: `Connection::deliver` reaches the
    /// same two numbers from the first replayed event. See `Ring::replay_since`
    /// — the branch is a short-circuit, and this is where its contract lives.
    ///
    /// **Mutation killed:** removing the `resume_from < oldest_retained` arm
    /// from `Ring::replay_since` — the first assertion gets
    /// `Replay::Events([5, 6, 7])`, a partial replay silently skipping seq 4.
    #[test]
    fn a_cursor_below_the_rings_tail_is_a_tail_miss_rather_than_a_partial_replay() {
        let session_id = SessionId::new();
        let mut ring = ring(3, usize::MAX);
        for seq in 5..8 {
            push(&mut ring, update(session_id, seq, "delta"));
        }

        assert!(
            matches!(
                ring.replay_since(4),
                Replay::ResyncRequired {
                    resume_from: 4,
                    oldest_retained: 5,
                }
            ),
            "seq 4 is below the ring's tail of 5, so it is a miss and not a replay of 5 onwards",
        );
        // The boundary from the other side: the tail itself is not a miss.
        assert!(
            matches!(ring.replay_since(5), Replay::Events(events) if events.len() == 3),
            "the tail is exactly reachable, so the whole ring replays",
        );
    }

    /// An empty ring has no tail, so no cursor can be older than it. Answering
    /// `resync_required` here would resync every first connection to a freshly
    /// created entry.
    #[test]
    fn an_empty_ring_replays_nothing_rather_than_demanding_a_resync() {
        let empty = ring(4096, 1024);
        for resume_from in [0, 1, u64::MAX] {
            assert!(
                matches!(empty.replay_since(resume_from), Replay::Events(events) if events.is_empty()),
                "an empty ring cannot have a tail older than {resume_from}",
            );
        }
    }

    /// The cursor is inclusive — it names the next seq the client needs, not
    /// the last one it saw — and seq 0 is a real event, so a cursor of 0
    /// replays everything rather than meaning "no cursor".
    #[test]
    fn replay_is_inclusive_of_the_cursor_and_seq_zero_is_a_real_event() {
        let session_id = SessionId::new();
        let mut ring = ring(4096, usize::MAX);
        for seq in 0..5 {
            push(&mut ring, update(session_id, seq, "delta"));
        }

        let seqs = |replay| match replay {
            Replay::Events(events) => events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            Replay::ResyncRequired { .. } => panic!("the ring holds every seq published"),
        };
        assert_eq!(seqs(ring.replay_since(0)), vec![0, 1, 2, 3, 4]);
        assert_eq!(seqs(ring.replay_since(3)), vec![3, 4]);
        assert_eq!(seqs(ring.replay_since(5)), Vec::<u64>::new());
        assert_eq!(seqs(ring.replay_since(u64::MAX)), Vec::<u64>::new());
    }
}
