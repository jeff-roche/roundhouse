//! `SessionId`-keyed fan-out registry for `socket_server::accept_loop`.
//!
//! Task 2's `serve` served exactly one connection to exactly one session; a
//! real daemon must let an arbitrary number of `round` clients create
//! sessions and let an arbitrary number of *other* clients later attach to
//! any of them (§11.3). That needs two things `serve` never had: a place to
//! look a `SessionId` up by value (so `Attach` can find a session a
//! *different* connection created), and, less obviously, **fan-out**: two
//! independent attached connections must each see every event a session
//! produces, so one `SessionId` cannot map to a single `Sender` the way a
//! first pass at this might reach for.
//!
//! # Fan-out shape
//!
//! Each session maps to a [`SessionEntry`] holding a `Vec` of that session's
//! currently-live subscriber `Sender`s. `create`/`attach` each mint a fresh
//! bounded `mpsc` channel, register the `Sender` half, and hand the
//! `Receiver` half back to the caller (`socket_server`'s per-connection
//! driver), which forwards everything it receives down that one
//! connection's socket via
//! [`serve_connection`](crate::socket_server::serve_connection). [`publish`]
//! fans one event out to every live subscriber.
//!
//! `Vec<Sender>` rather than `tokio::sync::broadcast` deliberately: this
//! registry's fan-out is dynamic (subscribers attach and detach across a
//! session's whole lifetime, not just at the moment of a single `subscribe`
//! call), and a `broadcast` channel's single ring buffer would force one
//! global lag policy across every subscriber and every session, whereas a
//! `Vec` of independent bounded `mpsc::Sender`s lets each subscriber's own
//! backpressure be its own problem — a slow or stuck watcher only ever
//! drops events destined for *it* (see `publish`'s doc comment), never
//! events destined for anyone else.
//!
//! # Handling a lagging or dead subscriber
//!
//! [`publish`] is deliberately **not** `async`: it uses `Sender::try_send`
//! rather than `send().await`, so a subscriber whose channel is full can
//! never block whoever is publishing (a `SessionActor`'s own task, in the
//! real wiring this registry exists to support) — that event is simply
//! dropped for that one subscriber, which is the daemon choosing to shed
//! load rather than stall the whole session over one slow watcher. A
//! subscriber whose `Receiver` has been dropped entirely (its connection
//! ended) is pruned from the `Vec` on the next `publish`.
//!
//! # Not leaking registry entries forever
//!
//! Relying on `publish` traffic alone to prune a dead subscriber would leak
//! forever for a session nobody ever publishes to again. [`detach`] is the
//! deterministic path: `socket_server`'s per-connection driver calls it the
//! moment its own connection loop ends (for *any* reason: peer disconnect,
//! a write failure, whatever), regardless of whether the session ever
//! publishes anything else. Once a session's subscriber list is empty —
//! whether reaped by `detach` or by `publish`'s own pruning — the whole map
//! entry is removed, so a registry serving a long sequence of short-lived
//! sessions does not grow without bound. (`attach`ing to a session after
//! every one of its subscribers has gone this way returns `None`, the same
//! as attaching to a `SessionId` that was never created — see [`attach`]'s
//! doc comment for why that is a known, deliberate limitation of this task,
//! not an oversight. `crates/roundhouse-daemon/tests/multi_client_attach.rs`
//! exercises this end to end: dropping a session's only client and then
//! polling `Attach` eventually observes the reap.)
//!
//! # Locking (ruling W1-R8)
//!
//! `sessions` is a plain `std::sync::Mutex`, never held across an `.await` —
//! every method below takes the lock, does one map operation (and, in
//! `create`/`attach`, one `Vec::push`), and releases it before returning or
//! doing anything else. In particular `create` and `attach` each take the
//! lock exactly *once*: an earlier draft of `attach` checked membership
//! under one lock acquisition, dropped it, and re-acquired it to register
//! the new subscriber — a real TOCTOU, since a concurrent `detach` reaping
//! that session's last other subscriber in the gap between those two
//! acquisitions would have its removal silently undone by the second
//! acquisition recreating the entry. Checking and inserting under the same
//! held lock closes that window.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Mutex;

use roundhouse_core::SessionId;
use roundhouse_proto::ClientEvent;
use tokio::sync::mpsc;

/// Per-subscriber channel depth. Small and finite on purpose: `publish`
/// sheds load onto a slow subscriber (see the module doc comment) rather
/// than growing an unbounded backlog for it, and a session's own event
/// volume between two client-visible frames is small.
const SUBSCRIBER_CHANNEL_CAPACITY: usize = 64;

/// Default ceiling on the number of live sessions one registry will hold at
/// once (security review Important 3 / ruling W1-R33). Generous relative to
/// any realistic single-daemon workload — this is a circuit breaker against
/// unbounded growth (a bug, or a peer that just keeps sending
/// `CreateSession`), not an operational tuning knob. Each entry is small
/// (a `Vec` of `Sender`s), so this bounds memory in the pathological case
/// without constraining real usage.
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Default ceiling on the number of subscribers (creator + every `Attach`)
/// one session will accept (security review Important 3 / ruling W1-R33).
/// `publish` clones `event` once per subscriber (module doc comment,
/// "Handling a lagging or dead subscriber"), so an unbounded subscriber
/// count is an unbounded per-event memory/CPU amplifier. Matches
/// [`SUBSCRIBER_CHANNEL_CAPACITY`]'s order of magnitude deliberately: a
/// session with more concurrently attached watchers than it has buffer
/// slots per watcher is already past any realistic operator scenario.
const DEFAULT_MAX_SUBSCRIBERS_PER_SESSION: usize = 64;

/// A handle identifying one call to [`SessionRegistry::create`] or
/// [`SessionRegistry::attach`], to be handed back to [`SessionRegistry::detach`]
/// once that subscriber's connection ends.
///
/// Deliberately opaque and not `Clone`: it wraps the exact cloned `Sender`
/// the registry stored for this subscription, since `Sender::same_channel`
/// is the cheapest correct way to identify "this exact subscription" among
/// a session's `Vec` of them without inventing and threading a second,
/// parallel id space purely to name registry entries. It is not a
/// general-purpose way to publish events — [`SessionRegistry::publish`] is.
pub struct Subscription(mpsc::Sender<ClientEvent>);

/// One session's registry-side bookkeeping.
///
/// Holds only `subscribers` today, but is kept as its own named struct
/// (rather than the map storing a bare `Vec<Sender<..>>` directly)
/// specifically so Task 5/7's real per-session wiring can add an `actor:
/// SessionActor` field here later without touching every call site that
/// already reaches into a session's entry — only the two or three places
/// that construct one. This task deliberately does not construct a real
/// `SessionActor`: `SessionActor::new` takes `runner: &'static TaskRunner`,
/// and `TaskRunner::bootstrap()` panics on a second call per process, so the
/// one real `TaskRunner` has to be bootstrapped once in `main.rs` and
/// threaded into this registry (e.g. via `SessionRegistry::new(runner:
/// &'static TaskRunner, ..)` or a builder) before `create` can construct
/// actors — wiring that belongs to whichever task actually threads a real
/// `SessionActor` through, not to this one.
#[derive(Default)]
struct SessionEntry {
    subscribers: Vec<mpsc::Sender<ClientEvent>>,
}

/// The `SessionId`-keyed session/subscriber map `socket_server::accept_loop`
/// consults on every accepted connection. See the module doc comment for the
/// fan-out design.
pub struct SessionRegistry {
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    max_sessions: usize,
    max_subscribers_per_session: usize,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_SESSIONS, DEFAULT_MAX_SUBSCRIBERS_PER_SESSION)
    }

    /// Same as [`Self::new`], but with the availability ceilings (security
    /// review Important 3 / ruling W1-R33) overridable — production code has
    /// no reason to call this over [`Self::new`]; it exists so tests can hit
    /// a cap with a handful of sessions/subscribers rather than the tens of
    /// thousands [`DEFAULT_MAX_SESSIONS`] allows.
    pub fn with_limits(max_sessions: usize, max_subscribers_per_session: usize) -> Self {
        SessionRegistry {
            sessions: Mutex::new(HashMap::new()),
            max_sessions,
            max_subscribers_per_session,
        }
    }

    /// Mints a brand new `SessionId` and registers the creating connection
    /// as its first subscriber.
    ///
    /// `workspace_name` is accepted (not yet used) because the real
    /// `SessionActor` this registry hands off to eventually (Task 5/7) is
    /// constructed from it; this task's registry only needs to exist and
    /// hold the fan-out map correctly, not build that actor (see
    /// [`SessionEntry`]'s doc comment).
    ///
    /// Returns `None`, rather than minting anything, once this registry
    /// already holds `max_sessions` live entries (security review
    /// Important 3 / ruling W1-R33) — an unbounded map is an unbounded
    /// memory sink for a peer (or a bug) that just keeps sending
    /// `CreateSession`. Otherwise returns the new id, a [`Subscription`] to
    /// hand back to [`Self::detach`] once the creating connection ends, and
    /// the `Receiver` half the caller forwards to that connection's socket.
    pub fn create(
        &self,
        _workspace_name: String,
    ) -> Option<(SessionId, Subscription, mpsc::Receiver<ClientEvent>)> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= self.max_sessions {
            return None;
        }
        let session_id = SessionId::new();
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        // `SessionId::new()` mints a fresh UUIDv4, so this can never collide
        // with an existing entry — a plain `insert` (not `entry(..).or_default()`)
        // is correct and makes that non-collision assumption visible here
        // rather than silently relying on `or_default` to paper over it.
        sessions.insert(
            session_id,
            SessionEntry {
                subscribers: vec![tx.clone()],
            },
        );
        Some((session_id, Subscription(tx), rx))
    }

    /// Looks up an existing session and registers a brand new subscriber
    /// channel for it, so a *different* connection than the one that ran
    /// [`Self::create`] can watch the same session's events.
    ///
    /// Returns `None` if `session_id` names a session that either never
    /// existed on this registry, or whose every subscriber has since
    /// disconnected and been reaped (see the module doc comment), **or**
    /// whose subscriber count is already at `max_subscribers_per_session`
    /// (security review Important 3 / ruling W1-R33) — `publish` clones the
    /// event once per subscriber, so an unbounded subscriber count is an
    /// unbounded per-event amplifier. A real daemon backed by a persisted
    /// session store would fall back to that store here to distinguish
    /// "never existed" from "exists but nobody is currently watching it" and
    /// revive the session; this task's registry is purely in-memory and does
    /// not have a store to fall back to, so both cases (and now the capacity
    /// case) collapse to `None`. Documented rather than silently accepted as
    /// correct.
    ///
    /// Looks up and registers under one lock acquisition — see the module
    /// doc comment's "Locking" section for the TOCTOU this avoids.
    pub fn attach(
        &self,
        session_id: SessionId,
    ) -> Option<(Subscription, mpsc::Receiver<ClientEvent>)> {
        let mut sessions = self.sessions.lock().unwrap();
        // `get_mut`, never `entry(..).or_default()`: attaching must not be
        // able to conjure a session into existence.
        let entry = sessions.get_mut(&session_id)?;
        if entry.subscribers.len() >= self.max_subscribers_per_session {
            return None;
        }
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        entry.subscribers.push(tx.clone());
        Some((Subscription(tx), rx))
    }

    /// Removes one subscriber from `session_id`'s fan-out list, and removes
    /// the whole session entry once that was its last subscriber (see the
    /// module doc comment on why entries must not just accumulate forever).
    ///
    /// A no-op if `session_id` is already gone (e.g. `detach` racing another
    /// `detach` for the same session's last two subscribers, or being called
    /// twice for the same `Subscription` by mistake) — never panics on an
    /// already-cleaned-up session.
    pub fn detach(&self, session_id: SessionId, subscription: &Subscription) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Entry::Occupied(mut entry) = sessions.entry(session_id) {
            entry
                .get_mut()
                .subscribers
                .retain(|tx| !tx.same_channel(&subscription.0));
            if entry.get().subscribers.is_empty() {
                entry.remove();
            }
        }
    }

    /// Fans `event` out to every live subscriber of `session_id`, dropping
    /// it for any subscriber whose channel is currently full (see the module
    /// doc comment: backpressure a publisher must never block on) — counted
    /// and logged, never silent (code review Minor 1 / ruling W1-R33, the
    /// same principle this lane already applied to redaction drops in
    /// W1-R24) — and pruning any subscriber whose `Receiver` has already
    /// been dropped. A no-op — not an error — if `session_id` names a
    /// session with no (or no longer any) subscribers; there is no one to
    /// tell.
    ///
    /// # This registry's one lossy point (fix 1's loss policy)
    ///
    /// `drive_session`/`serve_connection` (`socket_server.rs`) are lossless:
    /// both apply real backpressure via `reserve()` rather than ever
    /// dropping a `ClientEvent` or `ClientRequest` (ruling W1-R32). This
    /// `try_send` is the one place in the whole pipeline that sheds instead
    /// — deliberately, because the alternative is letting one slow *watcher*
    /// stall the session for every other subscriber (module doc comment,
    /// "Handling a lagging or dead subscriber"). So: the connection layer
    /// never drops; the registry's per-subscriber fan-out does, bounded to a
    /// slow subscriber's own [`SUBSCRIBER_CHANNEL_CAPACITY`]-deep backlog,
    /// and every drop is counted here.
    ///
    /// Not `async`: `try_send` is the whole point (see the module doc
    /// comment), so this never needs to await anything, and can be called
    /// from a plain synchronous context — including, deliberately, this
    /// crate's own tests.
    pub fn publish(&self, session_id: SessionId, event: ClientEvent) {
        let mut sessions = self.sessions.lock().unwrap();
        let Entry::Occupied(mut entry) = sessions.entry(session_id) else {
            return;
        };
        let mut dropped_full = 0usize;
        entry.get_mut().subscribers.retain(|tx| {
            match tx.try_send(event.clone()) {
                Ok(()) => true,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped_full += 1;
                    // Keep the subscriber — it is slow, not gone; only the
                    // event is shed.
                    true
                }
                Err(mpsc::error::TrySendError::Closed(_)) => false,
            }
        });
        if dropped_full > 0 {
            tracing::warn!(
                session_id = %session_id,
                dropped = dropped_full,
                "publish: shed event for full subscriber channel(s) rather than \
                 stalling the session over one slow watcher"
            );
        }
        if entry.get().subscribers.is_empty() {
            entry.remove();
        }
    }
}

#[cfg(test)]
mod tests {
    //! Fix round 1, fix 7 (code review Minor 1): `publish`'s drop-on-full
    //! path is now counted and logged rather than silent (see `publish`'s
    //! doc comment). This is a functional regression test for the retained
    //! behavior underneath that logging — a full-but-not-closed subscriber
    //! must lose the one event, not be pruned — since `tracing::warn!`
    //! output itself is not asserted here (this workspace has no
    //! `tracing-test`-style capture harness; see
    //! `roundhouse-engine::session_actor::wire_redaction_for_session` for
    //! the precedent this lane already follows of testing the functional
    //! behavior, not the log line, for exactly this kind of drop-count fix).

    use super::*;
    use roundhouse_core::{EventPayload, NoteLevel};

    fn note(session_id: SessionId, text: &str) -> ClientEvent {
        ClientEvent::TaskEvent {
            session_id,
            task_id: None,
            payload: Box::new(EventPayload::Note {
                level: NoteLevel::Info,
                text: text.into(),
            }),
        }
    }

    #[test]
    fn publish_sheds_on_a_full_subscriber_without_pruning_it() {
        let registry = SessionRegistry::new();
        let (session_id, _creator_subscription, mut creator_events) =
            registry.create("test".into()).unwrap();

        // Fill the subscriber channel to capacity without ever draining it.
        for i in 0..SUBSCRIBER_CHANNEL_CAPACITY {
            registry.publish(session_id, note(session_id, &i.to_string()));
        }
        // One more publish must be dropped (the channel is full, not
        // closed) — never panic, and never prune the subscriber for being
        // merely slow rather than gone.
        registry.publish(session_id, note(session_id, "overflow"));

        // Draining one slot and publishing again must succeed — proving
        // the subscriber is still registered (a pruned subscriber's
        // `Receiver` would instead have observed its `Sender` dropped).
        let mut delivered = 0usize;
        creator_events
            .try_recv()
            .expect("the subscriber must still be attached and hold its buffered events");
        delivered += 1;
        registry.publish(session_id, note(session_id, "after-drain"));

        while creator_events.try_recv().is_ok() {
            delivered += 1;
        }
        // `SUBSCRIBER_CHANNEL_CAPACITY` filled the channel, "overflow" was
        // shed, and "after-drain" filled the one slot that draining above
        // freed — exactly one publish (the overflow) must have been
        // dropped out of `SUBSCRIBER_CHANNEL_CAPACITY + 2` total attempts.
        assert_eq!(
            delivered,
            SUBSCRIBER_CHANNEL_CAPACITY + 1,
            "exactly one publish (the overflow) must have been dropped; \
             the channel must not have grown past its capacity nor lost \
             more than the one shed event"
        );
    }
}
