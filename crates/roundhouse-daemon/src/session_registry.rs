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
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        SessionRegistry {
            sessions: Mutex::new(HashMap::new()),
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
    /// Returns the new id, a [`Subscription`] to hand back to [`Self::detach`]
    /// once the creating connection ends, and the `Receiver` half the caller
    /// forwards to that connection's socket.
    pub fn create(
        &self,
        _workspace_name: String,
    ) -> (SessionId, Subscription, mpsc::Receiver<ClientEvent>) {
        let session_id = SessionId::new();
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        // `SessionId::new()` mints a fresh UUIDv4, so this can never collide
        // with an existing entry — a plain `insert` (not `entry(..).or_default()`)
        // is correct and makes that non-collision assumption visible here
        // rather than silently relying on `or_default` to paper over it.
        self.sessions.lock().unwrap().insert(
            session_id,
            SessionEntry {
                subscribers: vec![tx.clone()],
            },
        );
        (session_id, Subscription(tx), rx)
    }

    /// Looks up an existing session and registers a brand new subscriber
    /// channel for it, so a *different* connection than the one that ran
    /// [`Self::create`] can watch the same session's events.
    ///
    /// Returns `None` if `session_id` names a session that either never
    /// existed on this registry, or whose every subscriber has since
    /// disconnected and been reaped (see the module doc comment). A real
    /// daemon backed by a persisted session store would fall back to that
    /// store here to distinguish "never existed" from "exists but nobody is
    /// currently watching it" and revive the session; this task's registry
    /// is purely in-memory and does not have a store to fall back to, so
    /// both cases collapse to `None`. Documented rather than silently
    /// accepted as correct.
    ///
    /// Looks up and registers under one lock acquisition — see the module
    /// doc comment's "Locking" section for the TOCTOU this avoids.
    pub fn attach(
        &self,
        session_id: SessionId,
    ) -> Option<(Subscription, mpsc::Receiver<ClientEvent>)> {
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);
        let mut sessions = self.sessions.lock().unwrap();
        // `get_mut`, never `entry(..).or_default()`: attaching must not be
        // able to conjure a session into existence.
        let entry = sessions.get_mut(&session_id)?;
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
    /// it silently for any subscriber whose channel is currently full (see
    /// the module doc comment: backpressure a publisher must never block
    /// on), and pruning any subscriber whose `Receiver` has already been
    /// dropped. A no-op — not an error — if `session_id` names a session
    /// with no (or no longer any) subscribers; there is no one to tell.
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
        entry.get_mut().subscribers.retain(|tx| {
            !matches!(
                tx.try_send(event.clone()),
                Err(mpsc::error::TrySendError::Closed(_))
            )
        });
        if entry.get().subscribers.is_empty() {
            entry.remove();
        }
    }
}
