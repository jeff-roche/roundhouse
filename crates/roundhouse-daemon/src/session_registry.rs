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
//! # Entry lifetime = actor lifetime, not subscriber-list emptiness (ruling
//! W1-R51, Phase 7 Task 7)
//!
//! Before Task 7, this registry never held a real `SessionActor` — a
//! session's whole registry footprint WAS its subscriber list, so reaping
//! the entry the moment that list emptied was the only sane rule. Task 7
//! binds a real `Arc<SessionActor>` into every [`SessionEntry`], and
//! reapplying the old rule unmodified forces a bad choice: either the actor
//! dies with the entry — so closing the one attached `round` client
//! (`Vec::retain`'s subscriber count hitting zero) cancels whatever that
//! session's actor is doing, breaking a headless `round run` the moment its
//! terminal disconnects — or the actor outlives the entry, and a later
//! `round attach --session ID` reports "unknown session" for a session that
//! is plainly still running.
//!
//! **The rule now: a [`SessionEntry`]'s lifetime is its actor's lifetime.**
//! [`detach`] and [`publish`]'s own dead-subscriber pruning remove
//! subscribers from the list exactly as before, but an emptied subscriber
//! list is no longer, by itself, a reason to remove the whole entry — a
//! session with zero currently-attached clients is a completely ordinary,
//! supported state (that is the entire point of headless `round run`).
//! [`remove`] is the new, explicit, actor-lifetime-driven reap path: a
//! caller that observes this session's actor has genuinely ended (e.g.
//! watching `SessionActor::subscribe()` for `SessionState::Closed`) calls it
//! to free the map entry. Nothing in this crate yet drives an actor to
//! `Closed` (Task 7 wires session CREATION, not a live work-submission path
//! — see `main.rs`'s module doc for why), so in practice, today, an entry's
//! lifetime is bounded only by the daemon process's own lifetime — a
//! deliberate, documented consequence, not a leak: [`DEFAULT_MAX_SESSIONS`]
//! is what bounds it, and it is now the REAL ceiling for the first time
//! (before this change the effective ceiling was
//! `max_subscribers_per_session` acting as a proxy, since every session
//! reaped itself the instant its one subscriber left).
//!
//! (`attach`ing to a `SessionId` this registry never created still returns
//! `None`, same as before — see [`attach`]'s doc comment.)
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
use std::sync::{Arc, Mutex};

use roundhouse_core::SessionId;
use roundhouse_engine::SessionActor;
use roundhouse_mcp::host::McpHost;
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

/// One session's registry-side bookkeeping: the real, already-constructed
/// `SessionActor` that IS this session (Phase 7, Task 7 — the actor is built
/// by the caller, in an async context with access to the isolate/policy/MCP
/// resources this registry itself has none of, and handed to [`create`]
/// already-built) and the subscriber fan-out list. See the module doc
/// comment ("Entry lifetime = actor lifetime") for why the two no longer
/// share one reap condition.
struct SessionEntry {
    actor: Arc<SessionActor>,
    /// Kept alive for exactly as long as `actor` is (see the module doc
    /// comment, "Entry lifetime = actor lifetime"): a session with any
    /// configured MCP servers spawned real child processes for them
    /// (`McpHost::start`), and dropping this `Arc` early — the moment its
    /// creating connection's subscriber-list entry emptied, under the OLD
    /// rule this module replaces — would have nothing left keeping those
    /// processes' handles referenced. `None` for a session with zero
    /// configured MCP servers, the common case.
    #[allow(dead_code)]
    mcp_host: Option<Arc<McpHost>>,
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

    /// Registers an already-constructed `actor` as a brand new session,
    /// keyed on `actor.session_id()`, with the creating connection as its
    /// first subscriber.
    ///
    /// Takes the actor already built rather than building one itself
    /// (Phase 7, Task 7): constructing a real `SessionActor` needs async
    /// work this registry has no business doing directly — isolation
    /// (`Isolate::prepare`), MCP host startup (`McpHost::start`), redaction
    /// wiring — all before `SessionActor::new` itself, which is
    /// synchronous. `socket_server::drive_session`'s `CreateSession` branch
    /// does that async construction and hands the finished actor here; see
    /// `session_bootstrap` for the real construction path.
    ///
    /// Returns `None`, rather than registering anything, once this registry
    /// already holds `max_sessions` live entries (security review
    /// Important 3 / ruling W1-R33) — an unbounded map is an unbounded
    /// memory sink for a peer (or a bug) that just keeps sending
    /// `CreateSession`. Otherwise returns the new id, a [`Subscription`] to
    /// hand back to [`Self::detach`] once the creating connection ends, and
    /// the `Receiver` half the caller forwards to that connection's socket.
    ///
    /// # The channel is minted *before* the lock is taken (fix round 2, M2)
    ///
    /// An earlier version of this method minted the channel *after*
    /// acquiring `self.sessions`'s lock. This crate's `mpsc::channel` itself
    /// cannot panic, but keeping the mint outside the critical section
    /// (alongside `actor.session_id()`, an infallible getter) keeps the
    /// critical section itself minimal and un-panicking by inspection,
    /// which is what actually matters for `std::sync::Mutex` poisoning —
    /// see the module doc comment's "Locking" section (ruling W1-R8).
    ///
    /// The `max_sessions` check and the `insert` still happen under this
    /// one lock acquisition — see the module doc comment's "Locking"
    /// section for the TOCTOU that pairing avoids.
    pub fn create(
        &self,
        actor: Arc<SessionActor>,
        mcp_host: Option<Arc<McpHost>>,
    ) -> Option<(SessionId, Subscription, mpsc::Receiver<ClientEvent>)> {
        let session_id = actor.session_id();
        let (tx, rx) = mpsc::channel(SUBSCRIBER_CHANNEL_CAPACITY);

        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= self.max_sessions {
            return None;
        }
        // `session_id` came off a freshly-minted `SessionActor` (see
        // `session_bootstrap`, this registry's only real caller), which
        // itself mints a fresh `SessionId::new()` — so this can never
        // collide with an existing entry. A plain `insert` (not
        // `entry(..).or_default()`) is correct and makes that non-collision
        // assumption visible here rather than silently relying on
        // `or_default` to paper over it.
        sessions.insert(
            session_id,
            SessionEntry {
                actor,
                mcp_host,
                subscribers: vec![tx.clone()],
            },
        );
        Some((session_id, Subscription(tx), rx))
    }

    /// A clone of the live `SessionActor` bound to `session_id`, or `None`
    /// if this registry has no entry for it (never created, or already
    /// [`remove`](Self::remove)d). Exists for a future post-handshake
    /// request-routing consumer (W1-R37/52: only the connection that ran
    /// [`Self::create`] may ever route a request to this actor) — nothing
    /// in this crate calls this yet (see `socket_server::drive_session`'s
    /// module doc comment for why there is currently nothing to route).
    pub fn actor(&self, session_id: SessionId) -> Option<Arc<SessionActor>> {
        let sessions = self.sessions.lock().unwrap();
        sessions.get(&session_id).map(|entry| entry.actor.clone())
    }

    /// Unconditionally removes `session_id`'s entry, regardless of its
    /// current subscriber count — the actor-lifetime-driven reap path (see
    /// the module doc comment, "Entry lifetime = actor lifetime"). A caller
    /// that has observed this session's actor end its life (e.g. its
    /// `SessionActor::subscribe()` watch channel reporting
    /// `SessionState::Closed`) calls this to free the map entry; a no-op if
    /// the entry is already gone.
    pub fn remove(&self, session_id: SessionId) {
        self.sessions.lock().unwrap().remove(&session_id);
    }

    /// Looks up an existing session and registers a brand new subscriber
    /// channel for it, so a *different* connection than the one that ran
    /// [`Self::create`] can watch the same session's events.
    ///
    /// Returns `None` if `session_id` names a session that either never
    /// existed on this registry, or whose actor has since ended and been
    /// [`remove`](Self::remove)d (see the module doc comment, "Entry
    /// lifetime = actor lifetime" — a session with zero CURRENTLY attached
    /// subscribers, by contrast, is an ordinary, fully attachable state
    /// since Task 7), **or** whose subscriber count is already at
    /// `max_subscribers_per_session`
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

    /// Removes one subscriber from `session_id`'s fan-out list. **Does not**
    /// remove the whole session entry, even if that was its last subscriber
    /// — see the module doc comment, "Entry lifetime = actor lifetime"
    /// (ruling W1-R51): a session's actor may still be doing real work with
    /// nobody currently attached to watch it (a headless `round run` whose
    /// terminal disconnected), and reaping the entry here would make a
    /// later `round attach` to that same, still-live session report
    /// "unknown session." [`Self::remove`] is the actor-lifetime-driven
    /// reap path.
    ///
    /// A no-op if `session_id` is already gone (e.g. already
    /// [`remove`](Self::remove)d, or `detach` being called twice for the
    /// same `Subscription` by mistake) — never panics on an
    /// already-cleaned-up session.
    pub fn detach(&self, session_id: SessionId, subscription: &Subscription) {
        let mut sessions = self.sessions.lock().unwrap();
        if let Entry::Occupied(mut entry) = sessions.entry(session_id) {
            entry
                .get_mut()
                .subscribers
                .retain(|tx| !tx.same_channel(&subscription.0));
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
        // Does NOT remove the entry even if `subscribers` is now empty —
        // see the module doc comment, "Entry lifetime = actor lifetime"
        // (ruling W1-R51). `entry` (an `Entry::Occupied`) is dropped here
        // without a `.remove()` call, same as `detach` above.
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
    use roundhouse_core::{EventPayload, NoteLevel, OnDegrade, SessionSpec, SessionState, Tier};
    use roundhouse_policy::engine::PolicyEngine;
    use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
    use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
    use roundhouse_sandbox::Isolate;

    use crate::test_support::runner;

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

    /// A minimal but real `SessionActor` — every mechanism it wraps
    /// (isolation, policy, redaction) is real; only the isolate's probe
    /// result is faked (`test_with_probe`, no real bwrap/landlock syscalls),
    /// matching `roundhouse-engine`'s own `admission_integration.rs` test
    /// helper.
    async fn real_actor(dir: &std::path::Path) -> Arc<SessionActor> {
        let store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        let policy = Arc::new(PolicyEngine::from_rules(vec![]));
        let isolate: Arc<dyn Isolate> = Arc::new(BwrapLandlockIsolate::test_with_probe(
            MechanismProbeReport {
                landlock: MechanismStatus::Available,
                bwrap: MechanismStatus::Available,
                seccomp: MechanismStatus::Available,
                seatbelt: MechanismStatus::Unavailable {
                    reason: "n/a".into(),
                },
            },
        ));
        let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
        let handle = isolate.prepare(&spec).await.unwrap();
        Arc::new(SessionActor::new(
            SessionId::new(),
            writer,
            SessionState::Running,
            runner(),
            policy,
            dir.join("state"),
            dir.join("daemon-binary"),
            isolate,
            handle,
            spec,
            vec![],
        ))
    }

    #[tokio::test]
    async fn publish_sheds_on_a_full_subscriber_without_pruning_it() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SessionRegistry::new();
        let actor = real_actor(dir.path()).await;
        let (session_id, _creator_subscription, mut creator_events) =
            registry.create(actor, None).unwrap();

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

    /// The load-bearing regression this whole rework exists to prove
    /// (ruling W1-R51): detaching a session's LAST subscriber must no
    /// longer reap the entry — a fresh `attach` afterward must still
    /// succeed, proving the actor (and therefore whatever it may still be
    /// doing) survived the disconnect. Before this change, `detach`
    /// emptying the subscriber list removed the whole map entry, and this
    /// exact `attach` call would have returned `None`.
    #[tokio::test]
    async fn detaching_the_last_subscriber_does_not_reap_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SessionRegistry::new();
        let actor = real_actor(dir.path()).await;
        let (session_id, creator_subscription, _creator_events) =
            registry.create(actor, None).unwrap();

        registry.detach(session_id, &creator_subscription);

        assert!(
            registry.attach(session_id).is_some(),
            "a session must remain attachable after its last subscriber detaches — \
             its actor (and any work it may still be doing) outlives the connection \
             that created it"
        );
    }

    /// The same property from `publish`'s pruning side: a subscriber whose
    /// `Receiver` has been dropped (observed by `publish` as `Closed`, not
    /// merely `Full`) is pruned from the list, but — post-W1-R51 — that
    /// pruning down to zero subscribers must not reap the entry either.
    #[tokio::test]
    async fn publish_pruning_the_last_closed_subscriber_does_not_reap_the_session() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SessionRegistry::new();
        let actor = real_actor(dir.path()).await;
        let (session_id, _creator_subscription, creator_events) =
            registry.create(actor, None).unwrap();

        // Drop the only receiver so the sender `publish` holds becomes
        // `Closed` rather than merely `Full`.
        drop(creator_events);
        registry.publish(session_id, note(session_id, "nobody is listening"));

        assert!(
            registry.attach(session_id).is_some(),
            "pruning a closed subscriber down to zero must not reap the session either"
        );
    }

    /// [`SessionRegistry::remove`] is the one thing that DOES end a
    /// session's attachability, unconditionally — proving the two halves of
    /// "entry lifetime = actor lifetime" independently: subscriber-count
    /// changes never reap (proven above), and `remove` always does.
    #[tokio::test]
    async fn remove_reaps_the_session_regardless_of_subscriber_count() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SessionRegistry::new();
        let actor = real_actor(dir.path()).await;
        let (session_id, _creator_subscription, _creator_events) =
            registry.create(actor, None).unwrap();

        registry.remove(session_id);

        assert!(
            registry.attach(session_id).is_none(),
            "remove() must make the session unattachable"
        );
    }
}
