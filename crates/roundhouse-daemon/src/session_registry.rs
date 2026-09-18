//! `SessionId`-keyed registry of live sessions for `socket_server::accept_loop`.
//!
//! Task 2's `serve` served exactly one connection to exactly one session; a
//! real daemon must let an arbitrary number of `round` clients create
//! sessions and let an arbitrary number of *other* clients later attach to
//! any of them (§11.3). That needs a place to look a `SessionId` up by value,
//! so `Attach` can find a session a *different* connection created, and a
//! way to route a creator's post-handshake requests to the session's live
//! `SessionActor`.
//!
//! # Events do not flow through this registry (Phase 8 Task 21)
//!
//! Events come from the store: each connection runs its own
//! `roundhouse_store::SessionFollower`, which reads the session's committed
//! log from its cursor and then waits on the store's `CommitFeed` for more
//! (see `socket_server::drive_established_session`). The registry no longer
//! fans anything out. A [`Subscription`] is just a counted token: it holds one
//! of the session's [`DEFAULT_MAX_SUBSCRIBERS_PER_SESSION`] slots, which still
//! bounds how many connections (each with its own follower and store reads)
//! one session can have attached, and [`SessionRegistry::detach`] gives the
//! slot back.
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
//! [`detach`] removes subscribers from the list exactly as before, but an
//! emptied subscriber list is no longer, by itself, a reason to remove the
//! whole entry — a
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
//! [`register_headless`] (Phase 8, Task 4) is a second entry point onto that
//! same zero-subscriber state: a headless caller (a scheduled trigger
//! delivery, with no socket client attached) starts a session there
//! directly, rather than arriving after `create`'s one subscriber detaches.
//! It shares `create`'s exact insertion semantics (the `max_sessions` check,
//! keying on `actor.session_id()`) and takes no subscriber slot.
//!
//! (`attach`ing to a `SessionId` this registry has no entry for still returns
//! `None` — see [`attach`]'s doc comment. `socket_server::drive_session` then
//! falls back to the store, which can still replay a closed or reaped
//! session's log.)
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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use roundhouse_core::SessionId;
use roundhouse_engine::mcp_spawner::SessionMcp;
use roundhouse_engine::SessionActor;
use roundhouse_mcp::host::McpHost;

/// Default ceiling on the number of live sessions one registry will hold at
/// once (security review Important 3 / ruling W1-R33). Generous relative to
/// any realistic single-daemon workload — this is a circuit breaker against
/// unbounded growth (a bug, or a peer that just keeps sending
/// `CreateSession`), not an operational tuning knob. Each entry is small
/// (an actor handle and a `Vec` of subscription ids), so this bounds memory
/// in the pathological case
/// without constraining real usage.
const DEFAULT_MAX_SESSIONS: usize = 10_000;

/// Default ceiling on the number of subscribers (creator + every `Attach`)
/// one session will accept (security review Important 3 / ruling W1-R33).
/// Each subscriber is a connection running its own store follower, so an
/// unbounded subscriber count is an unbounded per-commit read amplifier: every
/// commit wakes every follower, and each one re-reads the store.
const DEFAULT_MAX_SUBSCRIBERS_PER_SESSION: usize = 64;

/// A counted token for one call to [`SessionRegistry::create`] or
/// [`SessionRegistry::attach`], to be handed back to [`SessionRegistry::detach`]
/// once that subscriber's connection ends.
///
/// Deliberately opaque and not `Clone`: it holds one of the session's
/// subscriber slots, and the id inside it names exactly that slot among the
/// session's `Vec` of them. It carries no events: those come from the store
/// (see the module doc comment).
pub struct Subscription(u64);

/// One session's registry-side bookkeeping: the real, already-constructed
/// `SessionActor` that IS this session (Phase 7, Task 7 — the actor is built
/// by the caller, in an async context with access to the isolate/policy/MCP
/// resources this registry itself has none of, and handed to [`create`]
/// already-built) and the ids of its live subscriptions. See the module doc
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
    /// This session's MCP dispatch handle (ruling W1-R119), so a
    /// post-handshake turn can actually dispatch to the MCP servers whose
    /// tools this session already offers the model. Distinct from
    /// `mcp_host`, which is the *process* supervisor: `mcp_host` keeps the
    /// child processes alive, `mcp` is what routes a tool call to them.
    /// `None` for a session with zero configured MCP servers.
    mcp: Option<SessionMcp>,
    subscribers: Vec<u64>,
}

/// The `SessionId`-keyed session/subscriber map `socket_server::accept_loop`
/// consults on every accepted connection. See the module doc comment.
pub struct SessionRegistry {
    sessions: Mutex<HashMap<SessionId, SessionEntry>>,
    /// Mints each [`Subscription`]'s id. Unique across every session this
    /// registry ever holds, so a stale token can never name another slot.
    next_subscription: AtomicU64,
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
            next_subscription: AtomicU64::new(0),
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
    /// `CreateSession`. Otherwise returns the new id and a [`Subscription`] to
    /// hand back to [`Self::detach`] once the creating connection ends.
    ///
    /// The `max_sessions` check and the `insert` happen under one lock
    /// acquisition — see the module doc comment's "Locking" section for the
    /// TOCTOU that pairing avoids.
    pub fn create(
        &self,
        actor: Arc<SessionActor>,
        mcp_host: Option<Arc<McpHost>>,
        mcp: Option<SessionMcp>,
    ) -> Option<(SessionId, Subscription)> {
        let session_id = actor.session_id();
        let subscription = self.mint_subscription();

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
                mcp,
                subscribers: vec![subscription.0],
            },
        );
        Some((session_id, subscription))
    }

    /// A fresh [`Subscription`] id, minted outside the lock (fix round 2,
    /// M2's reasoning: keep the critical section minimal).
    fn mint_subscription(&self) -> Subscription {
        Subscription(self.next_subscription.fetch_add(1, Ordering::Relaxed))
    }

    /// Registers an already-constructed `actor` as a brand new session, the
    /// same way [`Self::create`] does, but with **zero subscribers** — for a
    /// headless caller (Phase 8, Task 4: a
    /// scheduled trigger delivery) that has no connection to hold a
    /// subscriber slot.
    ///
    /// Zero-subscriber [`SessionEntry`]s are already a first-class, tested
    /// state in this module (ruling W1-R51: "entry lifetime = actor
    /// lifetime", not subscriber-list emptiness — see the module doc
    /// comment) — every session created via [`Self::create`] reaches this
    /// exact state the moment its one subscriber detaches, and stays fully
    /// attachable and functional. This method just starts a session there
    /// directly, instead of arriving after a detach. Nothing about that
    /// invariant is weakened by giving callers a direct path to it.
    ///
    /// Same `max_sessions` semantics as [`Self::create`]: returns `None`,
    /// registering nothing, once this registry already holds `max_sessions`
    /// live entries — see that method's doc comment for the full rationale.
    /// Returns the new session's id on success; a later `round attach
    /// --session ID` (or this crate's own [`Self::attach`]) can still mint
    /// this session's first real subscriber at any time, exactly as if a
    /// normal `create`d session's one subscriber had detached immediately.
    pub fn register_headless(
        &self,
        actor: Arc<SessionActor>,
        mcp_host: Option<Arc<McpHost>>,
        mcp: Option<SessionMcp>,
    ) -> Option<SessionId> {
        let session_id = actor.session_id();

        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= self.max_sessions {
            return None;
        }
        // Same non-collision reasoning as `create`'s own `insert` (never
        // `entry(..).or_default()`): `session_id` comes off a
        // freshly-minted `SessionActor`, so this can never collide with an
        // existing entry.
        sessions.insert(
            session_id,
            SessionEntry {
                actor,
                mcp_host,
                mcp,
                subscribers: Vec::new(),
            },
        );
        Some(session_id)
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

    /// A clone of the live [`SessionMcp`] bound to `session_id`, or `None`
    /// if this registry has no entry for it **or** that session configured
    /// no MCP servers (ruling W1-R119). `SessionMcp` is `Clone` and holds
    /// an `Arc<McpExecutor>`, so every clone dispatches through the one
    /// executor this session's `SessionActor::register_mcp` was told about
    /// — never a second, independently-policed one.
    ///
    /// Paired with [`Self::actor`] by `socket_server::run_submitted_turn`:
    /// a turn needs both, and reading them together is what lets a
    /// model-issued MCP tool call actually dispatch instead of hitting
    /// `run_agent_loop`'s "no MCP servers are configured" refusal.
    pub fn session_mcp(&self, session_id: SessionId) -> Option<SessionMcp> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .get(&session_id)
            .and_then(|entry| entry.mcp.clone())
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

    /// Whether this registry is already at `max_sessions` — a cheap,
    /// best-effort pre-check (fix round 1, SHOULD item) for a caller about
    /// to do expensive work (`session_bootstrap::create_real_session`:
    /// real isolation `prepare`, proxy registration, and potentially
    /// `McpHost::start` spawning real subprocesses) before ever calling
    /// [`Self::create`]. This is deliberately advisory, not a replacement
    /// for `create`'s own atomic check-then-insert: a peer racing many
    /// connections concurrently could still see `false` here and then lose
    /// the real race inside `create` (whose isolation/MCP work, already
    /// done by then, is a separate, documented, accepted gap — see the
    /// task report). What this DOES close: a single peer looping
    /// `CreateSession` sequentially past the cap no longer does a full
    /// isolation-prepare/MCP-spawn for every rejected attempt, only for the
    /// ones that make it past this check.
    pub fn is_full(&self) -> bool {
        self.sessions.lock().unwrap().len() >= self.max_sessions
    }

    /// Looks up a live session and takes one of its subscriber slots, so a
    /// *different* connection than the one that ran [`Self::create`] can
    /// watch the same session.
    ///
    /// Returns `None` if `session_id` has no entry here — it never existed on
    /// this registry, or its actor has since ended and been
    /// [`remove`](Self::remove)d (see the module doc comment, "Entry lifetime
    /// = actor lifetime" — a session with zero CURRENTLY attached subscribers,
    /// by contrast, is an ordinary, fully attachable state since Task 7) —
    /// **or** its subscriber count is already at `max_subscribers_per_session`
    /// (security review Important 3 / ruling W1-R33). A caller that needs to
    /// tell the capacity case apart can check [`Self::actor`]:
    /// `socket_server::drive_session` does, and replays a session with no
    /// live entry from the store instead.
    ///
    /// Looks up and registers under one lock acquisition — see the module
    /// doc comment's "Locking" section for the TOCTOU this avoids.
    pub fn attach(&self, session_id: SessionId) -> Option<Subscription> {
        let subscription = self.mint_subscription();
        let mut sessions = self.sessions.lock().unwrap();
        // `get_mut`, never `entry(..).or_default()`: attaching must not be
        // able to conjure a session into existence.
        let entry = sessions.get_mut(&session_id)?;
        if entry.subscribers.len() >= self.max_subscribers_per_session {
            return None;
        }
        entry.subscribers.push(subscription.0);
        Some(subscription)
    }

    /// Gives one subscriber slot back. **Does not**
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
                .retain(|id| *id != subscription.0);
        }
    }

    /// Test-only observability: `session_id`'s current subscriber count, or
    /// `None` if this registry has no entry for it. `SessionEntry`'s
    /// `subscribers` field is private by design (every production reader
    /// goes through `attach`/`detach`, never a raw count), but
    /// [`Self::register_headless`]'s whole distinguishing property from
    /// [`Self::create`] is that it starts a session with a subscriber count
    /// of exactly zero — `crate::session_manager`'s own tests need a direct
    /// way to assert that, not just an indirect one.
    #[cfg(test)]
    pub(crate) fn subscriber_count_for_test(&self, session_id: SessionId) -> Option<usize> {
        self.sessions
            .lock()
            .unwrap()
            .get(&session_id)
            .map(|entry| entry.subscribers.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::real_actor;

    /// Ruling W1-R119 (Task 8 fix round 1): the registry must actually
    /// **retain** the `SessionMcp` it is given, and hand it back — that is
    /// the seam whose absence made `socket_server::run_submitted_turn` pass
    /// `mcp: None` while the session's MCP tools were still offered to the
    /// model, so every model-issued MCP call got the honest "no MCP servers
    /// are configured for this session" refusal.
    ///
    /// Uses a real `SessionMcp` (the test-gated `SessionMcp::from_parts`,
    /// not `start_session_mcp` — `create_real_session`'s MCP path spawns a
    /// real subprocess, too heavy for a unit test, which is the same reason
    /// `session_bootstrap`'s own `apply_resolved_mcp_servers` tests exist),
    /// and asserts on `resolved_servers()` rather than merely `is_some()`:
    /// a registry that returned some *other* `SessionMcp` would pass an
    /// `is_some()` check.
    mod session_mcp_retention {
        use super::*;
        use roundhouse_engine::mcp_spawner::{EngineTaskSpawner, SessionMcp};
        use roundhouse_mcp::executor::TaskSpawner as McpTaskSpawner;
        use roundhouse_mcp::namespace::ToolNamespace;
        use roundhouse_mcp::transport::McpTransport;
        use roundhouse_mcp::wire::{DiscoverResult, McpError, McpResult, ToolCallRequest};
        use roundhouse_policy::engine::PolicyEngine;
        use roundhouse_policy::sealed::SealedContext;
        use roundhouse_policy::ServerId;

        const FAKE_SERVER: &str = "fake-server";

        struct FakeTransport;

        #[async_trait::async_trait]
        impl McpTransport for FakeTransport {
            async fn discover(&self) -> Result<DiscoverResult, McpError> {
                unreachable!("not exercised by this test")
            }
            async fn call_tool(&self, _req: ToolCallRequest) -> Result<McpResult, McpError> {
                unreachable!("not exercised by this test")
            }
            async fn shutdown(&self) -> Result<(), McpError> {
                Ok(())
            }
        }

        fn fake_session_mcp(
            dir: &std::path::Path,
            writer: roundhouse_store::EventWriter,
        ) -> SessionMcp {
            let ctx = SealedContext {
                state_dir: dir.join("state"),
                daemon_binary: dir.join("daemon-binary"),
                resolved_mcp_servers: Default::default(),
                requested_tier: roundhouse_core::Tier::Sandbox,
                attested_tier: roundhouse_core::Tier::Sandbox,
                home: roundhouse_policy::sealed::home_dir(),
            };
            let policy = Arc::new(
                PolicyEngine::from_rules(vec![])
                    .with_sealed_ctx_provider(Arc::new(move || ctx.clone())),
            );
            let connections: Vec<(ServerId, Arc<dyn McpTransport>)> =
                vec![(ServerId(FAKE_SERVER.to_string()), Arc::new(FakeTransport))];
            let task_spawner: Arc<dyn McpTaskSpawner> = Arc::new(EngineTaskSpawner::new(
                crate::test_support::runner(),
                writer,
                SessionId::new(),
            ));
            SessionMcp::from_parts(
                connections,
                ToolNamespace::build(&[]).unwrap(),
                policy,
                task_spawner,
            )
            .expect("the test PolicyEngine has a real sealed_ctx_provider installed")
        }

        #[tokio::test]
        async fn create_retains_the_session_mcp_and_session_mcp_hands_it_back() {
            let dir = tempfile::tempdir().unwrap();
            let registry = SessionRegistry::new();
            let actor = real_actor(dir.path()).await;
            let mcp = fake_session_mcp(dir.path(), actor.writer().clone());

            let (session_id, _subscription) = registry.create(actor, None, Some(mcp)).unwrap();

            let retained = registry
                .session_mcp(session_id)
                .expect("the registry must hand back the SessionMcp it was created with");
            assert_eq!(
                retained.resolved_servers(),
                vec![FAKE_SERVER.to_string()],
                "the retained SessionMcp must be the one this session was built with, not \
                 some other instance"
            );
        }

        /// The other half: a session created with no MCP servers must report
        /// `None`, not an empty-but-present handle — otherwise the assertion
        /// above would hold for a registry that fabricated one.
        #[tokio::test]
        async fn a_session_created_without_mcp_reports_none() {
            let dir = tempfile::tempdir().unwrap();
            let registry = SessionRegistry::new();
            let actor = real_actor(dir.path()).await;
            let (session_id, _subscription) = registry.create(actor, None, None).unwrap();
            assert!(registry.session_mcp(session_id).is_none());
        }
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
        let (session_id, creator_subscription) = registry.create(actor, None, None).unwrap();

        registry.detach(session_id, &creator_subscription);

        assert!(
            registry.attach(session_id).is_some(),
            "a session must remain attachable after its last subscriber detaches — \
             its actor (and any work it may still be doing) outlives the connection \
             that created it"
        );
    }

    /// A [`Subscription`] is a counted slot: once a session holds
    /// `max_subscribers_per_session` of them, `attach` refuses, and
    /// detaching one gives exactly that slot back.
    #[tokio::test]
    async fn detach_frees_exactly_one_subscriber_slot() {
        let dir = tempfile::tempdir().unwrap();
        let registry = SessionRegistry::with_limits(4, 2);
        let actor = real_actor(dir.path()).await;
        let (session_id, creator) = registry.create(actor, None, None).unwrap();
        let viewer = registry.attach(session_id).expect("one slot is still free");
        assert!(
            registry.attach(session_id).is_none(),
            "a third subscriber must be refused at max_subscribers_per_session = 2"
        );

        registry.detach(session_id, &viewer);
        assert_eq!(registry.subscriber_count_for_test(session_id), Some(1));
        let again = registry
            .attach(session_id)
            .expect("detaching the viewer must free its slot");

        // Detaching the same token twice must not free a second slot.
        registry.detach(session_id, &viewer);
        assert_eq!(registry.subscriber_count_for_test(session_id), Some(2));
        registry.detach(session_id, &creator);
        registry.detach(session_id, &again);
        assert_eq!(registry.subscriber_count_for_test(session_id), Some(0));
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
        let (session_id, _creator_subscription) = registry.create(actor, None, None).unwrap();

        registry.remove(session_id);

        assert!(
            registry.attach(session_id).is_none(),
            "remove() must make the session unattachable"
        );
    }
}
