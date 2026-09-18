//! Store-side commit notification (Phase 8 Task 21, Task 1): the primitive a follower
//! (SSE or UDS) uses to learn "a new event committed for this session" without polling
//! the database. This is deliberately NOT a broadcast of the event itself — §the
//! architecture's own rule that "the published payload is the stored row" means a
//! follower always re-reads the committed row through `events_after`/`session_events`
//! rather than being handed anything out of memory. `CommitFeed`/`CommitWatch` only ever
//! carry a signal to go re-read, never event content.
//!
//! Built on `tokio::sync::watch`, one channel per session, created lazily on first
//! `watch()` and pruned once its last `CommitWatch` drops. The channel's carried value is
//! a **generation counter** (`u64`), not a `seq` — `notify()` has no seq to hand out (a
//! batch can commit several seqs for one session in one call) and `seq 0` is a real,
//! valid event, so a seq-shaped "0 means nothing yet" sentinel would be ambiguous. The
//! generation is purely a wake signal: "something committed since you last looked," never
//! "here is what committed."

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use roundhouse_core::SessionId;
use tokio::sync::watch;

/// A handle to every session's commit-notification channel. Cheap to clone (an `Arc`
/// around the map) — `StorePool::commit_feed`/`with_commit_feed` are how callers share
/// one `CommitFeed` across every `StorePool`/`EventWriter` opened over the same database.
#[derive(Clone, Default)]
pub struct CommitFeed {
    senders: Arc<Mutex<HashMap<SessionId, watch::Sender<u64>>>>,
}

/// Hand-written rather than derived: a derived `Debug` would walk into
/// `watch::Sender<u64>`'s own `Debug`, which is harmless here (the carried value is just a
/// generation counter, not row content) but still more than this type needs to expose.
/// `StorePool` derives `Debug` and carries a `CommitFeed` field, so this type needs SOME
/// `Debug` impl for that derive to compile; this one reports only how many sessions are
/// currently tracked, matching this crate's existing convention (see `pool.rs`'s own
/// `StorePool` doc comment: "renders the pool's status ... and no row content").
impl std::fmt::Debug for CommitFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tracked_sessions = self
            .senders
            .lock()
            .map(|senders| senders.len())
            .unwrap_or(0);
        f.debug_struct("CommitFeed")
            .field("tracked_sessions", &tracked_sessions)
            .finish()
    }
}

impl CommitFeed {
    /// Bumps `session_id`'s generation counter, waking every pending `CommitWatch::
    /// changed()` for it. A no-op if nobody has ever called `watch(session_id)` — there is
    /// no channel to bump and creating one here would only leak an entry nothing will ever
    /// prune (a fresh channel starts with zero receivers, so it would immediately qualify
    /// for the same prune this function does below, except this call has no receiver-count
    /// to check against before it created the entry).
    ///
    /// Sync on purpose (per this type's own doc comment: callable from inside an `interact`
    /// closure). **Must be called only AFTER the commit it announces returned `Ok`** — see
    /// `writer.rs`'s `spawn_writer`, the sole production caller, for why: a session must
    /// never be told "something changed" for a write that never landed.
    ///
    /// Prunes the map entry once it has zero receivers — the channel itself survives via
    /// any live `CommitWatch`'s own `Arc` to the shared state (a `tokio::sync::watch`
    /// receiver does not depend on the sender still being reachable through this map to
    /// keep working), so pruning here only stops this map from growing unboundedly across
    /// a long-running daemon's full history of sessions, most of which nobody is watching
    /// by the time they close.
    pub fn notify(&self, session_id: SessionId) {
        let mut senders = self.senders.lock().expect("CommitFeed mutex poisoned");
        let Some(tx) = senders.get(&session_id) else {
            return;
        };
        tx.send_modify(|generation| *generation = generation.wrapping_add(1));
        if tx.receiver_count() == 0 {
            senders.remove(&session_id);
        }
    }

    /// Returns a `CommitWatch` following `session_id`'s generation counter, creating its
    /// channel on first use. Multiple `watch()` calls for the same session share one
    /// channel — every `CommitWatch` for that session wakes on the same `notify()`.
    pub fn watch(&self, session_id: SessionId) -> CommitWatch {
        let mut senders = self.senders.lock().expect("CommitFeed mutex poisoned");
        let tx = senders
            .entry(session_id)
            .or_insert_with(|| watch::channel(0u64).0);
        CommitWatch { rx: tx.subscribe() }
    }
}

/// A follower's view of one session's commit generation counter. Not `Clone`: each
/// `CommitWatch` tracks its own "have I seen the latest generation" state independently
/// (`tokio::sync::watch::Receiver`'s own semantics), so sharing one between two followers
/// with different read cursors would make one's `mark_seen()` silently swallow the other's
/// pending wake.
pub struct CommitWatch {
    rx: watch::Receiver<u64>,
}

impl CommitWatch {
    /// Marks the current generation as seen. Call this BEFORE reading the store, not
    /// after: a `notify()` that lands between `mark_seen()` and the read is still safely
    /// caught by the NEXT `changed()` (it arrives after this call's "seen" mark), whereas a
    /// `notify()` that lands between the read and `mark_seen()` would otherwise be lost —
    /// the read might have missed it, but marking seen afterward would consume it anyway.
    pub fn mark_seen(&mut self) {
        self.rx.borrow_and_update();
    }

    /// Resolves once a `notify()` has landed for a generation newer than the last one
    /// `mark_seen()`/`changed()` observed. Cancel-safe (`tokio::sync::watch::Receiver::
    /// changed()`'s own documented guarantee): dropping this future before it resolves —
    /// e.g. a `select!` arm that lost a race — does not consume the pending notification,
    /// so a later `changed()` call still sees it.
    ///
    /// Only ever returns early with no wake if every `CommitFeed` handle for this session
    /// has been dropped entirely (the channel's sender side is gone for good), which no
    /// production caller does today — a `CommitFeed` is shared for the process's lifetime
    /// via `StorePool`/`with_commit_feed`, never dropped out from under a live watcher.
    pub async fn changed(&mut self) {
        let _ = self.rx.changed().await;
    }
}
