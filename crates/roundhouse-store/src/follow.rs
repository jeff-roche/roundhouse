//! `SessionFollower`: a cancel-safe catch-up-then-follow reader over one session's event
//! log (Phase 8 Task 21, Task 3). Built on `CommitFeed`/`CommitWatch` (`commit_feed.rs`)
//! and the sync, paged `events_after`/`session_head` (`session_events.rs`): a follower
//! first drains everything already committed after its starting cursor, then waits for a
//! `CommitFeed::notify` wake and re-reads, forever, in `seq` order.
//!
//! `next()` is the `tokio::select!` arm the daemon's UDS connection loop races against
//! cancellation and client input, so it must be genuinely cancel-safe: dropping a `next()`
//! future at any await point must neither lose a committed event nor return one twice. The
//! cursor advances only at the moment an event is actually handed back to the caller — the
//! last few lines of `next()`, which contain no `.await` of their own — never while merely
//! reading or buffering a page, which is what makes that guarantee hold.
//!
//! Deliberately generic over [`PageSource`] rather than hard-wired to `StorePool`:
//! `roundhouse-web` needs the exact same catch-up-then-follow logic over its
//! permit-bounded store, so the paged reads are the seam between the two.

use std::collections::VecDeque;
use std::future::Future;

use roundhouse_core::SessionId;

use crate::commit_feed::{CommitFeed, CommitWatch};
use crate::pool::{StoreError, StorePool};
use crate::replay::StoredEvent;
use crate::session_events::{events_after, session_head};

/// The page size [`SessionFollower`] reads at a time, both for initial catch-up and for
/// every re-read after a commit wake. Also `roundhouse-web`'s own SSE page size — kept as
/// one constant so the two followers (UDS, SSE) can't silently drift apart.
pub const FOLLOW_PAGE: usize = 256;

/// Where a follower reads committed pages from. The daemon uses `StorePool`; roundhouse-web
/// implements it over its permit-bounded `BoundedStore`, so SSE reads stay inside its pool
/// bound.
pub trait PageSource: Send + Sync {
    /// Every event for `session_id` with `seq` strictly greater than `after`, ascending, up
    /// to `limit` rows. Same contract as [`crate::events_after`].
    fn read_after(
        &self,
        session_id: SessionId,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send;

    /// The highest committed `seq` for `session_id`, or `None` if it has none yet. Same
    /// contract as [`crate::session_head`].
    fn head(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Option<u64>, StoreError>> + Send;
}

impl PageSource for StorePool {
    fn read_after(
        &self,
        session_id: SessionId,
        after: Option<u64>,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<StoredEvent>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let conn = pool.get().await?;
            conn.interact(move |c| events_after(c, session_id, after, limit))
                .await
                .map_err(|e| StoreError::Interact(e.to_string()))?
        }
    }

    fn head(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Option<u64>, StoreError>> + Send {
        let pool = self.pool.clone();
        async move {
            let conn = pool.get().await?;
            conn.interact(move |c| session_head(c, session_id))
                .await
                .map_err(|e| StoreError::Interact(e.to_string()))?
        }
    }
}

/// A cancel-safe catch-up-then-follow reader over one session's event log. See this
/// module's own doc comment for the cancel-safety contract [`Self::next`] upholds.
pub struct SessionFollower<S: PageSource> {
    source: S,
    session_id: SessionId,
    cursor: Option<u64>,
    buffered: VecDeque<StoredEvent>,
    watch: CommitWatch,
}

impl<S: PageSource> SessionFollower<S> {
    /// Takes the `CommitWatch` BEFORE any read, so no commit can slip between catch-up and
    /// follow: a commit that lands after this call but before the first `read_after` is
    /// still caught by that very read (it is already durable by the time the read runs),
    /// and one that lands after the read is still caught by the watch's own `changed()` —
    /// there is no gap where a commit could be neither read nor waked for.
    pub fn new(source: S, feed: &CommitFeed, session_id: SessionId, after: Option<u64>) -> Self {
        Self {
            watch: feed.watch(session_id),
            source,
            session_id,
            cursor: after,
            buffered: VecDeque::new(),
        }
    }

    /// The next committed event after the cursor, in `seq` order, waiting for a commit if
    /// already caught up.
    ///
    /// CANCEL-SAFE: the only `.await` points below (`read_after`, `changed`) run before
    /// this call touches `self.cursor` or drains `self.buffered` — both mutate only in the
    /// last few lines, which contain no `.await` of their own. Dropping the returned future
    /// at any point therefore loses nothing (a page fetched but not yet consumed is simply
    /// re-fetched, identically, next call — `self.cursor` hasn't moved) and duplicates
    /// nothing (an event is never handed back before the cursor is advanced for it).
    pub async fn next(&mut self) -> Result<StoredEvent, StoreError> {
        loop {
            if let Some(event) = self.buffered.pop_front() {
                self.check_seq_follows_cursor(event.seq)?;
                self.cursor = Some(event.seq);
                return Ok(event);
            }

            // Mark seen BEFORE reading — see `CommitWatch::mark_seen`'s own doc comment
            // for why the order is load-bearing: a commit that lands between this call and
            // the read below is still caught by the read itself (already durable by the
            // time it runs), whereas a commit landing between the read and this call would
            // be lost if the order were reversed — `mark_seen` would consume its wake
            // without the read ever having seen it.
            self.watch.mark_seen();
            let page = self
                .source
                .read_after(self.session_id, self.cursor, FOLLOW_PAGE)
                .await?;

            if page.is_empty() {
                self.watch.changed().await;
                continue;
            }
            self.buffered.extend(page);
        }
    }

    /// `seq` of the last event returned by [`Self::next`], or `None` before the first.
    pub fn cursor(&self) -> Option<u64> {
        self.cursor
    }

    /// The event-sourcing invariant `next()` relies on: seqs are dense and gapless per
    /// session, so the next one returned must be exactly one past the cursor (or `0` before
    /// the first). `debug_assert!` catches it loudly in development; the `StoreError` below
    /// is what a release build surfaces instead of silently skipping ahead or panicking a
    /// follower loop the daemon's connection handling depends on staying up.
    fn check_seq_follows_cursor(&self, seq: u64) -> Result<(), StoreError> {
        let expected = self.cursor.map_or(0, |c| c + 1);
        debug_assert_eq!(
            seq, expected,
            "SessionFollower must return seqs in gapless order: expected {expected}, got {seq}"
        );
        if seq != expected {
            return Err(StoreError::Interact(format!(
                "SessionFollower for session {}: expected seq {expected}, got {seq}",
                self.session_id
            )));
        }
        Ok(())
    }
}
