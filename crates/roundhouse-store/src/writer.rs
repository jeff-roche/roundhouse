use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use roundhouse_core::{
    CancelReason, Delta, Event, EventPayload, Origin, SessionId, SessionOutcome, TaskId,
    TaskInput, TaskOutput, TaskRunner, Timestamp,
};
use rusqlite::OptionalExtension;
use tokio::sync::{mpsc, oneshot};

use crate::redact::Redactor;
use crate::txn::{
    begin_immediate, is_sqlite_busy, with_bounded_busy_attempt, INITIAL_BACKOFF, MAX_BUSY_RETRIES,
};
use crate::{pool::StorePool, StoreError};

/// The outcome of `EventWriter::close_session` (Task 19a Task 1).
///
/// Not `#[non_exhaustive]`: this crate's own `StoreError` convention (see `pool.rs`) is to
/// leave error/result enums exhaustively matchable and rely on an explicit audit (this
/// task's own) whenever a variant is added, rather than force every caller to carry a
/// silent wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReceipt {
    /// The session's log already ended in `SessionClosed` before this call — the close is
    /// idempotent, and nothing was appended.
    AlreadyClosed,
    /// This call minted the sweep and the `SessionClosed` terminator. `swept` is how many
    /// open tasks (Ruling P1: `Created`/`Decided`/`Running`/`Suspended`) were cancelled.
    Closed { swept: usize },
}

pub(crate) enum WriteCmd {
    Append {
        event: Box<Event>,
        reply: oneshot::Sender<Result<u64, StoreError>>,
    },
    AppendBatch {
        events: Vec<Event>,
        reply: oneshot::Sender<Result<Vec<u64>, StoreError>>,
    },
    /// Phase 8 Task 19 lane B, Task 5: same batching as `AppendBatch`, plus indexing every
    /// `Delta::Blob`/`TaskInput::Blob`/`TaskOutput::Blob` ref the batch's events carry, in
    /// the SAME transaction as the events insert. See `append_batch_with_blobs` (the free
    /// function).
    AppendBatchWithBlobs {
        events: Vec<Event>,
        state_dir: PathBuf,
        reply: oneshot::Sender<Result<Vec<u64>, StoreError>>,
    },
    // Task 19a Task 1: appended at the end of the enum on purpose — lane B
    // (phase8-t19b-deltas-streaming) adds its own variant to this same file, and keeping
    // additions additive/append-only here avoids gratuitous merge conflicts.
    CloseSession {
        runner: &'static TaskRunner,
        session_id: SessionId,
        ts: Timestamp,
        outcome: SessionOutcome,
        reply: oneshot::Sender<Result<CloseReceipt, StoreError>>,
    },
}

/// A handle to the single-writer event-append task. Cloneable; multiple
/// callers can share the same `EventWriter` and append events concurrently
/// — all appends are serialized by the writer task, not the client.
///
/// `redactor` (Task 19, §6.7) is consulted on every append, before
/// `serialize_payload` — a live secret value must never physically reach the
/// `events.payload` column. It's an `Arc<ArcSwap<Redactor>>`, shared with the
/// spawned writer task's own closure (see `spawn_writer`), so `set_redactor`
/// hot-swaps the live secret-value list for every future append without
/// restarting the writer task or interrupting in-flight ones.
#[derive(Clone)]
pub struct EventWriter {
    tx: mpsc::Sender<WriteCmd>,
    redactor: Arc<ArcSwap<Redactor>>,
}

/// Serialize an `EventPayload` to JSON.
///
/// Does *not* return `Err` for non-finite floating-point values (NaN/Infinity):
/// `serde_json` silently writes those as JSON `null` and returns `Ok` (verified
/// empirically — `serde_json::to_string` never errors on a non-finite `f32`/`f64`,
/// it only errors on genuinely non-serializable inputs, e.g. a map with
/// non-string keys). So a non-finite value here is a lossy round-trip
/// (`Some(NaN)` -> `null` -> `None` on replay), not a rejected write. This is
/// benign for the only float field embedded directly in an `EventPayload`
/// variant today, `Progress.fraction: Option<f32>`, where losing a
/// NaN/Infinity to `None` is an acceptable degradation, not data corruption.
///
/// **Stale-claim correction (Workflows Task 3 fix round 1, finding H2):** an
/// earlier version of this comment said `Progress.fraction` was "the only
/// float field on any `EventPayload` variant" — full stop, not scoped to
/// "embedded directly." That's no longer accurate for the workspace as a
/// whole: `roundhouse_flow::parse::steps::CapsDef::max_cost_usd` is a second
/// `f64` field, and unlike a progress fraction it represents a spend cap,
/// where a silent `NaN`/`Infinity` -> `null` -> `None` round-trip would mean
/// a cap survives a crash-resume as *no cap at all*. It is validated to be
/// finite and non-negative at parse time (`CapsDef`'s own `TryFrom`), so a
/// non-finite value can never exist inside one — and it does not reach
/// `EventPayload`/this function today (workflow execution, Task 5, is not
/// built yet). Whoever wires the first path from a parsed `CapsDef` into an
/// `EventPayload` inherits the question this comment's original, unscoped
/// claim would have hidden: confirm that path still can't carry a non-finite
/// value (it can't, today, only because `CapsDef` itself already rejects
/// one) rather than assuming this function's silent-`null` behavior is still
/// "benign" for every float in the workspace.
/// The `Result` return type is kept for whatever `serde_json::to_string` *can*
/// still fail on (and as a stable signature for callers), not because
/// non-finite floats trigger it.
pub fn serialize_payload(
    payload: &roundhouse_core::EventPayload,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(payload)
}

/// The interpreted tail of one session's log, for the tail guard's purposes only.
///
/// `Open`'s payload is deliberately NOT surfaced as a parsed `EventPayload` — callers only
/// ever need "is it closed or not" plus (for `Open`) the seq to increment from. See
/// `read_session_tail`'s doc comment for why a payload that fails to parse is folded into
/// `Open` rather than treated as an error.
enum SessionTail {
    /// The session has no events yet.
    Empty,
    /// The tail event exists and is *not* `SessionClosed` — includes a tail payload this
    /// crate itself never wrote (corrupt/garbage JSON), which is deliberately treated the
    /// same as "not closed" rather than as a hard error (see `read_session_tail`).
    Open { seq: i64 },
    /// The tail event is `SessionClosed` — the log has a real terminator.
    Closed,
}

/// Reads the highest `seq` and interprets its `payload` for `session_id`'s tail, inside an
/// already open transaction.
///
/// **Fails open on a payload that doesn't parse as JSON**, folding it into `SessionTail::
/// Open` rather than propagating a `StoreError`. This is deliberate, not an oversight: this
/// crate's own `recovery.rs` (Task 2's rewrite) is built specifically so crash recovery
/// never has to deserialize the event log at all — it is driven entirely by the `tasks`
/// materialized-cache table, precisely so a corrupted/garbage row elsewhere in the log
/// cannot break recovery (`tests/recovery_scale.rs`'s
/// `recovery_never_reads_the_event_log_so_a_corrupt_log_cannot_break_it` pins this down).
/// Recovery's only append path is `EventWriter::append_batch`, which now goes through this
/// same tail-guard lookup — if a stray pre-existing corrupt tail row turned into a hard
/// append failure here, one garbled historical byte would permanently wedge a session's
/// ability to ever be appended to again, which is a strictly worse outcome than declining
/// to detect `SessionClosed` on that one session. The tail guard's only job is to detect a
/// genuine, well-formed `SessionClosed` sentinel; "cannot parse the tail" is "cannot prove
/// this log is closed," which correctly resolves to "treat as open," not "reject."
fn read_session_tail(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
) -> Result<SessionTail, StoreError> {
    let mut stmt = tx.prepare_cached(
        "SELECT seq, payload FROM events WHERE session_id = ?1 ORDER BY seq DESC LIMIT 1",
    )?;
    let tail: Option<(i64, String)> = stmt
        .query_row([session_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    Ok(match tail {
        None => SessionTail::Empty,
        Some((seq, payload_json)) => match serde_json::from_str::<EventPayload>(&payload_json) {
            Ok(EventPayload::SessionClosed { .. }) => SessionTail::Closed,
            _ => SessionTail::Open { seq },
        },
    })
}

/// Task 19a's tail guard: the same per-session `MAX(seq)+1` lookup every append path
/// always did (`append_event_in_transaction`, `append_one`, `append_batch`), widened to
/// also read back the tail row's payload via `read_session_tail` and reject with
/// `StoreError::SessionClosed` if the log already ends in `SessionClosed` — a session's
/// close is a real terminator, not just another event a later append can follow.
fn next_seq_or_reject_closed(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
) -> Result<i64, StoreError> {
    match read_session_tail(tx, session_id)? {
        SessionTail::Empty => Ok(0),
        SessionTail::Closed => Err(StoreError::SessionClosed(session_id.to_string())),
        SessionTail::Open { seq } => Ok(seq + 1),
    }
}

/// Appends one event using an already-open write transaction.
///
/// This is the composable form of the writer's append operation. It assigns
/// the next per-session sequence, applies persistence-boundary redaction, and
/// updates the task projection before returning. The caller owns commit or
/// rollback, which lets event-log facts share an atomic transaction with a
/// workflow row or blob reference.
pub fn append_event_in_transaction(
    txn: &rusqlite::Transaction<'_>,
    event: &Event,
    redactor: &Redactor,
) -> Result<u64, StoreError> {
    let session_id = event.session_id.to_string();
    let task_id = event.task_id.map(|task_id| task_id.to_string());
    let (payload, redactions) = redactor.redact_event_payload(event.payload.clone());
    let payload_json =
        serialize_payload(&payload).map_err(|error| StoreError::Interact(error.to_string()))?;
    let next_seq: i64 = next_seq_or_reject_closed(txn, &session_id)?;
    txn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            session_id,
            next_seq,
            event.ts.as_unix_nanos(),
            task_id,
            payload_json,
            event.schema_v,
        ],
    )?;
    if let Some(task_id) = &task_id {
        crate::tasks_view::upsert_for_event(
            txn,
            task_id,
            &event.session_id.to_string(),
            next_seq,
            event.ts.as_unix_nanos(),
            &payload,
        )?;
        if redactions > 0 {
            let rows_affected = txn.execute(
                "UPDATE tasks SET redactions = redactions + ?1 WHERE task_id = ?2",
                rusqlite::params![redactions, task_id],
            )?;
            if rows_affected == 0 {
                return Err(StoreError::Sqlite(rusqlite::Error::StatementChangedRows(0)));
            }
        }
    }
    u64::try_from(next_seq)
        .map_err(|_| StoreError::Interact("event sequence exceeded u64 range".to_string()))
}

/// Spawn a dedicated async task that owns the event-append write transaction
/// and channel-receives `Append` commands from multiple callers. Returns an
/// `EventWriter` handle for sending append requests. The writer task runs until
/// the last `EventWriter` handle is dropped (the channel closes).
///
/// **Why a channel-actor pattern:** One dedicated task owns all writes serially.
/// Callers send append commands through the channel and await replies, rather than
/// each caller attempting to acquire its own DB connection and racing for the write lock.
/// This enforces single-writer discipline structurally (S-LOG-4/5) and makes the retry loop
/// recoverable from transient `SQLITE_BUSY` — the writer task survives client failures.
pub async fn spawn_writer(store: StorePool) -> EventWriter {
    let (tx, mut rx) = mpsc::channel::<WriteCmd>(1024);
    // Empty-pattern automaton by default: matches nothing, so every append is a genuine
    // no-op redaction pass until a real secret-value list is installed via
    // `EventWriter::set_redactor` — redaction is always structurally "on" (Ruling 2),
    // never simply absent because nobody configured it yet.
    let redactor = Arc::new(ArcSwap::from_pointee(Redactor::build(&[])));
    let redactor_for_task = Arc::clone(&redactor);

    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                WriteCmd::Append { event, reply } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_one(&store, *event, &redactor).await;
                    let _ = reply.send(result);
                }
                WriteCmd::AppendBatch { events, reply } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_batch(&store, events, &redactor).await;
                    let _ = reply.send(result);
                }
                WriteCmd::AppendBatchWithBlobs {
                    events,
                    state_dir,
                    reply,
                } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_batch_with_blobs(&store, events, state_dir, redactor).await;
                    let _ = reply.send(result);
                }
                WriteCmd::CloseSession {
                    runner,
                    session_id,
                    ts,
                    outcome,
                    reply,
                } => {
                    let redactor = redactor_for_task.load_full();
                    let result =
                        close_session(&store, runner, session_id, ts, outcome, redactor).await;
                    let _ = reply.send(result);
                }
            }
        }
    });

    EventWriter { tx, redactor }
}

/// S-LOG-4/5: bounded exponential backoff around the single-writer transaction. A
/// `SQLITE_BUSY`/`SQLITE_BUSY_SNAPSHOT` collision (another connection holding a
/// competing `BEGIN IMMEDIATE`, or — in WAL mode — a reader whose snapshot predates a
/// concurrent commit) is retried transparently; every other `rusqlite::Error` propagates
/// immediately, unretried.
///
/// Backoff: 5ms initial, doubles on each retry attempt (5, 10, 20, 40, 80, 160, 320, 640ms).
/// With 8 max retries, worst-case total wait is ~1.3s before giving up and surfacing the error.
async fn append_one(
    store: &StorePool,
    event: Event,
    redactor: &Redactor,
) -> Result<u64, StoreError> {
    let conn = store.pool.get().await?;
    let session_id = event.session_id.to_string();
    let task_id = event.task_id.map(|t| t.to_string());
    let ts_nanos = event.ts.as_unix_nanos();
    let schema_v = event.schema_v;

    // Redaction runs BEFORE serialization (§6.7, Task 19 addendum Ruling 1): the stored
    // row is always the already-redacted `EventPayload`, never the original. Run once,
    // outside the retry loop below — redaction is deterministic, so a `SQLITE_BUSY` retry
    // reuses the same redacted payload rather than redacting again.
    let (payload, redactions) = redactor.redact_event_payload(event.payload);
    let payload_json =
        serialize_payload(&payload).map_err(|e| StoreError::Interact(e.to_string()))?;

    let mut attempt: u32 = 0;
    let seq = loop {
        attempt += 1;
        let session_id = session_id.clone();
        let task_id = task_id.clone();
        let payload_json = payload_json.clone();
        let payload = payload.clone();

        let write_result = conn
            .interact(move |c| -> Result<u64, StoreError> {
                with_bounded_busy_attempt(c, |c| -> Result<u64, StoreError> {
                    // BEGIN IMMEDIATE: acquire the write lock immediately rather than deferring it.
                    // This enforces single-writer discipline: a writer holds the lock for its entire
                    // transaction, so no two writers can execute concurrently. Deferred transactions
                    // would allow multiple writers to run in parallel and race to the lock at commit
                    // time, which would be both unfair to clients and incompatible with S-LOG-4/5's
                    // retry guarantees.
                    let tx = begin_immediate(c)?;
                    // Task 19a's tail guard: rejects with `StoreError::SessionClosed` if
                    // this session's log already ends in `SessionClosed` (see
                    // `next_seq_or_reject_closed`'s doc comment).
                    let next_seq: i64 = next_seq_or_reject_closed(&tx, &session_id)?;
                    tx.execute(
                        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            session_id,
                            next_seq,
                            ts_nanos,
                            task_id,
                            payload_json,
                            schema_v
                        ],
                    )?;
                    // Same transaction as the events insert above (§6.10's pattern): a
                    // `tasks` row is never inconsistent with the event that produced it.
                    // Session-level events (`task_id: None`) have no `tasks` row to touch.
                    if let Some(task_id) = &task_id {
                        crate::tasks_view::upsert_for_event(
                            &tx,
                            task_id,
                            &session_id,
                            next_seq,
                            ts_nanos,
                            &payload,
                        )?;
                        // Task 19 addendum Ruling 5's gotcha: `upsert_for_event` early-returns
                        // (via `fold_task_state` returning `None`) for exactly the payload
                        // kinds redactable text lives in (`TaskDelta`/`Note`), so the
                        // redaction-count accumulation cannot live inside that function's
                        // existing match arms — it runs here instead, unconditionally
                        // alongside the `upsert_for_event` call, in the same transaction as
                        // the events insert.
                        //
                        // Fix round 1, item 4: same fail-closed discipline as
                        // `tasks_view::upsert_for_event`'s own `UPDATE` branch (which already
                        // turns a zero-row match into a hard error, not a silent no-op, per
                        // Task 0.5's security fix). A `TaskDelta`/`Note`/`TaskFailed` event
                        // with a `task_id` that has no corresponding `tasks` row (e.g. arriving
                        // before that task's `TaskCreated`, or a corrupt/partial history) would
                        // otherwise silently drop its redaction count — the event still
                        // commits, correctly redacted, but the audit-visible count for that
                        // task simply vanishes. That's exactly the class of bug this crate's
                        // own precedent exists to prevent.
                        if redactions > 0 {
                            let rows_affected = tx.execute(
                                "UPDATE tasks SET redactions = redactions + ?1 WHERE task_id = ?2",
                                rusqlite::params![redactions, task_id],
                            )?;
                            if rows_affected == 0 {
                                return Err(StoreError::Sqlite(
                                    rusqlite::Error::StatementChangedRows(0),
                                ));
                            }
                        }
                    }
                    tx.commit()?;
                    Ok(next_seq as u64)
                })
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(seq) => break seq,
            Err(StoreError::Sqlite(err)) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => return Err(err),
        }
    };

    Ok(seq)
}

/// One batch member, pre-serialized once (outside the retry loop, same reason
/// `append_one` precomputes `payload_json`/`session_id`/`task_id` strings before
/// its own loop): a retried attempt reuses this pre-serialized form (behind an
/// `Arc`, see below) rather than re-serializing on every `SQLITE_BUSY` retry.
struct PreparedEvent {
    session_id: String,
    task_id: Option<String>,
    ts_nanos: i64,
    payload_json: String,
    payload: EventPayload,
    schema_v: u16,
    /// Redaction count for this member's payload (Task 19, §6.7) — computed once here,
    /// alongside serialization, from the already-redacted `payload` above.
    redactions: u32,
}

/// Batched counterpart to `append_one`: applies every event in `events` inside
/// ONE `BEGIN IMMEDIATE` transaction, committing once for the whole batch
/// instead of once per event — that single commit is the entire point of
/// batching (see `recovery.rs`, the only production caller today).
///
/// **The seq-assignment trap this function exists to avoid:** `events.seq` is
/// scoped per `session_id` (`PRIMARY KEY (session_id, seq)`), and a batch can
/// easily contain multiple events for the same `session_id` (e.g. a session
/// with several tasks in flight when the daemon crashed). Querying
/// `SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE session_id = ?1` fresh
/// for every event risks two events for the same session both computing the
/// same "next" value and colliding on insert. Instead, this function maintains
/// an in-memory `next_seq_by_session: HashMap<String, i64>`: the FIRST time a
/// given `session_id` is seen in this batch, its starting value is seeded via
/// that `MAX(seq)+1` query; every subsequent event for that same `session_id`
/// within the same batch reuses and increments the in-memory value instead of
/// re-querying the database. This is safe because `BEGIN IMMEDIATE` holds the
/// exclusive write lock for the whole transaction, so no other writer can
/// insert into the same session concurrently while this runs.
///
/// Same `SQLITE_BUSY`-retrying pattern as `append_one`: on a busy collision,
/// the ENTIRE batch is retried from scratch, not resumed partway.
async fn append_batch(
    store: &StorePool,
    events: Vec<Event>,
    redactor: &Redactor,
) -> Result<Vec<u64>, StoreError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let conn = store.pool.get().await?;

    // `Arc`, not a plain `Vec` cloned per retry attempt: at crash-recovery
    // scale (S-SESS-4's 500 sessions x 200 tasks — up to 100,000 events in one
    // batch) a deep `Vec<PreparedEvent>::clone()` before every attempt (paid
    // even on the common, never-retried path) was a measurable share of the
    // wall-clock budget in `tests/recovery_scale.rs`. Every attempt after the
    // first only happens on a genuine `SQLITE_BUSY` collision (rare), so
    // cloning the `Arc` (one atomic increment) instead of the `Vec` (100,000
    // owned `String`/`EventPayload` clones) costs nothing on the fast path
    // and is still correct on a retry, since nothing here ever mutates the
    // shared data.
    let prepared: std::sync::Arc<Vec<PreparedEvent>> = std::sync::Arc::new(
        events
            .iter()
            .map(|event| {
                // Same redact-before-serialize ordering as append_one (§6.7, Ruling 1):
                // the stored row is always the redacted form.
                let (payload, redactions) = redactor.redact_event_payload(event.payload.clone());
                let payload_json =
                    serialize_payload(&payload).map_err(|e| StoreError::Interact(e.to_string()))?;
                Ok(PreparedEvent {
                    session_id: event.session_id.to_string(),
                    task_id: event.task_id.map(|t| t.to_string()),
                    ts_nanos: event.ts.as_unix_nanos(),
                    payload_json,
                    payload,
                    schema_v: event.schema_v,
                    redactions,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?,
    );

    let mut attempt: u32 = 0;
    let seqs = loop {
        attempt += 1;
        let batch = std::sync::Arc::clone(&prepared);

        let write_result = conn
            .interact(move |c| -> Result<Vec<u64>, StoreError> {
                with_bounded_busy_attempt(c, |c| -> Result<Vec<u64>, StoreError> {
                    // Same BEGIN IMMEDIATE discipline as append_one: acquire the
                    // exclusive write lock for the whole transaction up front.
                    let tx = begin_immediate(c)?;
                    let mut next_seq_by_session: HashMap<String, i64> = HashMap::new();
                    let mut seqs = Vec::with_capacity(batch.len());

                    // `prepare_cached`, not `tx.execute`/`tx.query_row` (which each
                    // reparse and recompile the SQL text from scratch on every
                    // call — negligible for `append_one`'s single call, but the
                    // dominant cost at this loop's scale, confirmed empirically
                    // against the 100k-task scale test in
                    // `tests/recovery_scale.rs`): both statements below are
                    // identical text on every iteration, so SQLite's per-connection
                    // statement cache turns each repeat call into a cheap
                    // lookup-and-rebind instead of a fresh parse.
                    //
                    // Task 19a's tail guard: the first time a `session_id` is seen in this
                    // batch, `next_seq_or_reject_closed` reads its tail and rejects the WHOLE
                    // batch (via `?`, out of this `BEGIN IMMEDIATE` transaction, so nothing
                    // commits) if that session's log already ends in `SessionClosed`. A
                    // `session_id` already in `next_seq_by_session` has necessarily just been
                    // appended to by an earlier item in THIS batch, and this crate mints no
                    // `SessionClosed` events into `append_batch` today (its only production
                    // caller, `recovery.rs`, only ever appends `TaskCancelled`), so re-checking
                    // on every repeat within one batch would be pure overhead, not an
                    // additional safety property.
                    for item in batch.iter() {
                        let next_seq = match next_seq_by_session.get(&item.session_id) {
                            Some(&seq) => seq,
                            None => next_seq_or_reject_closed(&tx, &item.session_id)?,
                        };

                        let mut insert_event = tx.prepare_cached(
                            "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        )?;
                        insert_event.execute(rusqlite::params![
                            item.session_id,
                            next_seq,
                            item.ts_nanos,
                            item.task_id,
                            item.payload_json,
                            item.schema_v
                        ])?;
                        // Returns this cached statement to the connection's
                        // statement cache before the next iteration (and before
                        // `upsert_for_event` below runs its own `prepare_cached`
                        // calls on the same `tx`) rather than waiting for
                        // end-of-scope.
                        drop(insert_event);
                        // Same transaction as the events insert above, for every
                        // batch member — not just the first — so the `tasks` cache
                        // never falls behind for a batch-appended event (Task 0.5's
                        // invariant, extended to the batched path).
                        if let Some(task_id) = &item.task_id {
                            crate::tasks_view::upsert_for_event(
                                &tx,
                                task_id,
                                &item.session_id,
                                next_seq,
                                item.ts_nanos,
                                &item.payload,
                            )?;
                            // Same gotcha as append_one (Ruling 5): can't shoehorn this into
                            // upsert_for_event's early-return for TaskDelta/Note payloads. Same
                            // fail-closed fix as append_one (fix round 1, item 4): a zero-row
                            // match means this batch member's task_id has no tasks row yet —
                            // hard error rather than silently dropping the redaction count.
                            if item.redactions > 0 {
                                let rows_affected = tx.execute(
                                "UPDATE tasks SET redactions = redactions + ?1 WHERE task_id = ?2",
                                rusqlite::params![item.redactions, task_id],
                            )?;
                                if rows_affected == 0 {
                                    return Err(StoreError::Sqlite(
                                        rusqlite::Error::StatementChangedRows(0),
                                    ));
                                }
                            }
                        }

                        next_seq_by_session.insert(item.session_id.clone(), next_seq + 1);
                        seqs.push(next_seq as u64);
                    }

                    tx.commit()?;
                    Ok(seqs)
                })
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(seqs) => break seqs,
            Err(StoreError::Sqlite(err)) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => return Err(err),
        }
    };

    Ok(seqs)
}

/// The single `BlobRef` a payload carries, if any — `Delta::Blob` (streamed shell output
/// routed to a blob, per Task 19b's convention), `TaskInput::Blob`, or `TaskOutput::Blob`
/// are the only three shapes in `EventPayload` that carry one (see each type's own
/// definition in `roundhouse-core`), and none of them can carry more than one at a time.
fn blob_ref_in_payload(payload: &EventPayload) -> Option<&roundhouse_core::BlobRef> {
    match payload {
        EventPayload::TaskDelta {
            delta: Delta::Blob(blob_ref),
        } => Some(blob_ref),
        EventPayload::TaskCreated {
            input: TaskInput::Blob(blob_ref),
            ..
        } => Some(blob_ref),
        EventPayload::TaskCompleted {
            output: TaskOutput::Blob(blob_ref),
            ..
        } => Some(blob_ref),
        _ => None,
    }
}

/// Pulls a genuinely retriable `SQLITE_BUSY`/`SQLITE_BUSY_SNAPSHOT` error out of a
/// `StoreError`, wherever it's nested — either directly (`StoreError::Sqlite`) or one
/// level down inside `StoreError::Blob(RecordBlobError::Sqlite(_))`, the two shapes a busy
/// collision can take when it surfaces through `append_event_in_transaction`/
/// `record_blob_write` rather than a raw SQL call this function makes itself (fix round 1,
/// Controller Ruling R6). `Ok` means "the caller should retry the whole attempt with this
/// as the outer, retriable error"; `Err` returns the original (non-retriable) `StoreError`
/// unchanged.
fn busy_error_in(err: StoreError) -> Result<rusqlite::Error, StoreError> {
    match err {
        StoreError::Sqlite(e) if is_sqlite_busy(&e) => Ok(e),
        StoreError::Blob(crate::blobs::RecordBlobError::Sqlite(e)) if is_sqlite_busy(&e) => Ok(e),
        other => Err(other),
    }
}

/// One `BEGIN IMMEDIATE`-through-`commit` attempt of `append_batch_with_blobs`'s
/// transaction, run inside `with_bounded_busy_attempt` (fix round 1, Controller Ruling
/// R6) — hence the doubly-nested return type: the OUTER `rusqlite::Result` is what
/// `with_bounded_busy_attempt`/the caller's retry loop inspect for `SQLITE_BUSY` (via
/// `is_sqlite_busy`), and the INNER `Result<Vec<u64>, StoreError>` is the real,
/// non-retriable business outcome (success, or a genuine failure like
/// `RecordBlobError::MissingFile`) once no more retries are worth attempting.
/// `busy_error_in` is what routes a busy error from `append_event_in_transaction`/
/// `record_blob_write` (both `StoreError`-typed, not raw `rusqlite::Error`) into the OUTER
/// slot so it's retried the same way a busy error from `begin_immediate`/`tx.commit()`
/// (already raw `rusqlite::Error`) is.
fn append_batch_with_blobs_attempt(
    c: &mut rusqlite::Connection,
    events: &[Event],
    state_dir: &Path,
    redactor: &Redactor,
) -> rusqlite::Result<Result<Vec<u64>, StoreError>> {
    let tx = match begin_immediate(c) {
        Ok(tx) => tx,
        Err(e) if is_sqlite_busy(&e) => return Err(e),
        Err(e) => return Ok(Err(StoreError::Sqlite(e))),
    };

    let mut seqs = Vec::with_capacity(events.len());
    for event in events {
        let seq = match append_event_in_transaction(&tx, event, redactor) {
            Ok(seq) => seq,
            Err(err) => {
                return match busy_error_in(err) {
                    Ok(busy) => Err(busy),
                    Err(other) => Ok(Err(other)),
                }
            }
        };
        if let Some(blob_ref) = blob_ref_in_payload(&event.payload) {
            if let Err(err) =
                crate::blobs::record_blob_write(&tx, state_dir, blob_ref, event.ts.as_unix_nanos())
            {
                return match busy_error_in(StoreError::from(err)) {
                    Ok(busy) => Err(busy),
                    Err(other) => Ok(Err(other)),
                };
            }
        }
        seqs.push(seq);
    }

    match tx.commit() {
        Ok(()) => Ok(Ok(seqs)),
        Err(e) if is_sqlite_busy(&e) => Err(e),
        Err(e) => Ok(Err(StoreError::Sqlite(e))),
    }
}

/// Batched append that also indexes every blob reference the batch's events carry, in the
/// SAME transaction as the events insert — extending §4.5's "a blob can never be
/// referenced by an event that isn't durably recorded, and vice versa" to the batch path
/// (Phase 8 Task 19 lane B, Task 5). This is what `record_blob_write`'s own doc comment
/// names as the mechanism wiring it into a real event-append transaction. Today's
/// production caller is `roundhouse_engine::tool_dispatch::flush_stream`, the shell
/// delta pump, reached from `roundhouse_engine::agent_loop::dispatch_builtin` and
/// `roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow` (Task 9).
///
/// Reuses `append_event_in_transaction` per event — same redaction, seq-assignment, and
/// `tasks`-view upkeep as a single `append` — then, for whichever of
/// `Delta::Blob`/`TaskInput::Blob`/`TaskOutput::Blob` that event's payload carries (if
/// any; see `blob_ref_in_payload`), calls `blobs::record_blob_write` in the SAME
/// transaction. Blob refs are never mutated by redaction (a `BlobRef` is a content hash,
/// not inline text — see `Redactor::redact_event_payload`'s handling of the same three
/// shapes), so scanning the ORIGINAL, pre-redaction `event.payload` for a ref to index is
/// equivalent to scanning the redacted one and cheaper. **This does NOT redact blob
/// CONTENT** — only the three shapes above (a content hash, never inline text) are ever
/// looked at; a caller that writes secret-bearing bytes to a blob (`blobs::write_blob`)
/// must redact them itself before that write.
///
/// **Ordering precondition this function assumes, not enforces (fix round 1, security
/// finding S7 / Controller Ruling R10):** every `BlobRef` this call is asked to index must
/// already have a real file on disk — i.e. the caller has already run `blobs::write_blob`
/// for it — BEFORE calling this function, the same precondition `record_blob_write` itself
/// documents. If this call's transaction rolls back (a later member's `MissingFile`, or a
/// non-retriable error of any kind), any file an EARLIER member's successful
/// `record_blob_write` referenced is left on disk with NO `blobs` row — an unindexed
/// orphan `gc_eligible_blobs` cannot discover (it queries the `blobs` table only, so a
/// file with no row is invisible to it, not merely ineligible). This is a real reclamation
/// gap: an unindexed file leaked by a rolled-back batch is not cleaned up by anything in
/// this crate today. Ruling R10 explicitly defers closing it (no `record_unreferenced_blob`
/// pre-pass added here) — `roundhouse-flow`'s checkpoint path
/// (`production.rs::index_prepared_checkpoint`) shows the alternative for a caller that
/// needs the file discoverable even across a failed owner transaction: call
/// `blobs::record_unreferenced_blob` (a zero-ref-count placeholder row) BEFORE the
/// transaction that would otherwise be this call, so GC can still find the file if that
/// transaction never happens. This function does not do that on a caller's behalf; a
/// caller with the same need should follow that same pattern itself.
///
/// A `RecordBlobError` (including `MissingFile` — a `BlobRef` with no backing file under
/// `state_dir`) propagates before `tx.commit()` runs, so the whole batch rolls back:
/// neither the events nor any ref-count bump from this call commits — for EVERY member of
/// the batch, not just the one that failed (see
/// `a_missing_blob_file_rolls_back_the_whole_batch_including_an_earlier_real_blob`'s own
/// doc comment for the two-member case this specifically proves).
///
/// **`SQLITE_BUSY` retry (fix round 1, Controller Ruling R6):** unlike the version of this
/// function shipped in this task's first draft, this DOES retry on `SQLITE_BUSY` /
/// `SQLITE_BUSY_SNAPSHOT`, with the same bounded backoff as `append_one`/`append_batch`
/// (`with_bounded_busy_attempt`, `MAX_BUSY_RETRIES`, `INITIAL_BACKOFF`) — see
/// `append_batch_with_blobs_attempt`/`busy_error_in` for how a busy error nested inside
/// `append_event_in_transaction`'s or `record_blob_write`'s own `StoreError`-typed result
/// gets routed into that retry loop. A retry re-runs the ENTIRE attempt from
/// `begin_immediate`, which is safe and idempotent here specifically because nothing about
/// it can have partially committed: the whole transaction, including every
/// `record_blob_write` ref-count bump, only ever commits or rolls back as one unit.
async fn append_batch_with_blobs(
    store: &StorePool,
    events: Vec<Event>,
    state_dir: PathBuf,
    redactor: Arc<Redactor>,
) -> Result<Vec<u64>, StoreError> {
    if events.is_empty() {
        return Ok(Vec::new());
    }

    let conn = store.pool.get().await?;
    let events = std::sync::Arc::new(events);

    let mut attempt: u32 = 0;
    let result = loop {
        attempt += 1;
        let events = std::sync::Arc::clone(&events);
        let state_dir = state_dir.clone();
        let redactor = Arc::clone(&redactor);

        let write_result = conn
            .interact(move |c| -> rusqlite::Result<Result<Vec<u64>, StoreError>> {
                with_bounded_busy_attempt(c, |c| {
                    append_batch_with_blobs_attempt(c, &events, &state_dir, &redactor)
                })
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(inner) => break inner,
            Err(err) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => break Err(StoreError::Sqlite(err)),
        }
    };

    result
}

/// Task 19a Task 1: closes a session in one transaction — mints
/// `TaskCancelled{by: System, reason: SessionClosed}` for every currently open task, then
/// appends `SessionClosed{outcome}` as the terminator, sweep events first, terminator
/// last, all inside one `BEGIN IMMEDIATE`. Idempotent: if the session's tail is already
/// `SessionClosed`, this is a no-op read (`CloseReceipt::AlreadyClosed`) — nothing is
/// appended and no `BEGIN IMMEDIATE` write is even attempted beyond the read itself.
///
/// Ruling P1 (binding, `.superpowers/sdd/2026-09-17-phase8-t19a-session-close/
/// global-constraints.md`): the sweep covers `tasks` rows in `Created`, `Decided`,
/// `Running`, **and `Suspended`** — deliberately wider than `recover_interrupted_tasks`
/// (`recovery.rs`), which only sweeps `Created`/`Decided`/`Running` and leaves `Suspended`
/// alone because a daemon restart re-arms a suspended task through the attention-queue
/// path (see `recovery.rs`'s own module doc comment). A session close has no "later" to
/// re-arm into once the session itself is gone, so a task merely waiting on an
/// approval/elicitation/reply/peer is cancelled too, not left stranded forever.
///
/// `runner` mints both the sweep's `TaskCancelled` events and the `SessionClosed`
/// terminator (`record_task_cancelled`/`record_session_closed` — the sole sanctioned way
/// to produce either, per `TaskRunner`'s own doc comment); `append_event_in_transaction`
/// (this same file) does the actual appending of each, reusing its tail guard, seq
/// assignment, redaction, and `tasks`-view upkeep rather than duplicating any of it here.
async fn close_session(
    store: &StorePool,
    runner: &'static TaskRunner,
    session_id: SessionId,
    ts: Timestamp,
    outcome: SessionOutcome,
    redactor: Arc<Redactor>,
) -> Result<CloseReceipt, StoreError> {
    let conn = store.pool.get().await?;
    let session_id_str = session_id.to_string();

    let mut attempt: u32 = 0;
    let receipt = loop {
        attempt += 1;
        let session_id_str = session_id_str.clone();
        let outcome = outcome.clone();
        // Unlike `append_one`/`append_batch` (which redact once, synchronously, before
        // ever entering `conn.interact`), this function mints and appends more than one
        // event *inside* the transaction via `append_event_in_transaction`, which needs a
        // live `&Redactor` at each call site — so the 'static `conn.interact` closure
        // below needs to own a handle to it. Cloning the `Arc` (one atomic increment) is
        // cheap and correct on a retry, since nothing here ever mutates the shared
        // automaton.
        let redactor = Arc::clone(&redactor);

        let write_result = conn
            .interact(move |c| -> Result<CloseReceipt, StoreError> {
                with_bounded_busy_attempt(c, |c| -> Result<CloseReceipt, StoreError> {
                    let tx = begin_immediate(c)?;

                    if matches!(
                        read_session_tail(&tx, &session_id_str)?,
                        SessionTail::Closed
                    ) {
                        return Ok(CloseReceipt::AlreadyClosed);
                    }

                    let mut stmt = tx.prepare(
                        "SELECT task_id FROM tasks WHERE session_id = ?1 \
                         AND state IN ('Created', 'Decided', 'Running', 'Suspended')",
                    )?;
                    let open_task_ids: Vec<String> = stmt
                        .query_map([&session_id_str], |row| row.get(0))?
                        .collect::<rusqlite::Result<_>>()?;
                    drop(stmt);

                    for task_id_str in &open_task_ids {
                        let task_id = TaskId::from_uuid(
                            uuid::Uuid::parse_str(task_id_str).map_err(|error| {
                                StoreError::Interact(format!(
                                    "corrupt task_id in tasks table: {error}"
                                ))
                            })?,
                        );
                        let cancelled = runner.record_task_cancelled(
                            session_id,
                            0, // seq reassigned by append_event_in_transaction
                            ts,
                            task_id,
                            Origin::System,
                            CancelReason::SessionClosed,
                            1,
                        );
                        append_event_in_transaction(&tx, &cancelled, &redactor)?;
                    }

                    let terminator = runner.record_session_closed(session_id, 0, ts, outcome, 1);
                    append_event_in_transaction(&tx, &terminator, &redactor)?;

                    tx.commit()?;
                    Ok(CloseReceipt::Closed {
                        swept: open_task_ids.len(),
                    })
                })
            })
            .await
            .map_err(|e| StoreError::Interact(e.to_string()))?;

        match write_result {
            Ok(receipt) => break receipt,
            Err(StoreError::Sqlite(err)) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRIES => {
                tokio::time::sleep(INITIAL_BACKOFF * 2u32.pow(attempt - 1)).await;
                continue;
            }
            Err(err) => return Err(err),
        }
    };

    Ok(receipt)
}

impl EventWriter {
    /// Hot-swaps the redactor consulted on every future `append`/`append_batch` call
    /// (Task 19, §6.7). Does not affect already-committed rows, only writes from this
    /// point forward. Safe to call concurrently with in-flight appends — `ArcSwap::store`
    /// is a single atomic pointer swap.
    pub fn set_redactor(&self, r: Redactor) {
        self.redactor.store(Arc::new(r));
    }

    /// Runs THIS writer's own live redactor over `text` and returns the
    /// redacted result plus the match count — the same automaton
    /// `append`/`append_batch` already consult before persisting, exposed
    /// so a caller can scan text that is never itself persisted through
    /// this writer (fix round A, ruling W1-R59: a dispatched tool's result
    /// is scanned before it's folded into the NEXT provider request, not
    /// before it's stored — `run_agent_loop`'s own `TaskCompleted` append
    /// already covers the storage side via the ordinary `redact_event_payload`
    /// path). Never mutates anything; `redact_event_payload`'s persistence-
    /// boundary guarantee is unaffected by this method's existence.
    pub fn redact_outbound(&self, text: &str) -> (String, u32) {
        self.redactor.load().redact(text)
    }

    /// Byte-oriented counterpart to [`Self::redact_outbound`] — same live redactor, same
    /// never-mutates-anything-persisted contract, but over raw bytes rather than validated
    /// UTF-8 text (Phase 8 Task 19 lane B, Task 5: shell stdout/stderr and other
    /// non-text-guaranteed streamed content). See `Redactor::redact_bytes`.
    ///
    /// **No production caller (Controller ruling R24).** The live streaming path reaches
    /// the same `Redactor::redact_bytes` through
    /// [`Self::redaction_split_and_redact`], which has to do the split and the redaction
    /// under one `ArcSwap::load`; this stays as the separately-tested standalone
    /// primitive. Kept deliberately, not dead code.
    pub fn redact_outbound_bytes(&self, bytes: &[u8]) -> (Vec<u8>, u32) {
        self.redactor.load().redact_bytes(bytes)
    }

    /// The number of bytes a streaming caller must hold back, unflushed, at every
    /// non-final split point so that no live secret value can straddle it undetected: the
    /// live redactor's longest pattern length minus one (0 for the default empty
    /// redactor). Reads the LIVE redactor via `ArcSwap::load` on every call, exactly like
    /// `redact_outbound`/`redact_outbound_bytes` — a `set_redactor` mid-stream changes the
    /// holdback a caller sees on its very next call, same as it changes what gets matched.
    ///
    /// On its own this bounds how far a match can straddle a boundary a caller already
    /// committed to — it does not choose that boundary. Pair it with
    /// [`Self::redaction_safe_split_len`], which does: see that method's, and
    /// `Redactor::safe_split_len`'s, own doc comments for why holdback alone isn't enough
    /// and why the split point must be chosen with the buffered bytes in view.
    ///
    /// **Race warning (fix round 1, security finding S3 / Controller Ruling R9): calling
    /// this and [`Self::redaction_safe_split_len`] as two separate calls is NOT safe** —
    /// each does its own independent `ArcSwap::load`, so a `set_redactor` landing between
    /// the two calls (e.g. `wire_redaction_for_session`, called on every session creation)
    /// can mean the holdback was computed against one redactor and the split against a
    /// DIFFERENT, freshly-installed one with a longer pattern, holding back too few bytes
    /// for what the split actually used. Prefer [`Self::redaction_split_for_flush`], which
    /// reads the redactor exactly once for both numbers. This method (and
    /// `redaction_safe_split_len`) remain as directly-callable, separately-tested
    /// primitives for callers that genuinely only need one of the two numbers (or that can
    /// otherwise guarantee no `set_redactor` lands between two calls of their own).
    ///
    /// **No production caller (Controller ruling R24).** This one is named directly by the
    /// phase text; it and [`Self::redaction_safe_split_len`] are the separately-tested
    /// primitives the two live methods ([`Self::redaction_split_for_coalescer`] and
    /// [`Self::redaction_split_and_redact`]) are built from. Kept deliberately.
    pub fn redaction_holdback(&self) -> usize {
        self.redactor.load().max_pattern_len().saturating_sub(1)
    }

    /// Pass-through to the live redactor's `Redactor::safe_split_len` — the split-point
    /// choice `redaction_holdback`'s doc comment says to pair it with. Same hot-swap
    /// semantics as every other method here: reads whichever `Redactor` is live at call
    /// time via `ArcSwap::load`.
    ///
    /// **Same race warning as [`Self::redaction_holdback`]: do not call this and
    /// `redaction_holdback` as two separate calls when you need them to agree on the same
    /// redactor.** Prefer [`Self::redaction_split_for_flush`].
    ///
    /// **No production caller (Controller ruling R24)** — see
    /// [`Self::redaction_holdback`]'s note: a deliberately retained primitive, not dead
    /// code.
    pub fn redaction_safe_split_len(&self, bytes: &[u8], max: usize) -> usize {
        self.redactor.load().safe_split_len(bytes, max)
    }

    /// Combines [`Self::redaction_holdback`] and [`Self::redaction_safe_split_len`] under a
    /// SINGLE `ArcSwap::load` (fix round 1, security finding S3 / Controller Ruling R9) —
    /// the race-free way to get a streaming flush's split point.
    ///
    /// **No production caller (Controller ruling R24).** Kept as a directly-callable,
    /// separately-tested primitive; the two methods production actually calls —
    /// [`Self::redaction_split_for_coalescer`] and [`Self::redaction_split_and_redact`] —
    /// are built from the same two pieces ([`Self::redaction_holdback`]'s formula and
    /// `Redactor::safe_split_len`). Deliberately retained, not dead code left behind.
    ///
    /// Returns the number of bytes of `bytes` that are safe to flush and redact now (via
    /// `redact_outbound_bytes`/`Redactor::redact_bytes` for a byte stream, or the
    /// UTF-8-char-boundary-floored counterpart for text — see
    /// `Redactor::safe_split_len`'s doc comment on flooring, S4) — the rest of `bytes`
    /// must be retained and prefixed onto whatever arrives next.
    ///
    /// **A return of `0` means "nothing is safely flushable yet under the live redactor's
    /// current holdback requirement" — it is not an error and not "flush nothing, ever".**
    /// The caller must keep buffering and try again once more bytes have arrived; nothing
    /// here bounds how long that buffering can go on unflushed — that bound belongs to the
    /// buffer's own size/time-based flush policy (a later task's concern), not to this
    /// method.
    pub fn redaction_split_for_flush(&self, bytes: &[u8]) -> usize {
        let redactor = self.redactor.load();
        let holdback = redactor.max_pattern_len().saturating_sub(1);
        let max = bytes.len().saturating_sub(holdback);
        redactor.safe_split_len(bytes, max)
    }

    /// The production [`crate::delta_sink`]-shaped split primitive (Phase 8 Task 19 lane B,
    /// Task 7): computes BOTH of `roundhouse_engine::delta_sink::SplitFn`'s modes from a
    /// SINGLE `ArcSwap::load` of the live redactor PER CALL — one non-final-or-final split
    /// QUERY sees one consistent redactor snapshot for its own holdback-and-split-point pair,
    /// the same race [`Self::redaction_split_for_flush`] closes for its own (no-`max`,
    /// non-final-only) shape.
    ///
    /// Today's production caller is the `SplitFn` closure
    /// `roundhouse_engine::chat::run_chat_turn_with_clock` builds for its `DeltaCoalescer`
    /// (Task 7). The shell delta pump (`roundhouse_engine::tool_dispatch::flush_stream`)
    /// uses [`Self::redaction_split_and_redact`] instead, which folds this split choice and
    /// the redaction itself into one snapshot (Task 8).
    ///
    /// **Residual, stated explicitly (fix round 1, finding M1 — an earlier draft of this
    /// comment overclaimed the guarantee at the wrong granularity):** one streaming flush
    /// decision inside `DeltaCoalescer` routinely calls this method SEVERAL times — the
    /// size-shrink loop in `attempt_nonfinal_flush`/`carve_final_chunk`, and `carve_final_chunk`'s
    /// own R13 geometric-growth-plus-bisection search — each call an independent `load()`. A
    /// `set_redactor` landing between two of those calls within the same flush is NOT
    /// serialized against this method; the two calls can legitimately see different redactor
    /// snapshots, so a boundary chosen under one redactor could be redacted under another.
    /// Note that append-time redaction does NOT repair that: `redact_event_payload` runs
    /// per payload and cannot see a match straddling two of them — which is the very thing
    /// `Redactor::safe_split_len`'s caller contract (item 1) exists to prevent.
    ///
    /// What actually makes this safe is structural, not compensating: **no writer that
    /// deltas stream through ever sees a mid-stream `set_redactor` in production today.**
    /// Each session owns its own `EventWriter`, and
    /// `roundhouse_engine::create_session_with_egress` calls
    /// `roundhouse_engine::wire_redaction_for_session` on it exactly once, at session
    /// creation, before any streaming starts. The one writer that does see repeated
    /// `set_redactor` calls is the daemon's shared `proxy_writer`
    /// (`roundhouse_daemon`'s `register_proxy_secrets`, re-installing the accumulated
    /// union on every new session) — and no deltas stream through that writer at all.
    /// **Residual: if a future change calls `set_redactor` on a session's OWN writer
    /// mid-turn, this breaks**, and the multi-call flush above is where it would break.
    /// This method's snapshot consistency is about the correctness of a single
    /// split-point ANSWER, not about serializing an entire multi-call flush against
    /// redactor rotation.
    ///
    /// `max` is an EXTERNAL cap this method always honors on top of whatever the redactor
    /// itself would allow — never a hint an implementation may ignore. `SplitFn`'s contract
    /// requires the returned `k <= min(max, bytes.len())`; a wrapper that dropped `max` here
    /// would hand `DeltaCoalescer` a cut its own size-shrink loop never verified, since the
    /// coalescer clamps to `max` before trusting the answer (see `DeltaCoalescer::
    /// attempt_nonfinal_flush`'s doc comment).
    ///
    /// - `final_flush == false`: applies the holdback (`redaction_holdback()`) THEN caps at
    ///   `max` — `redactor.safe_split_len(bytes, max.min(bytes.len().saturating_sub(holdback)))`
    ///   — mirroring `redaction_split_for_flush`'s own holdback formula, but honoring an
    ///   externally supplied `max` too instead of only ever asking about the whole buffer.
    /// - `final_flush == true`: no holdback (nothing more is coming for this run) —
    ///   `redactor.safe_split_len(bytes, max)` directly.
    ///
    /// **Monotonicity in `max` (load-bearing for `DeltaCoalescer::carve_final_chunk`'s R13
    /// narrowest-cut search, which calls this ONLY with `final_flush = true`):** the
    /// `final_flush = true` branch is a direct, unmodified call to `Redactor::safe_split_len`,
    /// so it inherits that method's own documented property verbatim — it answers `0` exactly
    /// when a match starting at offset `0` extends past `min(max, bytes.len())`, and is
    /// non-decreasing in `max` (a larger `max` can only ever admit a cut at least as large,
    /// since `safe_split_len` starts its own candidate at `max.min(bytes.len())` and only ever
    /// walks it down to an earlier match's `start()`, never below what a smaller `max` would
    /// have produced). The `final_flush = false` branch composes two non-decreasing functions
    /// of `max` (the `min` cap, then `safe_split_len` itself), so it is non-decreasing too,
    /// though `carve_final_chunk`'s search never exercises that branch.
    pub fn redaction_split_for_coalescer(
        &self,
        bytes: &[u8],
        max: usize,
        final_flush: bool,
    ) -> usize {
        let redactor = self.redactor.load();
        if final_flush {
            redactor.safe_split_len(bytes, max)
        } else {
            let holdback = redactor.max_pattern_len().saturating_sub(1);
            let capped = max.min(bytes.len().saturating_sub(holdback));
            redactor.safe_split_len(bytes, capped)
        }
    }

    /// Combines [`Self::redaction_split_for_coalescer`]'s split choice and
    /// [`Self::redact_outbound_bytes`]'s redaction under a SINGLE `ArcSwap::load` of the live
    /// redactor (Phase 8 Task 19 lane B, Task 8 fix round 1, security finding M4). Two
    /// independent loads — call `redaction_split_for_coalescer` and then separately
    /// `redact_outbound_bytes` on the returned prefix — let a `set_redactor` land between them:
    /// the holdback/cut computed against the OLD redactor and the automaton scan run against the
    /// NEW one can legitimately disagree (a longer pattern in the new redactor could straddle a
    /// cut the old one judged safe), which is exactly the race
    /// [`Self::redaction_split_for_coalescer`]'s own doc comment already closed for computing
    /// `final_flush`'s two component numbers together — this method closes the identical race one
    /// level up, for a caller that also needs the redacted bytes themselves under that same
    /// snapshot.
    ///
    /// Returns `(cut, redacted, matches)`: `cut` is exactly what
    /// `redaction_split_for_coalescer(bytes, max, final_flush)` would have returned under the SAME
    /// snapshot; `redacted`/`matches` are `redact_bytes(&bytes[..cut])` under that identical
    /// snapshot. A non-final `cut` of `0` means nothing is safely flushable yet — `redacted` is
    /// then empty and the caller must not persist it (mirrors
    /// `redaction_split_for_coalescer`'s own "0 means keep buffering" contract).
    pub fn redaction_split_and_redact(
        &self,
        bytes: &[u8],
        max: usize,
        final_flush: bool,
    ) -> (usize, Vec<u8>, u32) {
        let redactor = self.redactor.load();
        let cut = if final_flush {
            redactor.safe_split_len(bytes, max)
        } else {
            let holdback = redactor.max_pattern_len().saturating_sub(1);
            let capped = max.min(bytes.len().saturating_sub(holdback));
            redactor.safe_split_len(bytes, capped)
        };
        let (redacted, matches) = redactor.redact_bytes(&bytes[..cut]);
        (cut, redacted, matches)
    }

    /// Append an event to the log. The event's `seq` field is ignored (the writer
    /// assigns a monotonic sequence number per session). Returns the assigned `seq`,
    /// or an error if serialization, database locking, or the writer task fails.
    ///
    /// The `SQLITE_BUSY` retries (S-LOG-4/5) are transparent to the caller — the
    /// function blocks internally until the lock is acquired or max retries are exceeded.
    pub async fn append(&self, event: Event) -> Result<u64, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::Append {
                event: Box::new(event),
                reply,
            })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }

    /// Append a batch of events in one transaction, one commit for the whole
    /// batch rather than one per event. Returns each event's assigned `seq`,
    /// in the same order as the input `events`. An empty `events` is a
    /// harmless no-op (`Ok(vec![])`) — recovery legitimately calls this with
    /// zero events on a clean boot.
    ///
    /// Per-session sequence assignment across the batch is handled correctly
    /// even when the batch contains multiple events for the same
    /// `session_id` — see `append_batch`'s (the free function's) doc comment
    /// for the seq-assignment design this depends on.
    pub async fn append_batch(&self, events: Vec<Event>) -> Result<Vec<u64>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::AppendBatch { events, reply })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }

    /// Same as `append_batch`, plus indexing every `Delta::Blob`/`TaskInput::Blob`/
    /// `TaskOutput::Blob` ref the batch's events carry, in the SAME transaction as the
    /// events insert (Phase 8 Task 19 lane B, Task 5). `state_dir` is the workspace's blob
    /// root — the same directory `blobs::write_blob`/`record_blob_write` use elsewhere.
    ///
    /// A blob ref whose file isn't actually present under `state_dir`
    /// (`blobs::RecordBlobError::MissingFile`, surfaced here as `StoreError::Blob`) fails
    /// the WHOLE call: neither the events nor any ref-count bump commit — for every
    /// member of the batch, not just the one that failed. Retries on `SQLITE_BUSY` with
    /// the same bounded backoff as `append`/`append_batch`. Every `BlobRef` passed in must
    /// already have a real file on disk (`blobs::write_blob` already ran for it); this
    /// does NOT redact blob content, only the reference. See `append_batch_with_blobs`'s
    /// (the free function's) own doc comment for the full design, including the
    /// unindexed-orphan-file gap a rolled-back call can leave behind (fix round 1,
    /// security findings S6/S7).
    pub async fn append_batch_with_blobs(
        &self,
        events: Vec<Event>,
        state_dir: PathBuf,
    ) -> Result<Vec<u64>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::AppendBatchWithBlobs {
                events,
                state_dir,
                reply,
            })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }

    /// Closes a session (Task 19a Task 1): sweeps every currently open task
    /// (`Created`/`Decided`/`Running`/`Suspended` — Ruling P1) into
    /// `TaskCancelled{by: System, reason: SessionClosed}`, then appends
    /// `SessionClosed{outcome}` as the terminator, sweep events first, terminator last,
    /// all in one transaction. Idempotent — closing an already-closed session returns
    /// `CloseReceipt::AlreadyClosed` and appends nothing. See `close_session`'s (the free
    /// function's) doc comment for the full design.
    ///
    /// `runner` is `&'static` because it is the one process-wide `TaskRunner` singleton
    /// (`TaskRunner::bootstrap()`'s doc comment) — the same convention
    /// `roundhouse_engine::SessionActor` already uses for its own `runner` field, which is
    /// this method's intended caller (`SessionActor::close`, a later task in this lane).
    pub async fn close_session(
        &self,
        runner: &'static TaskRunner,
        session_id: SessionId,
        ts: Timestamp,
        outcome: SessionOutcome,
    ) -> Result<CloseReceipt, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(WriteCmd::CloseSession {
                runner,
                session_id,
                ts,
                outcome,
                reply,
            })
            .await
            .map_err(|_| StoreError::Interact("writer task shut down".into()))?;
        rx.await
            .map_err(|_| StoreError::Interact("writer task dropped reply".into()))?
    }
}
