//! Daemon-owned session-tree adapter for workflow child admission.

use std::collections::HashSet;
use std::sync::Arc;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{
    EventPayload, JobId, Origin, SessionId, SessionSpec, SessionState, TaskId, TaskInput, TaskKind,
    TaskRunner, Timestamp,
};
use roundhouse_flow::compose::MAX_DIRECT_CHILD_CALLS;
use roundhouse_flow::durability::WorkflowRun;
use roundhouse_flow::exec::run_loop::{SessionTree, WorkflowHostError};
use thiserror::Error;

/// Adapts the daemon's shared spawn tree to the synchronous workflow host
/// contract. Agent and workflow children use the same direct-child counter.
#[derive(Clone)]
pub struct WorkflowSessionTree {
    tree: Arc<SpawnTree>,
    runner: &'static TaskRunner,
    session_spec: SessionSpec,
}

impl WorkflowSessionTree {
    pub fn new(
        tree: Arc<SpawnTree>,
        runner: &'static TaskRunner,
        session_spec: SessionSpec,
    ) -> Self {
        Self {
            tree,
            runner,
            session_spec,
        }
    }

    pub fn tree(&self) -> &Arc<SpawnTree> {
        &self.tree
    }
}

impl SessionTree for WorkflowSessionTree {
    fn reserve_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
    ) -> Result<u32, WorkflowHostError> {
        let direct_children = self.tree.direct_children(parent);
        self.tree
            .reserve_child(parent, child, MAX_DIRECT_CHILD_CALLS)
            .ok_or(WorkflowHostError::ChildReservationRefused { session_id: parent })?;
        Ok(direct_children)
    }

    fn release_child(&mut self, parent: SessionId, child: SessionId) {
        self.tree.release_child_reservation(parent, child);
    }

    fn persist_child_session(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        parent: SessionId,
        child: &WorkflowRun,
    ) -> Result<(), WorkflowHostError> {
        // The stored `session_spec` is a reusable template (see this struct's
        // fields), not the actual calling session — its own `parent` field
        // (if any) must never leak onto the child. The child's `parent` is
        // always the real, immediate parent passed in above.
        let mut spec = self.session_spec.clone();
        spec.parent = Some(parent);
        let event = self.runner.record_session_created(
            child.session_id,
            0,
            child.started_at,
            Box::new(spec),
            1,
        );
        roundhouse_store::append_event_in_transaction(
            txn,
            &event,
            &roundhouse_store::redact::Redactor::build(&[]),
        )?;
        Ok(())
    }

    fn persist_parent_call_task(
        &mut self,
        txn: &rusqlite::Transaction<'_>,
        parent: SessionId,
        created_at: Timestamp,
        task_id: TaskId,
        input: TaskInput,
    ) -> Result<(), WorkflowHostError> {
        let event = self.runner.record_task_created(
            parent,
            0,
            created_at,
            task_id,
            TaskKind::Agent,
            None,
            Origin::System,
            input,
            1,
        );
        roundhouse_store::append_event_in_transaction(
            txn,
            &event,
            &roundhouse_store::redact::Redactor::build(&[]),
        )?;
        Ok(())
    }

    fn register_child(
        &mut self,
        parent: SessionId,
        child: SessionId,
        _job_id: JobId,
    ) -> Result<(), WorkflowHostError> {
        self.tree.commit_child_reservation(parent, child);
        Ok(())
    }

    /// The `call:` half of removal-on-termination: a child run that has
    /// reached a terminal state gives its parent's fan-out slot back.
    ///
    /// Reached from `finish_run`'s own terminal path in `roundhouse-flow`,
    /// beside `refund_child_run` — the durable grant and the runtime edge are
    /// both returned where the child ends, rather than the grant alone. This
    /// is the same `SpawnTree` `reserve_child`/`register_child` above admit
    /// into, and the same one the `agent` tool's sub-agent children use, so a
    /// freed slot is freed for both kinds of child.
    ///
    /// The scheduled-delivery driver reaches this through the child's own
    /// terminal `finish_run` path. Keeping removal here means the runtime edge
    /// is released beside the durable budget refund, not by a caller that must
    /// remember both halves.
    ///
    /// Discharges the trait's idempotency requirement outright rather than by
    /// care at the call site: `SpawnTree::remove_child` is documented
    /// idempotent and pinned by its own
    /// `direct_children_can_be_counted_and_removed_idempotently`, so a
    /// duplicate termination signal — this call and, say, a later reaper
    /// agreeing about the same child — frees one slot, not two.
    fn child_terminated(&mut self, parent: SessionId, child: SessionId) {
        self.tree.remove_child(parent, child);
    }

    fn direct_children(&mut self, parent: SessionId) -> Result<u32, WorkflowHostError> {
        Ok(self.tree.direct_children(parent))
    }
}

/// Durable facts the daemon could not use to reconstruct its runtime spawn tree.
///
/// Deliberately **not** a variant per unreadable event row: a single malformed
/// lifecycle row is skipped and logged rather than turned into one of these —
/// see [`reconcile_spawn_tree`]'s *"One bad row is skipped, not fatal"*
/// section for why. What remains here is the unrecoverable kind: the store
/// itself cannot be read (`Sqlite`), or a `workflow_run.session_id` — a column
/// only this daemon's own writers ever fill, and one whose loss would
/// misclassify an *ended* run as live — is not a uuid.
#[derive(Debug, Error)]
pub enum ReconcileSpawnTreeError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("{column} holds {value:?}, which is not a session id")]
    MalformedSessionId { column: &'static str, value: String },
}

// The serialized discriminant text of the three session-lifecycle payloads
// this scan cares about. `EventPayload` is an externally tagged serde enum
// and `roundhouse_store::serialize_payload` is a plain `to_string`, so a
// stored payload begins with `{"<VariantName>":`.
//
// These drive a SQL prefilter ONLY — every matched row is still deserialized
// and matched as a real `EventPayload` below, so a prefix that matched too
// much would cost a wasted parse, never a wrong edge. A prefix that matched
// too *little* would silently restore nothing, which is why
// `the_payload_prefixes_match_what_the_store_actually_writes` pins all three
// against bytes the real writer produced.
const SESSION_CREATED_PAYLOAD_PREFIX: &str = r#"{"SessionCreated":"#;
const SESSION_CLOSED_PAYLOAD_PREFIX: &str = r#"{"SessionClosed":"#;
const SESSION_STATE_CHANGED_PAYLOAD_PREFIX: &str = r#"{"SessionStateChanged":"#;

/// Rebuilds the daemon's runtime spawn tree from durable facts, once, at boot
/// — and reports how many parent→child edges it restored.
///
/// # One pass, both kinds of child
///
/// The edge comes from the **child's own `SessionCreated`**: every child
/// session this daemon spawns records its immediate parent in
/// `SessionSpec::parent`, whether it was spawned by a workflow `call:`
/// (`WorkflowSessionTree::persist_child_session`) or by the `agent` tool
/// (`DaemonSubAgentHost::persist_session_created`). Scanning that one fact
/// covers both, which the previous shape — a join through
/// `workflow_run.parent_run_id` — structurally could not: a sub-agent child
/// has no `workflow_run` row, so every sub-agent edge was lost at every
/// restart.
///
/// The consequence worth naming: a `SessionCreated` written *before*
/// `SessionSpec::parent` existed deserializes with `parent: None` (see that
/// field's own doc comment) and so restores no edge. Such a child's slot is
/// freed by a restart rather than leaked by one, which is the safe direction,
/// and no pre-existing store in this pre-release system carries edges that
/// matter.
///
/// # Only children that have not ended
///
/// A child that has already finished must not come back holding one of its
/// parent's [`MAX_DIRECT_CHILD_CALLS`] fan-out slots for the life of the
/// process. Two durable end-signals are honoured, and they are not
/// symmetrical:
///
/// - **Workflow `call:` child** — its `workflow_run` row has ended. Expressed
///   as `ended_at IS NOT NULL` rather than as a list of terminal state
///   discriminants: the two are the same fact by an invariant both writers
///   enforce (`insert_run_row`'s `TerminalStateEndedAtMismatch` guard and
///   `transition`'s), and `ended_at` needs no copy of a discriminant spelling
///   that `roundhouse-flow` deliberately keeps in one place.
/// - **Sub-agent child** — a `SessionClosed`, or a `SessionStateChanged`
///   carrying [`SessionState::Closed`], on the child's own log.
///
/// # KNOWN GAP: nothing writes a sub-agent child's end today
///
/// The second bullet is, as of this task, a filter with no production writer
/// in front of it. **No code in this workspace appends `SessionClosed` or
/// `SessionStateChanged { state: Closed, .. }` to the log**:
/// `SubAgentSessions::retire_child` (one of the two ways a tracked sub-agent
/// ends — the other being `SubAgentSessions::take_for_reap`, used by
/// `spawn_session_reaper`'s `RetireSubAgent` reap action)
/// removes the map entry and the tree edge and tears the session down entirely
/// in memory, writing nothing, and `SessionActor::cancel` — the only
/// production appender of a session-lifecycle state event at all — writes
/// `Cancelling`, which §8.13 is explicit is *not* terminal. (The retired demo
/// path and the socket handshake do build such payloads, but as `ClientEvent`
/// *frames* sent to a client; neither becomes a row.)
///
/// So today: **a retired sub-agent child reappears here as an occupied slot
/// after a restart, and this function cannot tell it from a live one.**
///
/// ## What that costs, stated plainly
///
/// [`MAX_DIRECT_CHILD_CALLS`] is `roundhouse_bus::limits::MAX_FAN_OUT` — **8**,
/// and it is the *same* eight slots both kinds of child draw from. Restoration
/// applies no ceiling of its own (`SpawnTree::record_child`, unlike
/// `reserve_child`, takes no `max_children`). So a parent session that has ever
/// spawned eight sub-agents over its lifetime **can never spawn another after a
/// daemon restart, for the rest of that session's life**: all eight edges come
/// back on that restart, and on every restart after it, because nothing ever
/// writes the signal that would drop one. It does not self-heal on a later
/// boot; only a real terminal writer heals it.
///
/// ## The other half of the same gap: resources are never reclaimed either
///
/// Fan-out accounting is the consequence a restart makes visible, but it is
/// not the only one, and the second does not need a restart to bite. Every
/// [`LiveSubAgent`](crate::sub_agent_host::LiveSubAgent) holds a real
/// [`HeadlessSession`](crate::session_manager::HeadlessSession): a real
/// isolation mount, a real proxy registration, and possibly a real MCP
/// subprocess. `SubAgentSessions::retire_child` is the one thing that gives
/// any of those back, and it has **no production caller at all** — not merely
/// none across restarts. Nothing terminates a sub-agent session in a live,
/// running daemon, so every sub-agent a parent ever spawns keeps its mount,
/// its proxy registration and its subprocess **for the life of the daemon
/// process**, whether or not the model ever looks at that child again.
///
/// This is bounded rather than an unbounded resource exhaustion:
/// `SessionRegistry`'s `DEFAULT_MAX_SESSIONS` (10,000) refuses a new session
/// fail-closed once the daemon is holding that many, and the eight-slot
/// fan-out ceiling above bounds what any one parent can accumulate. So the
/// end state is a daemon that stops accepting sessions, not one that exhausts
/// the host. It is still a distinct operational consequence from the fan-out
/// one, and closing it takes the same fix: a real terminal signal for a
/// sub-agent session, which then drives `retire_child`.
///
/// ## A restored edge has no `SubAgentSessions` record behind it
///
/// One asymmetry worth stating outright, because it survives the obvious fix:
/// this function restores a sub-agent child's *edge* into the `SpawnTree` (so
/// fan-out accounting is right), but it does **not** recreate a
/// `SubAgentSessions` entry for that child — the `HeadlessSession` it would
/// need died with the previous process. So even once a real terminal-signal
/// writer exists, `retire_child` can never be called for a restart-recovered
/// sub-agent: there is no [`LiveSubAgent`](crate::sub_agent_host::LiveSubAgent)
/// to `take`. Such an edge is only ever cleared by this function's own
/// `SessionClosed` filter on a *subsequent* restart, never during the live
/// process that recovered it.
///
/// **This is a new failure mode introduced by wiring this function at boot**,
/// not a pre-existing one. Until then `reconcile_spawn_tree` had no production
/// caller, so a restart reset every parent's fan-out to zero — wrong in the
/// permissive direction (a parent could exceed eight live children across a
/// restart) rather than the locking one. Whoever decides whether to ship with
/// the sub-agent terminal writer still deferred is deciding between those two
/// wrongs, and should be deciding it with this paragraph in hand.
///
/// This is a real, current gap, documented rather than papered over (AGENTS.md's
/// escalation norm). Closing it means appending a durable session-lifecycle
/// event when a sub-agent is retired — a change to the frozen event contract
/// and its own task, not something this one invented on the side. The filter
/// is written now so that the day such a writer lands, boot recovery is
/// already correct; it was pinned meanwhile by
/// `sub_agent_host`'s own restart test, renamed to
/// `a_retired_sub_agent_child_does_not_reappear_after_a_restart` once a
/// writer landed (Phase 8, T19a Task 6) and the gap closed.
///
/// The workflow half has the mirror-image situation and it is *not* a gap in
/// this function: `finish_run` really does write a terminal `workflow_run`
/// state (and `child_terminated` beside it), so the row read here is the same
/// fact the live hook keys off, and the scheduled-delivery driver now produces
/// such terminal child rows in a running daemon.
///
/// # One bad row is skipped, not fatal
///
/// A lifecycle row whose payload will not deserialize into an `EventPayload`,
/// or whose `events.session_id` column is not a uuid, is **skipped with a
/// loud `tracing::error!`** — named individually, and counted again in one
/// summary line before this function returns. It does not abort the scan and
/// it does not fail the boot.
///
/// That is a deliberate choice between two bounded-wrong outcomes, and it is
/// the same tradeoff the KNOWN GAP above already accepts. The `events` table
/// physically rejects `DELETE` (S-LOG-2), so a row that refuses the boot
/// refuses **every** boot after it, forever: one unreadable byte sequence
/// anywhere in the log and the daemon can never start again, with no operator
/// remedy short of abandoning the store. Skipping costs one under-recovered
/// edge — a parent whose fan-out is counted one slot too low, permissive by
/// exactly one child, against a ceiling of eight. An unbounded "never starts
/// again" failure is worse than a bounded "under-recovered by one row" one.
///
/// This tolerance is scoped to a single malformed row and nothing wider: a
/// store that cannot be read at all (`rusqlite` failing the query or the row
/// decode) still returns `Err` and still refuses the boot, as does a
/// `workflow_run.session_id` that is not a uuid.
pub fn reconcile_spawn_tree(
    conn: &rusqlite::Connection,
    tree: &SpawnTree,
) -> Result<usize, ReconcileSpawnTreeError> {
    let SessionLifecycleFacts {
        edges,
        closed,
        skipped,
    } = session_lifecycle_facts(conn)?;
    if skipped > 0 {
        // Loud on purpose: this is the one place an operator can learn that
        // the tree they are about to admit children against is knowably
        // incomplete. `skipped` is a count this code produced, not log input.
        tracing::error!(
            skipped_rows = skipped,
            "spawn-tree boot recovery skipped unreadable session-lifecycle rows; the restored \
             fan-out may be under-counted by up to that many children. Boot continues by design \
             — see reconcile_spawn_tree's documentation"
        );
    }
    let ended_runs = sessions_whose_runs_have_all_ended(conn)?;

    let mut restored = HashSet::new();
    for (parent, child) in edges {
        if closed.contains(&child) || ended_runs.contains(&child) {
            continue;
        }
        // `record_child` is itself idempotent; the set is what keeps the
        // reported count honest if a session somehow carries more than one
        // `SessionCreated`.
        if restored.insert((parent, child)) {
            tree.record_child(parent, child);
        }
    }
    Ok(restored.len())
}

/// The two facts boot recovery needs out of the event log.
struct SessionLifecycleFacts {
    /// `(parent, child)` for every `SessionCreated` whose spec names a parent.
    edges: Vec<(SessionId, SessionId)>,
    /// Sessions durably known to have closed.
    closed: HashSet<SessionId>,
    /// How many matched rows could not be read at all and were skipped —
    /// reported by [`reconcile_spawn_tree`] in one summary line.
    skipped: usize,
}

/// Collects both in one pass over the event log.
///
/// Collected together, and filtered afterwards rather than during, because a
/// session's `SessionClosed` is appended after its `SessionCreated` — deciding
/// a child's fate on sight would depend on the order rows came back in.
fn session_lifecycle_facts(
    conn: &rusqlite::Connection,
) -> Result<SessionLifecycleFacts, ReconcileSpawnTreeError> {
    // A full scan of `events`: the table carries no payload-kind column to
    // index on (see `roundhouse-store`'s migration for its shape), so the
    // `LIKE` prefilter narrows what is *deserialized*, not what is *read*.
    // Acceptable for a one-off boot step and named here so it is not
    // rediscovered as a surprise on a large store; the alternative is a
    // migration adding an indexed discriminant column, which is its own task.
    let mut statement = conn.prepare(
        "SELECT session_id, seq, payload
           FROM events
          WHERE payload LIKE ?1 OR payload LIKE ?2 OR payload LIKE ?3",
    )?;
    let rows = statement.query_map(
        rusqlite::params![
            format!("{SESSION_CREATED_PAYLOAD_PREFIX}%"),
            format!("{SESSION_CLOSED_PAYLOAD_PREFIX}%"),
            format!("{SESSION_STATE_CHANGED_PAYLOAD_PREFIX}%"),
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )?;

    let mut edges = Vec::new();
    let mut closed = HashSet::new();
    let mut skipped = 0usize;
    for row in rows {
        // A `rusqlite` error here is the connection or the column decode
        // failing, not one row's contents being nonsense — that is the
        // unrecoverable kind, and it still propagates.
        let (session, seq, payload) = row?;
        // Neither the raw `session_id` text nor the payload (nor a serde
        // error's Display, which quotes its input) is ever rendered into a
        // log: an unreadable row is by definition a row no trusted writer
        // produced, and this crate's binding invariant is static strings only
        // in `tracing` fields (see `roundhouse-daemon`'s Cargo.toml, fix round
        // 5 MUST 2). `seq` is an integer and `SessionId` a parsed uuid, so
        // both are safe locators.
        let Ok(session) = parse_session_id("events.session_id", &session) else {
            skipped += 1;
            tracing::error!(
                seq,
                reason = "session_id is not a uuid",
                "skipping an unreadable session-lifecycle event row during spawn-tree boot \
                 recovery; its spawn-tree edge (if any) is not restored"
            );
            continue;
        };
        let Ok(payload) = serde_json::from_str::<EventPayload>(&payload) else {
            skipped += 1;
            tracing::error!(
                session_id = %session,
                seq,
                reason = "payload is not a deserializable EventPayload",
                "skipping an unreadable session-lifecycle event row during spawn-tree boot \
                 recovery; its spawn-tree edge (if any) is not restored"
            );
            continue;
        };
        match payload {
            EventPayload::SessionCreated { spec } => {
                if let Some(parent) = spec.parent {
                    edges.push((parent, session));
                }
            }
            EventPayload::SessionClosed { .. }
            | EventPayload::SessionStateChanged {
                state: SessionState::Closed,
                ..
            } => {
                closed.insert(session);
            }
            _ => {}
        }
    }
    Ok(SessionLifecycleFacts {
        edges,
        closed,
        skipped,
    })
}

/// Sessions whose workflow run (or runs) have all ended — the durable
/// "terminal" signal for a workflow `call:` child, per this module's
/// [`reconcile_spawn_tree`] doc.
///
/// A session with no `workflow_run` row at all is deliberately absent from
/// this set rather than counted as ended: that is every sub-agent child, and
/// every one of them is still live as far as durable state can say.
fn sessions_whose_runs_have_all_ended(
    conn: &rusqlite::Connection,
) -> Result<HashSet<SessionId>, ReconcileSpawnTreeError> {
    let mut statement = conn.prepare(
        "SELECT session_id
           FROM workflow_run
          GROUP BY session_id
         HAVING SUM(CASE WHEN ended_at IS NULL THEN 1 ELSE 0 END) = 0",
    )?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut ended = HashSet::new();
    for row in rows {
        ended.insert(parse_session_id("workflow_run.session_id", &row?)?);
    }
    Ok(ended)
}

fn parse_session_id(
    column: &'static str,
    value: &str,
) -> Result<SessionId, ReconcileSpawnTreeError> {
    uuid::Uuid::parse_str(value)
        .map(SessionId::from_uuid)
        .map_err(|_| ReconcileSpawnTreeError::MalformedSessionId {
            column,
            value: value.to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{JobId, SessionSpec, Timestamp};
    use roundhouse_flow::caps::ResourceCaps;
    use roundhouse_flow::durability::{insert_workflow_run, open_test_db, RunState, WorkflowRun};
    use roundhouse_flow::exec::RunId;

    fn child_run(parent_run_id: RunId, session_id: SessionId) -> WorkflowRun {
        WorkflowRun {
            id: RunId::new(),
            job_id: JobId::new(),
            job_version: 1,
            content_hash: "sha256:child".into(),
            session_id,
            binding_id: None,
            trigger_event_id: None,
            state: RunState::Running,
            parent_run_id: Some(parent_run_id),
            forked_from_run_id: None,
            awaiting_until: None,
            checkpoint_ref: None,
            checkpoint_blob_ref: None,
            started_at: Timestamp::from_unix_nanos(1),
            ended_at: None,
            session_depth: Some(1),
            caps: Some(ResourceCaps {
                max_tokens: 300,
                max_cost_usd: 300.0,
                max_tasks: 300,
                max_tool_calls: 300,
                max_subagents: 300,
                max_bytes_written: 300,
                max_escalations: 300,
                ..ResourceCaps::default()
            }),
        }
    }

    /// A root (unparented) run whose budget is large enough to fund every
    /// child the tests below insert under it.
    fn root_run(session_id: SessionId) -> WorkflowRun {
        let mut run = child_run(RunId::new(), session_id);
        run.parent_run_id = None;
        run.session_depth = Some(0);
        let caps = run.caps.as_mut().unwrap();
        caps.max_tokens = 6_000;
        caps.max_cost_usd = 6_000.0;
        caps.max_tasks = 6_000;
        caps.max_tool_calls = 6_000;
        caps.max_subagents = 6_000;
        caps.max_bytes_written = 6_000;
        caps.max_escalations = 6_000;
        run
    }

    fn append(conn: &mut rusqlite::Connection, event: &roundhouse_core::Event) {
        let txn = roundhouse_store::begin_immediate(conn).unwrap();
        roundhouse_store::append_event_in_transaction(
            &txn,
            event,
            &roundhouse_store::redact::Redactor::build(&[]),
        )
        .unwrap();
        txn.commit().unwrap();
    }

    /// The one durable fact boot recovery reads: a child session's own
    /// `SessionCreated`, carrying the parent it was spawned under. Written
    /// through the real store path (`append_event_in_transaction`), so these
    /// tests read back exactly the bytes production writes — the same call
    /// `WorkflowSessionTree::persist_child_session` and
    /// `DaemonSubAgentHost::persist_session_created` make.
    fn session_created(
        conn: &mut rusqlite::Connection,
        session: SessionId,
        parent: Option<SessionId>,
    ) {
        let mut spec = SessionSpec::test_default();
        spec.parent = parent;
        let event = crate::test_support::runner().record_session_created(
            session,
            0,
            Timestamp::from_unix_nanos(1),
            Box::new(spec),
            1,
        );
        append(conn, &event);
    }

    fn session_closed(conn: &mut rusqlite::Connection, session: SessionId) {
        let event = crate::test_support::runner().record_session_closed(
            session,
            0,
            Timestamp::from_unix_nanos(2),
            roundhouse_core::SessionOutcome::Completed,
            1,
        );
        append(conn, &event);
    }

    fn session_state_changed(
        conn: &mut rusqlite::Connection,
        session: SessionId,
        state: roundhouse_core::SessionState,
    ) {
        let event = crate::test_support::runner().record_session_state_changed(
            session,
            0,
            Timestamp::from_unix_nanos(2),
            state,
            None,
            1,
        );
        append(conn, &event);
    }

    /// A terminal child run, as `transition_run` leaves one: a terminal state
    /// **and** a stamped `ended_at` (the pairing `insert_run_row` refuses to
    /// break — see its `TerminalStateEndedAtMismatch` guard).
    fn ended_child_run(
        parent_run_id: RunId,
        session_id: SessionId,
        state: RunState,
    ) -> WorkflowRun {
        let mut run = child_run(parent_run_id, session_id);
        run.state = state;
        run.ended_at = Some(Timestamp::from_unix_nanos(2));
        run
    }

    #[test]
    fn reconciliation_restores_only_children_whose_session_created_names_a_parent() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent = root_run(parent_session);
        let parent_run = parent.id;
        let created_child = SessionId::new();
        let missing_lifecycle_child = SessionId::new();
        insert_workflow_run(&mut conn, &parent).unwrap();
        insert_workflow_run(&mut conn, &child_run(parent_run, created_child)).unwrap();
        insert_workflow_run(&mut conn, &child_run(parent_run, missing_lifecycle_child)).unwrap();

        session_created(&mut conn, created_child, Some(parent_session));

        let tree = Arc::new(SpawnTree::new());
        reconcile_spawn_tree(&conn, &tree).unwrap();

        assert_eq!(tree.descendants(parent_session), vec![created_child]);
        assert_eq!(
            tree.direct_children(missing_lifecycle_child),
            0,
            "a child run whose session never got a SessionCreated is no one's child"
        );
    }

    /// The restart simulation this task exists for: **one** pass over the
    /// durable log restores the live children of **both** kinds, and restores
    /// neither ended one.
    ///
    /// Seeded into the store directly to isolate boot recovery from the
    /// scheduled-delivery driver's separate parent-to-child execution proof.
    /// The rows are the contract boot recovery actually reads, and they are
    /// seeded through the real writers (`insert_workflow_run`,
    /// `append_event_in_transaction`).
    #[test]
    fn boot_recovery_restores_live_children_of_both_kinds_and_skips_the_ended_ones() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent = root_run(parent_session);
        let parent_run = parent.id;
        insert_workflow_run(&mut conn, &parent).unwrap();

        // (a) a live workflow `call:` child.
        let live_call_child = SessionId::new();
        insert_workflow_run(&mut conn, &child_run(parent_run, live_call_child)).unwrap();
        session_created(&mut conn, live_call_child, Some(parent_session));

        // (b) an ended workflow `call:` child, in each of the three terminal
        // states, since "terminal" here is the whole of `RunState::is_terminal`
        // and not just `Completed`.
        let ended_call_children: Vec<SessionId> =
            [RunState::Completed, RunState::Failed, RunState::Cancelled]
                .into_iter()
                .map(|state| {
                    let child = SessionId::new();
                    insert_workflow_run(&mut conn, &ended_child_run(parent_run, child, state))
                        .unwrap();
                    session_created(&mut conn, child, Some(parent_session));
                    child
                })
                .collect();

        // (c) a live sub-agent child: a `SessionCreated` naming its parent and
        // no `workflow_run` row at all. The old `workflow_run.parent_run_id`
        // join could not see this child; the point of the generalized scan is
        // that one pass now covers it.
        let sub_agent_child = SessionId::new();
        session_created(&mut conn, sub_agent_child, Some(parent_session));

        // (d) an ended sub-agent child — ended in the only way this codebase
        // can durably say so, an explicit `SessionClosed` on its own log.
        let closed_sub_agent_child = SessionId::new();
        session_created(&mut conn, closed_sub_agent_child, Some(parent_session));
        session_closed(&mut conn, closed_sub_agent_child);

        // (e) a root session: its spec names no parent, so it is nobody's
        // child and must not be fabricated into one.
        let root_session = SessionId::new();
        session_created(&mut conn, root_session, None);

        let tree = Arc::new(SpawnTree::new());
        let restored = reconcile_spawn_tree(&conn, &tree).unwrap();

        let mut recovered = tree.descendants(parent_session);
        recovered.sort_by_key(|session| session.to_string());
        let mut expected = vec![live_call_child, sub_agent_child];
        expected.sort_by_key(|session| session.to_string());
        assert_eq!(
            recovered, expected,
            "exactly the two live children — one of each kind — come back"
        );
        assert_eq!(restored, 2, "and the reported count is the edges recorded");
        for ended in ended_call_children {
            assert_eq!(
                tree.direct_children(ended),
                0,
                "an ended child occupies nothing itself either"
            );
        }
        assert_eq!(
            tree.direct_children(root_session),
            0,
            "a parentless session gets no phantom edge"
        );
    }

    /// The two end-signals are a union, not alternatives: whichever arrives is
    /// enough. A child whose `workflow_run` row is still live but whose session
    /// log carries a `SessionClosed` has ended — the session is the unit the
    /// spawn tree counts, and a run cannot outlive the session it runs in.
    ///
    /// Not a hypothetical branch: it is exactly the shape a `call:` child takes
    /// if a future terminal-writer for sessions lands before the child-run
    /// driver that would end its row (or if the daemon dies between the two).
    #[test]
    fn a_closed_session_is_ended_even_when_its_run_row_still_looks_live() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent = root_run(parent_session);
        let parent_run = parent.id;
        insert_workflow_run(&mut conn, &parent).unwrap();

        let closed_but_running = SessionId::new();
        insert_workflow_run(&mut conn, &child_run(parent_run, closed_but_running)).unwrap();
        session_created(&mut conn, closed_but_running, Some(parent_session));
        session_closed(&mut conn, closed_but_running);

        let tree = Arc::new(SpawnTree::new());
        let restored = reconcile_spawn_tree(&conn, &tree).unwrap();

        assert_eq!(restored, 0);
        assert_eq!(
            tree.direct_children(parent_session),
            0,
            "either signal alone ends the child; they are not required together"
        );
    }

    /// Reconciliation must be safe to run more than once against one tree, and
    /// must not double-count a session that carries more than one
    /// `SessionCreated` — `SpawnTree::record_child` dedupes the edge itself, so
    /// the thing at risk is the *reported count*, which a boot line prints and
    /// a future caller might act on.
    #[test]
    fn reconciliation_is_idempotent_over_repeats_and_duplicate_creations() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let child = SessionId::new();
        session_created(&mut conn, child, Some(parent_session));
        session_created(&mut conn, child, Some(parent_session));

        let tree = Arc::new(SpawnTree::new());
        assert_eq!(
            reconcile_spawn_tree(&conn, &tree).unwrap(),
            1,
            "two SessionCreated rows for one child are one edge, counted once"
        );
        assert_eq!(tree.direct_children(parent_session), 1);

        assert_eq!(reconcile_spawn_tree(&conn, &tree).unwrap(), 1);
        assert_eq!(
            tree.direct_children(parent_session),
            1,
            "a second pass over the same tree consumes no further slot"
        );
    }

    /// Inserts a row into `events` that the real writers could never have
    /// produced. Raw SQL on purpose: `append_event_in_transaction` takes a
    /// typed `Event`, so there is no way through it to seed the corruption
    /// this test is about. `INSERT` is the one verb the append-only triggers
    /// allow, and the rows written here are never updated or deleted.
    fn insert_unparseable_event(conn: &rusqlite::Connection, session_id: &str, payload: &str) {
        conn.execute(
            "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v) \
             VALUES (?1, 1, 1, NULL, ?2, 1)",
            rusqlite::params![session_id, payload],
        )
        .unwrap();
    }

    /// One malformed lifecycle row must cost exactly its own edge, not the
    /// daemon's ability to start.
    ///
    /// `events` physically rejects `DELETE`, so a row that aborts boot aborts
    /// **every** boot, forever — the daemon could never start again. The ruling
    /// for this branch is to skip the row loudly and keep going, which is what
    /// this pins: two genuinely unreadable rows (an undeserializable
    /// `SessionCreated` payload, and a `session_id` column that is not a uuid)
    /// sitting beside two good edges, and both good edges still come back with
    /// no `Err`.
    #[test]
    fn a_malformed_lifecycle_row_is_skipped_rather_than_refusing_the_whole_scan() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let first = SessionId::new();
        let second = SessionId::new();
        session_created(&mut conn, first, Some(parent_session));
        session_created(&mut conn, second, Some(parent_session));

        // (a) matches the `SessionCreated` prefilter, but `spec` is a string
        // where `SessionSpec` must be an object — serde cannot make an
        // `EventPayload` of it.
        insert_unparseable_event(
            &conn,
            &SessionId::new().to_string(),
            r#"{"SessionCreated":{"spec":"not-a-session-spec"}}"#,
        );
        // (b) a `session_id` column that is not a uuid. Its payload is
        // asserted well-formed and prefilter-matching first, so this row can
        // only be skipped by the id arm — otherwise it would either never be
        // read at all or be skipped by (a)'s arm, and pass vacuously.
        let closed_payload = r#"{"SessionClosed":{"outcome":"Completed"}}"#;
        assert!(closed_payload.starts_with(SESSION_CLOSED_PAYLOAD_PREFIX));
        assert!(serde_json::from_str::<EventPayload>(closed_payload).is_ok());
        insert_unparseable_event(&conn, "not-a-uuid", closed_payload);

        let tree = Arc::new(SpawnTree::new());
        let restored = reconcile_spawn_tree(&conn, &tree)
            .expect("a malformed row must not fail the whole reconciliation");

        assert_eq!(
            restored, 2,
            "both well-formed edges survive two unreadable rows"
        );
        let descendants: HashSet<SessionId> =
            tree.descendants(parent_session).into_iter().collect();
        assert_eq!(descendants, HashSet::from([first, second]));
    }

    /// `SessionActor::cancel` is the one production writer of a session
    /// lifecycle state event, and it writes `Cancelling` — which §8.13 is
    /// explicit is *not* terminal: the session is draining, not gone. Boot
    /// recovery must keep that child's slot, or a cooperative cancel would
    /// silently hand its parent a free slot the instant a daemon restarted.
    #[test]
    fn a_cancelling_child_is_still_a_child_because_cancel_is_cooperative() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let cancelling = SessionId::new();
        let closed = SessionId::new();
        session_created(&mut conn, cancelling, Some(parent_session));
        session_state_changed(
            &mut conn,
            cancelling,
            roundhouse_core::SessionState::Cancelling,
        );
        session_created(&mut conn, closed, Some(parent_session));
        session_state_changed(&mut conn, closed, roundhouse_core::SessionState::Closed);

        let tree = Arc::new(SpawnTree::new());
        reconcile_spawn_tree(&conn, &tree).unwrap();

        assert_eq!(
            tree.descendants(parent_session),
            vec![cancelling],
            "Cancelling keeps the slot; Closed gives it back"
        );
    }

    /// A fork (`control::retry_from_step` → `durability::fork_run`) mints a
    /// **new** session id while **inheriting** the original's `parent_run_id`,
    /// and writes no `SessionCreated` for that new session — nothing calls
    /// `register_child` for a fork, so a fork's session was never a tracked
    /// child in the first place.
    ///
    /// Under the old `workflow_run.parent_run_id` join a fork row was a
    /// candidate edge, excluded only by the second half of that query (no
    /// lifecycle event). Under the generalized scan it is not even in the
    /// input, which is the stronger property — pinned here with a **real**
    /// fork rather than a hand-built imitation of one, so that a future change
    /// making forks write their own `SessionCreated` fails this test instead of
    /// quietly minting a phantom child at every boot.
    #[test]
    fn a_forked_runs_fresh_session_is_not_a_phantom_child_at_boot() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent = root_run(parent_session);
        let parent_run = parent.id;
        insert_workflow_run(&mut conn, &parent).unwrap();

        let original_child = SessionId::new();
        let original = ended_child_run(parent_run, original_child, RunState::Completed);
        insert_workflow_run(&mut conn, &original).unwrap();
        session_created(&mut conn, original_child, Some(parent_session));

        let fork_session = SessionId::new();
        let fork = roundhouse_flow::control::retry_from_step(
            &mut conn,
            original.id,
            "only-step",
            &["only-step"],
            fork_session,
            Timestamp::from_unix_nanos(3),
        )
        .expect("a terminal, parented run can be retried from its first step");
        assert_eq!(
            roundhouse_flow::durability::recover_run(&conn, fork.new_run_id)
                .unwrap()
                .run
                .parent_run_id,
            Some(parent_run),
            "the fork really did inherit the original's parent — the edge case is live"
        );

        let tree = Arc::new(SpawnTree::new());
        reconcile_spawn_tree(&conn, &tree).unwrap();

        assert_eq!(
            tree.descendants(parent_session),
            Vec::<SessionId>::new(),
            "the original ended and the fork was never a tracked child: no edges at all"
        );
        assert_eq!(tree.direct_children(parent_session), 0);
    }

    /// The SQL prefilter below reads the serialized payload's own discriminant
    /// text. Pinned against what the store actually writes so that a rename or
    /// a change of serde representation fails here — loudly — instead of
    /// silently matching zero rows and quietly restoring no edges at boot.
    #[test]
    fn the_payload_prefixes_match_what_the_store_actually_writes() {
        let mut conn = open_test_db();
        let session = SessionId::new();
        session_created(&mut conn, session, None);
        session_state_changed(&mut conn, session, roundhouse_core::SessionState::Closed);
        session_closed(&mut conn, session);

        let mut statement = conn
            .prepare("SELECT payload FROM events WHERE session_id = ?1 ORDER BY seq")
            .unwrap();
        let payloads: Vec<String> = statement
            .query_map([session.to_string()], |row| row.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();

        assert!(payloads[0].starts_with(SESSION_CREATED_PAYLOAD_PREFIX));
        assert!(payloads[1].starts_with(SESSION_STATE_CHANGED_PAYLOAD_PREFIX));
        assert!(payloads[2].starts_with(SESSION_CLOSED_PAYLOAD_PREFIX));
    }

    #[test]
    fn child_admission_persists_lifecycle_and_grant_before_registering_the_edge() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent_run = RunId::new();
        let mut parent = child_run(RunId::new(), parent_session);
        parent.id = parent_run;
        parent.parent_run_id = None;
        parent.session_depth = Some(0);
        let caps = parent.caps.as_mut().unwrap();
        caps.max_tokens = 600;
        caps.max_cost_usd = 600.0;
        caps.max_tasks = 600;
        caps.max_tool_calls = 600;
        caps.max_subagents = 600;
        caps.max_bytes_written = 600;
        caps.max_escalations = 600;
        insert_workflow_run(&mut conn, &parent).unwrap();

        let child = child_run(parent_run, SessionId::new());
        let tree = Arc::new(SpawnTree::new());
        let mut host = WorkflowSessionTree::new(
            Arc::clone(&tree),
            crate::test_support::runner(),
            SessionSpec::test_default(),
        );
        assert_eq!(
            host.reserve_child(parent_session, child.session_id)
                .unwrap(),
            0
        );
        assert_eq!(tree.direct_children(parent_session), 0);

        let txn = roundhouse_store::begin_immediate(&mut conn).unwrap();
        host.persist_child_session(&txn, parent_session, &child)
            .unwrap();
        roundhouse_flow::durability::insert_workflow_run_in_transaction(&txn, &child).unwrap();
        txn.commit().unwrap();
        host.register_child(parent_session, child.session_id, child.job_id)
            .unwrap();

        let lifecycle_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM events WHERE session_id = ?1",
                [child.session_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(lifecycle_count, 1);
        assert_eq!(
            roundhouse_flow::durability::recover_run(&conn, child.id)
                .unwrap()
                .run
                .parent_run_id,
            Some(parent_run)
        );
        assert_eq!(tree.direct_children(parent_session), 1);
    }

    /// The `call:` half of removal-on-termination, end to end over a real
    /// [`SpawnTree`]: a saturated parent gets a slot back when one child ends,
    /// and gets **exactly one** back however many times it is told.
    ///
    /// Written against the ceiling rather than against a single child on
    /// purpose — `direct_children` dropping from 1 to 0 would pass just as
    /// well with the ceiling check broken, and the ceiling is the thing this
    /// leak actually cost: before `child_terminated` had a caller, eight
    /// `call:` children was every `call:` a parent could make for the life of
    /// the daemon process, whether or not any of them had finished.
    #[test]
    fn a_terminated_child_frees_exactly_one_of_its_parents_fan_out_slots() {
        let parent = SessionId::new();
        let tree = Arc::new(SpawnTree::new());
        let mut host = WorkflowSessionTree::new(
            Arc::clone(&tree),
            crate::test_support::runner(),
            SessionSpec::test_default(),
        );

        let children: Vec<SessionId> = (0..MAX_DIRECT_CHILD_CALLS)
            .map(|_| {
                let child = SessionId::new();
                host.reserve_child(parent, child)
                    .expect("under the ceiling");
                host.register_child(parent, child, JobId::new()).unwrap();
                child
            })
            .collect();
        assert_eq!(tree.direct_children(parent), MAX_DIRECT_CHILD_CALLS);
        assert!(
            host.reserve_child(parent, SessionId::new()).is_err(),
            "a saturated parent must be refused before the fix is even relevant"
        );

        host.child_terminated(parent, children[0]);

        assert_eq!(
            tree.direct_children(parent),
            MAX_DIRECT_CHILD_CALLS - 1,
            "the ended child's slot goes back"
        );
        let replacement = SessionId::new();
        host.reserve_child(parent, replacement)
            .expect("and the freed slot is usable: a new `call:` is admitted");
        host.register_child(parent, replacement, JobId::new())
            .unwrap();
        assert_eq!(tree.direct_children(parent), MAX_DIRECT_CHILD_CALLS);

        // Idempotency at the CALL SITE, not just in `SpawnTree`: a duplicate
        // termination signal for one child must not free a second slot that
        // one of its live siblings is still holding.
        host.child_terminated(parent, children[1]);
        host.child_terminated(parent, children[1]);
        assert_eq!(
            tree.direct_children(parent),
            MAX_DIRECT_CHILD_CALLS - 1,
            "two removals of ONE child free one slot, not two"
        );
        host.reserve_child(parent, SessionId::new())
            .expect("the one freed slot is available");
        assert!(
            host.reserve_child(parent, SessionId::new()).is_err(),
            "and only that one: the second call handed out no phantom slot"
        );
    }

    #[test]
    fn persist_child_session_sets_parent_to_the_actual_parent_not_the_template_spec() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        // Stands in for whatever the stored template spec's own `parent`
        // happens to be — must never leak onto the child's spec below.
        let unrelated_session = SessionId::new();
        let parent_run = RunId::new();
        let mut parent = child_run(RunId::new(), parent_session);
        parent.id = parent_run;
        parent.parent_run_id = None;
        parent.session_depth = Some(0);
        let caps = parent.caps.as_mut().unwrap();
        caps.max_tokens = 600;
        caps.max_cost_usd = 600.0;
        caps.max_tasks = 600;
        caps.max_tool_calls = 600;
        caps.max_subagents = 600;
        caps.max_bytes_written = 600;
        caps.max_escalations = 600;
        insert_workflow_run(&mut conn, &parent).unwrap();

        let child = child_run(parent_run, SessionId::new());
        let tree = Arc::new(SpawnTree::new());
        let mut template_spec = SessionSpec::test_default();
        template_spec.parent = Some(unrelated_session);
        let mut host = WorkflowSessionTree::new(
            Arc::clone(&tree),
            crate::test_support::runner(),
            template_spec,
        );
        host.reserve_child(parent_session, child.session_id)
            .unwrap();

        let txn = roundhouse_store::begin_immediate(&mut conn).unwrap();
        host.persist_child_session(&txn, parent_session, &child)
            .unwrap();
        roundhouse_flow::durability::insert_workflow_run_in_transaction(&txn, &child).unwrap();
        txn.commit().unwrap();

        let payload: String = conn
            .query_row(
                "SELECT payload FROM events WHERE session_id = ?1",
                [child.session_id.to_string()],
                |row| row.get(0),
            )
            .unwrap();
        let payload: EventPayload = serde_json::from_str(&payload).unwrap();
        match payload {
            EventPayload::SessionCreated { spec } => {
                assert_eq!(spec.parent, Some(parent_session));
                assert_ne!(spec.parent, Some(unrelated_session));
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }
}
