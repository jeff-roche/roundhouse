//! Daemon-owned session-tree adapter for workflow child admission.

use std::sync::Arc;

use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_core::{EventPayload, JobId, SessionId, SessionSpec, TaskRunner};
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
#[derive(Debug, Error)]
pub enum ReconcileSpawnTreeError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Restores runtime workflow edges after boot from committed child-run rows
/// whose child session has a durable `SessionCreated` event.
pub fn reconcile_spawn_tree(
    conn: &rusqlite::Connection,
    tree: &SpawnTree,
) -> Result<(), ReconcileSpawnTreeError> {
    let mut statement = conn.prepare(
        "SELECT parent.session_id, child.session_id, event.payload
           FROM workflow_run child
           JOIN workflow_run parent ON parent.id = child.parent_run_id
           JOIN events event ON event.session_id = child.session_id
          WHERE child.parent_run_id IS NOT NULL",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (parent, child, payload) = row?;
        let payload: EventPayload = serde_json::from_str(&payload)?;
        if !matches!(payload, EventPayload::SessionCreated { .. }) {
            continue;
        }
        let parent = SessionId::from_uuid(
            uuid::Uuid::parse_str(&parent).map_err(|_| rusqlite::Error::InvalidQuery)?,
        );
        let child = SessionId::from_uuid(
            uuid::Uuid::parse_str(&child).map_err(|_| rusqlite::Error::InvalidQuery)?,
        );
        tree.record_child(parent, child);
    }
    Ok(())
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

    #[test]
    fn reconciliation_restores_only_child_runs_with_a_created_session() {
        let mut conn = open_test_db();
        let parent_session = SessionId::new();
        let parent_run = RunId::new();
        let created_child = SessionId::new();
        let missing_lifecycle_child = SessionId::new();
        let mut parent = child_run(RunId::new(), parent_session);
        parent.id = parent_run;
        parent.parent_run_id = None;
        parent.session_depth = Some(0);
        parent.caps.as_mut().unwrap().max_cost_usd = 600.0;
        parent.caps.as_mut().unwrap().max_tokens = 600;
        parent.caps.as_mut().unwrap().max_tasks = 600;
        parent.caps.as_mut().unwrap().max_tool_calls = 600;
        parent.caps.as_mut().unwrap().max_subagents = 600;
        parent.caps.as_mut().unwrap().max_bytes_written = 600;
        parent.caps.as_mut().unwrap().max_escalations = 600;
        insert_workflow_run(&mut conn, &parent).unwrap();
        insert_workflow_run(&mut conn, &child_run(parent_run, created_child)).unwrap();
        insert_workflow_run(&mut conn, &child_run(parent_run, missing_lifecycle_child)).unwrap();

        let event = crate::test_support::runner().record_session_created(
            created_child,
            0,
            Timestamp::from_unix_nanos(1),
            Box::new(SessionSpec::test_default()),
            1,
        );
        let txn = roundhouse_store::begin_immediate(&mut conn).unwrap();
        roundhouse_store::append_event_in_transaction(
            &txn,
            &event,
            &roundhouse_store::redact::Redactor::build(&[]),
        )
        .unwrap();
        txn.commit().unwrap();

        let tree = Arc::new(SpawnTree::new());
        reconcile_spawn_tree(&conn, &tree).unwrap();

        assert_eq!(tree.direct_children(parent_session), 1);
        assert_eq!(tree.direct_children(created_child), 0);
        assert_eq!(tree.direct_children(missing_lifecycle_child), 0);
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
