//! §8.6's Runs inbox query: the recent workflow runs, each with its terminal
//! `Report` task's persisted output, and each one's findings already diffed
//! against the previous run of the same binding.
//!
//! # Why this lives in `roundhouse-flow` and not in `roundhouse-web`
//!
//! Ruling P86. The obvious home for "the query behind the Runs inbox" is the
//! crate that serves the inbox, and that is where the plan put it — a hand-
//! written join across **`roundhouse-store`'s** `tasks` and `events` tables,
//! inside a leaf crate that declares no edge to `roundhouse-store` and has no
//! compile-time link to its schema. A store migration renaming `payload` or
//! `kind` would break the inbox silently, and `xtask/tests/workspace_shape.rs`
//! could not catch it, because it tracks crate edges and not column names.
//!
//! This crate is the one that already owns every other piece —
//! [`crate::durability::WorkflowRun`],
//! [`crate::durability::previous_run_for_binding`], [`Report`],
//! [`validate_report`], [`diff_findings`] — and it already declares both
//! `roundhouse-store` and `rusqlite`. The precedent is
//! `roundhouse_store::attention::blocked_anywhere` and
//! `suspended::suspended_tasks`: a cross-table query exposed as a typed
//! function rather than SQL written at the call site.
//!
//! What stays in `roundhouse-web` is what is genuinely presentation: the triage
//! sort, decision-signature collapsing, the JSON wire shape and the route.
//!
//! # Two untyped contracts this query rests on, both named rather than assumed
//!
//! 1. **`tasks.kind` holds `TaskKind`'s `Debug` rendering.**
//!    `roundhouse_store::tasks_view::task_kind_as_sql_str` is literally
//!    `format!("{kind:?}")`. `report_task_kind` therefore *computes* the
//!    string from [`TaskKind::Report`] rather than spelling `'Report'` as a
//!    literal, so renaming the variant is a compile error here instead of a
//!    query that silently matches nothing. It does not make the *format* safe —
//!    `roundhouse_store::attention`'s module docs describe the same implicit
//!    cross-crate contract at length, and this is a second reader of it.
//! 2. **`EventPayload` is externally tagged.** It carries no
//!    `#[serde(tag = …)]`, so a `TaskCompleted { output: TaskOutput::Json(v) }`
//!    serializes as `{"TaskCompleted":{"output":{"Json":v},"usage":…}}`, which
//!    is the shape `extract_report_json` walks. `EventPayload` derives
//!    `Serialize` and not `Deserialize` (S-LOG-1), so this cannot be a typed
//!    round-trip. It is pinned instead by
//!    `a_real_serialized_task_completed_event_is_where_the_report_is_read_from`,
//!    which serializes a real [`roundhouse_core::EventPayload`] and reads it
//!    back through this module rather than hand-writing the JSON.
//!
//! # What this module does not decide
//!
//! Nothing in this workspace yet drives a run to a terminal state with a
//! `Report` task — B12c owns the run loop — so this is written and tested
//! against seeded rows and has no end-to-end path through it today.
//!
//! It also does not filter on [`crate::durability::RunState`]. **Having a
//! report is the filter**: §8.6 makes the report the terminal task of a run, so
//! a run without one has nothing for the inbox to show, whatever its state
//! says, and a `failed` run *with* one has `Outcome::Failed` to show and
//! belongs in the inbox. Deriving the inbox's contents from `RunState` would
//! collapse the two axes [`crate::report::Outcome`]'s doc comment exists to
//! keep apart.

use rusqlite::Connection;
use thiserror::Error;

use roundhouse_core::{BindingId, SessionId, TaskKind};

use crate::durability::{previous_run_for_binding, recent_workflow_runs, DurabilityError};
use crate::exec::RunId;
use crate::report::{diff_findings, validate_report, Finding, FindingStatus, Report, ReportError};

/// How many runs the inbox loads at most.
///
/// A cap, not a page size: there is no cursor here and this task does not build
/// one. It exists because `workflow_run` grows once per run forever while the
/// inbox is a single screen — see `durability::recent_workflow_runs` for why an uncapped
/// listing is the wrong default. **Residual for whoever needs run 201:** this is
/// where pagination goes, and the natural cursor is the `(started_at, id)` pair
/// the ordering already uses.
pub const MAX_INBOX_RUNS: usize = 200;

/// One run as the inbox shows it: which run, which binding, what it found, and
/// how that compares to the last time this binding ran.
#[derive(Debug, Clone, PartialEq)]
pub struct RunSummary {
    pub run_id: RunId,
    /// `None` for a manually-invoked run, which has no binding and therefore no
    /// "previous run of the same binding" to diff against — see
    /// [`crate::durability::WorkflowRun::binding_id`].
    pub binding_id: Option<BindingId>,
    pub report: Report,
    /// §8.6's fingerprint diff: every finding of *this* run tagged
    /// new/persisting, plus the previous run's findings that are gone, tagged
    /// resolved. Every finding is tagged [`FindingStatus::New`] when the
    /// binding has no previous run (or the run has no binding at all), which is
    /// [`diff_findings`]'s answer against an empty previous set and is the
    /// truthful one: a binding's first run has genuinely found all of them for
    /// the first time.
    pub diffed_findings: Vec<(Finding, FindingStatus)>,
}

/// Why the inbox could not be loaded.
#[derive(Debug, Error)]
pub enum RunsError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Durability(#[from] DurabilityError),
    /// A `Report` task completed with an output that is not a valid §8.6
    /// report.
    ///
    /// **Hard-fails the whole load rather than skipping the run.** A report
    /// that does not parse is the one case where showing nothing is worse than
    /// showing an error: the inbox exists so a human sees what a run found, and
    /// a silently dropped row reads exactly like a run that found nothing. Same
    /// fail-closed convention as `roundhouse_store::suspended_tasks` and
    /// `attention::blocked_anywhere`, which also refuse a malformed row rather
    /// than passing over it.
    #[error("run {run_id}'s report task output is not a valid report: {source}")]
    InvalidReport {
        run_id: RunId,
        #[source]
        source: ReportError,
    },
}

/// The Runs inbox's rows, newest run first, at most `limit` of them (see
/// [`MAX_INBOX_RUNS`]).
///
/// A run with no completed `Report` task is **omitted**, not represented as an
/// empty row: it has not finished, or it produced nothing to triage. That is
/// the only silent skip here — a report that *exists* and does not parse is
/// [`RunsError::InvalidReport`].
///
/// # Cost
///
/// One query for the run list, then up to three per run (this run's report, the
/// previous run of the binding, that run's report). Bounded by `limit`, on an
/// in-process SQLite connection, with `previous_run_for_binding` served by
/// migration 0007's `binding_id`/`started_at` index. **Not optimised, and
/// deliberately so**: the one caller renders at most [`MAX_INBOX_RUNS`] rows,
/// and a single join doing the same work would have to reproduce
/// `previous_run_for_binding`'s strictly-earlier `(started_at, id)` bound in
/// SQL, which is the part of this that is easy to get subtly wrong. If this
/// becomes hot, that is the trade to revisit.
pub fn load_run_summaries(conn: &Connection, limit: usize) -> Result<Vec<RunSummary>, RunsError> {
    let mut summaries = Vec::new();
    for run in recent_workflow_runs(conn, limit)? {
        let Some(report) = load_report(conn, run.session_id, run.id)? else {
            continue;
        };

        let previous_findings = match run.binding_id {
            None => Vec::new(),
            Some(binding_id) => match previous_run_for_binding(conn, binding_id, run.id)? {
                None => Vec::new(),
                Some(previous) => load_report(conn, previous.session_id, previous.id)?
                    .map(|report| report.findings)
                    .unwrap_or_default(),
            },
        };

        summaries.push(RunSummary {
            run_id: run.id,
            binding_id: run.binding_id,
            diffed_findings: diff_findings(&previous_findings, &report.findings),
            report,
        });
    }
    Ok(summaries)
}

/// The statement [`load_report`] runs.
///
/// A named constant so the query-plan test can ask SQLite about **the string
/// the code executes**, rather than about a copy of it that could drift.
const LOAD_REPORT_SQL: &str = "SELECT e.payload
           FROM events e
           JOIN tasks t ON t.task_id = e.task_id
          WHERE t.session_id = ?1 AND t.kind = ?2
          ORDER BY e.seq DESC";

/// The report a run's session persisted, or `None` if it has none yet.
///
/// Takes the newest `TaskCompleted`-with-JSON event of any `Report` task in the
/// session. Newest rather than only-one because §8.13's retry-from-step can put
/// more than one `Report` task in front of this query, and the run's answer is
/// the last one it produced; `run_id` is carried only to name the run in
/// [`RunsError::InvalidReport`].
///
/// # What the cost actually is, measured rather than reasoned about
///
/// An earlier version of this comment said the `ORDER BY … DESC` plus a lazy
/// iterator "stops at the first matching row, so a session with a long log costs
/// one index seek and not a full scan". The lazy iteration is real; the
/// inference from it was not. `EXPLAIN QUERY PLAN` on this statement against the
/// real migrations (SQLite 3.53.2) says:
///
/// ```text
/// SEARCH t USING INDEX tasks_session_id_idx (session_id=?)
/// SEARCH e USING INDEX events_task_id_idx (task_id=?)
/// USE TEMP B-TREE FOR ORDER BY
/// ```
///
/// No index supplies `e.seq DESC` over the *joined* rowset, so SQLite
/// materialises and sorts it before yielding anything: the first row is not
/// cheap because it is first. What is true, and is the part that matters, is
/// that the sorted set is **bounded to this session's `Report`-task events** by
/// the two index searches and the `kind` predicate — not to the session's whole
/// log — and a session has a handful of those. (The searches alone bound it to
/// the session's tasks and their events; `t.kind = ?2` has no index and is a
/// plain filter, which is the part that narrows it to `Report`.) The cost is
/// fine; the mechanism was described wrongly.
///
/// That plan is now **asserted** rather than quoted:
/// `tests::the_report_query_sorts_through_a_temp_b_tree` runs
/// `EXPLAIN QUERY PLAN` over [`LOAD_REPORT_SQL`] against the same migrations
/// and fails if the `USE TEMP B-TREE` line goes away. A future migration adding
/// an index that serves this `ORDER BY` would make the paragraph above wrong,
/// and it should be a failing test rather than prose nobody re-measures — which
/// is exactly what happened to the claim this replaced.
fn load_report(
    conn: &Connection,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<Report>, RunsError> {
    let mut stmt = conn.prepare(LOAD_REPORT_SQL)?;
    let mut rows = stmt.query(rusqlite::params![
        session_id.to_string(),
        report_task_kind()
    ])?;

    while let Some(row) = rows.next()? {
        let payload: String = row.get(0)?;
        if let Some(json) = extract_report_json(&payload) {
            return validate_report(&json)
                .map(Some)
                .map_err(|source| RunsError::InvalidReport { run_id, source });
        }
    }
    Ok(None)
}

/// How [`TaskKind::Report`] is spelled in `tasks.kind`.
///
/// Computed from the variant rather than written as `'Report'`, so that
/// renaming it is a compile error here rather than a query that matches nothing
/// — see this module's docs for the limits of that (the *format* is still
/// `derive(Debug)`'s, which nothing pins).
fn report_task_kind() -> String {
    format!("{:?}", TaskKind::Report)
}

/// The `TaskOutput::Json` value out of a serialized `TaskCompleted` event, or
/// `None` for any other event (a `TaskCreated`, a `TaskCompleted` carrying
/// `Text`/`Blob`, or anything unparseable).
///
/// See this module's docs for why the shape is
/// `{"TaskCompleted":{"output":{"Json":…}}}` and what pins it.
fn extract_report_json(payload: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(payload).ok()?;
    value
        .get("TaskCompleted")?
        .get("output")?
        .get("Json")
        .cloned()
}

/// Test-only helper: one completed [`crate::durability::WorkflowRun`] that
/// [`load_run_summaries`] will return, with `report` as its terminal `Report`
/// task's output. Returns the run's id.
///
/// # Why this is here rather than in the crate that serves the inbox
///
/// Same reason as the query above it, ruling P86. `roundhouse-web` renders the
/// inbox, and its own test suite could only reach past
/// `AppState::store_connection` with a database that has runs in it — but
/// seeding one means `INSERT`s against **`roundhouse-store`'s** `workflow_run`,
/// `tasks` and `events` tables, and `roundhouse-web` declares neither
/// `rusqlite` nor any compile-time link to that schema. Writing those `INSERT`s
/// there would put the crate back in the position P86 took it out of, in its
/// tests instead of its source, which is the same hazard with a thinner excuse.
///
/// So the seeding lives beside the query it seeds for, and `roundhouse-web`
/// dev-depends on this crate with `features = ["test-util"]`.
///
/// **What that bought, specifically.** Before it, `roundhouse-web`'s only
/// real-store fixture asserted `[]` against an empty database, so four
/// mutations of `runs::list_runs`'s outer map survived the sweep: `.take(1)`,
/// `.skip(1)` and `.take(0)` on the run list, and dropping the
/// `sort_for_triage` call entirely (WC4-WC7). Every one of them is invisible to
/// a fixture whose correct answer is the empty list.
///
/// # `&Report`, and the round-trip it checks on the way past
///
/// The parameter is a typed [`Report`] rather than a `serde_json::Value`, so a
/// caller does not hand-write §8.6's document shape — and the serialized form
/// is fed back through [`validate_report`] here, before it is written. That is
/// not belt-and-braces: [`Report`] derives `Serialize` and **not**
/// `Deserialize` (its `extra` map is `#[serde(flatten)]`, and this module's
/// docs record why the pair cannot be a typed round-trip), so nothing else in
/// the workspace would notice if the two drifted. A seeded row the real query
/// then rejects as [`RunsError::InvalidReport`] would fail a caller's test with
/// a message about the *query*; this fails it here, naming the report.
///
/// # Cost model
///
/// `started_at_nanos` orders the runs: [`crate::durability::recent_workflow_runs`]
/// returns `ORDER BY started_at DESC, id DESC`, so a caller that wants query
/// order to differ from triage order controls it with this. Every run gets a
/// fresh [`SessionId`], so the event `seq` is always `1` and no caller has to
/// track one.
///
/// # Its relationship to the finer helper below
///
/// This is the "one ordinary completed run" shape — a run row plus its report —
/// and it is the only shape an out-of-crate caller can want, which is why it is
/// the coarse one. The negative cases this crate's own `tests/runs.rs` needs (a
/// `TaskOutput::Text`, a hand-written malformed payload, two `Report` tasks in
/// *one* session at different `seq`s for §8.13's retry-from-step case) are not
/// expressible through this signature — but they are all expressible through
/// [`seed_report_task`], which is exactly parameterised on those axes.
///
/// An earlier version of this paragraph said the two sets of `INSERT`s were
/// deliberately unfolded because the finer shapes could not be expressed. That
/// answered the wrong question: the obstacle was **directional** — the helper
/// lived in a test target, and `src/` cannot call into one. Moving it here
/// removed it, and this function now writes its task and event rows through it.
///
/// Ruling L7, exactly as [`crate::durability::open_test_db`] states it: gated
/// behind `cfg(test)` / the `test-util` feature so daemon code can never reach
/// for this as though it were a way to record a real run. It is not — it writes
/// a run row directly rather than through the state machine in
/// [`crate::durability`], so nothing it produces has a legal transition history.
#[cfg(any(test, feature = "test-util"))]
pub fn seed_completed_run_with_report(
    conn: &mut Connection,
    binding_id: Option<BindingId>,
    started_at_nanos: i64,
    report: &Report,
) -> RunId {
    use roundhouse_core::{JobId, TaskOutput, Timestamp};

    use crate::durability::{insert_workflow_run, RunState, WorkflowRun};

    let json = serde_json::to_value(report).expect("a Report serializes");
    validate_report(&json).expect(
        "a seeded Report must survive its own Serialize -> validate_report round trip, or the \
         query under test would reject the row rather than return it",
    );

    let run = WorkflowRun {
        id: RunId::new(),
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:seeded".into(),
        session_id: SessionId::new(),
        binding_id,
        trigger_event_id: None,
        // `ended_at` is `Some` because `insert_workflow_run` refuses a terminal
        // state without one — the "run that looks live forever" guard.
        state: RunState::Completed,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: Timestamp::from_unix_nanos(started_at_nanos),
        ended_at: Some(Timestamp::from_unix_nanos(started_at_nanos + 1)),
    };
    insert_workflow_run(conn, &run).expect("a fresh run row inserts");

    seed_report_task(conn, run.session_id, 1, TaskOutput::Json(json));

    run.id
}

/// Test-only helper: one completed `Report` task in `session_id` at `seq`,
/// carrying `output` — the `tasks` row and the `TaskCompleted` event row that
/// [`load_report`] joins across.
///
/// # Why the `output` is a parameter and the kind is not
///
/// The three axes the negative cases vary are the session, the `seq` and the
/// output — a `TaskOutput::Text`, a hand-written malformed payload, or two
/// reports in one session at different `seq`s (§8.13's retry-from-step case).
/// The task *kind* is not one of them: every caller here is seeding a `Report`,
/// which is what [`load_report`]'s `t.kind = ?` predicate selects on, and a
/// caller wanting a different kind is testing that predicate rather than using
/// this. `tests/runs.rs` has exactly one such case and writes its own rows.
///
/// # It lives in `src/` because that is the only direction that works
///
/// It was written in this crate's `tests/runs.rs`, which meant
/// [`seed_completed_run_with_report`] could not call it — a `src/` module cannot
/// reach into a test target — so the same two `INSERT`s were written twice. The
/// obstacle was directional, not expressive, and moving the helper is what
/// removes it.
///
/// Plain `INSERT`s and not `roundhouse_store`'s async `EventWriter`: what these
/// rows exist for is a **read**, and the writer would only add a runtime. Every
/// column the real schema requires is supplied explicitly, so a migration adding
/// another `NOT NULL` column breaks this rather than silently passing.
///
/// Ruling L7, same gate and same reason as [`seed_completed_run_with_report`]
/// above: these rows have no legal transition history, so daemon code must never
/// be able to reach for them.
#[cfg(any(test, feature = "test-util"))]
pub fn seed_report_task(
    conn: &Connection,
    session_id: SessionId,
    seq: i64,
    output: roundhouse_core::TaskOutput,
) {
    use roundhouse_core::{EventPayload, TaskId, Usage};

    let task_id = TaskId::new();
    conn.execute(
        "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq)
         VALUES (?1, ?2, ?3, 'Completed', NULL, ?4, ?4)",
        rusqlite::params![
            task_id.to_string(),
            session_id.to_string(),
            // Written exactly as `tasks_view::task_kind_as_sql_str` writes it,
            // which is what `report_task_kind` above reads back.
            report_task_kind(),
            seq
        ],
    )
    .expect("a Report task row inserts");

    let payload = roundhouse_store::serialize_payload(&EventPayload::TaskCompleted {
        output,
        usage: Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
        },
    })
    .expect("an EventPayload serializes to JSON");

    conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
         VALUES (?1, ?2, 0, ?3, ?4, 1)",
        rusqlite::params![session_id.to_string(), seq, task_id.to_string(), payload],
    )
    .expect("an event row inserts");
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{EventPayload, TaskOutput, Usage};

    /// [`load_report`]'s cost paragraph quotes a plan; this is what keeps the
    /// quote true. The claim that matters is the **negative** one — no index
    /// serves `ORDER BY e.seq DESC` over the join, so SQLite sorts the joined
    /// rowset — and `USE TEMP B-TREE` is how that shows up in the plan.
    ///
    /// Asserted against the real migrations through
    /// [`crate::durability::open_test_db`], not against a hand-built schema:
    /// the plan is a function of which indexes exist, so a fixture with
    /// different indexes would measure a different database. A migration that
    /// added a serving index would fail here, which is the point — the previous
    /// version of that paragraph was an unmeasured inference, and replacing it
    /// with a more specific unmeasured one would have been the same mistake
    /// with better prose.
    #[test]
    fn the_report_query_sorts_through_a_temp_b_tree() {
        let conn = crate::durability::open_test_db();
        let mut stmt = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {LOAD_REPORT_SQL}"))
            .expect("the report query prepares against the real schema");
        let plan: Vec<String> = stmt
            .query_map(rusqlite::params![None::<String>, None::<String>], |row| {
                row.get::<_, String>(3)
            })
            .expect("EXPLAIN QUERY PLAN yields rows")
            .collect::<Result<_, _>>()
            .expect("every plan row has a detail column");
        let plan = plan.join("\n");

        assert!(
            plan.contains("USE TEMP B-TREE"),
            "load_report's doc comment says the joined rowset is sorted rather than walked in \
             index order; the plan now says:\n{plan}"
        );
    }

    /// The contract of §2 of this module's docs, checked against the real type
    /// rather than against a hand-written JSON string: whatever
    /// `EventPayload`'s `Serialize` produces is what [`extract_report_json`]
    /// has to walk. A `#[serde(tag = …)]` added to `EventPayload`, or a rename
    /// of `TaskCompleted`/`output`, fails here.
    #[test]
    fn a_real_serialized_task_completed_event_is_where_the_report_is_read_from() {
        let payload = EventPayload::TaskCompleted {
            output: TaskOutput::Json(serde_json::json!({"headline": "hello"})),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_read_tokens: 0,
            },
        };
        let serialized = roundhouse_store::serialize_payload(&payload)
            .expect("an EventPayload serializes to JSON");

        assert_eq!(
            extract_report_json(&serialized),
            Some(serde_json::json!({"headline": "hello"})),
            "the report is read out of the real serialized shape, not an assumed one"
        );
    }

    /// A completed task whose output is not JSON has no report in it, and must
    /// not be mistaken for one — otherwise a `Text` output would reach
    /// [`validate_report`] and turn a perfectly ordinary chat task into a
    /// [`RunsError::InvalidReport`].
    #[test]
    fn a_completed_task_with_a_non_json_output_yields_no_report() {
        let payload = EventPayload::TaskCompleted {
            output: TaskOutput::Text("not a report".into()),
            usage: Usage {
                input_tokens: 0,
                output_tokens: 0,
                cache_read_tokens: 0,
            },
        };
        let serialized = roundhouse_store::serialize_payload(&payload)
            .expect("an EventPayload serializes to JSON");

        assert_eq!(extract_report_json(&serialized), None);
    }

    /// `tasks.kind` is written by `roundhouse_store`'s
    /// `task_kind_as_sql_str`, which is `format!("{kind:?}")`. This pins that
    /// the string this module matches on is the one that function writes.
    #[test]
    fn the_report_kind_is_spelled_the_way_the_tasks_table_stores_it() {
        assert_eq!(report_task_kind(), format!("{:?}", TaskKind::Report));
        assert_eq!(report_task_kind(), "Report");
    }
}
