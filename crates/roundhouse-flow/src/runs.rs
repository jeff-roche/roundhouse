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

/// The report a run's session persisted, or `None` if it has none yet.
///
/// Takes the newest `TaskCompleted`-with-JSON event of any `Report` task in the
/// session. Newest rather than only-one because §8.13's retry-from-step can put
/// more than one `Report` task in front of this query, and the run's answer is
/// the last one it produced; `run_id` is carried only to name the run in
/// [`RunsError::InvalidReport`].
///
/// The `ORDER BY … DESC` plus a lazy iterator means this stops at the first
/// matching row, so a session with a long log costs one index seek and not a
/// full scan of its events.
fn load_report(
    conn: &Connection,
    session_id: SessionId,
    run_id: RunId,
) -> Result<Option<Report>, RunsError> {
    let mut stmt = conn.prepare(
        "SELECT e.payload
           FROM events e
           JOIN tasks t ON t.task_id = e.task_id
          WHERE t.session_id = ?1 AND t.kind = ?2
          ORDER BY e.seq DESC",
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_core::{EventPayload, TaskOutput, Usage};

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
