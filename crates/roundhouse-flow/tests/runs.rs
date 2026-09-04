//! Task 34 (Phase 5, Subsystem D5) — §8.6's Runs inbox query.
//!
//! **The fixture is the real database.** `open_test_db` applies
//! `roundhouse_store::migrations()`, so `workflow_run`, `tasks` and `events`
//! here are the tables the daemon actually has — `STRICT`, every `NOT NULL`
//! column present, the `state` `CHECK` constraints live, and the append-only
//! triggers on `events` armed. That is the whole point of ruling P86: the
//! plan's version of this test hand-rolled a permissive two-column `tasks` and
//! a four-column `events`, so its `INSERT`s would have been rejected outright
//! by the real schema and the query under test would never once have run
//! against the tables it meets in production.
//!
//! Rows are written with plain `INSERT`s rather than through
//! `roundhouse_store`'s async `EventWriter`, because what is being exercised is
//! a **read**, and the writer would only add a runtime to a synchronous test.
//! Every column the real schema requires is supplied explicitly, so a migration
//! that adds another `NOT NULL` column breaks this file rather than silently
//! passing.

use roundhouse_core::{
    BindingId, EventPayload, JobId, SessionId, TaskId, TaskKind, TaskOutput, Timestamp, Usage,
};
use roundhouse_flow::durability::{insert_workflow_run, open_test_db, RunState, WorkflowRun};
use roundhouse_flow::exec::RunId;
use roundhouse_flow::report::FindingStatus;
use roundhouse_flow::runs::{load_run_summaries, RunsError, MAX_INBOX_RUNS};
use rusqlite::{params, Connection};

/// A completed run. `ended_at` is `Some` because `insert_workflow_run` refuses
/// a terminal state without one — the "run that looks live forever" guard.
fn completed_run(binding_id: Option<BindingId>, started_at: i64) -> WorkflowRun {
    WorkflowRun {
        id: RunId::new(),
        job_id: JobId::new(),
        job_version: 1,
        content_hash: "sha256:a".into(),
        session_id: SessionId::new(),
        binding_id,
        trigger_event_id: None,
        state: RunState::Completed,
        parent_run_id: None,
        forked_from_run_id: None,
        awaiting_until: None,
        started_at: Timestamp::from_unix_nanos(started_at),
        ended_at: Some(Timestamp::from_unix_nanos(started_at + 1)),
    }
}

fn insert(conn: &mut Connection, run: &WorkflowRun) {
    insert_workflow_run(conn, run).expect("a fresh run row inserts");
}

/// §8.6's core report shape, with one finding per `(id, severity)` pair.
fn report_json(headline: &str, findings: &[(&str, &str)]) -> serde_json::Value {
    let findings: Vec<serde_json::Value> = findings
        .iter()
        .map(|(id, severity)| {
            serde_json::json!({
                "id": id,
                "title": format!("finding {id}"),
                "severity": severity,
                "location": "src/lib.rs:1",
            })
        })
        .collect();
    serde_json::json!({
        "outcome": "findings",
        "severity": "med",
        "headline": headline,
        "needs_human": false,
        "cost": { "usd": 0.0, "tokens": 0 },
        "findings": findings,
    })
}

/// Writes a completed `Report` task into `session_id` at `seq`: the `tasks`
/// cache row the join looks up, and the `TaskCompleted` event the report is
/// read out of. The payload is produced by `roundhouse_store::serialize_payload`
/// from a real `EventPayload`, not hand-written, so the externally-tagged shape
/// the query walks is the one the writer actually produces.
fn seed_report_task(conn: &Connection, session_id: SessionId, seq: i64, output: TaskOutput) {
    let task_id = TaskId::new();
    conn.execute(
        "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq)
         VALUES (?1, ?2, ?3, 'Completed', NULL, ?4, ?4)",
        params![
            task_id.to_string(),
            session_id.to_string(),
            // Written exactly as `tasks_view::task_kind_as_sql_str` writes it.
            format!("{:?}", TaskKind::Report),
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
    .expect("an EventPayload serializes");

    conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
         VALUES (?1, ?2, 0, ?3, ?4, 1)",
        params![session_id.to_string(), seq, task_id.to_string(), payload],
    )
    .expect("an event row inserts");
}

fn seed_report(conn: &Connection, session_id: SessionId, seq: i64, report: serde_json::Value) {
    seed_report_task(conn, session_id, seq, TaskOutput::Json(report));
}

fn status_of(summary: &roundhouse_flow::runs::RunSummary, id: &str) -> Option<FindingStatus> {
    summary
        .diffed_findings
        .iter()
        .find(|(finding, _)| finding.id == id)
        .map(|(_, status)| *status)
}

/// The whole of finding 3/4's fix in one test: `binding_id` comes off the real
/// column, and the current run's findings are tagged against the **previous run
/// of the same binding** — persisting, new, and resolved, which are three
/// different answers a diff against nothing could not produce.
#[test]
fn a_runs_findings_are_diffed_against_the_previous_run_of_its_binding() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();

    let older = completed_run(Some(binding_id), 1_000);
    insert(&mut conn, &older);
    seed_report(
        &conn,
        older.session_id,
        1,
        report_json("older", &[("a", "med"), ("gone", "low")]),
    );

    let newer = completed_run(Some(binding_id), 2_000);
    insert(&mut conn, &newer);
    seed_report(
        &conn,
        newer.session_id,
        1,
        report_json("newer", &[("a", "med"), ("b", "low")]),
    );

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    let newest = summaries
        .iter()
        .find(|summary| summary.run_id == newer.id)
        .expect("the newer run is in the inbox");

    assert_eq!(
        newest.binding_id,
        Some(binding_id),
        "binding_id is read from the real column, not left empty"
    );
    assert_eq!(newest.report.headline, "newer");
    assert_eq!(status_of(newest, "a"), Some(FindingStatus::Persisting));
    assert_eq!(status_of(newest, "b"), Some(FindingStatus::New));
    assert_eq!(
        status_of(newest, "gone"),
        Some(FindingStatus::Resolved),
        "a finding the previous run had and this one does not is carried in as resolved"
    );
}

/// The other half of that diff, and the one a query joining on `binding_id`
/// alone would get wrong: the binding's **first** run has no previous run even
/// once later runs of the same binding exist. Its findings are all new, not
/// persisting against a run from its own future.
#[test]
fn the_first_run_of_a_binding_diffs_against_nothing_even_once_later_runs_exist() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();

    let first = completed_run(Some(binding_id), 1_000);
    insert(&mut conn, &first);
    seed_report(
        &conn,
        first.session_id,
        1,
        report_json("first", &[("a", "med")]),
    );

    let second = completed_run(Some(binding_id), 2_000);
    insert(&mut conn, &second);
    seed_report(
        &conn,
        second.session_id,
        1,
        report_json("second", &[("a", "med")]),
    );

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    let earliest = summaries
        .iter()
        .find(|summary| summary.run_id == first.id)
        .expect("the first run is in the inbox");

    assert_eq!(
        status_of(earliest, "a"),
        Some(FindingStatus::New),
        "the binding's first run found it for the first time; a later run is not its past"
    );
    assert_eq!(earliest.diffed_findings.len(), 1);
}

/// A manually-invoked `round workflow run` has no binding, so there is no
/// "previous run of the same binding" to diff against and every finding is new.
/// Notably it must **not** diff against some other binding's run, which is what
/// a query treating `NULL = NULL` loosely would do.
#[test]
fn a_run_with_no_binding_diffs_against_nothing() {
    let mut conn = open_test_db();

    let bound = completed_run(Some(BindingId::new()), 1_000);
    insert(&mut conn, &bound);
    seed_report(
        &conn,
        bound.session_id,
        1,
        report_json("bound", &[("a", "med")]),
    );

    let manual = completed_run(None, 2_000);
    insert(&mut conn, &manual);
    seed_report(
        &conn,
        manual.session_id,
        1,
        report_json("manual", &[("a", "med")]),
    );

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    let manual_summary = summaries
        .iter()
        .find(|summary| summary.run_id == manual.id)
        .expect("a manually-invoked run is still in the inbox");

    assert_eq!(manual_summary.binding_id, None);
    assert_eq!(status_of(manual_summary, "a"), Some(FindingStatus::New));
}

/// A run still executing has no `Report` task yet. It is left out rather than
/// shown as an empty row — the alternative would need a `RunSummary` with no
/// report in it, and §8.6's inbox is a list of what runs *found*.
#[test]
fn a_run_with_no_report_task_is_omitted_rather_than_shown_empty() {
    let mut conn = open_test_db();

    let reported = completed_run(None, 1_000);
    insert(&mut conn, &reported);
    seed_report(&conn, reported.session_id, 1, report_json("done", &[]));

    let unreported = completed_run(None, 2_000);
    insert(&mut conn, &unreported);

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    let ids: Vec<RunId> = summaries.iter().map(|summary| summary.run_id).collect();

    assert_eq!(
        ids,
        vec![reported.id],
        "only the run that produced a report is in the inbox"
    );
}

/// A session's non-`Report` tasks are not reports, however they completed. This
/// is what the `t.kind = ?` predicate buys, and without it the newest completed
/// task in the session — a `Chat`, here — would be validated as a report and
/// blow up the whole load.
#[test]
fn a_completed_task_of_another_kind_in_the_same_session_is_not_read_as_a_report() {
    let mut conn = open_test_db();

    let run = completed_run(None, 1_000);
    insert(&mut conn, &run);
    seed_report(&conn, run.session_id, 1, report_json("the report", &[]));

    // A later, non-Report task in the same session, completing with JSON.
    let chat_id = TaskId::new();
    conn.execute(
        "INSERT INTO tasks (task_id, session_id, kind, state, parent, created_seq, updated_seq)
         VALUES (?1, ?2, ?3, 'Completed', NULL, 9, 9)",
        params![
            chat_id.to_string(),
            run.session_id.to_string(),
            format!("{:?}", TaskKind::Chat)
        ],
    )
    .expect("a Chat task row inserts");
    let payload = roundhouse_store::serialize_payload(&EventPayload::TaskCompleted {
        output: TaskOutput::Json(serde_json::json!({"not": "a report"})),
        usage: Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
        },
    })
    .expect("an EventPayload serializes");
    conn.execute(
        "INSERT INTO events (session_id, seq, ts, task_id, payload, schema_v)
         VALUES (?1, 9, 0, ?2, ?3, 1)",
        params![run.session_id.to_string(), chat_id.to_string(), payload],
    )
    .expect("an event row inserts");

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].report.headline, "the report");
}

/// §8.13's retry-from-step can leave a session with more than one `Report`
/// task. The run's answer is the last report it produced, which is what the
/// `ORDER BY e.seq DESC` picks.
#[test]
fn the_newest_report_wins_when_a_session_produced_more_than_one() {
    let mut conn = open_test_db();

    let run = completed_run(None, 1_000);
    insert(&mut conn, &run);
    seed_report(&conn, run.session_id, 1, report_json("superseded", &[]));
    seed_report(&conn, run.session_id, 2, report_json("final", &[]));

    let summaries = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    assert_eq!(summaries[0].report.headline, "final");
}

/// Newest run first, and the cap is a real cap. Three runs and a limit of two
/// is the smallest fixture that separates the two: with two runs, an `ASC`
/// ordering and a broken limit are indistinguishable from each other, and a
/// limit of `1` would be satisfied by any single row. Here `ASC` and "the limit
/// is ignored" each fail on their own assertion.
#[test]
fn runs_come_back_newest_first_and_the_limit_truncates_the_oldest() {
    let mut conn = open_test_db();

    let mut runs = Vec::new();
    for started_at in [1_000, 2_000, 3_000] {
        let run = completed_run(None, started_at);
        insert(&mut conn, &run);
        seed_report(
            &conn,
            run.session_id,
            1,
            report_json(&format!("at {started_at}"), &[]),
        );
        runs.push(run);
    }

    let all = load_run_summaries(&conn, MAX_INBOX_RUNS).expect("the inbox loads");
    assert_eq!(
        all.iter().map(|s| s.run_id).collect::<Vec<_>>(),
        vec![runs[2].id, runs[1].id, runs[0].id],
        "newest started_at first"
    );

    let capped = load_run_summaries(&conn, 2).expect("the inbox loads");
    assert_eq!(
        capped.iter().map(|s| s.run_id).collect::<Vec<_>>(),
        vec![runs[2].id, runs[1].id],
        "the limit drops the oldest, not the newest"
    );
}

/// A `Report` task that completed with something that is not a §8.6 report is a
/// hard error naming the run, not a row quietly missing from the inbox. A
/// dropped row is indistinguishable from a run that found nothing, which is the
/// one wrong answer this inbox must not give.
#[test]
fn an_unparseable_report_fails_the_load_rather_than_vanishing() {
    let mut conn = open_test_db();

    let run = completed_run(None, 1_000);
    insert(&mut conn, &run);
    // Valid JSON, valid `TaskCompleted`, missing every core field.
    seed_report(
        &conn,
        run.session_id,
        1,
        serde_json::json!({"headline": "x"}),
    );

    let error = load_run_summaries(&conn, MAX_INBOX_RUNS)
        .expect_err("a malformed report is refused, not skipped");
    match error {
        RunsError::InvalidReport { run_id, .. } => assert_eq!(run_id, run.id),
        other => panic!("expected InvalidReport naming the run, got {other:?}"),
    }
}

/// An empty database is an empty inbox, not an error and not a panic — the
/// state every fresh install is in.
#[test]
fn an_empty_database_yields_an_empty_inbox() {
    let conn = open_test_db();
    assert!(load_run_summaries(&conn, MAX_INBOX_RUNS)
        .expect("an empty database loads")
        .is_empty());
}
