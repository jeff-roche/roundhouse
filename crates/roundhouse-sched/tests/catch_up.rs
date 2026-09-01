//! Phase 5, Subsystem A, Task 4: `trigger_event` persistence, the dedupe
//! index, and catch-up semantics. See
//! `docs/architecture/05-scheduling-and-workflows.md` §8.2 and Ruling P4
//! (the `trigger_event` table lives in `roundhouse_store::migrations`).
use chrono::{TimeZone, Utc};
use roundhouse_core::{BindingId, JobId};
use roundhouse_sched::store::{compute_catch_up, open_test_db, record_trigger_event};
use roundhouse_sched::trigger::{Binding, CatchUp, TriggerEvent, TriggerSpec};

fn cron_binding_with_catch_up(catch_up: CatchUp) -> Binding {
    let mut binding = Binding::new_cron(JobId::new(), "0 2 * * *".to_string(), chrono_tz::Tz::UTC);
    if let TriggerSpec::Cron { catch_up: c_up, .. } = &mut binding.spec {
        *c_up = catch_up;
    }
    binding
}

#[test]
fn catch_up_latest_collapses_missed_occurrences_to_one() {
    let binding = cron_binding_with_catch_up(CatchUp::Latest);
    let missed = vec![
        Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 25, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 26, 2, 0, 0).unwrap(),
    ];
    let to_run = compute_catch_up(&binding, missed.clone());
    assert_eq!(to_run, vec![*missed.last().unwrap()]);
}

#[test]
fn catch_up_all_runs_every_missed_occurrence_from_a_real_gap() {
    let binding = cron_binding_with_catch_up(CatchUp::All);
    let missed = vec![
        Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 25, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 26, 2, 0, 0).unwrap(),
    ];
    let to_run = compute_catch_up(&binding, missed.clone());
    assert_eq!(to_run, missed);
}

#[test]
fn catch_up_none_drops_every_missed_occurrence() {
    let binding = cron_binding_with_catch_up(CatchUp::None);
    let missed = vec![
        Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 25, 2, 0, 0).unwrap(),
    ];
    let to_run = compute_catch_up(&binding, missed);
    assert!(to_run.is_empty());
}

#[test]
fn non_cron_triggers_run_every_missed_instant_regardless_of_a_catch_up_policy() {
    let binding = Binding::new(JobId::new(), TriggerSpec::Manual);
    let missed = vec![Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap()];
    let to_run = compute_catch_up(&binding, missed.clone());
    assert_eq!(to_run, missed);
}

fn sample_event(binding_id: BindingId, idempotency_key: &str) -> TriggerEvent {
    TriggerEvent {
        binding_id,
        idempotency_key: idempotency_key.to_string(),
        scheduled_for: Utc::now(),
        fired_at: Utc::now(),
        is_catch_up: false,
        session_id: None,
    }
}

#[test]
fn duplicate_idempotency_key_is_deduped_at_the_store_layer() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();
    let ev = sample_event(binding_id, "webhook-delivery-abc123");

    let first = record_trigger_event(&mut conn, &ev).expect("first insert succeeds");
    let second = record_trigger_event(&mut conn, &ev).expect("second insert does not error");

    assert!(first, "first insert is new");
    assert!(!second, "duplicate is deduped, not double-run");
}

#[test]
fn a_different_idempotency_key_on_the_same_binding_is_not_deduped() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();
    let first_ev = sample_event(binding_id, "run-1");
    let second_ev = sample_event(binding_id, "run-2");

    assert!(record_trigger_event(&mut conn, &first_ev).unwrap());
    assert!(record_trigger_event(&mut conn, &second_ev).unwrap());
}

/// The emphasis in the task brief: dedupe must be enforced by a real
/// database constraint, not merely checked in Rust before insert (which
/// races under concurrent callers). This bypasses `record_trigger_event`
/// entirely and inserts the same `(binding_id, idempotency_key)` pair twice
/// with raw SQL, proving the `trigger_event_dedupe` UNIQUE index itself
/// rejects the true duplicate.
#[test]
fn the_unique_index_itself_rejects_a_true_duplicate_insert() {
    let conn = open_test_db();
    let binding_id = BindingId::new();
    let insert_sql = "INSERT INTO trigger_event
            (binding_id, idempotency_key, scheduled_for, fired_at, is_catch_up, session_id)
         VALUES (?1, ?2, ?3, ?4, 0, NULL)";

    conn.execute(
        insert_sql,
        rusqlite::params![
            binding_id.to_string(),
            "dup-key",
            Utc::now().to_rfc3339(),
            Utc::now().to_rfc3339(),
        ],
    )
    .expect("first raw insert succeeds");

    let err = conn
        .execute(
            insert_sql,
            rusqlite::params![
                binding_id.to_string(),
                "dup-key",
                Utc::now().to_rfc3339(),
                Utc::now().to_rfc3339(),
            ],
        )
        .expect_err("a true duplicate must be rejected by the unique index, not silently applied");

    match err {
        rusqlite::Error::SqliteFailure(e, _) => {
            assert_eq!(e.code, rusqlite::ErrorCode::ConstraintViolation);
        }
        other => panic!("expected a SQLite constraint violation, got {other:?}"),
    }
}
