//! Phase 5, Subsystem A, Task 4: `trigger_event` persistence, the dedupe
//! index, and catch-up semantics. See
//! `docs/architecture/05-scheduling-and-workflows.md` §8.2 and Ruling P4
//! (the `trigger_event` table lives in `roundhouse_store::migrations`).
use chrono::{TimeZone, Utc};
use roundhouse_core::{BindingId, JobId};
use roundhouse_sched::store::{
    compute_catch_up, occurrence_key, open_test_db, record_trigger_event, StoreError,
    MAX_IDEMPOTENCY_KEY_LEN,
};
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

/// M5 fix: `.last()` on the input `Vec` is *positional*, not *temporal* —
/// `CatchUp::Latest` must pick the temporally latest occurrence even when
/// callers pass `missed` out of chronological order.
#[test]
fn catch_up_latest_picks_the_temporally_latest_occurrence_even_when_input_is_unsorted() {
    let binding = cron_binding_with_catch_up(CatchUp::Latest);
    let latest = Utc.with_ymd_and_hms(2026, 8, 26, 2, 0, 0).unwrap();
    let missed = vec![
        latest, // deliberately listed first, not last
        Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap(),
        Utc.with_ymd_and_hms(2026, 8, 25, 2, 0, 0).unwrap(),
    ];
    let to_run = compute_catch_up(&binding, missed);
    assert_eq!(
        to_run,
        vec![latest],
        "Latest must pick the temporally latest instant, not whatever is positionally last"
    );
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

/// M3: `occurrence_key` is keyed on the occurrence's own identity
/// (`binding_id`, `scheduled_for`), so recomputing it for the *same*
/// scheduled occurrence — as a crash-and-retry would — always reproduces the
/// same key, which is exactly what lets the `trigger_event_dedupe` index
/// catch a re-run of the same occurrence.
#[test]
fn occurrence_key_is_stable_across_recomputation_for_the_same_occurrence() {
    let binding_id = BindingId::new();
    let scheduled_for = Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap();

    let key_a = occurrence_key(binding_id, scheduled_for);
    let key_b = occurrence_key(binding_id, scheduled_for);

    assert_eq!(
        key_a, key_b,
        "the same (binding_id, scheduled_for) must always derive the same key"
    );
}

#[test]
fn occurrence_key_differs_for_a_different_scheduled_occurrence() {
    let binding_id = BindingId::new();
    let key_a = occurrence_key(
        binding_id,
        Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap(),
    );
    let key_b = occurrence_key(
        binding_id,
        Utc.with_ymd_and_hms(2026, 8, 25, 2, 0, 0).unwrap(),
    );

    assert_ne!(key_a, key_b);
}

/// M3: using `occurrence_key` end to end proves the crash-and-retry case a
/// fire-time-derived key would defeat — the *same* scheduled occurrence,
/// "retried" after a simulated crash, still dedupes.
#[test]
fn occurrence_key_based_events_dedupe_across_a_simulated_crash_and_retry() {
    let mut conn = open_test_db();
    let binding_id = BindingId::new();
    let scheduled_for = Utc.with_ymd_and_hms(2026, 8, 24, 2, 0, 0).unwrap();

    // First attempt: fires, but the caller crashes before ever learning the
    // firing was recorded.
    let first_ev = TriggerEvent {
        binding_id,
        idempotency_key: occurrence_key(binding_id, scheduled_for),
        scheduled_for,
        fired_at: scheduled_for, // real fired_at would differ; irrelevant to the key
        is_catch_up: false,
        session_id: None,
    };
    assert!(record_trigger_event(&mut conn, &first_ev).unwrap());

    // Retry after "recovery": same occurrence, but `fired_at` is necessarily
    // a later wall-clock timestamp this time. The key must still match.
    let retry_ev = TriggerEvent {
        binding_id,
        idempotency_key: occurrence_key(binding_id, scheduled_for),
        scheduled_for,
        fired_at: Utc::now(),
        is_catch_up: false,
        session_id: None,
    };
    assert!(
        !record_trigger_event(&mut conn, &retry_ev).unwrap(),
        "a retried occurrence must dedupe even though fired_at differs from the first attempt"
    );
}

/// M3: the idempotency-key length cap is enforced, not merely documented.
#[test]
fn an_over_long_idempotency_key_is_rejected() {
    let mut conn = open_test_db();
    let ev = TriggerEvent {
        binding_id: BindingId::new(),
        idempotency_key: "x".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1),
        scheduled_for: Utc::now(),
        fired_at: Utc::now(),
        is_catch_up: false,
        session_id: None,
    };

    let err = record_trigger_event(&mut conn, &ev).unwrap_err();
    assert!(matches!(err, StoreError::IdempotencyKeyTooLong { .. }));
}

#[test]
fn a_key_at_exactly_the_cap_is_accepted() {
    let mut conn = open_test_db();
    let ev = TriggerEvent {
        binding_id: BindingId::new(),
        idempotency_key: "x".repeat(MAX_IDEMPOTENCY_KEY_LEN),
        scheduled_for: Utc::now(),
        fired_at: Utc::now(),
        is_catch_up: false,
        session_id: None,
    };

    assert!(record_trigger_event(&mut conn, &ev).unwrap());
}
