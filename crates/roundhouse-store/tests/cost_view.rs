//! Tests for `roundhouse_store::cost` (Task 20): cost attribution as a derived view
//! over `(usage, pricing_snapshot_id)`, never a stored column (§9.7).
//!
//! Adapted from the Task 20 plan brief per the addendum's binding rulings: no
//! `Store::open_temp()`/`.append()`/`TaskOutput::test_infer()`/`StoreError::NotFound`/
//! `debug_table_columns` exist — real construction goes through `open()` +
//! `spawn_writer()` + `TaskRunner::record_*` (Ruling 8), real `TaskOutput` is built as
//! `TaskOutput::Json(json!({"provider": ..., "model": ...}))` (Ruling 5), `Usage` has no
//! `pricing_snapshot_id` field (Ruling 3), `PricingLookup::cost_for` takes
//! `&ProviderId`/`&ModelId` (Ruling 4), and schema introspection is a raw `PRAGMA
//! table_info(tasks)` query inlined here (Ruling 6).

use roundhouse_core::{
    Origin, SessionId, TaskId, TaskInput, TaskKind, TaskOutput, Timestamp, Usage,
};
use roundhouse_provider::fallback::Cost;
use roundhouse_provider::{ModelId, ProviderId};
use roundhouse_store::cost::{task_cost_view, PriceEntry, PricingSnapshot, PricingSnapshotId};
use roundhouse_store::{open, spawn_writer, StorePool};
use std::collections::HashMap;

static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Creates a task (`TaskCreated`) and then immediately completes it
/// (`TaskCompleted`) with the given provider/model/usage, matching the real
/// production shape a `TaskCompleted` output takes for an infer/chat attempt
/// (`roundhouse_provider::fallback`: `TaskOutput::Json(json!({"provider": ...,
/// "model": ...}))`). A bare `TaskCompleted` with no preceding `TaskCreated` is
/// rejected by the real writer (`tasks_view::upsert_for_event`'s zero-row-UPDATE
/// guard), so both events are required here.
async fn seed_completed_task(
    writer: &roundhouse_store::EventWriter,
    session_id: SessionId,
    task_id: TaskId,
    provider: &str,
    model: &str,
    usage: Usage,
) {
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Infer,
            None,
            Origin::Model,
            TaskInput::Text("infer".into()),
            1,
        ))
        .await
        .unwrap();

    let output = TaskOutput::Json(serde_json::json!({
        "provider": provider,
        "model": model,
    }));

    writer
        .append(RUNNER.record_task_completed(session_id, 0, now_ts(), task_id, output, usage, 1))
        .await
        .unwrap();
}

#[tokio::test]
async fn tasks_table_has_no_stored_cost_column() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();

    let conn = store.pool.get().await.unwrap();
    let columns: Vec<String> = conn
        .interact(|c| -> Result<Vec<String>, rusqlite::Error> {
            let mut stmt = c.prepare("PRAGMA table_info(tasks)")?;
            let cols = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(cols)
        })
        .await
        .unwrap()
        .unwrap();

    assert!(
        !columns.iter().any(|c| c == "cost" || c == "cost_usd"),
        "cost must be a derived view over (usage, pricing_snapshot_id), never a stored \
         column (§9.7); found columns: {columns:?}"
    );
}

#[tokio::test]
async fn unknown_model_yields_unknown_cost_but_retains_the_usage_tokens() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    seed_completed_task(
        &writer,
        session_id,
        task_id,
        "anthropic",
        "brand-new-unlisted-model",
        Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_read_tokens: 0,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table: HashMap::new(), // no entry for this model
    };

    let (usage, cost) = task_cost_view(&query_store, task_id, &snapshot)
        .await
        .unwrap();

    assert_eq!(
        usage.input_tokens, 100,
        "tokens are still recorded even when pricing is unknown"
    );
    assert!(matches!(cost, Cost::Unknown));
}

#[tokio::test]
async fn pricing_landing_later_makes_a_historical_task_backfillable_without_mutating_it() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    seed_completed_task(
        &writer,
        session_id,
        task_id,
        "anthropic",
        "brand-new-unlisted-model",
        Usage {
            input_tokens: 100,
            output_tokens: 50,
            cache_read_tokens: 0,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();

    // First: no pricing entry exists yet — cost is Unknown.
    let no_pricing_snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table: HashMap::new(),
    };
    let (_, cost_before) = task_cost_view(&query_store, task_id, &no_pricing_snapshot)
        .await
        .unwrap();
    assert!(matches!(cost_before, Cost::Unknown));

    // A newer PricingSnapshot lands later, supplied fresh by the caller — the event
    // log is never touched.
    let mut table = HashMap::new();
    table.insert(
        (
            ProviderId("anthropic".to_string()),
            ModelId("brand-new-unlisted-model".to_string()),
        ),
        PriceEntry {
            input_pico_usd_per_token: 3_000_000,
            output_pico_usd_per_token: 15_000_000,
            cache_write_pico_usd_per_token: None,
        },
    );
    let later_snapshot = PricingSnapshot {
        id: PricingSnapshotId(2),
        table,
    };

    let (usage, cost) = task_cost_view(&query_store, task_id, &later_snapshot)
        .await
        .unwrap();
    assert_eq!(usage.input_tokens, 100);
    assert_eq!(usage.output_tokens, 50);
    match cost {
        Cost::Known(pico) => {
            assert_eq!(
                pico,
                100 * 3_000_000 + 50 * 15_000_000,
                "recomputed cost must match the newer snapshot's price table exactly"
            );
        }
        Cost::Unknown => panic!(
            "recomputing over the same historical event with newer pricing must succeed \
             without touching the event log"
        ),
    }
}

#[tokio::test]
async fn task_cost_view_errors_for_a_task_with_no_completed_event() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let task_id = TaskId::new();

    // Created but never completed.
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Infer,
            None,
            Origin::Model,
            TaskInput::Text("infer".into()),
            1,
        ))
        .await
        .unwrap();

    let query_store: StorePool = open(&db_path).await.unwrap();
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table: HashMap::new(),
    };

    let result = task_cost_view(&query_store, task_id, &snapshot).await;
    assert!(
        result.is_err(),
        "a task with no TaskCompleted event must be a real error, not a panic or a \
         fabricated cost"
    );
}

#[tokio::test]
async fn session_cost_rollup_sums_known_costs_and_counts_unknowns() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let known_task = TaskId::new();
    let unknown_task = TaskId::new();

    seed_completed_task(
        &writer,
        session_id,
        known_task,
        "anthropic",
        "priced-model",
        Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 0,
        },
    )
    .await;
    seed_completed_task(
        &writer,
        session_id,
        unknown_task,
        "anthropic",
        "unpriced-model",
        Usage {
            input_tokens: 20,
            output_tokens: 8,
            cache_read_tokens: 0,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();
    let mut table = HashMap::new();
    table.insert(
        (
            ProviderId("anthropic".to_string()),
            ModelId("priced-model".to_string()),
        ),
        PriceEntry {
            input_pico_usd_per_token: 1_000,
            output_pico_usd_per_token: 2_000,
            cache_write_pico_usd_per_token: None,
        },
    );
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table,
    };

    let rollup = roundhouse_store::cost::session_cost_rollup(&query_store, session_id, &snapshot)
        .await
        .unwrap();

    assert_eq!(rollup.known_pico_usd, 10 * 1_000 + 5 * 2_000);
    assert_eq!(rollup.unknown_task_count, 1);
}
