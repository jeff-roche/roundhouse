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
            cache_read_pico_usd_per_token: None,
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
            cache_read_pico_usd_per_token: None,
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
    assert_eq!(rollup.unattributable_task_count, 0);
}

/// Fix round 1, item 1: the security review reproduced this directly — a session
/// containing a real chat-shaped completed task (`TaskOutput::Text(String::new())`,
/// byte-identical to what `roundhouse-engine`'s `chat.rs::append_completed` actually
/// produces) used to abort `session_cost_rollup` for the ENTIRE session on the first
/// such task, because `task_cost_view`'s `Err` was propagated unconditionally out of the
/// loop. Chat-shaped completed tasks are the NORMAL case in a real session, not an
/// anomaly, so this must not fail the whole rollup — it must be counted as
/// `unattributable_task_count` and the rollup must still succeed, correctly reflecting
/// the properly-priced task alongside it.
#[tokio::test]
async fn session_cost_rollup_tolerates_a_real_chat_shaped_completed_task() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    let session_id = SessionId::new();
    let priced_task = TaskId::new();
    let chat_task = TaskId::new();

    seed_completed_task(
        &writer,
        session_id,
        priced_task,
        "anthropic",
        "priced-model",
        Usage {
            input_tokens: 10,
            output_tokens: 5,
            cache_read_tokens: 0,
        },
    )
    .await;

    // A real chat task, completed exactly the way
    // `roundhouse-engine/src/chat.rs`'s `append_completed` actually does it: `TaskKind::Chat`,
    // `TaskOutput::Text(String::new())`, `Usage::default()`.
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            chat_task,
            TaskKind::Chat,
            None,
            Origin::User,
            TaskInput::Text("hello".into()),
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_task_completed(
            session_id,
            0,
            now_ts(),
            chat_task,
            TaskOutput::Text(String::new()),
            Usage::default(),
            1,
        ))
        .await
        .unwrap();

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
            cache_read_pico_usd_per_token: None,
        },
    );
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table,
    };

    let rollup = roundhouse_store::cost::session_cost_rollup(&query_store, session_id, &snapshot)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "session_cost_rollup must not fail the whole session over one chat-shaped \
                 completed task, got Err: {e}"
            )
        });

    assert_eq!(
        rollup.known_pico_usd,
        10 * 1_000 + 5 * 2_000,
        "the properly-priced task's cost must still be reflected correctly"
    );
    assert_eq!(rollup.unknown_task_count, 0);
    assert_eq!(
        rollup.unattributable_task_count, 1,
        "the chat-shaped task must be counted as unattributable, not silently dropped \
         and not treated as a pricing-coverage gap"
    );
}

/// Fix round 1, item 2: `Usage::cache_read_tokens` is a real, billed token class (for
/// the Anthropic provider this repo ships) and must actually be priced when a
/// `PriceEntry` supplies a rate for it — the security review reproduced 1,000,000
/// cache-read tokens against a fully-populated `PriceEntry` silently returning
/// `Cost::Known(0)` under the pre-fix code.
#[tokio::test]
async fn cache_read_tokens_are_priced_when_a_rate_is_supplied() {
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
        "cache-heavy-model",
        Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 1_000_000,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();
    let mut table = HashMap::new();
    table.insert(
        (
            ProviderId("anthropic".to_string()),
            ModelId("cache-heavy-model".to_string()),
        ),
        PriceEntry {
            input_pico_usd_per_token: 3_000_000,
            output_pico_usd_per_token: 15_000_000,
            cache_read_pico_usd_per_token: Some(300_000),
        },
    );
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table,
    };

    let (_, cost) = task_cost_view(&query_store, task_id, &snapshot)
        .await
        .unwrap();

    match cost {
        Cost::Known(pico) => assert_eq!(
            pico,
            1_000_000 * 300_000,
            "cache-read tokens must actually be priced, not silently treated as free"
        ),
        Cost::Unknown => panic!("a fully-populated PriceEntry must yield Cost::Known"),
    }
}

/// Companion to the above: a nonzero `cache_read_tokens` count against a `PriceEntry`
/// that has NO cache-read rate must fall back to `Cost::Unknown`, not silently price
/// those tokens at zero — the same fail-closed discipline `cost_for` already applies to
/// an entirely-missing `PriceEntry`.
#[tokio::test]
async fn cache_read_tokens_with_no_price_entry_yields_unknown_not_silent_zero() {
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
        "cache-heavy-model",
        Usage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 1_000_000,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();
    let mut table = HashMap::new();
    table.insert(
        (
            ProviderId("anthropic".to_string()),
            ModelId("cache-heavy-model".to_string()),
        ),
        PriceEntry {
            input_pico_usd_per_token: 3_000_000,
            output_pico_usd_per_token: 15_000_000,
            cache_read_pico_usd_per_token: None, // no cache-read rate supplied
        },
    );
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table,
    };

    let (_, cost) = task_cost_view(&query_store, task_id, &snapshot)
        .await
        .unwrap();

    assert!(
        matches!(cost, Cost::Unknown),
        "cache-read tokens with no known rate must yield Cost::Unknown, never a cost \
         figure that silently excludes them"
    );
}

/// Fix round 1, item 3: the price table is fully caller-supplied and unvalidated, so a
/// mis-scaled `PriceEntry` combined with ordinary token counts must not panic (debug
/// builds) or silently wrap into a fabricated number (release builds — this workspace
/// doesn't enable `overflow-checks` in its release profile). `cost_for` must fold any
/// overflow to `Cost::Unknown` instead.
#[tokio::test]
async fn overflowing_price_arithmetic_yields_unknown_instead_of_panicking_or_wrapping() {
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
        "overflow-model",
        Usage {
            input_tokens: u64::MAX,
            output_tokens: 0,
            cache_read_tokens: 0,
        },
    )
    .await;

    let query_store: StorePool = open(&db_path).await.unwrap();
    let mut table = HashMap::new();
    table.insert(
        (
            ProviderId("anthropic".to_string()),
            ModelId("overflow-model".to_string()),
        ),
        PriceEntry {
            // u64::MAX * 2 overflows u64 — this must not panic.
            input_pico_usd_per_token: 2,
            output_pico_usd_per_token: 0,
            cache_read_pico_usd_per_token: None,
        },
    );
    let snapshot = PricingSnapshot {
        id: PricingSnapshotId(1),
        table,
    };

    let (_, cost) = task_cost_view(&query_store, task_id, &snapshot)
        .await
        .unwrap();

    assert!(
        matches!(cost, Cost::Unknown),
        "overflowing price arithmetic must fold to Cost::Unknown, never panic or wrap"
    );
}
