//! Tests for Task 19: Aho-Corasick redaction at the persistence boundary
//! (`roundhouse_store::redact::Redactor`). Real store types throughout, per the task-19
//! addendum: `StorePool`/`EventWriter`/`TaskRunner`, not the brief's fictional `Store`.
//!
//! Step 1's core guarantee: a live secret value must never physically reach the raw
//! `events.payload` column — checked with a direct raw-SQL read
//! (`redact::debug_read_raw_payload_text`), not by trusting the redacted `EventPayload`
//! constructed in memory. Step 6 (scoped per Ruling 8): `Redactor::scan_outbound` is
//! exercised directly against a real `StorePool`/`EventWriter`/`TaskRunner` trio — it is
//! not wired into any provider call site by this task.

use roundhouse_core::{
    Delta, EventPayload, NoteLevel, Origin, SessionId, TaskId, TaskInput, TaskKind, Timestamp,
};
use roundhouse_store::redact::{debug_read_raw_payload_text, Redactor, SecretLeakDisposition};
use roundhouse_store::{open, session_events, spawn_writer};

/// `TaskRunner::bootstrap()` panics on a second call in the same process (S-LOG-1) — every
/// test in this file shares one process, so they must share one `TaskRunner` instance
/// (same pattern as `tests/append.rs`/`tests/session_events.rs`).
static RUNNER: once_cell::sync::Lazy<roundhouse_core::TaskRunner> =
    once_cell::sync::Lazy::new(roundhouse_core::TaskRunner::bootstrap);

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// `upsert_for_event`'s `UPDATE` branch hard-errors on a zero-row match (Task 0.5's
/// security fix) — a `TaskDelta` needs a real `TaskCreated` row to update first. Returns
/// the new `task_id`.
async fn create_task(writer: &roundhouse_store::EventWriter, session_id: SessionId) -> TaskId {
    let task_id = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Chat,
            None,
            Origin::Model,
            TaskInput::Text("test".into()),
            1,
        ))
        .await
        .unwrap();
    task_id
}

#[tokio::test]
async fn live_secret_value_never_lands_in_the_stored_row() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = create_task(&writer, session_id).await;

    writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            task_id,
            Delta::Text {
                text: "the key is sk-live-abc123 don't share it".into(),
            },
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&dir.path().join("events.db")).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        !raw_row_text.contains("sk-live-abc123"),
        "a leaked value must never reach the SQLite row, even read directly: {raw_row_text}"
    );
    assert!(
        raw_row_text.contains("[REDACTED]"),
        "the redacted placeholder must appear in its place: {raw_row_text}"
    );
}

#[tokio::test]
async fn redaction_count_is_zero_when_nothing_matches_making_failure_visible() {
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
    let (redacted, count) = redactor.redact_event_payload(EventPayload::TaskDelta {
        delta: Delta::Text {
            text: "nothing secret here".into(),
        },
    });
    assert_eq!(
        count, 0,
        "0 is the diagnostic signal that redaction found nothing — not an error, but must \
         be visible per-task, never silently dropped"
    );
    match redacted {
        EventPayload::TaskDelta {
            delta: Delta::Text { text },
        } => assert_eq!(text, "nothing secret here"),
        other => panic!("unexpected payload: {other:?}"),
    }
}

/// Proves the redaction-count accumulation runs on a path INDEPENDENT of
/// `upsert_for_event`'s early-return for `TaskDelta`/`Note` (Task 19 addendum, Ruling 5's
/// gotcha) — this test would fail (`redactions` would stay 0) if the accumulation had been
/// naively added inside `upsert_for_event`'s existing match arms instead of as a separate,
/// unconditional `UPDATE` alongside it.
#[tokio::test]
async fn redaction_count_accumulates_on_the_tasks_row_for_task_delta_and_note_events() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = create_task(&writer, session_id).await;

    // Two redactable events for the same task: one TaskDelta match, one Note match.
    writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            task_id,
            Delta::Text {
                text: "leak: sk-live-abc123".into(),
            },
            1,
        ))
        .await
        .unwrap();
    writer
        .append(RUNNER.record_note(
            session_id,
            0,
            now_ts(),
            Some(task_id),
            NoteLevel::Info,
            "also leaked: sk-live-abc123".into(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let conn = query_store.pool.get().await.unwrap();
    let task_id_str = task_id.to_string();
    let redactions: i64 = conn
        .interact(move |c| {
            c.query_row(
                "SELECT redactions FROM tasks WHERE task_id = ?1",
                [task_id_str],
                |row| row.get(0),
            )
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        redactions, 2,
        "the tasks.redactions counter must accumulate across both the TaskDelta and Note \
         events for this task, even though upsert_for_event itself early-returns (no state \
         change) for both payload kinds"
    );
}

#[tokio::test]
async fn outbound_payload_containing_a_live_secret_is_ask_by_default_and_deny_hardened() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);

    let session_id = SessionId::new();
    let outbound = "please use this key: sk-live-abc123 to authenticate";

    let disposition = redactor
        .scan_outbound(&RUNNER, &writer, session_id, outbound, false)
        .await
        .unwrap();
    assert_eq!(
        disposition,
        Some(SecretLeakDisposition::Ask),
        "§6.7: SecretLeak is Ask by default"
    );

    let hardened_disposition = redactor
        .scan_outbound(&RUNNER, &writer, session_id, outbound, true)
        .await
        .unwrap();
    assert_eq!(
        hardened_disposition,
        Some(SecretLeakDisposition::Deny),
        "§6.7: SecretLeak is Deny under --profile hardened"
    );

    let events = session_events(
        &open(&dir.path().join("events.db")).await.unwrap(),
        session_id,
    )
    .await
    .unwrap();
    assert!(
        events.iter().any(|e| matches!(
            &e.payload,
            EventPayload::Note { level: NoteLevel::Warn, text } if text.contains("SecretLeak")
        )),
        "a detected leak must be a visible Note event, not a log line"
    );
}

#[tokio::test]
async fn outbound_payload_with_no_secret_is_none_and_never_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);

    let disposition = redactor
        .scan_outbound(
            &RUNNER,
            &writer,
            SessionId::new(),
            "nothing sensitive here",
            false,
        )
        .await
        .unwrap();
    assert_eq!(disposition, None);
}

// ---------------------------------------------------------------------------------------
// Fix Round 1 regressions
// ---------------------------------------------------------------------------------------

/// Fix round 1, item 2: an empty-string secret value must never reach the Aho-Corasick
/// automaton — an empty pattern matches at every position, which (pre-fix) mangled
/// unrelated legitimate text and produced a wildly inflated match count. Pre-fix, this test
/// fails: `redact("key=sk-live-abc123!")` returns a mangled string with `count` far above 1
/// (an empty pattern matches at every one of the ~20 byte-positions in the input).
#[test]
fn empty_string_secret_value_is_filtered_and_never_mangles_output() {
    let redactor = Redactor::build(&["".to_string(), "sk-live-abc123".to_string()]);
    let (redacted, count) = redactor.redact("key=sk-live-abc123!");
    assert_eq!(
        redacted, "key=[REDACTED]!",
        "an empty pattern must never reach the automaton — output must be a clean, single \
         substitution of the real secret, not mangled by matching at every position"
    );
    assert_eq!(
        count, 1,
        "only the genuine non-empty pattern match counts — the empty string must contribute \
         nothing"
    );
}

/// Fix round 1, item 3: with a shorter secret value that is a prefix of a longer one (e.g.
/// stale + rotated key sharing a prefix), the automaton must redact the FULL longer match,
/// not stop at the shorter prefix and leave the longer secret's distinguishing suffix
/// exposed. Pre-fix (default `LeftmostFirst`/standard match semantics), this test fails:
/// redacting `"key=sk-live-abc123!"` against `["sk-live", "sk-live-abc123"]` produces
/// `"key=[REDACTED]-abc123!"` — the shorter pattern wins and `-abc123` leaks in the clear.
#[test]
fn longer_secret_value_wins_over_a_shorter_prefix_shadowing_pattern() {
    let redactor = Redactor::build(&["sk-live".to_string(), "sk-live-abc123".to_string()]);
    let (redacted, count) = redactor.redact("key=sk-live-abc123!");
    assert_eq!(
        redacted, "key=[REDACTED]!",
        "the longer, more specific secret value must be the one that wins at this position \
         — no residual suffix of the real secret may remain in the output"
    );
    assert_eq!(count, 1);
}

/// Fix round 1, item 4: a `TaskDelta` (or `Note`/`TaskFailed`) event whose `task_id` has no
/// corresponding `tasks` row (no `TaskCreated` was ever appended for it) must fail loudly,
/// matching `tasks_view::upsert_for_event`'s own established zero-row-match hard-error
/// convention, rather than silently dropping the redaction count for a task row that will
/// never exist. Pre-fix, this `append` call succeeds (the payload is correctly redacted and
/// committed) but the redaction count for this nonexistent task simply vanishes with no
/// error and no trace; post-fix it must return `Err`.
#[tokio::test]
async fn task_delta_with_no_prior_task_created_row_hard_errors_instead_of_silently_dropping_the_count(
) {
    let dir = tempfile::tempdir().unwrap();
    let store = open(&dir.path().join("events.db")).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    // Deliberately skip create_task: this task_id has no tasks row.
    let orphan_task_id = TaskId::new();

    let result = writer
        .append(RUNNER.record_task_delta(
            session_id,
            0,
            now_ts(),
            orphan_task_id,
            Delta::Text {
                text: "leak: sk-live-abc123".into(),
            },
            1,
        ))
        .await;

    assert!(
        result.is_err(),
        "a TaskDelta with a redaction match but no corresponding tasks row must hard-error, \
         not silently commit while dropping the redaction count"
    );
}

// ---------------------------------------------------------------------------------------
// Fix Round A (Phase 7, Task 5) — F3: TaskCreated.input / TaskCompleted.output coverage
// ---------------------------------------------------------------------------------------

/// F3: `TaskCreated.input` as `TaskInput::Json` — the shape
/// `agent_loop.rs::dispatch_builtin` now emits for every dispatched tool call — must have
/// its string VALUES redacted, recursively through nested objects/arrays, before it ever
/// reaches the append-only log. Pre-fix, this event's whole `input` passed through
/// `redact_event_payload`'s catch-all `other => (other, 0)` arm untouched.
#[tokio::test]
async fn task_created_json_input_is_redacted_recursively_through_nested_values() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Write,
            None,
            Origin::Model,
            TaskInput::Json(serde_json::json!({
                "path": "/tmp/notes.txt",
                "contents": "the key is sk-live-abc123 — keep it safe",
                "nested": { "tags": ["public", "sk-live-abc123"] },
            })),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        !raw_row_text.contains("sk-live-abc123"),
        "a live secret nested anywhere inside TaskInput::Json must never reach the stored \
         row: {raw_row_text}"
    );
    assert!(
        raw_row_text.contains("[REDACTED]"),
        "the redacted placeholder must appear in its place: {raw_row_text}"
    );
    // The field name itself ("contents") is a fixed schema key, not model-echoed
    // content — object keys are deliberately never redacted (see
    // `Redactor::redact_event_payload`'s doc comment) — so it must survive verbatim.
    assert!(
        raw_row_text.contains("\"contents\""),
        "object keys must survive untouched — only string VALUES are redacted: \
         {raw_row_text}"
    );
}

/// F3, the other half: `TaskCompleted.output` as `TaskOutput::Text` — what
/// `dispatch_builtin` records for every completed builtin tool call, including a `shell`
/// call's full captured stdout/stderr — must be redacted before it reaches the log.
#[tokio::test]
async fn task_completed_text_output_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = create_task(&writer, session_id).await;

    writer
        .append(RUNNER.record_task_completed(
            session_id,
            0,
            now_ts(),
            task_id,
            roundhouse_core::TaskOutput::Text(
                "exit_code=Some(0)\nstdout:\nyour key is sk-live-abc123\nstderr:\n".into(),
            ),
            roundhouse_core::Usage::default(),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        !raw_row_text.contains("sk-live-abc123"),
        "a live secret in a completed task's captured output must never reach the stored \
         row: {raw_row_text}"
    );
    assert!(raw_row_text.contains("[REDACTED]"), "got: {raw_row_text}");
}

/// F3: `TaskInput::Text` (the plain-string variant, not the `Json` shape) must also be
/// covered — this closes the ORIGINAL doc comment's other named gap
/// ("`TaskCreated.input` (a task's actual prompt/command, when `TaskInput::Text`)") in the
/// same pass.
#[tokio::test]
async fn task_created_text_input_is_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Chat,
            None,
            Origin::User,
            TaskInput::Text("please use sk-live-abc123 to log in".into()),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        !raw_row_text.contains("sk-live-abc123"),
        "got: {raw_row_text}"
    );
    assert!(raw_row_text.contains("[REDACTED]"), "got: {raw_row_text}");
}

// ---------------------------------------------------------------------------------------
// Fix Round B — M2 (depth cap) and M3 (object-key gap, characterized not fixed)
// ---------------------------------------------------------------------------------------

/// M2 (ruling W1-R69): `redact_json_value` must not stack-overflow on a pathologically
/// deep `TaskInput::Json` — the security lens reproduced the ORIGINAL (unbounded) bug at
/// depth 10,000. This test uses depth 1,000 instead — a deliberate choice, not a
/// weakening: even independent of this crate's own logic, merely CONSTRUCTING (and, if
/// dropped normally, tearing down) a bare depth-10,000 `serde_json::Value` overflows this
/// test binary's own per-test thread stack in this environment (confirmed empirically —
/// with every line of `Redactor` logic removed from the picture, a bare `drop()` of such a
/// value still overflows). That is an orthogonal, environment-specific limit on how deep a
/// `Value` this test binary can even HOLD, not a property of the fix under test. Depth
/// 1,000 is unaffected by that limit, is still ~16x past this method's own
/// `MAX_JSON_REDACT_DEPTH` (64) and ~8x past `serde_json`'s own parser depth limit (128,
/// meaning a value this deep could never arrive by DESERIALIZING untrusted input in the
/// first place), and is more than sufficient to prove the fix: `redact_event_payload`
/// completes without crashing, and the secret sitting far below the depth cap does not
/// leak into the output — it is discarded outright once the cap is reached (replaced with
/// a fixed placeholder, torn down iteratively rather than via ordinary recursive `Drop`),
/// not redacted via the substring automaton.
#[test]
fn redact_json_value_does_not_stack_overflow_on_pathological_nesting_and_never_leaks() {
    let mut value = serde_json::json!("sk-live-abc123");
    for _ in 0..1_000 {
        value = serde_json::json!([value]);
    }

    let redactor = Redactor::build(&["sk-live-abc123".to_string()]);
    let (redacted, _count) = redactor.redact_event_payload(EventPayload::TaskCreated {
        kind: TaskKind::Read,
        parent: None,
        origin: Origin::Model,
        input: TaskInput::Json(value),
    });

    // The redacted value itself is now shallow (truncated at the depth
    // cap), so serializing it back is safe and cannot itself overflow.
    let serialized = serde_json::to_string(&redacted).unwrap();
    assert!(
        !serialized.contains("sk-live-abc123"),
        "must not leak the secret even past the depth cap: {serialized}"
    );
    assert!(
        serialized.contains("TRUNCATED"),
        "the truncation must be visible, not silent: {serialized}"
    );
}

/// M3 (ruling W1-R69): characterizes the ACCEPTED residual gap, not a vulnerability this
/// task closes — object keys are never redacted, so a model-authored JSON object with an
/// extra key that happens to look like a live secret carries that key verbatim into the
/// log. This is expected today (see `redact_event_payload`'s doc comment for the honest,
/// corrected reasoning); it exists so a future change either closes the gap deliberately
/// or this test forces an explicit decision to accept it again.
#[tokio::test]
async fn a_live_secret_used_as_an_object_key_survives_in_the_key_position_by_design() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;
    writer.set_redactor(Redactor::build(&["sk-live-abc123".to_string()]));

    let session_id = SessionId::new();
    let task_id = TaskId::new();
    writer
        .append(RUNNER.record_task_created(
            session_id,
            0,
            now_ts(),
            task_id,
            TaskKind::Write,
            None,
            Origin::Model,
            TaskInput::Json(serde_json::json!({
                "path": "/tmp/x",
                "sk-live-abc123": "an extra, model-authored key"
            })),
            1,
        ))
        .await
        .unwrap();

    let query_store = open(&db_path).await.unwrap();
    let raw_row_text = debug_read_raw_payload_text(&query_store, session_id, task_id)
        .await
        .unwrap();
    assert!(
        raw_row_text.contains("sk-live-abc123"),
        "documented, accepted residual: a secret used as an OBJECT KEY is not redacted \
         today — got: {raw_row_text}"
    );
}
