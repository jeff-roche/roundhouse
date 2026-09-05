//! Phase 7, Task 6: proves `wire_redaction_for_session` actually reaches
//! the real persistence boundary — `roundhouse-store/src/writer.rs`
//! installs an empty-secret-list `Redactor` at `spawn_writer` time, and
//! before this task nothing in the workspace ever called
//! `EventWriter::set_redactor` outside a `roundhouse-store` unit test.
//!
//! Note the real store API this test uses differs from the brief's
//! original sketch (`Store::open_temp`/`store.session_events_all()`,
//! neither of which exists on this branch — `roundhouse-store` has no
//! `Store` type at all): `roundhouse_store::open` returns a `StorePool`,
//! and `roundhouse_store::session_events` is the real session-scoped read
//! query (already used by `tests/admission_integration.rs` in this same
//! crate). `spawn_writer` takes ownership of the `StorePool` it's given,
//! so reading back afterward needs a second `open()` against the same
//! file, matching that same precedent test's pattern.

use roundhouse_core::{EventPayload, NoteLevel, SessionId};
use roundhouse_store::{open, session_events, spawn_writer};

#[tokio::test]
async fn a_provider_api_key_present_at_session_creation_is_redacted_from_a_later_persisted_event() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = open(&db_path).await.unwrap();
    let writer = spawn_writer(store).await;

    // `TaskRunner::bootstrap()` panics on a second call per process; this
    // test file has exactly one test, so calling it directly (rather than
    // the `once_cell::sync::Lazy` shared-static pattern
    // `admission_integration.rs` uses for a multi-test file) is safe.
    let runner = roundhouse_core::TaskRunner::bootstrap();

    // A realistic API-key-shaped secret, comfortably past
    // `wire_redaction_for_session`'s `MIN_REDACTABLE_SECRET_LEN`
    // destructive-pattern-guard floor (fix round 1, W1-R24/W1-R27: that
    // floor is 4 bytes today and exists only to reject a pathologically
    // short, 1-3 byte pattern that would mangle unrelated log text — it is
    // no longer a production security threshold, and the daemon's own
    // `"demo"` placeholder is fixed at its source in `main.rs` instead of
    // relying on this floor to exclude it).
    let secret = "sk-live-super-secret-key-value";
    assert!(secret.len() >= 4);

    // Session creation's new code path: install the redactor BEFORE any
    // event referencing the secret is appended. This is the exact ordering
    // `wire_redaction_for_session`'s doc comment requires, and the real
    // call site in `roundhouse-daemon/src/demo.rs` follows the same shape
    // (called immediately after `spawn_writer`, strictly before the first
    // `append`).
    roundhouse_engine::wire_redaction_for_session(&writer, &[secret.to_string()]);

    let session_id = SessionId::new();
    let event = runner.record_note(
        session_id,
        0, // ignored — EventWriter::append assigns the real per-session seq
        roundhouse_core::Timestamp::from_unix_nanos(0),
        None,
        NoteLevel::Info,
        format!("using key {secret} for this request"),
        1,
    );
    writer.append(event).await.unwrap();

    // Read back through a second, independent `StorePool` against the same
    // file — `spawn_writer` above took ownership of the first one.
    let read_store = open(&db_path).await.unwrap();
    let events = session_events(&read_store, session_id).await.unwrap();

    assert_eq!(
        events.len(),
        1,
        "the one event this test appended must be readable back"
    );
    let EventPayload::Note { text, .. } = &events[0].payload else {
        panic!("expected a Note payload, got {:?}", events[0].payload);
    };

    assert!(
        !text.contains(secret),
        "the live API key must never appear verbatim in a persisted event"
    );
    assert!(
        text.contains("[REDACTED]"),
        "expected the redaction placeholder to appear in place of the secret, got: {text:?}"
    );
}
