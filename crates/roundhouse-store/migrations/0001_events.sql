CREATE TABLE events (
    session_id  TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    ts          INTEGER NOT NULL,   -- Timestamp::as_unix_nanos() (i64) — see Resolved Ambiguity #5 (X4 fix): Timestamp has no to_rfc3339/parse_rfc3339, so it round-trips as a raw nanosecond count, not text
    task_id     TEXT,
    payload     TEXT    NOT NULL,   -- JSON-encoded EventPayload
    schema_v    INTEGER NOT NULL,
    PRIMARY KEY (session_id, seq)
);

CREATE INDEX idx_events_task ON events (task_id) WHERE task_id IS NOT NULL;

CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only: UPDATE forbidden');
END;

CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events table is append-only: DELETE forbidden');
END;
