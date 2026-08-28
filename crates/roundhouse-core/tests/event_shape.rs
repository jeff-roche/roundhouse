use roundhouse_core::{
    Delta, Envelope, EventPayload, NoteLevel, Origin, TaskId, TaskInput, TaskKind, Timestamp,
};

#[test]
fn task_kind_covers_core_flat_kinds_and_open_vendor_verb() {
    let core_kinds = [
        TaskKind::Chat,
        TaskKind::Infer,
        TaskKind::Shell,
        TaskKind::Read,
        TaskKind::Write,
        TaskKind::Edit,
        TaskKind::Find,
        TaskKind::Http,
        TaskKind::Web,
        TaskKind::Mcp,
        TaskKind::Git,
        TaskKind::Memory,
        TaskKind::Agent,
        TaskKind::Message,
        TaskKind::Compact,
        TaskKind::Checkpoint,
        TaskKind::Plan,
        TaskKind::Elicit,
        TaskKind::Flow,
        TaskKind::Report,
    ];
    assert_eq!(core_kinds.len(), 20);

    let plugin_kind = TaskKind::Plugin { vendor: "acme".into(), verb: "deploy".into() };
    match plugin_kind {
        TaskKind::Plugin { vendor, verb } => assert_eq!((vendor.as_str(), verb.as_str()), ("acme", "deploy")),
        _ => unreachable!(),
    }
}

#[test]
fn delta_covers_all_streaming_shapes() {
    let deltas = vec![
        Delta::Text { text: "hi".into() },
        Delta::Thinking { text: "reasoning".into(), signature: None },
        Delta::Stdout { bytes: bytes::Bytes::from_static(b"out") },
        Delta::Stderr { bytes: bytes::Bytes::from_static(b"err") },
        Delta::ToolArgs { fragment: "{\"a\":".into() },
        Delta::Child { session: roundhouse_core::SessionId::new(), seq: 1 },
    ];
    assert_eq!(deltas.len(), 6);
}

#[test]
fn delta_stdout_and_stderr_round_trip_bytes_through_json() {
    // Regression test: Stderr was copy/paste-annotated `#[serde(skip)]`
    // instead of Stdout's `#[serde(with = "bytes_as_vec")]`, which made any
    // stderr delta silently vanish on serialize (a default-valued unit, not
    // an error) with no test catching it. Both variants must round-trip
    // identically.
    let stdout = Delta::Stdout { bytes: bytes::Bytes::from_static(b"stdout bytes") };
    let stdout_json = serde_json::to_string(&stdout).unwrap();
    let stdout_back: Delta = serde_json::from_str(&stdout_json).unwrap();
    match stdout_back {
        Delta::Stdout { bytes } => assert_eq!(bytes.as_ref(), b"stdout bytes"),
        other => panic!("expected Delta::Stdout to round-trip, got {other:?}"),
    }

    let stderr = Delta::Stderr { bytes: bytes::Bytes::from_static(b"stderr bytes") };
    let stderr_json = serde_json::to_string(&stderr).unwrap();
    let stderr_back: Delta = serde_json::from_str(&stderr_json).unwrap();
    match stderr_back {
        Delta::Stderr { bytes } => assert_eq!(bytes.as_ref(), b"stderr bytes"),
        other => panic!("expected Delta::Stderr to round-trip, got {other:?}"),
    }
}

#[test]
fn event_payload_task_created_carries_kind_parent_origin_input() {
    let payload = EventPayload::TaskCreated {
        kind: TaskKind::Shell,
        parent: None::<TaskId>,
        origin: Origin::Model,
        input: TaskInput::Json(serde_json::json!({"argv": ["ls"]})),
    };
    match payload {
        EventPayload::TaskCreated { kind: TaskKind::Shell, parent: None, origin: Origin::Model, .. } => {}
        _ => panic!("TaskCreated did not match expected shape"),
    }
}

#[test]
fn note_and_message_are_cross_cutting_payloads() {
    let ts = Timestamp::from_unix_nanos(0);
    let _ = ts;
    let _note = EventPayload::Note { level: NoteLevel::Info, text: "hello".into() };
    let _msg = EventPayload::Message { envelope: Envelope::default_for_test() };
}

#[test]
fn task_started_carries_an_optional_handle_for_long_running_tasks() {
    use roundhouse_core::{Handle, IsolationAttestation, Tier};

    // A `shell` task that runs to completion: no handle needed.
    let short_lived = EventPayload::TaskStarted {
        isolation: IsolationAttestation { tier: Tier::Worktree, digest: "d1".into(), net_enforced: true },
        handle: None,
    };
    match short_lived {
        EventPayload::TaskStarted { handle: None, .. } => {}
        _ => panic!("expected no handle for a short-lived task"),
    }

    // A `shell` task running `npm run dev` (§4.3): non-terminating, carries a handle.
    let long_running = EventPayload::TaskStarted {
        isolation: IsolationAttestation { tier: Tier::Worktree, digest: "d2".into(), net_enforced: true },
        handle: Some(Handle::Pid(12345)),
    };
    match long_running {
        EventPayload::TaskStarted { handle: Some(Handle::Pid(12345)), .. } => {}
        _ => panic!("expected Some(Handle::Pid(12345)) for a long-running task"),
    }
}
