use roundhouse_core::{
    fold_session_state, EventPayload, NoteLevel, SessionOutcome, SessionSpec, SessionState,
};

fn created() -> EventPayload {
    EventPayload::SessionCreated {
        spec: Box::new(SessionSpec::test_default()),
    }
}

fn state_changed(state: SessionState) -> EventPayload {
    EventPayload::SessionStateChanged {
        state,
        reason: None,
    }
}

fn closed(outcome: SessionOutcome) -> EventPayload {
    EventPayload::SessionClosed { outcome }
}

fn note() -> EventPayload {
    EventPayload::Note {
        level: NoteLevel::Info,
        text: "unrelated".into(),
    }
}

/// Table-driven per the brief: each case is a name, an event-payload
/// sequence, and the expected `fold_session_state` result.
#[test]
fn fold_session_state_covers_the_documented_cases() {
    let cases: Vec<(&str, Vec<EventPayload>, Option<SessionState>)> = vec![
        ("empty slice folds to None", vec![], None),
        (
            "a slice with no session-lifecycle event folds to None",
            vec![note()],
            None,
        ),
        (
            "SessionCreated folds to Created",
            vec![created()],
            Some(SessionState::Created),
        ),
        (
            "SessionStateChanged folds to its carried state",
            vec![created(), state_changed(SessionState::Suspended)],
            Some(SessionState::Suspended),
        ),
        (
            "SessionStateChanged to Cancelling",
            vec![created(), state_changed(SessionState::Cancelling)],
            Some(SessionState::Cancelling),
        ),
        (
            "SessionClosed folds to Closed",
            vec![
                created(),
                state_changed(SessionState::Running),
                closed(SessionOutcome::Completed),
            ],
            Some(SessionState::Closed),
        ),
        (
            "an unrelated event between lifecycle events leaves state unchanged",
            vec![created(), note(), state_changed(SessionState::Running)],
            Some(SessionState::Running),
        ),
        (
            "SessionClosed absorbs a later SessionStateChanged: result stays Closed",
            vec![
                created(),
                closed(SessionOutcome::Cancelled),
                state_changed(SessionState::Running),
            ],
            Some(SessionState::Closed),
        ),
        (
            "SessionClosed absorbs a later unrelated event too",
            vec![created(), closed(SessionOutcome::Completed), note()],
            Some(SessionState::Closed),
        ),
        (
            "SessionClosed absorbs a later SessionClosed: result stays Closed",
            vec![
                created(),
                closed(SessionOutcome::Completed),
                closed(SessionOutcome::Cancelled),
            ],
            Some(SessionState::Closed),
        ),
    ];

    for (name, events, expected) in cases {
        assert_eq!(fold_session_state(&events), expected, "case: {name}");
    }
}
