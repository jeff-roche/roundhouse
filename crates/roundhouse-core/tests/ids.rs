use roundhouse_core::{Address, SessionId, TaskId, TeamId, WorkspaceId};

#[test]
fn ids_are_distinct_types_that_round_trip_through_json() {
    let session = SessionId::new();
    let json = serde_json::to_string(&session).unwrap();
    let back: SessionId = serde_json::from_str(&json).unwrap();
    assert_eq!(session, back);

    let task = TaskId::new();
    assert_ne!(
        session.to_string(),
        task.to_string(),
        "ids must not collide by construction"
    );
}

#[test]
fn address_variants_match_spec_shape() {
    let workspace = WorkspaceId::new();
    let team = TeamId::new();
    let session = SessionId::new();

    let by_session = Address::Session { id: session };
    let by_handle = Address::Handle {
        workspace,
        name: "reviewer".to_string(),
    };
    let by_team = Address::Team { team };
    let by_role = Address::Role {
        team,
        role: "lead".to_string(),
    };
    let by_human = Address::Human { session };

    // Exhaustive match compiles iff every §7.2 variant exists with these field names.
    for addr in [by_session, by_handle, by_team, by_role, by_human] {
        match addr {
            Address::Session { id: _ } => {}
            Address::Handle {
                workspace: _,
                name: _,
            } => {}
            Address::Team { team: _ } => {}
            Address::Role { team: _, role: _ } => {}
            Address::Human { session: _ } => {}
        }
    }
}
