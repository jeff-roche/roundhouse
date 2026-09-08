use roundhouse_core::{SessionId, TaskId, Timestamp};
use roundhouse_policy::approval::{
    synthesize_grant, GrantProvenance, GrantScope, RememberedGrant, RememberedGrantError,
};
use roundhouse_policy::{FsOp, Outcome, ParsedCommand, PolicyEngine, TaskParams};
use std::path::{Path, PathBuf};

fn provenance() -> GrantProvenance {
    GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    }
}

#[test]
fn remembered_always_grant_survives_serialization_and_allows_only_the_approved_call() {
    let approved = TaskParams::Shell(ParsedCommand {
        program: "cargo".into(),
        argv: vec!["test".into(), "--lib".into()],
    });
    let grant = synthesize_grant(
        &approved,
        GrantScope::Always,
        provenance(),
        Path::new("/workspace"),
    );

    let persisted = grant.into_remembered().expect("Always is durable");
    let reloaded: RememberedGrant =
        serde_json::from_str(&serde_json::to_string(&persisted).unwrap()).unwrap();
    let engine = PolicyEngine::from_rules(vec![reloaded.into_rule()]);

    assert_eq!(engine.decide(&approved).outcome, Outcome::Allow);
    assert_eq!(
        engine
            .decide(&TaskParams::Shell(ParsedCommand {
                program: "cargo".into(),
                argv: vec!["test".into(), "--all".into()],
            }))
            .outcome,
        Outcome::Ask
    );
}

#[test]
fn ephemeral_grants_cannot_be_remembered() {
    for (scope, name) in [
        (GrantScope::Once, "Once"),
        (GrantScope::Session, "Session"),
        (GrantScope::ExactArgv { hash: [0; 32] }, "ExactArgv"),
    ] {
        let grant = synthesize_grant(
            &TaskParams::Shell(ParsedCommand {
                program: "cargo".into(),
                argv: vec!["test".into()],
            }),
            scope,
            provenance(),
            Path::new("/workspace"),
        );

        assert!(matches!(
            grant.into_remembered(),
            Err(RememberedGrantError::UnenforcedLifetime(actual)) if actual == name
        ));
    }
}

#[test]
fn remembered_directory_grant_survives_serialization_without_escaping_its_boundary() {
    let approved = TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/workspace/src/lib.rs"),
        canonical: Ok(PathBuf::from("/workspace/src/lib.rs")),
    };
    let grant = synthesize_grant(
        &approved,
        GrantScope::Directory {
            path: PathBuf::from("/workspace/src"),
        },
        provenance(),
        Path::new("/workspace"),
    );
    let persisted = grant.into_remembered().expect("Directory is durable");
    let reloaded: RememberedGrant =
        serde_json::from_str(&serde_json::to_string(&persisted).unwrap()).unwrap();
    let engine = PolicyEngine::from_rules(vec![reloaded.into_rule()]);

    assert_eq!(engine.decide(&approved).outcome, Outcome::Allow);
    assert_eq!(
        engine
            .decide(&TaskParams::Fs {
                op: FsOp::Write,
                path: PathBuf::from("/workspace/secrets.txt"),
                canonical: Ok(PathBuf::from("/workspace/secrets.txt")),
            })
            .outcome,
        Outcome::Ask
    );
}

#[test]
fn remembered_grant_rejects_a_scope_that_does_not_match_its_rule() {
    let grant = synthesize_grant(
        &TaskParams::Shell(ParsedCommand {
            program: "cargo".into(),
            argv: vec!["test".into()],
        }),
        GrantScope::Always,
        provenance(),
        Path::new("/workspace"),
    );
    let persisted = grant.into_remembered().expect("Always is durable");
    let mut wire = serde_json::to_value(persisted).unwrap();
    wire["scope"] = serde_json::Value::String("Directory".into());

    assert!(serde_json::from_value::<RememberedGrant>(wire).is_err());
}

#[test]
fn remembered_grant_rejects_a_rule_id_that_does_not_match_its_provenance() {
    let grant = synthesize_grant(
        &TaskParams::Shell(ParsedCommand {
            program: "cargo".into(),
            argv: vec!["test".into()],
        }),
        GrantScope::Always,
        provenance(),
        Path::new("/workspace"),
    );
    let persisted = grant.into_remembered().expect("Always is durable");
    let mut wire = serde_json::to_value(persisted).unwrap();
    wire["rule"]["id"] = serde_json::Value::String("grant:forged".into());

    assert!(serde_json::from_value::<RememberedGrant>(wire).is_err());
}

#[test]
fn remembered_grant_rejects_provenance_tampering_that_keeps_the_original_rule_id() {
    let grant = synthesize_grant(
        &TaskParams::Shell(ParsedCommand {
            program: "cargo".into(),
            argv: vec!["test".into()],
        }),
        GrantScope::Always,
        provenance(),
        Path::new("/workspace"),
    );
    let persisted = grant.into_remembered().expect("Always is durable");
    let mut wire = serde_json::to_value(persisted).unwrap();
    wire["provenance"]["task_id"] =
        serde_json::Value::String("00000000-0000-0000-0000-000000000001".into());

    assert!(serde_json::from_value::<RememberedGrant>(wire).is_err());
}

#[test]
fn remembered_grant_rejects_a_non_allow_outcome_on_the_wire() {
    let grant = synthesize_grant(
        &TaskParams::Shell(ParsedCommand {
            program: "cargo".into(),
            argv: vec!["test".into()],
        }),
        GrantScope::Always,
        provenance(),
        Path::new("/workspace"),
    );
    let persisted = grant.into_remembered().expect("Always is durable");
    let mut wire = serde_json::to_value(persisted).unwrap();
    wire["rule"]["outcome"] = serde_json::Value::String("Deny".into());

    assert!(serde_json::from_value::<RememberedGrant>(wire).is_err());
}
