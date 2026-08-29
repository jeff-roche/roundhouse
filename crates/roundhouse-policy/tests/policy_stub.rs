use roundhouse_core::PolicyDecision;
use roundhouse_policy::{FsOp, ParsedCommand, Policy, PolicyInput, TaskParams};

struct AlwaysAsk;

impl Policy for AlwaysAsk {
    fn decide(&self, _input: &PolicyInput) -> PolicyDecision {
        PolicyDecision::Ask
    }
}

#[test]
fn task_params_shell_variant_carries_a_parsed_command() {
    let params = TaskParams::Shell(ParsedCommand {
        program: "ls".into(),
        argv: vec!["-la".into()],
    });
    match params {
        TaskParams::Shell(cmd) => assert_eq!(cmd.program, "ls"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn task_params_fs_variant_carries_op_and_canonical_result() {
    let params = TaskParams::Fs {
        op: FsOp::Read,
        path: "/tmp/x".into(),
        canonical: Ok("/tmp/x".into()),
    };
    match params {
        TaskParams::Fs { op: FsOp::Read, .. } => {}
        _ => panic!("wrong variant"),
    }
}

#[test]
fn policy_trait_is_object_safe_and_stubbable() {
    let policy: Box<dyn Policy> = Box::new(AlwaysAsk);
    let input = PolicyInput {
        params: TaskParams::Shell(ParsedCommand {
            program: "git".into(),
            argv: vec!["status".into()],
        }),
        taint: roundhouse_policy::Taint::Trusted,
    };
    assert_eq!(policy.decide(&input), PolicyDecision::Ask);
}
