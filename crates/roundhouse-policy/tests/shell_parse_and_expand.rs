use roundhouse_policy::shell::classify::{
    parse_command, resolve_variable_expansions, Classification, SessionEnv,
};

#[test]
fn unparseable_input_is_opaque() {
    let result = parse_command("echo (((( unbalanced");
    assert!(matches!(
        result,
        Classification::Opaque(roundhouse_policy::shell::classify::OpaqueReason::ParseError)
    ));
}

#[test]
fn plain_variable_expansion_is_resolved_to_literal_before_matching() {
    let mut env = SessionEnv::default();
    env.set("HOME", "/home/agent");

    let Classification::Program(mut cmd) = parse_command("echo $HOME/notes.txt") else {
        panic!("expected parseable")
    };
    resolve_variable_expansions(&mut cmd.program_ast, &env);

    let argv = cmd.first_node_argv();
    assert_eq!(
        argv,
        vec!["echo".to_string(), "/home/agent/notes.txt".to_string()]
    );
}

#[test]
fn variable_expansion_containing_command_substitution_is_not_resolved() {
    let mut env = SessionEnv::default();
    env.set("SAFE", "value");

    let Classification::Program(mut cmd) = parse_command("echo $(whoami)") else {
        panic!("expected parseable")
    };
    resolve_variable_expansions(&mut cmd.program_ast, &env);

    assert!(
        cmd.contains_unresolved_command_substitution(),
        "$(...) must survive step 2 untouched for step 3 to hard-deny it"
    );
}
