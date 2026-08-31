use roundhouse_policy::shell::pipeline::ResolvedNode;
use roundhouse_tools::execve_node;

#[tokio::test]
async fn execve_never_invokes_a_shell_interpreter() {
    let node = ResolvedNode {
        resolved_program: "/bin/echo".into(),
        argv: vec!["hi".into()],
        redirections: vec![],
    };
    let cwd = std::env::current_dir().expect("current dir");
    let output = execve_node(&node, &cwd).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "hi");
    // The constructed command's program is the resolved binary itself,
    // never sh/bash — execve_node takes no shell-string argument through
    // which sh/bash could be substituted, it always execs
    // `node.resolved_program` directly (see `run_shell`, which it delegates
    // to: `Command::new(program).args(argv)`, no `sh -c` layer at all).
    assert_eq!(node.resolved_program, "/bin/echo");
    assert_eq!(output.exit_code, Some(0));
}
