//! Maps one resolved built-in [`crate::tool_catalog::ToolTarget::Builtin`]
//! tool call onto `roundhouse-policy`'s `TaskParams` (what
//! `SessionActor::admit_task` judges) and `roundhouse-tools`' real executor
//! (what actually performs the action once admitted) — Phase 7 Task 5's
//! "dispatch bridge," split out of `agent_loop.rs` for its own unit tests per
//! the plan's explicit request.
//!
//! # Containment decision (carry-forward CF-1)
//! `tool_catalog`'s published schemas mirror the real executor signatures
//! literally: `ShellParams.cwd` and `FindParams.root` are model-supplied,
//! required fields (Task 1's review flagged this as a security-relevant
//! decision Task 5 must make explicitly, not a style choice). This module
//! takes them **as the model supplies them** rather than silently
//! substituting a session-derived value: the published tool schema promises
//! the model that `cwd`/`root` are its own to name, and dispatch honoring
//! exactly what it published avoids the worse mismatch of a schema that
//! lies about what dispatch actually does with the field. Containment for
//! what a model-named `cwd`/`root` can actually reach is enforced at a
//! different layer — `SessionActor::admit_task`'s sealed floor (path-prefix
//! rules against the daemon's own state dir/binary and dotfile trees, see
//! `roundhouse_policy::sealed`) plus whatever sandbox tier the session's
//! `Isolate`/`Handle` achieved — not by this dispatch layer re-deriving a
//! "safer" path the model never asked for. Real process-level sandboxing of
//! the dispatched executor call itself (running it through the session's
//! `Isolate::spawn` rather than in-process) remains out of this task's scope
//! (see `agent_loop.rs`'s module doc comment) — this module wires the real
//! admission gate in front of the real executors, which is the concrete gap
//! Task 5 exists to close; routing execution through the sandbox tier too is
//! further, not-yet-numbered integration work, same as
//! `SessionActor`'s own pre-existing doc comments already flag for the
//! "no unified task-execution entry point" gap.
//!
//! # Unbounded results (carry-forward CF-7 item 4)
//! None of the four `Fs` executors or `run_shell` cap how much data they
//! return — `read_file`'s whole-file `String`, `run_shell`'s captured
//! stdout/stderr, and `find_files`' match list are all folded, whole, into
//! `execute_builtin`'s returned `ToolResultPart::text` below. That text is
//! then folded into `agent_loop::run_agent_loop`'s next-turn
//! `request.messages` (that function's own doc comment names the exact
//! fold site) — so a built-in call against a very large file or a
//! chatty command has the identical unbounded-context shape CF-7 item 4
//! already flags for the MCP arm's `stdio.rs:206`. Pre-existing in
//! `roundhouse-tools` (no size cap on any of these signatures); this task
//! does not add one — noted here so it is not silently narrowed to "only
//! an MCP problem."

use roundhouse_core::TaskKind;
use roundhouse_policy::{FsOp, ParsedCommand, TaskParams};
use roundhouse_provider::ToolResultPart;
use std::path::{Path, PathBuf};

/// Errors building `TaskParams`/`TaskInput` from a model's tool-call
/// arguments, or running the real executor once admitted.
#[derive(Debug, thiserror::Error)]
pub enum ToolDispatchError {
    /// The model's `input` JSON is missing a required argument, or that
    /// argument isn't the type the tool's published schema promises.
    #[error("the `{tool}` tool call is missing or has an invalid `{field}` argument")]
    BadArgs {
        tool: &'static str,
        field: &'static str,
    },
    /// `kind` isn't one of the five built-in kinds this module dispatches
    /// (`Read`/`Write`/`Edit`/`Find`/`Shell`) — unreachable through
    /// `tool_catalog::resolve_tool_target`'s real output today, but this
    /// module's own match must still be exhaustive rather than assume that
    /// invariant holds forever.
    #[error("dispatching TaskKind::{kind:?} through the builtin tool catalog is not supported")]
    UnsupportedKind { kind: TaskKind },
    /// [`execute_builtin`] was handed a `TaskParams::Fs` whose `canonical`
    /// is `Err` — should never happen in practice, since
    /// `SessionActor::admit_task`'s own `PolicyEngine::decide` denies any
    /// such params outright (§6.2: "a path that fails to canonicalise is
    /// Deny, never Ask"), so admission can never return `Ok` for one. Kept
    /// as a named, fail-closed error rather than a `panic!`/`unwrap`, in
    /// case that invariant is ever weakened upstream.
    #[error("cannot execute a tool call whose path failed to resolve: {0:?}")]
    UnresolvedPath(roundhouse_policy::PathErr),
    /// `execute_builtin` was handed a `TaskParams` variant none of the five
    /// built-in kinds produce (`Http`/`Mcp`/`Git`/`Agent`) — unreachable
    /// through `task_params_for`'s real output today, but the match must
    /// still be exhaustive rather than assume that invariant holds forever.
    #[error(
        "dispatching this TaskParams shape through the builtin tool catalog is not supported: {0}"
    )]
    UnsupportedParams(String),
    /// The real `roundhouse-tools` executor itself failed (I/O error,
    /// ambiguous edit match, glob error, etc.).
    #[error("{0}")]
    Tool(#[from] roundhouse_tools::ToolError),
}

fn str_field(
    input: &serde_json::Value,
    tool: &'static str,
    field: &'static str,
) -> Result<String, ToolDispatchError> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or(ToolDispatchError::BadArgs { tool, field })
}

fn argv_field(
    input: &serde_json::Value,
    tool: &'static str,
) -> Result<Vec<String>, ToolDispatchError> {
    let arr = input
        .get("argv")
        .and_then(|v| v.as_array())
        .ok_or(ToolDispatchError::BadArgs {
            tool,
            field: "argv",
        })?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(str::to_string)
                .ok_or(ToolDispatchError::BadArgs {
                    tool,
                    field: "argv",
                })
        })
        .collect()
}

/// Resolves `path` to the genuinely-canonicalized, symlink-followed,
/// absolute path `TaskCreateRequest::params`'s documented security
/// invariant requires — never the raw model-supplied string.
///
/// `std::fs::canonicalize` requires the path to already exist, which is
/// true for `read`/`edit`/`find` targets but not for a `write` creating a
/// brand-new file. In that case this resolves the parent directory instead
/// (following any symlinks in *that* chain) and rejoins the file name, so
/// admission still judges a real, resolved location rather than an
/// unresolved string — it never falls back to trusting the raw path
/// verbatim. If neither the path nor its parent can be resolved, that is a
/// real resolution failure (`Err`), and `PolicyEngine::decide`'s own
/// documented behavior denies any such path outright (§6.2: "a path that
/// fails to canonicalise is Deny, never Ask").
fn resolve_canonical(path: &Path) -> Result<PathBuf, roundhouse_policy::PathErr> {
    if let Ok(p) = path.canonicalize() {
        return Ok(p);
    }
    let file_name = path.file_name().ok_or_else(|| {
        roundhouse_policy::PathErr(format!("path has no file name component: {path:?}"))
    })?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let canonical_parent = parent.canonicalize().map_err(|e| {
        roundhouse_policy::PathErr(format!("cannot resolve parent directory of {path:?}: {e}"))
    })?;
    Ok(canonical_parent.join(file_name))
}

fn fs_params(op: FsOp, raw_path: &str) -> TaskParams {
    let path = PathBuf::from(raw_path);
    let canonical = resolve_canonical(&path);
    TaskParams::Fs {
        op,
        path,
        canonical,
    }
}

/// Builds the `TaskParams` `SessionActor::admit_task` judges a model's
/// tool-call against, from its raw `input` JSON. Must be called (and its
/// result admitted) BEFORE [`execute_builtin`] ever runs the real executor
/// — see `agent_loop.rs`'s dispatch order.
pub fn task_params_for(
    kind: TaskKind,
    input: &serde_json::Value,
) -> Result<TaskParams, ToolDispatchError> {
    match kind {
        TaskKind::Read => Ok(fs_params(FsOp::Read, &str_field(input, "read", "path")?)),
        TaskKind::Write => Ok(fs_params(FsOp::Write, &str_field(input, "write", "path")?)),
        TaskKind::Edit => Ok(fs_params(FsOp::Edit, &str_field(input, "edit", "path")?)),
        TaskKind::Find => Ok(fs_params(FsOp::Find, &str_field(input, "find", "root")?)),
        TaskKind::Shell => {
            let program = str_field(input, "shell", "program")?;
            let argv = argv_field(input, "shell")?;
            Ok(TaskParams::Shell(ParsedCommand { program, argv }))
        }
        other => Err(ToolDispatchError::UnsupportedKind { kind: other }),
    }
}

/// Runs the real `roundhouse-tools` executor for an already-admitted
/// built-in tool call, and folds its result into the `ToolResultPart`
/// content the model reads back.
///
/// **Takes `params` — the exact, already-admitted `TaskParams` `task_params_for`
/// built and `SessionActor::admit_task` judged — not a second, independent
/// parse of `input`.** This is a deliberate TOCTOU guard: for every `Fs`
/// kind, the path this function actually opens is `params`'s already-resolved
/// `canonical` `PathBuf`, never a fresh `Path::new(&raw_string_from_input)`.
/// If execution re-derived the path from `input` on its own, a symlink
/// swapped between admission and execution (or any other divergence between
/// the two derivations) would let admission judge one location while
/// execution touches another — exactly the TOCTOU
/// `TaskCreateRequest::params`'s own documented invariant ("`canonical` MUST
/// be ... the real path this task will touch") exists to close. `input` is
/// still consulted for the fields `TaskParams` doesn't carry (`write`'s
/// `contents`, `edit`'s `find`/`replace`, `find`'s `pattern`, `shell`'s
/// `cwd` — see this module's doc comment on the `cwd`/`root` containment
/// decision).
///
/// Never call this before `params` has been admitted through
/// `SessionActor::admit_task` — this function performs no admission check
/// of its own.
pub async fn execute_builtin(
    params: &TaskParams,
    input: &serde_json::Value,
) -> Result<Vec<ToolResultPart>, ToolDispatchError> {
    match params {
        TaskParams::Fs {
            op: FsOp::Read,
            canonical,
            ..
        } => {
            let path = canonical
                .as_ref()
                .map_err(|e| ToolDispatchError::UnresolvedPath(e.clone()))?;
            let contents = roundhouse_tools::read_file(path).await?;
            Ok(vec![ToolResultPart { text: contents }])
        }
        TaskParams::Fs {
            op: FsOp::Write,
            canonical,
            ..
        } => {
            let path = canonical
                .as_ref()
                .map_err(|e| ToolDispatchError::UnresolvedPath(e.clone()))?;
            let contents = str_field(input, "write", "contents")?;
            roundhouse_tools::write_file(path, contents.as_bytes()).await?;
            Ok(vec![ToolResultPart {
                text: format!("wrote {} bytes to {}", contents.len(), path.display()),
            }])
        }
        TaskParams::Fs {
            op: FsOp::Edit,
            canonical,
            ..
        } => {
            let path = canonical
                .as_ref()
                .map_err(|e| ToolDispatchError::UnresolvedPath(e.clone()))?;
            let find = str_field(input, "edit", "find")?;
            let replace = str_field(input, "edit", "replace")?;
            let outcome = roundhouse_tools::edit_file(path, &find, &replace).await?;
            Ok(vec![ToolResultPart {
                text: format!("edited {}\n{}", path.display(), outcome.diff),
            }])
        }
        TaskParams::Fs {
            op: FsOp::Find,
            canonical,
            ..
        } => {
            let root = canonical
                .as_ref()
                .map_err(|e| ToolDispatchError::UnresolvedPath(e.clone()))?;
            let pattern = str_field(input, "find", "pattern")?;
            let matches = roundhouse_tools::find_files(root, &pattern)?;
            let text = matches
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n");
            Ok(vec![ToolResultPart { text }])
        }
        TaskParams::Shell(cmd) => {
            let cwd = str_field(input, "shell", "cwd")?;
            let output =
                roundhouse_tools::run_shell(&cmd.program, &cmd.argv, Path::new(&cwd)).await?;
            let text = format!(
                "exit_code={:?}\nstdout:\n{}\nstderr:\n{}",
                output.exit_code,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            Ok(vec![ToolResultPart { text }])
        }
        other => Err(ToolDispatchError::UnsupportedParams(format!("{other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_path(dir: &Path, name: &str) -> (PathBuf, String) {
        let path = dir.join(name);
        (path.clone(), path.to_string_lossy().to_string())
    }

    #[test]
    fn task_params_for_read_builds_fs_read_with_a_real_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "existing.txt");
        std::fs::write(&path, b"hello").unwrap();

        let params =
            task_params_for(TaskKind::Read, &serde_json::json!({ "path": path_str })).unwrap();
        match params {
            TaskParams::Fs {
                op: FsOp::Read,
                canonical: Ok(c),
                ..
            } => assert_eq!(c, path.canonicalize().unwrap()),
            other => panic!("expected TaskParams::Fs{{op: Read, canonical: Ok(_)}}, got {other:?}"),
        }
    }

    #[test]
    fn task_params_for_write_resolves_a_not_yet_existing_file_via_its_parent() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "brand-new.txt");
        assert!(!path.exists(), "test setup bug: file must not exist yet");

        let params =
            task_params_for(TaskKind::Write, &serde_json::json!({ "path": path_str })).unwrap();
        match params {
            TaskParams::Fs {
                op: FsOp::Write,
                canonical: Ok(c),
                ..
            } => assert_eq!(
                c,
                dir.path().canonicalize().unwrap().join("brand-new.txt"),
                "a not-yet-existing write target must resolve via its real, canonicalized parent"
            ),
            other => {
                panic!("expected TaskParams::Fs{{op: Write, canonical: Ok(_)}}, got {other:?}")
            }
        }
    }

    #[test]
    fn task_params_for_write_under_an_unresolvable_parent_is_a_canonical_err() {
        let params = task_params_for(
            TaskKind::Write,
            &serde_json::json!({ "path": "/definitely/does/not/exist/anywhere/file.txt" }),
        )
        .unwrap();
        match params {
            TaskParams::Fs {
                op: FsOp::Write,
                canonical: Err(_),
                ..
            } => {}
            other => {
                panic!("expected TaskParams::Fs{{op: Write, canonical: Err(_)}}, got {other:?}")
            }
        }
    }

    #[test]
    fn task_params_for_edit_maps_to_fs_op_edit() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "edit-me.txt");
        std::fs::write(&path, b"hello").unwrap();

        let params = task_params_for(
            TaskKind::Edit,
            &serde_json::json!({ "path": path_str, "find": "hello", "replace": "bye" }),
        )
        .unwrap();
        assert!(matches!(
            params,
            TaskParams::Fs {
                op: FsOp::Edit,
                canonical: Ok(_),
                ..
            }
        ));
    }

    #[test]
    fn task_params_for_find_maps_root_to_fs_op_find() {
        let dir = tempfile::tempdir().unwrap();
        let root_str = dir.path().to_string_lossy().to_string();

        let params = task_params_for(
            TaskKind::Find,
            &serde_json::json!({ "root": root_str, "pattern": "*.rs" }),
        )
        .unwrap();
        assert!(matches!(
            params,
            TaskParams::Fs {
                op: FsOp::Find,
                canonical: Ok(_),
                ..
            }
        ));
    }

    #[test]
    fn task_params_for_shell_builds_parsed_command_with_no_cwd_field() {
        let params = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({ "program": "true", "argv": ["-x"], "cwd": "/tmp" }),
        )
        .unwrap();
        match params {
            TaskParams::Shell(cmd) => {
                assert_eq!(cmd.program, "true");
                assert_eq!(cmd.argv, vec!["-x".to_string()]);
            }
            other => panic!("expected TaskParams::Shell, got {other:?}"),
        }
    }

    #[test]
    fn task_params_for_missing_field_is_bad_args_not_a_panic() {
        let err = task_params_for(TaskKind::Read, &serde_json::json!({})).unwrap_err();
        assert!(matches!(
            err,
            ToolDispatchError::BadArgs {
                tool: "read",
                field: "path"
            }
        ));
    }

    #[tokio::test]
    async fn execute_builtin_read_returns_the_real_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "hello.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let input = serde_json::json!({ "path": path_str });
        let params = task_params_for(TaskKind::Read, &input).unwrap();
        let parts = execute_builtin(&params, &input).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].text, "hello world");
    }

    #[tokio::test]
    async fn execute_builtin_write_creates_the_file_with_the_given_contents() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "new.txt");

        let input = serde_json::json!({ "path": path_str, "contents": "hi there" });
        let params = task_params_for(TaskKind::Write, &input).unwrap();
        execute_builtin(&params, &input).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi there");
    }

    #[tokio::test]
    async fn execute_builtin_edit_replaces_the_single_match() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "edit.txt");
        std::fs::write(&path, "hello world").unwrap();

        let input = serde_json::json!({ "path": path_str, "find": "world", "replace": "there" });
        let params = task_params_for(TaskKind::Edit, &input).unwrap();
        execute_builtin(&params, &input).await.unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello there");
    }

    #[tokio::test]
    async fn execute_builtin_edit_fails_closed_on_an_ambiguous_match() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "ambiguous.txt");
        std::fs::write(&path, "a a a").unwrap();

        let input = serde_json::json!({ "path": path_str, "find": "a", "replace": "b" });
        let params = task_params_for(TaskKind::Edit, &input).unwrap();
        let err = execute_builtin(&params, &input).await.unwrap_err();
        assert!(matches!(
            err,
            ToolDispatchError::Tool(roundhouse_tools::ToolError::AmbiguousMatch(3))
        ));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "a a a",
            "a failed edit must leave the file byte-for-byte unchanged"
        );
    }

    #[tokio::test]
    async fn execute_builtin_find_globs_relative_to_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.rs"), "").unwrap();
        std::fs::write(dir.path().join("b.txt"), "").unwrap();
        let root_str = dir.path().to_string_lossy().to_string();

        let input = serde_json::json!({ "root": root_str, "pattern": "*.rs" });
        let params = task_params_for(TaskKind::Find, &input).unwrap();
        let parts = execute_builtin(&params, &input).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].text.ends_with("a.rs"));
    }

    #[tokio::test]
    async fn execute_builtin_shell_captures_real_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let cwd_str = dir.path().to_string_lossy().to_string();

        let input = serde_json::json!({
            "program": "echo",
            "argv": ["hello-from-shell"],
            "cwd": cwd_str,
        });
        let params = task_params_for(TaskKind::Shell, &input).unwrap();
        let parts = execute_builtin(&params, &input).await.unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].text.contains("hello-from-shell"));
        assert!(parts[0].text.contains("exit_code=Some(0)"));
    }

    #[tokio::test]
    async fn execute_builtin_uses_the_already_admitted_canonical_path_not_a_fresh_parse_of_input() {
        // The TOCTOU guard: build `params` for one file, then hand
        // `execute_builtin` a DIFFERENT `input.path` — it must still act on
        // `params`'s canonical path, proving execution never independently
        // re-derives the path from `input`.
        let dir = tempfile::tempdir().unwrap();
        let (admitted_path, admitted_path_str) = round_trip_path(dir.path(), "admitted.txt");
        std::fs::write(&admitted_path, "admitted contents").unwrap();
        let (decoy_path, decoy_path_str) = round_trip_path(dir.path(), "decoy.txt");
        std::fs::write(&decoy_path, "decoy contents").unwrap();

        let params = task_params_for(
            TaskKind::Read,
            &serde_json::json!({ "path": admitted_path_str }),
        )
        .unwrap();
        // A hostile/racy `input` naming a different path than what was
        // admitted — execution must ignore it entirely for path purposes.
        let mismatched_input = serde_json::json!({ "path": decoy_path_str });

        let parts = execute_builtin(&params, &mismatched_input).await.unwrap();
        assert_eq!(
            parts[0].text, "admitted contents",
            "execute_builtin must read the admitted canonical path, never a path re-parsed from \
             `input`"
        );
    }

    #[tokio::test]
    async fn execute_builtin_unsupported_params_is_a_named_error_not_a_panic() {
        let params = TaskParams::Http {
            method: roundhouse_policy::Method::Get,
            url: "https://example.com".into(),
            body_len: 0,
        };
        let err = execute_builtin(&params, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolDispatchError::UnsupportedParams(_)));
    }

    #[test]
    fn task_params_for_unsupported_kind_is_a_named_error_not_a_panic() {
        let err = task_params_for(TaskKind::Chat, &serde_json::json!({})).unwrap_err();
        assert!(matches!(
            err,
            ToolDispatchError::UnsupportedKind {
                kind: TaskKind::Chat
            }
        ));
    }

    /// Regression guard for a real question raised in review: does building
    /// `TaskParams::Shell` directly from the model's `program`/`argv` (never
    /// routed through `roundhouse_policy::shell::pipeline`'s AST-based
    /// `resolve_nodes`/`decide_pipeline`) leave the sealed floor's
    /// priv-escalation rule blind to a fully-qualified path like
    /// `/usr/bin/sudo`? It does not: `sealed_program`
    /// (`roundhouse-policy/src/sealed.rs`) checks BOTH the raw `program`
    /// string AND its `Path::file_name()` basename against `SEALED_PROGRAMS`
    /// — so a path prefix cannot hide a sealed program name. (The
    /// AST/pipeline machinery this dispatch bypasses exists for a
    /// DIFFERENT, raw-shell-string-taking tool this catalog does not define
    /// — `tool_catalog::builtin_tool_defs`'s `shell` tool already takes
    /// discrete `program`/`argv`, exactly the single-resolved-node
    /// granularity `sealed_program`/`decide_sealed` expect, with no shell
    /// grammar to parse and — since `run_shell` always execs directly,
    /// never via `sh -c` — no interpreter for an `argv` element to be
    /// reinterpreted by.)
    #[test]
    fn a_fully_qualified_sealed_program_path_is_still_denied_by_the_sealed_floor() {
        let params = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({ "program": "/usr/bin/sudo", "argv": ["-l"] }),
        )
        .unwrap();
        let policy = roundhouse_policy::engine::PolicyEngine::from_rules(vec![]);
        let ctx = roundhouse_policy::sealed::default_context();
        let decision = policy.decide_sealed(&params, &ctx);
        assert_eq!(
            decision.outcome,
            roundhouse_policy::engine::Outcome::Deny,
            "a fully-qualified path to a sealed priv-escalation program must still be denied"
        );
    }
}
