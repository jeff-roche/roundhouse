//! Maps one resolved built-in [`crate::tool_catalog::ToolTarget::Builtin`]
//! tool call onto `roundhouse-policy`'s `TaskParams` (what
//! `SessionActor::admit_task` judges) and `roundhouse-tools`' real executor
//! (what actually performs the action once admitted) — Phase 7 Task 5's
//! "dispatch bridge," split out of `agent_loop.rs` for its own unit tests per
//! the plan's explicit request.
//!
//! # Containment decision (carry-forward CF-1) — CORRECTED in fix round A
//! `tool_catalog`'s published schemas mirror the real executor signatures
//! literally: `ShellParams.cwd` and `FindParams.root` are model-supplied,
//! required fields (Task 1's review flagged this as a security-relevant
//! decision Task 5 must make explicitly, not a style choice). This module
//! takes them **as the model supplies them** rather than silently
//! substituting a session-derived value: the published tool schema promises
//! the model that `cwd`/`root` are its own to name.
//!
//! **`find`'s `root` is genuinely contained by `roundhouse_tools::find_files`
//! itself** (component-wise `starts_with` against the canonicalized root —
//! `find.rs:46-95` — every match must resolve inside it).
//!
//! **The original version of this comment claimed the identical thing was
//! true of `shell`'s `cwd`, via `SessionActor::admit_task`'s sealed floor.
//! That was false: no sealed rule or `Predicate` anywhere in
//! `roundhouse-policy` inspects a working directory at all** (fix round A,
//! finding F2 — a deliberate decision justified by a mechanism that didn't
//! exist is worse than an undocumented one). `cwd` is now contained
//! independently, in THIS module: [`resolve_shell_cwd`] canonicalizes it and
//! rejects anything not component-wise inside the daemon's own working
//! directory (this dispatch's stand-in "workspace root" — see that
//! function's doc comment for why), the same shape `find_files` uses,
//! BEFORE `task_params_for` ever returns — a rejected `cwd` never reaches
//! `admit_task` at all. `shell`'s `program` is resolved the same way (see
//! [`resolve_shell_program`]): the canonical, resolved binary — not the raw
//! model string — is what `ParsedCommand.program` carries, so policy judges
//! the real binary and a model-controlled `cwd` can no longer smuggle a
//! different one in under a relative name (finding F2's other half; see
//! ruling W1-R57).
//!
//! Real process-level sandboxing of the dispatched executor call itself
//! (running it through the session's `Isolate::spawn` rather than
//! in-process) remains out of this task's scope (see `agent_loop.rs`'s
//! module doc comment) — this module wires the real admission gate in front
//! of the real executors, which is the concrete gap Task 5 exists to close;
//! routing execution through the sandbox tier too is further,
//! not-yet-numbered integration work, same as `SessionActor`'s own
//! pre-existing doc comments already flag for the "no unified
//! task-execution entry point" gap.
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

use roundhouse_core::{SessionState, TaskKind};
use roundhouse_policy::{FsOp, ParsedCommand, TaskParams};
use roundhouse_provider::ToolResultPart;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::watch;

/// Wall-clock bound on one dispatched `shell` call (fix round A, finding
/// F6). Not ruled on explicitly — a judgment call, recorded here so it is
/// easy to find and reconsider: long enough for an ordinary build/test
/// command, short enough that a hung or runaway process doesn't tie up a
/// dispatch turn indefinitely. `max_turns`/turn-level timeouts remain the
/// caller's problem; this is strictly the single-call bound `spawn_cancellable`
/// needs to be reachable through at all.
const SHELL_TIMEOUT: Duration = Duration::from_secs(120);

/// Grace period between SIGTERM and SIGKILL escalation when a dispatched
/// shell call is cancelled (timeout or session cancellation) — passed
/// straight through to `roundhouse_tools::cancel_running_shell`.
const SHELL_CANCEL_GRACE: Duration = Duration::from_secs(5);

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
    /// The daemon's own current working directory — this dispatch's
    /// containment boundary for `shell`'s `cwd`/`program` (see
    /// [`resolve_shell_cwd`]/[`resolve_shell_program`]) — could not be read.
    #[error("cannot resolve the daemon's own working directory: {0}")]
    WorkspaceRootUnavailable(String),
    /// The model-supplied `cwd` failed to canonicalize, or resolved outside
    /// the workspace root (fix round A, finding F2 / ruling W1-R58).
    #[error("shell cwd rejected: {0}")]
    ShellCwdRejected(String),
    /// The model-supplied `program` could not be resolved to a real binary
    /// (PATH lookup failed for a bare name; canonicalization failed or
    /// escaped the workspace root for a `/`-containing relative name) (fix
    /// round A, finding F2 / rulings W1-R56/W1-R57).
    #[error("shell program rejected: {0}")]
    ShellProgramRejected(String),
    /// `execute_builtin`'s `TaskParams::Shell` arm was reached without a
    /// pre-resolved `cwd` in `ResolvedExtras` — unreachable through
    /// `task_params_for`'s real output today (it always populates
    /// `shell_cwd` for `TaskKind::Shell`, or returns `Err` before producing
    /// a `TaskParams::Shell` at all), but kept as a named, fail-closed error
    /// rather than an `unwrap`/`expect` in case that invariant is ever
    /// weakened upstream.
    #[error(
        "internal error: shell dispatch is missing its pre-resolved, already-admitted working \
         directory"
    )]
    MissingResolvedCwd,
    /// A dispatched shell call was cancelled — either it exceeded
    /// [`SHELL_TIMEOUT`], or the owning session left `Created`/`Running`
    /// while it was in flight (fix round A, finding F6). The process group
    /// has already been signalled (SIGTERM, escalating to SIGKILL) via
    /// `roundhouse_tools::cancel_running_shell` by the time this is
    /// returned.
    #[error("shell command cancelled: {0}")]
    ShellCancelled(String),
    /// The real `roundhouse-tools` executor itself failed (I/O error,
    /// ambiguous edit match, glob error, etc.).
    #[error("{0}")]
    Tool(#[from] roundhouse_tools::ToolError),
}

/// Dispatch-relevant values [`task_params_for`] resolves that don't fit
/// into the frozen `TaskParams` shape — currently just `shell`'s
/// already-validated, canonical working directory (`ParsedCommand` has no
/// `cwd` field to carry it — see this module's doc comment on the
/// containment decision). [`execute_builtin`] must use this value verbatim
/// rather than re-deriving it from `input`, for the same TOCTOU reason
/// `TaskParams::Fs.canonical` exists: the path judged at admission must be
/// the exact path touched at execution.
#[derive(Debug, Clone, Default)]
pub struct ResolvedExtras {
    pub shell_cwd: Option<PathBuf>,
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

/// The containment boundary a dispatched `shell` call's `cwd` (and, for a
/// relative `/`-containing `program`, its resolved binary too) must stay
/// inside (ruling W1-R58). Nothing in the workspace today defines a
/// per-session or per-workspace filesystem root — `SessionSpec.workspace` is
/// an opaque `WorkspaceId`, not a path — so this dispatch uses the daemon
/// process's own current working directory as its stand-in: `round daemon`
/// is meant to be launched from within the project/repo it's operating on
/// (the same assumption `roundhouse-config`'s project-scope loading already
/// makes), so this is the most direct real boundary available without
/// inventing new session-wide state or touching `SessionActor::new`'s
/// signature. **This is a judgment call, not something W1-R58 ruled on
/// directly — flagged in the fix-round report for confirmation.** Read
/// fresh on every call rather than cached: nothing in this daemon ever
/// calls `std::env::set_current_dir`, so it is effectively invariant for the
/// process's lifetime, but reading it fresh costs nothing and doesn't rely
/// on that invariant silently.
fn workspace_root() -> Result<PathBuf, ToolDispatchError> {
    std::env::current_dir().map_err(|e| ToolDispatchError::WorkspaceRootUnavailable(e.to_string()))
}

/// Resolves and validates the model-supplied `cwd`: canonicalized (a real,
/// symlink-followed, already-existing directory — required for
/// `Command::current_dir` to succeed anyway) and required to be
/// component-wise inside [`workspace_root`] — the same
/// canonicalize-then-`starts_with` shape `find_files` (`find.rs:46-95`)
/// already uses. **Rejection, not a companion `Fs` admission** (ruling
/// W1-R58 explicitly prefers this over the alternative of running `cwd`
/// through its own `TaskParams::Fs` admission): a `cwd` that fails this
/// check never reaches `admit_task` at all — `task_params_for` returns
/// `Err` before building any `TaskParams::Shell`.
fn resolve_shell_cwd(raw_cwd: &str) -> Result<PathBuf, ToolDispatchError> {
    let root = workspace_root()?;
    let canonical = Path::new(raw_cwd).canonicalize().map_err(|e| {
        ToolDispatchError::ShellCwdRejected(format!("cwd {raw_cwd:?} not accessible: {e}"))
    })?;
    if !canonical.starts_with(&root) {
        return Err(ToolDispatchError::ShellCwdRejected(format!(
            "cwd {canonical:?} is outside the workspace root {root:?}"
        )));
    }
    Ok(canonical)
}

/// Resolves the model-supplied `program` to the absolute, canonical binary
/// that will actually run (fix round A, finding F2 / rulings
/// W1-R56/W1-R57) — this value, not the raw model string, is what
/// [`task_params_for`] puts into `ParsedCommand.program`, so policy judges
/// the real binary rather than a string the model's own choice of `cwd`
/// could silently redirect elsewhere.
///
/// Splits on shape (ruling W1-R56): `spawn_cancellable`'s `env_clear()`
/// (fix round A, finding F1) removes `PATH` from the CHILD's own
/// environment, so a bare name is a PATH lookup — not `cwd`-relative — and
/// resolving it against `cwd` would simply fail to find anything.
/// - **Contains `/`:** joined against `canonical_cwd` (an already-absolute
///   `program` replaces the join entirely, matching `Path::join`'s own
///   semantics) and canonicalized.
///   - If the ORIGINAL string was relative (`./gradlew`,
///     `node_modules/.bin/foo`), the canonicalized result is additionally
///     required to stay inside the workspace root — this is exactly the
///     vector F2 proved: the model's choice of `cwd` selecting which binary
///     of a relative name actually runs.
///   - If the original string was already absolute (`/usr/bin/git`), it is
///     NOT additionally confined to the workspace root: its resolution
///     never depended on `cwd` in the first place, so `cwd` gives the model
///     no leverage over which binary a fully-qualified path names, and
///     confining it would only break legitimate calls to system binaries
///     with no corresponding security benefit. **Not spelled out verbatim
///     in W1-R56/57's text — a deliberate, documented narrowing, flagged in
///     the fix-round report.** (CF-16 itself only anticipates *relative*
///     program allow-rules breaking, not absolute ones, which is consistent
///     with this reading.)
/// - **Bare name (no `/`):** resolved via the **daemon's own** `PATH`
///   (deterministic, never model-controlled) to an absolute path — mirrors
///   `roundhouse-mcp/src/transport/stdio.rs`'s `resolve_command` shape for
///   the identical reason (a hash-pin-style guarantee that the string
///   judged is the binary that runs), reimplemented here rather than
///   reached across the crate boundary (that function is private and
///   `roundhouse-mcp` is out of this lane's charter for anything beyond the
///   narrow, ruled `roundhouse-tools`/`roundhouse-store` additions).
fn resolve_shell_program(
    raw_program: &str,
    canonical_cwd: &Path,
) -> Result<PathBuf, ToolDispatchError> {
    if raw_program.contains('/') {
        let was_absolute = Path::new(raw_program).is_absolute();
        let joined = canonical_cwd.join(raw_program);
        let canonical = joined.canonicalize().map_err(|e| {
            ToolDispatchError::ShellProgramRejected(format!(
                "program {raw_program:?} not accessible: {e}"
            ))
        })?;
        if !was_absolute {
            let root = workspace_root()?;
            if !canonical.starts_with(&root) {
                return Err(ToolDispatchError::ShellProgramRejected(format!(
                    "resolved program {canonical:?} is outside the workspace root {root:?}"
                )));
            }
        }
        Ok(canonical)
    } else {
        let path_var = std::env::var_os("PATH").ok_or_else(|| {
            ToolDispatchError::ShellProgramRejected(
                "PATH is not set in the daemon's own environment".to_string(),
            )
        })?;
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(raw_program);
            if candidate.is_file() {
                return candidate.canonicalize().map_err(|e| {
                    ToolDispatchError::ShellProgramRejected(format!(
                        "program {raw_program:?} resolved to {candidate:?} but could not be \
                         canonicalized: {e}"
                    ))
                });
            }
        }
        Err(ToolDispatchError::ShellProgramRejected(format!(
            "program {raw_program:?} not found on the daemon's PATH"
        )))
    }
}

/// The explicit, `env_clear()`-safe environment allowlist for a dispatched
/// shell call (fix round A, finding F1) — copies the shape
/// `roundhouse-mcp/src/transport/stdio.rs:119`'s `build_command` already
/// uses ("explicit allowlist only, never inherits the daemon's own env").
/// **Contains exactly `PATH`, read from the daemon's own environment, and
/// nothing else** — the minimal addition `resolve_shell_program`'s bare-name
/// branch needs to keep working post-`env_clear()` (ruling W1-R56), chosen
/// deliberately narrow: every other env var (`ANTHROPIC_API_KEY` among them
/// — the exact finding F1 reproduced) is a daemon secret or daemon-internal
/// detail the dispatched child has no legitimate need for.
fn shell_env_allowlist() -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        env.push(("PATH".to_string(), path.to_string_lossy().to_string()));
    }
    env
}

/// Builds the `TaskParams` `SessionActor::admit_task` judges a model's
/// tool-call against, from its raw `input` JSON, plus any [`ResolvedExtras`]
/// [`execute_builtin`] needs but `TaskParams` can't carry. Must be called
/// (and its `TaskParams` admitted) BEFORE [`execute_builtin`] ever runs the
/// real executor — see `agent_loop.rs`'s dispatch order.
pub fn task_params_for(
    kind: TaskKind,
    input: &serde_json::Value,
) -> Result<(TaskParams, ResolvedExtras), ToolDispatchError> {
    match kind {
        TaskKind::Read => Ok((
            fs_params(FsOp::Read, &str_field(input, "read", "path")?),
            ResolvedExtras::default(),
        )),
        TaskKind::Write => Ok((
            fs_params(FsOp::Write, &str_field(input, "write", "path")?),
            ResolvedExtras::default(),
        )),
        TaskKind::Edit => Ok((
            fs_params(FsOp::Edit, &str_field(input, "edit", "path")?),
            ResolvedExtras::default(),
        )),
        TaskKind::Find => Ok((
            fs_params(FsOp::Find, &str_field(input, "find", "root")?),
            ResolvedExtras::default(),
        )),
        TaskKind::Shell => {
            let raw_program = str_field(input, "shell", "program")?;
            let argv = argv_field(input, "shell")?;
            let raw_cwd = str_field(input, "shell", "cwd")?;
            let canonical_cwd = resolve_shell_cwd(&raw_cwd)?;
            let canonical_program = resolve_shell_program(&raw_program, &canonical_cwd)?;
            let program = canonical_program.to_string_lossy().to_string();
            Ok((
                TaskParams::Shell(ParsedCommand { program, argv }),
                ResolvedExtras {
                    shell_cwd: Some(canonical_cwd),
                },
            ))
        }
        other => Err(ToolDispatchError::UnsupportedKind { kind: other }),
    }
}

/// Runs the real `roundhouse-tools` executor for an already-admitted
/// built-in tool call, and folds its result into the `ToolResultPart`
/// content the model reads back.
///
/// **Takes `params`/`extras` — the exact, already-admitted `TaskParams`
/// (and its accompanying [`ResolvedExtras`]) `task_params_for` built and
/// `SessionActor::admit_task` judged — not a second, independent parse of
/// `input`.** This is a deliberate TOCTOU guard: for every `Fs` kind, the
/// path this function actually opens is `params`'s already-resolved
/// `canonical` `PathBuf`; for `Shell`, the working directory is
/// `extras.shell_cwd` and the program is `params`'s already-canonical
/// `ParsedCommand.program` — never anything freshly re-derived from
/// `input`. If execution re-derived any of these from `input` on its own, a
/// symlink swap (or any other divergence between the two derivations)
/// between admission and execution would let admission judge one target
/// while execution touches another — exactly the TOCTOU
/// `TaskCreateRequest::params`'s own documented invariant ("`canonical` MUST
/// be ... the real path this task will touch") exists to close. `input` is
/// still consulted for the fields `TaskParams`/`ResolvedExtras` don't carry
/// (`write`'s `contents`, `edit`'s `find`/`replace`, `find`'s `pattern`) —
/// never for a path/program/cwd.
///
/// `cancel`, when `Some`, is raced against [`SHELL_TIMEOUT`] for the
/// `Shell` arm (fix round A, finding F6): if the owning session leaves
/// `Created`/`Running` while the child is in flight, it is cancelled the
/// same way a timeout is. `None` (used by every non-`Shell` call, and by
/// tests that don't care about session-cancellation) means the wall-clock
/// bound is still enforced, just without that extra signal.
///
/// Never call this before `params` has been admitted through
/// `SessionActor::admit_task` — this function performs no admission check
/// of its own.
pub async fn execute_builtin(
    params: &TaskParams,
    extras: &ResolvedExtras,
    input: &serde_json::Value,
    cancel: Option<watch::Receiver<SessionState>>,
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
                .map_err(|e| ToolDispatchError::UnresolvedPath(e.clone()))?
                .clone();
            let pattern = str_field(input, "find", "pattern")?;
            // fix round A, SHOULD item F9: `find_files` is synchronous/CPU-bound
            // (its own doc comment says as much — "async callers should wrap
            // this in spawn_blocking if needed") — a `**` glob over a large
            // admitted root must not block this async runtime worker.
            let matches =
                tokio::task::spawn_blocking(move || roundhouse_tools::find_files(&root, &pattern))
                    .await
                    .map_err(|e| {
                        ToolDispatchError::Tool(roundhouse_tools::ToolError::Glob(format!(
                            "find_files task panicked or was cancelled: {e}"
                        )))
                    })??;
            let text = matches
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join("\n");
            Ok(vec![ToolResultPart { text }])
        }
        TaskParams::Shell(cmd) => {
            let cwd = extras
                .shell_cwd
                .as_deref()
                .ok_or(ToolDispatchError::MissingResolvedCwd)?;
            let env = shell_env_allowlist();
            let output =
                run_shell_dispatch(&cmd.program, &cmd.argv, cwd, &env, SHELL_TIMEOUT, cancel)
                    .await?;
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

/// Runs a dispatched `shell` call through `roundhouse_tools::spawn_cancellable`
/// (never the uncancellable `run_shell` — fix round A, finding F6), racing
/// its natural completion against `timeout` and, when `cancel` is `Some`,
/// the owning session leaving `Created`/`Running`. Either losing condition
/// cancels the real process group (`cancel_running_shell`, SIGTERM
/// escalating to SIGKILL, confirmed via its own liveness probe) before
/// returning [`ToolDispatchError::ShellCancelled`] — this function never
/// reports success without the process having genuinely exited on its own.
///
/// stdout/stderr are drained concurrently via spawned tasks
/// ([`ShellHandle::take_stdio`]'s own doc comment explains why: `wait`
/// alone never reads the pipes, so a chatty child could deadlock against a
/// full OS pipe buffer while this function is busy racing the other two
/// conditions instead of reading).
async fn run_shell_dispatch(
    program: &str,
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
    cancel: Option<watch::Receiver<SessionState>>,
) -> Result<roundhouse_tools::ShellOutput, ToolDispatchError> {
    let mut handle = roundhouse_tools::spawn_cancellable(program, argv, cwd, env).await?;
    let (stdout, stderr) = handle.take_stdio();
    let stdout_task = tokio::spawn(drain_to_end(stdout));
    let stderr_task = tokio::spawn(drain_to_end(stderr));

    let mut cancel = cancel;
    let cancel_reason = tokio::select! {
        result = handle.wait() => {
            return match result {
                Ok(status) => {
                    // A panic in a plain read-to-end loop is not expected;
                    // treat a lost reader task the same as "read nothing"
                    // rather than propagating a JoinError through a shell
                    // result the model is waiting on.
                    let stdout = stdout_task.await.unwrap_or_default();
                    let stderr = stderr_task.await.unwrap_or_default();
                    Ok(roundhouse_tools::ShellOutput {
                        stdout,
                        stderr,
                        exit_code: status.code(),
                    })
                }
                Err(e) => Err(ToolDispatchError::Tool(e)),
            };
        }
        () = tokio::time::sleep(timeout) => {
            format!("exceeded its {timeout:?} wall-clock bound")
        }
        () = wait_for_session_cancel(&mut cancel) => {
            "the owning session was cancelled/suspended/closed".to_string()
        }
    };

    // Best-effort: cancellation failing to confirm is itself a real
    // condition (`CancelError::GroupStillAlive`), but this function's own
    // job is reporting the shell call as cancelled either way — a caller
    // that needs to know cancellation itself failed would need a different
    // return shape than "the tool call didn't succeed," which is all a
    // dispatched tool result can express today.
    let _ = roundhouse_tools::cancel_running_shell(&mut handle, SHELL_CANCEL_GRACE).await;
    Err(ToolDispatchError::ShellCancelled(cancel_reason))
}

/// Resolves once the watched session leaves `Created`/`Running`, or never
/// resolves at all (`cancel: None`, or the `SessionActor` — and with it the
/// `watch::Sender` — has been dropped, which only `None`'s sibling branches
/// in [`run_shell_dispatch`]'s `select!` can still make progress against).
async fn wait_for_session_cancel(cancel: &mut Option<watch::Receiver<SessionState>>) {
    match cancel {
        Some(rx) => loop {
            if !matches!(*rx.borrow(), SessionState::Created | SessionState::Running) {
                return;
            }
            if rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        },
        None => std::future::pending().await,
    }
}

/// Reads a piped child stdio handle to the end, or returns an empty buffer
/// if the pipe was never present (stdio wasn't piped, or `take_stdio` was
/// never called) — never fails the whole dispatch over a drain error.
async fn drain_to_end<R: tokio::io::AsyncRead + Unpin>(io: Option<R>) -> Vec<u8> {
    let mut buf = Vec::new();
    if let Some(mut io) = io {
        use tokio::io::AsyncReadExt;
        let _ = io.read_to_end(&mut buf).await;
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip_path(dir: &Path, name: &str) -> (PathBuf, String) {
        let path = dir.join(name);
        (path.clone(), path.to_string_lossy().to_string())
    }

    /// `resolve_shell_cwd`/`resolve_shell_program` require a shell dispatch's
    /// `cwd` (and any relative, `/`-containing `program`) to resolve inside
    /// [`workspace_root`] — this test binary's `std::env::current_dir()`,
    /// i.e. the crate directory `cargo test` runs from. Ordinary
    /// `tempfile::tempdir()` (under `/tmp`) is OUTSIDE that root, so shell
    /// tests need a tempdir created INSIDE it instead.
    fn workspace_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::env::current_dir().unwrap())
            .expect("creating a tempdir under the test binary's own cwd")
    }

    #[test]
    fn task_params_for_read_builds_fs_read_with_a_real_canonical_path() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "existing.txt");
        std::fs::write(&path, b"hello").unwrap();

        let (params, extras) =
            task_params_for(TaskKind::Read, &serde_json::json!({ "path": path_str })).unwrap();
        assert!(extras.shell_cwd.is_none());
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

        let (params, _extras) =
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
        let (params, _extras) = task_params_for(
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

        let (params, _extras) = task_params_for(
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

        let (params, _extras) = task_params_for(
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
    fn task_params_for_shell_resolves_a_bare_program_via_path_and_returns_the_canonical_cwd() {
        let dir = workspace_temp_dir();
        let cwd_str = dir.path().to_string_lossy().to_string();

        // "true" is a bare name — resolved via the daemon's own PATH
        // (ruling W1-R56), never against `cwd`, and the canonical result is
        // NOT required to be inside the workspace root (system binaries
        // live outside it).
        let (params, extras) = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({ "program": "true", "argv": ["-x"], "cwd": cwd_str }),
        )
        .unwrap();
        match params {
            TaskParams::Shell(cmd) => {
                assert!(
                    Path::new(&cmd.program).is_absolute(),
                    "the resolved program must be an absolute, canonical path, got {:?}",
                    cmd.program
                );
                assert!(cmd.program.ends_with("/true"));
                assert_eq!(cmd.argv, vec!["-x".to_string()]);
            }
            other => panic!("expected TaskParams::Shell, got {other:?}"),
        }
        assert_eq!(
            extras.shell_cwd.as_deref(),
            Some(dir.path().canonicalize().unwrap().as_path()),
            "the resolved, canonical cwd must be returned for execute_builtin to reuse verbatim"
        );
    }

    #[test]
    fn task_params_for_shell_cwd_outside_the_workspace_root_is_rejected() {
        // fix round A, finding F2 / ruling W1-R58: a cwd escaping the
        // workspace root (here, the real system /tmp — never inside this
        // test binary's own cwd) must be rejected before admission, not
        // silently accepted.
        let err = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({ "program": "true", "argv": [], "cwd": "/tmp" }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolDispatchError::ShellCwdRejected(_)),
            "expected ShellCwdRejected, got {err:?}"
        );
    }

    #[test]
    fn task_params_for_shell_relative_program_escaping_the_workspace_root_is_rejected() {
        // The F2 vector itself: a relative, `/`-containing program name
        // whose resolution against `cwd` would land outside the workspace
        // root must be refused, not silently admitted with a
        // policy-invisible cwd deciding which binary that name means.
        // `workspace_temp_dir()` creates `cwd` one level directly under
        // `workspace_root()`, so `../..` from `cwd` lands on
        // `workspace_root`'s own parent — a real, existing directory
        // (`cargo test`'s cwd always has one) that is definitely NOT inside
        // `workspace_root`.
        let cwd = workspace_temp_dir();

        let err = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": "../..",
                "argv": [],
                "cwd": cwd.path().to_string_lossy(),
            }),
        )
        .unwrap_err();
        assert!(
            matches!(err, ToolDispatchError::ShellProgramRejected(_)),
            "expected ShellProgramRejected, got {err:?}"
        );
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
        let (params, extras) = task_params_for(TaskKind::Read, &input).unwrap();
        let parts = execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].text, "hello world");
    }

    #[tokio::test]
    async fn execute_builtin_write_creates_the_file_with_the_given_contents() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "new.txt");

        let input = serde_json::json!({ "path": path_str, "contents": "hi there" });
        let (params, extras) = task_params_for(TaskKind::Write, &input).unwrap();
        execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hi there");
    }

    #[tokio::test]
    async fn execute_builtin_edit_replaces_the_single_match() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "edit.txt");
        std::fs::write(&path, "hello world").unwrap();

        let input = serde_json::json!({ "path": path_str, "find": "world", "replace": "there" });
        let (params, extras) = task_params_for(TaskKind::Edit, &input).unwrap();
        execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello there");
    }

    #[tokio::test]
    async fn execute_builtin_edit_fails_closed_on_an_ambiguous_match() {
        let dir = tempfile::tempdir().unwrap();
        let (path, path_str) = round_trip_path(dir.path(), "ambiguous.txt");
        std::fs::write(&path, "a a a").unwrap();

        let input = serde_json::json!({ "path": path_str, "find": "a", "replace": "b" });
        let (params, extras) = task_params_for(TaskKind::Edit, &input).unwrap();
        let err = execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap_err();
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
        let (params, extras) = task_params_for(TaskKind::Find, &input).unwrap();
        let parts = execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].text.ends_with("a.rs"));
    }

    #[tokio::test]
    async fn execute_builtin_shell_captures_real_stdout_via_the_cancellable_bounded_path() {
        let dir = workspace_temp_dir();
        let cwd_str = dir.path().to_string_lossy().to_string();

        let input = serde_json::json!({
            "program": "echo",
            "argv": ["hello-from-shell"],
            "cwd": cwd_str,
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();
        let parts = execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].text.contains("hello-from-shell"));
        assert!(parts[0].text.contains("exit_code=Some(0)"));
    }

    #[tokio::test]
    async fn execute_builtin_shell_times_out_a_runaway_process_and_confirms_cancellation() {
        // fix round A, finding F6: a process that never exits on its own
        // must be bounded, not left running forever. Uses a real, short
        // `SHELL_TIMEOUT` override via the lower-level `run_shell_dispatch`
        // directly (bypassing the module's 120s production constant, which
        // this test cannot wait out) — this is the same function
        // `execute_builtin`'s Shell arm calls.
        let dir = workspace_temp_dir();
        let env = shell_env_allowlist();

        let result = run_shell_dispatch(
            "sleep",
            &["30".to_string()],
            dir.path(),
            &env,
            Duration::from_millis(200),
            None,
        )
        .await;

        assert!(
            matches!(result, Err(ToolDispatchError::ShellCancelled(_))),
            "a runaway process must be cancelled and reported, got {result:?}"
        );
    }

    #[tokio::test]
    async fn execute_builtin_shell_cancels_when_the_session_leaves_running() {
        // The other half of F6: the session's own cancellation signal must
        // be enough to cancel a running shell call even well before the
        // wall-clock timeout.
        let dir = workspace_temp_dir();
        let env = shell_env_allowlist();
        let (tx, rx) = watch::channel(SessionState::Running);

        // Sends the cancellation shortly after the shell call starts —
        // spawned separately so it runs concurrently with the `.await`
        // below (which borrows `dir`/`env`, so `run_shell_dispatch` itself
        // is awaited directly here rather than spawned as its own task).
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            tx.send(SessionState::Cancelling).unwrap();
        });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            run_shell_dispatch(
                "sleep",
                &["30".to_string()],
                dir.path(),
                &env,
                Duration::from_secs(30),
                Some(rx),
            ),
        )
        .await
        .expect("run_shell_dispatch must return promptly once cancelled");

        sender.await.expect("sender task must not panic");
        assert!(
            matches!(result, Err(ToolDispatchError::ShellCancelled(_))),
            "session cancellation must cancel the in-flight shell call, got {result:?}"
        );
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

        let (params, extras) = task_params_for(
            TaskKind::Read,
            &serde_json::json!({ "path": admitted_path_str }),
        )
        .unwrap();
        // A hostile/racy `input` naming a different path than what was
        // admitted — execution must ignore it entirely for path purposes.
        let mismatched_input = serde_json::json!({ "path": decoy_path_str });

        let parts = execute_builtin(&params, &extras, &mismatched_input, None)
            .await
            .unwrap();
        assert_eq!(
            parts[0].text, "admitted contents",
            "execute_builtin must read the admitted canonical path, never a path re-parsed from \
             `input`"
        );
    }

    #[tokio::test]
    async fn execute_builtin_shell_uses_the_already_admitted_canonical_cwd_and_program() {
        // The same TOCTOU guard, for the shell arm specifically: `extras`
        // carries the admitted cwd, and `params.program` already carries
        // the admitted canonical program — a mismatched `input` must not
        // change either.
        let dir = workspace_temp_dir();
        let input = serde_json::json!({
            "program": "true",
            "argv": [],
            "cwd": dir.path().to_string_lossy(),
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();

        let decoy_input = serde_json::json!({
            "program": "false",
            "argv": [],
            "cwd": "/definitely/does/not/exist",
        });

        let parts = execute_builtin(&params, &extras, &decoy_input, None)
            .await
            .unwrap();
        assert!(
            parts[0].text.contains("exit_code=Some(0)"),
            "must run the admitted `true`, not the decoy input's `false`, got {:?}",
            parts[0].text
        );
    }

    #[tokio::test]
    async fn execute_builtin_unsupported_params_is_a_named_error_not_a_panic() {
        let params = TaskParams::Http {
            method: roundhouse_policy::Method::Get,
            url: "https://example.com".into(),
            body_len: 0,
        };
        let err = execute_builtin(
            &params,
            &ResolvedExtras::default(),
            &serde_json::json!({}),
            None,
        )
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
    /// grammar to parse and — since dispatch never invokes a shell
    /// interpreter — no interpreter for an `argv` element to be
    /// reinterpreted by.)
    #[test]
    fn a_fully_qualified_sealed_program_path_is_still_denied_by_the_sealed_floor() {
        // Hermetic on purpose: a dummy file named `sudo`, resolved via a
        // relative (`./sudo`) program name inside the workspace root, so
        // this test never depends on a real `/usr/bin/sudo` existing on the
        // machine running it. `sealed_program`'s basename check matches on
        // the FILE NAME regardless of where it lives, which is exactly the
        // property under test.
        let dir = workspace_temp_dir();
        std::fs::write(dir.path().join("sudo"), "not a real binary").unwrap();

        let (params, _extras) = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": "./sudo",
                "argv": ["-l"],
                "cwd": dir.path().to_string_lossy(),
            }),
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
