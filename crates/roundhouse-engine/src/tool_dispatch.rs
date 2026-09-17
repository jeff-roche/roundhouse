//! Maps one resolved built-in [`crate::tool_catalog::ToolTarget::Builtin`]
//! tool call — the five that name a `roundhouse-tools` executor, never
//! `TaskKind::Agent`, which `agent_loop` routes to
//! [`crate::tools::agent_spawn_tool`] instead —
//! onto `roundhouse-policy`'s `TaskParams` (what
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
//! itself** (component-wise `starts_with` against the canonicalized root,
//! in `roundhouse_tools::find_files` — every match must resolve inside
//! it).
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
//! **Honesty caveat (fix round B, finding I3 / ruling W1-R68), so this
//! containment isn't over-claimed: `argv` is never validated as paths.**
//! `cat ../../../etc/shadow` is unaffected by the `cwd` gate in ANY
//! configuration — the gate only ever inspects `cwd`/`program` themselves,
//! never what a resolved, policy-admitted program is then told to operate
//! on via its arguments. The `cwd` gate closes F2's specific "which binary
//! runs" vector, not "what that binary can touch." Real per-argument path
//! containment would need policy visibility into shell arguments, out of
//! this task's scope.
//!
//! Model-facing shell execution runs through the session's `Isolate::spawn`
//! after admission. Filesystem helpers remain in-process because they do not
//! create child processes; their path canonicalization and policy checks stay
//! in this dispatch bridge.
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
//! already flags for the MCP arm's `StdioMcpTransport::spawn` stdout
//! reader. Pre-existing in
//! `roundhouse-tools` (no size cap on any of these signatures); this task
//! does not add one — noted here so it is not silently narrowed to "only
//! an MCP problem."

use crate::session_actor::TaskIsolator;
use roundhouse_core::{Delta, Progress, SessionId, SessionState, TaskId, TaskKind, TaskRunner};
use roundhouse_policy::{FsOp, ParsedCommand, TaskParams};
use roundhouse_provider::ToolResultPart;
use roundhouse_sandbox::{Child, CommandSpec, IsolationError};
use roundhouse_store::EventWriter;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// Wall-clock bound on one dispatched `shell` call from the chat path
/// (`agent_loop::dispatch_builtin`) (fix round A, finding F6). Not ruled on
/// explicitly — a judgment call, recorded here so it is easy to find and
/// reconsider: long enough for an ordinary build/test command, short enough
/// that a hung or runaway process doesn't tie up a dispatch turn
/// indefinitely. `max_turns`/turn-level timeouts remain the caller's
/// problem; this is strictly the single-call bound `spawn_cancellable` needs
/// to be reachable through at all.
///
/// Phase 8 Task 25.4 Task 3: [`execute_builtin`] no longer hardcodes this —
/// it now takes a `timeout` parameter, and this constant is only the value
/// `dispatch_builtin` passes explicitly. The workflow path
/// (`workflow_dispatch::dispatch_tool_for_workflow`) passes the run's real
/// `PendingWork.step_timeout` instead, never this constant.
pub(crate) const SHELL_TIMEOUT: Duration = Duration::from_secs(120);

/// Grace period between SIGTERM and SIGKILL escalation when a dispatched
/// shell call is cancelled (timeout or session cancellation) — passed
/// straight through to `roundhouse_tools::cancel_running_shell`.
#[cfg(test)]
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
    /// (`Read`/`Write`/`Edit`/`Find`/`Shell`).
    ///
    /// **`TaskKind::Agent` reaches this only by mistake, and that is now a
    /// live possibility rather than a hypothetical** (Phase 8, L5):
    /// `tool_catalog::resolve_tool_target` resolves `"agent"` to
    /// `ToolTarget::Builtin(TaskKind::Agent)`, and it is `agent_loop`'s own
    /// match — one arm above the five real executors — that routes it to
    /// `tools::agent_spawn_tool` instead of here. A regression that deletes
    /// that arm lands on this variant rather than dispatching a spawn as if
    /// it were a filesystem call, which is exactly why this stays a named,
    /// fail-closed error instead of an unreachable assumption.
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
    /// through `task_params_for`'s real output today (a real
    /// `TaskParams::Agent` is built by `tools::agent_spawn_tool`, which never
    /// calls into this module), but the match must still be exhaustive rather
    /// than assume that invariant holds forever.
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
    /// A filesystem target resolved outside the session workspace.
    #[error("filesystem path rejected: {0}")]
    WorkspacePathRejected(String),
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
    /// A dispatched shell call exceeded its wall-clock `timeout` (fix round
    /// A, finding F6). The process group has already been signalled
    /// (SIGTERM, escalating to SIGKILL) via
    /// `roundhouse_tools::cancel_running_shell` by the time this is
    /// returned.
    ///
    /// **Distinct from [`Self::ShellSessionCancelled`]**, added by Phase 8
    /// Task 25.4 Task 4 so a caller can tell "this step ran out of its own
    /// declared time budget" (an ordinary failure) apart from "§8.13's
    /// cooperative cancel was observed" (`WorkStatus::Cancelled`, not
    /// `Failed`, at the workflow-dispatch layer —
    /// `roundhouse_engine::workflow_dispatch::dispatch_tool_for_workflow`'s
    /// own doc comment has the full mapping). Before Task 4 the two shared
    /// one variant; splitting them is the minimal change that lets a caller
    /// distinguish the two without parsing this `Display` string.
    #[error("shell command cancelled: {0}")]
    ShellCancelled(String),
    /// A dispatched shell call was cancelled because the owning session left
    /// `Created`/`Running` while it was in flight (fix round A, finding F6;
    /// split out from [`Self::ShellCancelled`] by Phase 8 Task 25.4 Task 4 —
    /// see that variant's own doc comment for why). The process group has
    /// already been signalled (SIGTERM, escalating to SIGKILL) via
    /// `roundhouse_tools::cancel_running_shell` by the time this is
    /// returned.
    #[error("shell command cancelled by session state change: {0}")]
    ShellSessionCancelled(String),
    /// The real `roundhouse-tools` executor itself failed (I/O error,
    /// ambiguous edit match, glob error, etc.).
    #[error("{0}")]
    Tool(#[from] roundhouse_tools::ToolError),
    /// The session sandbox could not start or control the admitted child.
    #[error("isolated tool execution failed: {0}")]
    Isolation(String),
}

impl ToolDispatchError {
    /// The two strings a refusal raised by [`task_params_for`] — i.e. one
    /// raised BEFORE `SessionActor::admit_task` ever runs — contributes to
    /// the session: the `TaskError.category` recorded in the append-only
    /// log, and the message the model reads back in its `ToolResultPart`.
    ///
    /// **Never `self.to_string()` (ruling W1-R131).** Every variant's
    /// `Display` above is written for a daemon operator reading a log, and
    /// several of them interpolate values that must not cross back to the
    /// model:
    ///
    /// - `ShellCwdRejected`/`ShellProgramRejected` embed a canonicalized
    ///   host path and the daemon's own workspace root — the root is not
    ///   named anywhere in the system prompt, so returning it discloses the
    ///   daemon's absolute working directory to whoever controls the
    ///   provider response (in practice a prompt-injected model, since
    ///   untrusted tool output is folded into `request.messages` on the
    ///   next turn).
    /// - Both also embed `std::io::Error`'s `Display` for an
    ///   attacker-chosen absolute path. ENOENT, EACCES and ENOTDIR render
    ///   differently, which turns a rejected `shell` call into a
    ///   **filesystem existence-and-permission oracle over the whole
    ///   host** — and, because these checks run before admission, one the
    ///   fail-closed policy default never gets to see.
    ///
    /// So the rule this function exists to enforce, stated for whoever adds
    /// the next variant: **the returned message must be built only from
    /// this module's own string literals and `&'static str` fields — never
    /// from a path, an `io::Error`, or any value derived from the model's
    /// own `input`.** Collapsing every reason within one variant to a
    /// single sentence is deliberate: telling the model *which* argument to
    /// fix (`cwd` vs `program`) is useful and discloses nothing, whereas
    /// telling it *why* within that argument is the oracle. The detailed
    /// `Display` is not lost — `dispatch_builtin` logs it via `tracing`,
    /// and the refusal's `TaskCreated` carries the model's verbatim
    /// `input`, so an operator can still see exactly what was attempted.
    pub fn unadmitted_refusal(&self) -> (&'static str, String) {
        match self {
            Self::BadArgs { tool, field } => (
                "bad_tool_arguments",
                // `tool`/`field` are `&'static str` literals from this
                // module's own call sites, never model-supplied.
                format!("the `{tool}` tool call is missing or has an invalid `{field}` argument"),
            ),
            Self::UnsupportedKind { kind } => (
                "unsupported_tool_kind",
                format!("dispatching TaskKind::{kind:?} through the builtin tool catalog is not supported"),
            ),
            Self::ShellCwdRejected(_) => (
                "shell_cwd_rejected",
                "shell cwd rejected: the requested working directory is not an accessible \
                 directory inside this session's workspace"
                    .to_string(),
            ),
            Self::ShellProgramRejected(_) => (
                "shell_program_rejected",
                "shell program rejected: the requested program does not resolve to an \
                 executable file inside this session's workspace"
                    .to_string(),
            ),
            Self::WorkspaceRootUnavailable(_) => (
                "workspace_root_unavailable",
                "shell dispatch is unavailable: this session's workspace containment boundary \
                 could not be established"
                    .to_string(),
            ),
            Self::WorkspacePathRejected(_) => (
                "workspace_path_rejected",
                "the tool call's filesystem path is outside this session's workspace".to_string(),
            ),
            // The remaining variants are not reachable from
            // `task_params_for` today (they are raised by
            // [`execute_builtin`], on the far side of admission). They are
            // still given a rendering here rather than a catch-all `_` arm,
            // so that adding a variant — or making one of these reachable
            // before admission — is a compile error that forces the same
            // disclosure question to be answered again.
            Self::UnresolvedPath(_) => (
                "unresolved_path",
                "the tool call's path could not be resolved".to_string(),
            ),
            Self::UnsupportedParams(_) => (
                "unsupported_tool_params",
                "this tool call's parameter shape is not dispatchable through the builtin tool \
                 catalog"
                    .to_string(),
            ),
            Self::MissingResolvedCwd => (
                "missing_resolved_cwd",
                "internal error: shell dispatch is missing its pre-resolved, already-admitted \
                 working directory"
                    .to_string(),
            ),
            Self::ShellCancelled(_) => (
                "shell_cancelled",
                "the shell command was cancelled before it completed".to_string(),
            ),
            Self::ShellSessionCancelled(_) => (
                "shell_session_cancelled",
                "the shell command was cancelled before it completed".to_string(),
            ),
            Self::Tool(_) => (
                "tool_error",
                "the tool call failed".to_string(),
            ),
            Self::Isolation(_) => (
                "isolation_error",
                "the tool could not be started in its required isolation boundary".to_string(),
            ),
        }
    }
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

fn fs_params(op: FsOp, raw_path: &str, workspace_root: &Path) -> TaskParams {
    let path = resolve_workspace_path(raw_path, workspace_root);
    let canonical = resolve_canonical(&path);
    TaskParams::Fs {
        op,
        path,
        canonical,
    }
}

fn fs_params_for_scope(
    op: FsOp,
    raw_path: &str,
    workspace_root: &Path,
    enforce_workspace: bool,
) -> Result<TaskParams, ToolDispatchError> {
    let params = fs_params(op, raw_path, workspace_root);
    if !enforce_workspace {
        return Ok(params);
    }
    let inside = match &params {
        TaskParams::Fs {
            canonical: Ok(path),
            ..
        } => path.starts_with(workspace_root),
        TaskParams::Fs {
            canonical: Err(_), ..
        } => false,
        _ => false,
    };
    if !inside {
        return Err(ToolDispatchError::WorkspacePathRejected(
            "resolved filesystem path is outside the session workspace".to_string(),
        ));
    }
    Ok(params)
}

/// The legacy public [`task_params_for`] API uses the process current
/// directory as its compatibility root. Production dispatch always calls
/// [`task_params_for_in_workspace`] with the canonical root resolved from the
/// daemon's workspace registry; no client-provided path or daemon cwd is used
/// for a live session.
fn workspace_root() -> Result<PathBuf, ToolDispatchError> {
    let root = std::env::current_dir()
        .map_err(|e| ToolDispatchError::WorkspaceRootUnavailable(e.to_string()))?;
    reject_root_of_slash(root)
}

/// The `/`-rejection itself, split out from [`workspace_root`] so it's
/// directly unit-testable without mutating this process's real working
/// directory (which — being global, process-wide state — would race every
/// other concurrently-running test in this binary).
fn reject_root_of_slash(root: PathBuf) -> Result<PathBuf, ToolDispatchError> {
    if root == Path::new("/") {
        return Err(ToolDispatchError::WorkspaceRootUnavailable(
            "the workspace root is '/' — refusing to use it as the shell containment boundary, \
             since that collapses cwd/program containment to no boundary at all (fix round B, \
             ruling W1-R68)"
                .to_string(),
        ));
    }
    Ok(root)
}

/// Resolves and validates the model-supplied `cwd`: canonicalized (a real,
/// symlink-followed, already-existing directory — required for
/// `Command::current_dir` to succeed anyway) and required to be
/// component-wise inside [`workspace_root`] — the same
/// canonicalize-then-`starts_with` shape `roundhouse_tools::find_files`
/// already uses. **Rejection, not a companion `Fs` admission** (ruling
/// W1-R58 explicitly prefers this over the alternative of running `cwd`
/// through its own `TaskParams::Fs` admission): a `cwd` that fails this
/// check never reaches `admit_task` at all — `task_params_for_in_workspace` returns
/// `Err` before building any `TaskParams::Shell`.
fn resolve_shell_cwd(raw_cwd: &str, root: &Path) -> Result<PathBuf, ToolDispatchError> {
    let candidate = resolve_workspace_path(raw_cwd, root);
    let canonical = candidate.canonicalize().map_err(|e| {
        ToolDispatchError::ShellCwdRejected(format!("cwd {raw_cwd:?} not accessible: {e}"))
    })?;
    if canonical.to_str().is_none() {
        return Err(ToolDispatchError::ShellCwdRejected(
            "cwd resolves to a non-UTF-8 path".to_string(),
        ));
    }
    if !canonical.starts_with(root) {
        return Err(ToolDispatchError::ShellCwdRejected(format!(
            "cwd {canonical:?} is outside the workspace root {root:?}"
        )));
    }
    Ok(canonical)
}

/// Resolves the model-supplied `program` to the absolute binary that will
/// actually run (fix round A, finding F2 / rulings W1-R56/W1-R57; corrected
/// in fix round B, finding I2 / ruling W1-R67; the bare-name branch brought
/// into agreement with the rest in fix round C1, ruling W1-R71/MUST 1) —
/// this value, not the raw model string, is what [`task_params_for`] puts
/// into `ParsedCommand.program`, so policy judges the real binary rather
/// than a string the model's own choice of `cwd` could silently redirect
/// elsewhere.
///
/// **The precise, single rule (fix round C1, ruling W1-R75): in BOTH
/// branches below, `ParsedCommand.program` is the canonicalized DIRECTORY
/// containing the binary, joined with the LITERAL, model/PATH-supplied
/// final path component — never a fully symlink-resolved path.** CF-16's
/// own ledger entry previously called this a "canonical absolute path,"
/// which is imprecise enough to mislead an operator. Concretely: an
/// operator running `readlink -f` (or any other full-resolution tool) on
/// the binary they intend to allow/deny will NOT, in general, get a
/// string that matches. Measured on this repo's own dev environment:
/// `/bin/sh` resolves to `/usr/bin/bash`, `python3` to
/// `/usr/bin/python3.14`, `awk` to `/usr/bin/gawk` — yet the value this
/// function returns for `program: "sh"` or `program: "/bin/sh"` is
/// `/usr/bin/sh` (directory resolved, name preserved), not
/// `/usr/bin/bash`. Operator-facing docs must state THIS rule, not the
/// "canonical absolute path" one.
///
/// Splits on shape (ruling W1-R56): `spawn_cancellable`'s `env_clear()`
/// (fix round A, finding F1) removes `PATH` from the CHILD's own
/// environment, so a bare name is a PATH lookup — not `cwd`-relative — and
/// resolving it against `cwd` would simply fail to find anything.
/// - **Contains `/`:** joined against `canonical_cwd` (an already-absolute
///   `program` replaces the join entirely, matching `Path::join`'s own
///   semantics), then resolved in TWO different ways for two different
///   purposes (ruling W1-R67 — do not collapse these back into one):
///   - **Containment check:** the join is FULLY canonicalized (every
///     symlink resolved, including the final component) and required to be
///     a regular file (M4). If the original string was relative
///     (`./gradlew`, `node_modules/.bin/foo`), that fully-resolved target
///     is additionally required to stay inside the workspace root — this
///     is exactly the vector F2 proved: the model's choice of `cwd`
///     selecting which binary of a relative name actually runs. An
///     already-absolute original string (`/usr/bin/git`) is NOT confined to
///     the workspace root: its resolution never depended on `cwd` in the
///     first place, so `cwd` gives the model no leverage over which binary
///     a fully-qualified path names, and confining it would only break
///     legitimate calls to system binaries with no corresponding security
///     benefit. (CF-16 itself only anticipates *relative* program
///     allow-rules breaking, not absolute ones — consistent with this
///     reading. Not spelled out verbatim in W1-R56/57's original text; a
///     deliberate, documented narrowing.)
///   - **The value actually returned:** the DIRECTORY portion of the join,
///     canonicalized, with the ORIGINAL final path component preserved
///     VERBATIM (never the fully-resolved target above). Canonicalizing the
///     directory is what defeats a model-controlled `cwd`; preserving the
///     final component is what keeps `is_interpreter`
///     (`roundhouse_policy::shell::interpreter::is_interpreter`) and
///     `sealed_program`'s basename
///     semantics intact — both match on basename, and resolving a symlinked
///     final component (`python3` -> `/usr/bin/python3.14`) would silently
///     defeat both once an operator followed CF-16 and rewrote a rule to
///     the canonical path (finding I2).
/// - **Bare name (no `/`):** resolved via the **daemon's own** `PATH`
///   (deterministic, never model-controlled) to an absolute path — mirrors
///   `roundhouse-mcp/src/transport/stdio.rs`'s `resolve_command` shape for
///   the identical reason (a hash-pin-style guarantee that the string
///   judged is the binary that runs), reimplemented here rather than
///   reached across the crate boundary (that function is private and
///   `roundhouse-mcp` is out of this lane's charter for anything beyond the
///   narrow, ruled `roundhouse-tools`/`roundhouse-store` additions). This
///   branch never needed symlink resolution to defend against F2's
///   cwd-smuggling vector — a PATH lookup is under the daemon's own
///   control, not the model's. **But it still needs the identical
///   directory/final-component split as the `/`-containing branch above**
///   (fix round C1, finding from ruling W1-R71/MUST 1 — round B fixed only
///   the `/`-containing branch and left this one fully canonicalizing,
///   which both (a) defeats `is_interpreter`/`sealed_program`'s basename
///   matching exactly as I2 described, measured post-round-B:
///   `python3` -> `/usr/bin/python3.14`, `awk` -> `/usr/bin/gawk`, and (b)
///   is strictly worse than round A: the two branches now produce
///   DIFFERENT canonical strings for the identical binary, so
///   `Predicate::Shell`'s exact-string match (its `cmd.program !=
///   *program` compare in `roundhouse-policy`'s `engine.rs`) lets the
///   model choose which string policy sees by deciding whether to spell
///   the program with a `/` — an operator's `Deny /usr/bin/python3` is
///   evaded by sending `program: "python3"`). See
///   [`resolve_bare_program_on_path`].
fn resolve_shell_program(
    raw_program: &str,
    canonical_cwd: &Path,
    root: &Path,
) -> Result<PathBuf, ToolDispatchError> {
    if raw_program.contains('/') {
        let was_absolute = Path::new(raw_program).is_absolute();
        let joined = canonical_cwd.join(raw_program);

        // Fully resolve — following every symlink, including the final
        // component — ONLY for the containment check below (fix round B,
        // ruling W1-R67): a program whose ultimate target escapes the
        // workspace root must still be rejected (e.g. `./shim` symlinked to
        // something outside root) — that property must not be lost.
        let fully_resolved = joined.canonicalize().map_err(|e| {
            ToolDispatchError::ShellProgramRejected(format!(
                "program {raw_program:?} not accessible: {e}"
            ))
        })?;
        // M4 (ruling W1-R69): a directory (or anything else that isn't a
        // regular file) is never a valid program — `program="/"` must not
        // silently pass containment and then fail confusingly at exec.
        if !fully_resolved.is_file() {
            return Err(ToolDispatchError::ShellProgramRejected(format!(
                "program {raw_program:?} does not resolve to a regular file"
            )));
        }
        if !was_absolute && !fully_resolved.starts_with(root) {
            return Err(ToolDispatchError::ShellProgramRejected(format!(
                "resolved program {fully_resolved:?} is outside the workspace root {root:?}"
            )));
        }

        // **The value actually returned is deliberately NOT `fully_resolved`
        // above (fix round B, finding I2 / ruling W1-R67).** Canonicalizing
        // the FULL path — including the final component — resolves
        // symlinks, and both `is_interpreter` (`roundhouse-policy`'s
        // `shell::interpreter`) and `sealed_program` (`roundhouse-policy`'s
        // `sealed`) match on
        // BASENAME. Measured: `python3` canonicalizes to
        // `/usr/bin/python3.14` and `awk` to `/usr/bin/gawk` on a real
        // distro — `is_interpreter` on either canonical form is `false`.
        // Storing the fully-resolved path in `ParsedCommand.program` would
        // have meant that once an operator followed CF-16 and rewrote their
        // rule to the canonical path, `python3 -c '<anything>'` would be
        // admitted without `allow_interpreter` ever being set — a named
        // §6.3 security control silently losing coverage as a side effect
        // of the very fix meant to close a different hole. The same
        // mechanism would let a distro shipping `sudo -> sudo-rs` evade
        // `sealed_program`'s basename check identically.
        //
        // The fix: canonicalize only the DIRECTORY portion — this is what
        // actually defeats a model-controlled `cwd` (F2's real mechanism
        // has nothing to do with the final path component) — and preserve
        // the ORIGINAL final path component verbatim, so basename-matching
        // security controls keep seeing the name the model/operator
        // actually used.
        let file_name = joined.file_name().ok_or_else(|| {
            ToolDispatchError::ShellProgramRejected(format!(
                "program {raw_program:?} has no file name component"
            ))
        })?;
        let parent = joined
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let canonical_parent = parent.canonicalize().map_err(|e| {
            ToolDispatchError::ShellProgramRejected(format!(
                "cannot resolve the directory containing program {raw_program:?}: {e}"
            ))
        })?;
        Ok(canonical_parent.join(file_name))
    } else {
        let path_var = std::env::var_os("PATH").ok_or_else(|| {
            ToolDispatchError::ShellProgramRejected(
                "PATH is not set in the daemon's own environment".to_string(),
            )
        })?;
        resolve_bare_program_on_path(raw_program, &path_var)
    }
}

fn resolve_workspace_path(raw_path: &str, workspace_root: &Path) -> PathBuf {
    let path = Path::new(raw_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    }
}

/// The bare-name half of [`resolve_shell_program`], split out so tests can
/// inject a controlled `PATH` value directly rather than mutating the
/// process-global `PATH` env var — `std::env::set_var` on `PATH` would race
/// every other test in this binary run in parallel (fix round C1, ruling
/// W1-R71/MUST 1's own guidance).
///
/// Walks `path_var` for the first entry containing a regular file named
/// `raw_program`, exactly as before — but the value returned is now, like
/// the `/`-containing branch, the PATH **directory** canonicalized with the
/// **literal** `raw_program` name appended, never the fully-resolved
/// target. A distro shipping `python3 -> python3.14` must not silently
/// launder a bare `python3` invocation past `is_interpreter`/
/// `sealed_program`'s basename matching, and the two branches must agree on
/// one canonical string per binary so an operator's exact-match
/// `Predicate::Shell` rule can't be dodged by a model choosing which
/// spelling (`python3` vs `./python3`) to send.
fn resolve_bare_program_on_path(
    raw_program: &str,
    path_var: &std::ffi::OsStr,
) -> Result<PathBuf, ToolDispatchError> {
    for dir in std::env::split_paths(path_var) {
        let candidate = dir.join(raw_program);
        if candidate.is_file() {
            let canonical_dir = dir.canonicalize().map_err(|e| {
                ToolDispatchError::ShellProgramRejected(format!(
                    "cannot resolve the PATH directory {dir:?} containing program \
                     {raw_program:?}: {e}"
                ))
            })?;
            let resolved = canonical_dir.join(raw_program);
            if resolved.to_str().is_none() {
                return Err(ToolDispatchError::ShellProgramRejected(
                    "program resolves to a non-UTF-8 path".to_string(),
                ));
            }
            return Ok(resolved);
        }
    }
    Err(ToolDispatchError::ShellProgramRejected(format!(
        "program {raw_program:?} not found on the daemon's PATH"
    )))
}

/// The names of environment variables re-added to a dispatched shell's
/// otherwise `env_clear()`'d environment (fix round A, finding F1; named
/// const per fix round B, ruling W1-R69's allowlist-hardening item).
///
/// **The exclusion rule this list must never violate, stated so a future
/// widening has something concrete to check itself against:** never add a
/// name matching [`crate::session_actor::SECRET_ENV_NAME_SUFFIXES`]
/// (`_KEY`/`_TOKEN`/`_SECRET`/`_PASSWORD`, case-insensitive), and never add
/// a name whose live VALUE `session_actor::live_secret_values` collects for
/// this session — [`shell_env_allowlist`] enforces the former with a
/// `debug_assert!` so a careless future edit fails loudly in every test run
/// rather than silently.
///
/// PATH-only **will** be widened eventually (a real-world consequence, not
/// hypothetical: `git` cannot read `~/.gitconfig` and `cargo`/`npm` fail
/// outright without `HOME`), and the risk named explicitly is that the
/// inevitable next addition becomes something as broad as
/// `envs(std::env::vars())` instead of one more named, reviewed entry.
const SHELL_ENV_ALLOWLIST_NAMES: &[&str] = &["PATH"];

/// The explicit, `env_clear()`-safe environment allowlist for a dispatched
/// shell call — copies the shape
/// `roundhouse-mcp`'s `transport::stdio::build_command` already
/// uses ("explicit allowlist only, never inherits the daemon's own env").
/// Built from [`SHELL_ENV_ALLOWLIST_NAMES`] — see that const's doc comment
/// for the exclusion rule this function asserts against on every call.
fn shell_env_allowlist() -> Vec<(String, String)> {
    let mut env = Vec::new();
    for name in SHELL_ENV_ALLOWLIST_NAMES {
        debug_assert!(
            !crate::session_actor::is_secret_env_var_name(name),
            "SHELL_ENV_ALLOWLIST_NAMES contains {name:?}, which looks like a declared-secret \
             env var name — see that const's own doc comment for the exclusion rule this \
             violates"
        );
        if let Some(value) = std::env::var_os(name) {
            env.push(((*name).to_string(), value.to_string_lossy().to_string()));
        }
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
    let root = workspace_root()?;
    task_params_for_root(kind, input, &root, false)
}

/// Builds dispatch parameters relative to the session's resolved workspace
/// root. Relative filesystem and shell paths never consult process cwd.
pub fn task_params_for_in_workspace(
    kind: TaskKind,
    input: &serde_json::Value,
    workspace_root: &Path,
) -> Result<(TaskParams, ResolvedExtras), ToolDispatchError> {
    let workspace_root = reject_root_of_slash(workspace_root.to_path_buf())?;
    task_params_for_root(kind, input, &workspace_root, true)
}

fn task_params_for_root(
    kind: TaskKind,
    input: &serde_json::Value,
    workspace_root: &Path,
    enforce_workspace: bool,
) -> Result<(TaskParams, ResolvedExtras), ToolDispatchError> {
    match kind {
        TaskKind::Read => Ok((
            fs_params_for_scope(
                FsOp::Read,
                &str_field(input, "read", "path")?,
                workspace_root,
                enforce_workspace,
            )?,
            ResolvedExtras::default(),
        )),
        TaskKind::Write => Ok((
            fs_params_for_scope(
                FsOp::Write,
                &str_field(input, "write", "path")?,
                workspace_root,
                enforce_workspace,
            )?,
            ResolvedExtras::default(),
        )),
        TaskKind::Edit => Ok((
            fs_params_for_scope(
                FsOp::Edit,
                &str_field(input, "edit", "path")?,
                workspace_root,
                enforce_workspace,
            )?,
            ResolvedExtras::default(),
        )),
        TaskKind::Find => Ok((
            fs_params_for_scope(
                FsOp::Find,
                &str_field(input, "find", "root")?,
                workspace_root,
                enforce_workspace,
            )?,
            ResolvedExtras::default(),
        )),
        TaskKind::Shell => {
            let raw_program = str_field(input, "shell", "program")?;
            let argv = argv_field(input, "shell")?;
            let raw_cwd = str_field(input, "shell", "cwd")?;
            let canonical_cwd = resolve_shell_cwd(&raw_cwd, workspace_root)?;
            let canonical_program =
                resolve_shell_program(&raw_program, &canonical_cwd, workspace_root)?;
            let program = canonical_program
                .to_str()
                .ok_or_else(|| {
                    ToolDispatchError::ShellProgramRejected(
                        "program resolves to a non-UTF-8 path".to_string(),
                    )
                })?
                .to_string();
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
/// `cancel`, when `Some`, is raced against `timeout` for the `Shell` arm
/// (fix round A, finding F6): if the owning session leaves
/// `Created`/`Running` while the child is in flight, it is cancelled the
/// same way a timeout is. `None` (used by every non-`Shell` call, and by
/// tests that don't care about session-cancellation) means the wall-clock
/// bound is still enforced, just without that extra signal.
///
/// `timeout` is the `Shell` arm's real wall-clock bound (Phase 8 Task 25.4
/// Task 3) — threaded into [`run_isolated_shell_dispatch`], which is what
/// makes an elapsed timeout a real process-group kill (SIGTERM escalating to
/// SIGKILL, confirmed) rather than merely dropping this future and orphaning
/// the child. Every caller passes a real value: `agent_loop::dispatch_builtin`
/// passes [`SHELL_TIMEOUT`] explicitly (its own behavior is unchanged — only
/// this function's signature grew a parameter); `dispatch_tool_for_workflow`
/// passes the run's real `PendingWork.step_timeout`. The four filesystem
/// arms ignore it entirely — they have no internal bound of their own, and
/// are instead covered by `DeliveryExecutor::execute_pending`'s outer
/// `tokio::time::timeout` safety net on the workflow path. `agent_loop`'s
/// chat path has no equivalent outer wrap for filesystem calls — pre-existing
/// and out of this task's scope, which is explicitly limited to
/// `execute_pending`.
///
/// Never call this before `params` has been admitted through
/// `SessionActor::admit_task` — this function performs no admission check
/// of its own.
#[allow(clippy::too_many_arguments)]
pub async fn execute_builtin(
    params: &TaskParams,
    extras: &ResolvedExtras,
    input: &serde_json::Value,
    cancel: Option<watch::Receiver<SessionState>>,
    pre_spawned: Option<Child>,
    isolator: &dyn TaskIsolator,
    timeout: Duration,
    delta_sink: Option<ShellDeltaSink>,
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
            let output = run_isolated_shell_dispatch(
                isolator,
                &cmd.program,
                &cmd.argv,
                cwd,
                &env,
                timeout,
                cancel,
                pre_spawned,
                delta_sink,
            )
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

pub(crate) fn isolated_shell_command(cmd: &ParsedCommand, cwd: &Path) -> CommandSpec {
    CommandSpec {
        program: cmd.program.clone(),
        argv: cmd.argv.clone(),
        cwd: Some(cwd.to_string_lossy().into_owned()),
        env: shell_env_allowlist(),
    }
}

/// Per-flush chunk-size trigger/cap for streamed shell stdout/stderr deltas
/// (Phase 8 Task 19 lane B, Task 8) — deliberately distinct from
/// `crate::delta_sink::FLUSH_SIZE_THRESHOLD` (2 KiB, sized for a provider's
/// text tokens): shell output arrives in much larger, bursty reads, so this
/// is sized to bound blob/event count rather than perceived latency. A
/// stream's buffer is offered to the splitter once it reaches this size —
/// the actual flushed length can be smaller (a redaction holdback) or is
/// capped at this size (never larger) by `flush_stream`'s own `max`.
const SHELL_FLUSH_CHUNK_BYTES: usize = 64 * 1024;

/// Cadence for the pump's time-based flush — matches
/// `crate::delta_sink::FLUSH_INTERVAL`'s 4Hz convention, so a slow trickle of
/// shell output (well under [`SHELL_FLUSH_CHUNK_BYTES`]) still reaches the
/// store promptly instead of waiting indefinitely for enough bytes to
/// accumulate.
const SHELL_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// The shared, in-flight byte budget bounding how much buffered-but-not-yet-
/// flushed shell output the delta channel may hold across BOTH streams
/// combined (Controller ruling) — a stalled or slow writer must not let this
/// grow without bound, since [`drain_to_end`] never awaits the pump/writer
/// (see that function's own doc comment). Over budget, a chunk is dropped
/// from the DELTA STREAM ONLY — never from the authoritative `ShellOutput`
/// buffer `drain_to_end` still assembles independently — and counted as lag
/// via [`DeltaChannel::lag`].
const SHELL_DELTA_BUDGET_BYTES: usize = 4 * 1024 * 1024;

/// Which shell stream a streamed [`Delta::Blob`] came from — selects the
/// blob's mime convention (01 §4.5: "shell output always goes to blobs").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellStream {
    Stdout,
    Stderr,
}

impl ShellStream {
    fn mime(self) -> &'static str {
        match self {
            ShellStream::Stdout => "application/vnd.roundhouse.stdout",
            ShellStream::Stderr => "application/vnd.roundhouse.stderr",
        }
    }
}

/// Notifies [`run_shell_delta_pump`] that it should attempt a time-based
/// flush of whatever is currently buffered for either stream, even if
/// neither has reached [`SHELL_FLUSH_CHUNK_BYTES`] yet. The production
/// implementation ([`IntervalFlushTicker`]) sleeps a fixed interval; a test
/// drives this deterministically instead (`ManualTicker`, in this module's
/// own test suite) — no wall-clock sleeps in a test (AGENTS.md /
/// `feedback_no_clock_timing_tests`).
#[async_trait::async_trait]
trait FlushTicker: Send {
    /// Resolves once it is time to attempt a flush. May resolve spuriously
    /// (an implementation is free to fire more often than strictly needed —
    /// `flush_stream` is a harmless no-op on an empty buffer); must never
    /// resolve for good (a ticker that stops ticking simply means future
    /// flushes wait on size/close triggers instead).
    async fn tick(&mut self);
}

/// The real, wall-clock-backed [`FlushTicker`] [`ShellDeltaSink::new`]
/// installs — mirrors `chat.rs`'s `SystemClock`/`MonotonicClock` split for
/// the identical reason: production always uses the real clock, and a test
/// substitutes a deterministic fake instead of sleeping.
struct IntervalFlushTicker {
    interval: tokio::time::Interval,
}

impl IntervalFlushTicker {
    fn new(period: Duration) -> Self {
        let mut interval = tokio::time::interval(period);
        // The first `tick()` call on a freshly-created `Interval` resolves
        // immediately (tokio's own documented behavior) — irrelevant here,
        // since an immediate first flush attempt on an empty buffer is a
        // harmless no-op in `flush_stream`. `Delay` (rather than the
        // default `Burst`) avoids a stalled pump "catching up" with a burst
        // of back-to-back ticks once it resumes.
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        IntervalFlushTicker { interval }
    }
}

#[async_trait::async_trait]
impl FlushTicker for IntervalFlushTicker {
    async fn tick(&mut self) {
        self.interval.tick().await;
    }
}

/// Everything [`run_shell_delta_pump`] needs to mint and persist real
/// `TaskDelta`/`TaskProgress` events for one dispatched `shell` call's
/// stdout/stderr — the writer, runner, session/task identity, blob root, and
/// flush cadence (Phase 8 Task 19 lane B, Task 8, plan 16). Constructed by
/// the caller that already holds these (a `SessionActor`, via its
/// `writer()`/`runner()`/`session_id()`/`state_dir()` accessors) and handed
/// to [`execute_builtin`]/[`run_isolated_shell_dispatch`] as
/// `Option<ShellDeltaSink>` — `None` (every existing call site, until Task 9
/// wires this up) preserves today's single-buffered-string behavior exactly.
pub struct ShellDeltaSink {
    writer: EventWriter,
    runner: &'static TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    state_dir: PathBuf,
    ticker: Box<dyn FlushTicker>,
}

impl ShellDeltaSink {
    /// Always installs the real, wall-clock [`IntervalFlushTicker`] — a test
    /// needing deterministic control over time-based flushes constructs this
    /// struct directly instead (its fields are private to this module, and
    /// this module's own `#[cfg(test)] mod tests` is a descendant of it).
    pub fn new(
        writer: EventWriter,
        runner: &'static TaskRunner,
        session_id: SessionId,
        task_id: TaskId,
        state_dir: PathBuf,
    ) -> Self {
        ShellDeltaSink {
            writer,
            runner,
            session_id,
            task_id,
            state_dir,
            ticker: Box::new(IntervalFlushTicker::new(SHELL_FLUSH_INTERVAL)),
        }
    }
}

/// Why a [`ShellChunk::Gap`] was sent — carried through to
/// [`emit_gap_progress`]'s message text (fix round 1 follow-up, finding 8's
/// note: a test must be able to pin down "exactly one cap-close discontinuity"
/// distinctly from an arbitrary, environment-dependent number of budget-drop
/// ones, which a single undifferentiated `Gap` variant cannot support).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GapReason {
    /// [`try_send_chunk`] dropped a chunk for being over the shared
    /// [`SHELL_DELTA_BUDGET_BYTES`] budget — can happen zero, one, or many
    /// times over a single stream's life, depending on how far the pump
    /// falls behind a fast producer.
    Budget,
    /// [`drain_to_end`] reached the [`MAX_SHELL_OUTPUT_BYTES`] cap — happens
    /// at most once per stream, always as that stream's last event before
    /// its channel closes.
    Cap,
}

impl std::fmt::Display for GapReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GapReason::Budget => write!(f, "budget"),
            GapReason::Cap => write!(f, "cap"),
        }
    }
}

/// One item on a [`DeltaChannel`] — either a genuine chunk of stream bytes,
/// or a discontinuity marker (Phase 8 Task 19 lane B, Task 8 fix round 1,
/// security finding I1): [`try_send_chunk`] sends [`Self::Gap`] whenever it
/// drops a chunk for being over the shared [`SHELL_DELTA_BUDGET_BYTES`]
/// budget, and [`drain_to_end`] sends it once more, immediately before
/// dropping its sender, the instant the [`MAX_SHELL_OUTPUT_BYTES`] cap is
/// reached. Either way it means "bytes existed here that will never reach
/// the pump" — see [`handle_stream_event`]'s `Gap` arm for why that must
/// never be treated the same as a clean, contiguous continuation.
enum ShellChunk {
    Data(Vec<u8>),
    Gap(GapReason),
}

/// The shared plumbing [`drain_to_end`] uses to forward a copy of each
/// chunk it reads to [`run_shell_delta_pump`], without ever awaiting it
/// (R1/R4: the drain must never await the writer, so a stalled pump/writer
/// can't deadlock a child's own pipes). `in_flight`/`lag` are each a SINGLE
/// `Arc<AtomicUsize>` shared across BOTH streams' channels — deliberately
/// one combined budget/lag pair, not one per stream (Controller ruling): the
/// progress message's "K B not streamed" is one combined number.
struct DeltaChannel {
    tx: mpsc::UnboundedSender<ShellChunk>,
    in_flight: Arc<AtomicUsize>,
    lag: Arc<AtomicUsize>,
}

/// Attempts to forward `chunk` (already known non-empty; enforced by a
/// `debug_assert!` rather than a runtime check — every call site already
/// establishes this, per fix round 1 finding 7) into `channel`, reserving
/// its length against the shared [`SHELL_DELTA_BUDGET_BYTES`] budget first.
/// Over budget, the chunk is dropped from the delta stream only — the
/// caller's own `ShellOutput` accumulation is untouched — its length is
/// added to the shared lag counter, and a [`ShellChunk::Gap`] marker is sent
/// in its place (fix round 1, security finding I1) so the pump never
/// silently concatenates the bytes on either side of the drop as if they
/// were contiguous. Never awaits anything: `try_send` and the atomics below
/// are both synchronous.
fn try_send_chunk(channel: &DeltaChannel, chunk: &[u8]) {
    debug_assert!(
        !chunk.is_empty(),
        "try_send_chunk's only call site (drain_to_end) never offers an empty chunk"
    );
    let len = chunk.len();
    let mut current = channel.in_flight.load(Ordering::Relaxed);
    loop {
        let reserved = current + len;
        if reserved > SHELL_DELTA_BUDGET_BYTES {
            channel.lag.fetch_add(len, Ordering::Relaxed);
            let _ = channel.tx.send(ShellChunk::Gap(GapReason::Budget));
            return;
        }
        match channel.in_flight.compare_exchange_weak(
            current,
            reserved,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    // An unbounded channel's `send` is synchronous and non-blocking. A
    // closed receiver (the pump already returned — e.g. this call raced its
    // own stream's EOF/drop) is not this drain's problem to report; the
    // reserved budget is simply never reclaimed by a pump that no longer
    // exists, which is harmless since the whole `ShellDeltaSink`/budget pair
    // is scoped to this one dispatched call.
    let _ = channel.tx.send(ShellChunk::Data(chunk.to_vec()));
}

/// Per-stream mutable pump state: the bytes buffered since the last flush
/// (or the last discontinuity — see [`handle_stream_event`]'s `Gap` arm),
/// the cumulative count of bytes actually, durably flushed (for the
/// progress message — only ever advanced once `flush_stream` reports
/// success), and the receiving half of this stream's [`DeltaChannel`] —
/// `None` once this stream's `drain_to_end` has dropped its sender AND the
/// resulting final flush has run.
struct StreamPumpState {
    kind: ShellStream,
    buf: Vec<u8>,
    flushed: u64,
    rx: Option<mpsc::UnboundedReceiver<ShellChunk>>,
}

impl StreamPumpState {
    fn new(kind: ShellStream, rx: Option<mpsc::UnboundedReceiver<ShellChunk>>) -> Self {
        StreamPumpState {
            kind,
            buf: Vec::new(),
            flushed: 0,
            rx,
        }
    }
}

/// Flushes as much of `stream.buf` as the live redactor's
/// `EventWriter::redaction_split_and_redact` currently allows, appending a
/// `Delta::Blob` plus one `TaskProgress` (Controller ruling: "at most one
/// TaskProgress" per flush) in a single `append_batch_with_blobs` call. A
/// no-op if `stream.buf` is empty (both for an idle tick and for a
/// zero-output stream's own final flush).
///
/// **`final_flush`:** `false` for a size/tick-triggered flush — the chosen
/// cut is redaction's own non-final holdback-and-split answer, and if that
/// answer is `0` (nothing safely flushable under the live redactor's
/// holdback yet — R1), this is a harmless no-op; whatever is buffered is
/// simply carried into the next flush attempt. `true` is reserved for the
/// stream's genuine, gap-free close (real EOF, or — since fix round 1,
/// security finding I1 — the tail segment remaining after the LAST
/// discontinuity was already handled by [`handle_stream_event`]'s `Gap` arm,
/// which is what makes a subsequent unconditional release safe again):
/// `EventWriter::redaction_split_and_redact(bytes, bytes.len(), true)`
/// always returns `cut == bytes.len()` (no match found by scanning `bytes`
/// itself can ever end past `bytes.len()`, so `Redactor::safe_split_len`'s
/// straddle check can never trigger at `k = bytes.len()`) — "it releases
/// everything," per the brief, with no shrink/bisection loop needed the way
/// `DeltaCoalescer::carve_final_chunk` needs one for `Delta::Text` (that
/// module also floors to a UTF-8 char boundary, which raw shell bytes never
/// need to). **This is only safe because a discontinuity is never allowed to
/// reach this branch with unhandled pre-gap bytes still concatenated onto
/// post-gap ones** — see [`handle_stream_event`]'s `Gap` arm, which is the
/// one place that guarantees it.
///
/// **Orphan blobs (security finding M3, controller ruling R17):** this
/// function calls `write_blob` before `append_batch_with_blobs`, and two
/// paths can leave a written blob file with no `blobs` row ever
/// referencing it — an orphan `gc_eligible_blobs` can never discover (that
/// query only ever sees rows that exist): (1) `append_batch_with_blobs`
/// itself failing after `write_blob` already succeeded (handled below by
/// counting the bytes as lag rather than losing them silently — see the
/// error arm), and (2) this whole future being dropped by
/// [`run_isolated_shell_dispatch`]'s outer `tokio::select!` on a
/// timeout/cancel while awaiting `append_batch_with_blobs`, after the
/// `spawn_blocking(write_blob)` call has already completed (`spawn_blocking`
/// runs the closure to completion regardless of whether its `JoinHandle` is
/// still being awaited). Per ruling R10, this task does not add a
/// `record_unreferenced_blob` pre-pass to close either gap; reclaiming an
/// unindexed file is a recorded follow-up, not this task's job.
#[allow(clippy::too_many_arguments)]
async fn flush_stream(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    state_dir: &Path,
    stream: &mut StreamPumpState,
    other_flushed: u64,
    final_flush: bool,
    lag: &AtomicUsize,
) -> Result<(), ToolDispatchError> {
    if stream.buf.is_empty() {
        return Ok(());
    }
    let max = if final_flush {
        stream.buf.len()
    } else {
        stream.buf.len().min(SHELL_FLUSH_CHUNK_BYTES)
    };
    let (cut, redacted, _matches) =
        writer.redaction_split_and_redact(&stream.buf, max, final_flush);
    if cut == 0 {
        // Non-final only (see this function's own doc comment for why a
        // final flush can never land here): nothing is safely flushable yet
        // under the live redactor's holdback requirement — keep buffering.
        return Ok(());
    }
    stream.buf.drain(..cut); // remove the consumed prefix regardless of what happens below --
                             // a failure past this point must count these bytes as lag
                             // (finding M2/9), never silently retry or lose them.

    let mime = stream.kind.mime().to_string();
    let state_dir_owned = state_dir.to_path_buf();
    let blob_ref = match tokio::task::spawn_blocking(move || {
        roundhouse_store::blobs::write_blob(&state_dir_owned, &redacted, Some(mime))
    })
    .await
    {
        Ok(Ok(blob_ref)) => blob_ref,
        Ok(Err(e)) => {
            tracing::warn!(
                error = %e, dropped_bytes = cut,
                "shell delta blob write failed; counting the dropped bytes as lag"
            );
            lag.fetch_add(cut, Ordering::Relaxed);
            return Err(ToolDispatchError::Isolation(format!(
                "shell delta blob write failed: {e}"
            )));
        }
        Err(e) => {
            tracing::warn!(
                error = %e, dropped_bytes = cut,
                "shell delta blob write task panicked; counting the dropped bytes as lag"
            );
            lag.fetch_add(cut, Ordering::Relaxed);
            return Err(ToolDispatchError::Isolation(format!(
                "shell delta blob write panicked: {e}"
            )));
        }
    };

    // Computed but not yet committed to `stream.flushed` (fix round 1,
    // finding 9): the progress message below must not claim bytes as
    // flushed until the append that actually records them succeeds.
    let tentative_flushed = stream.flushed + cut as u64;
    let (stdout_flushed, stderr_flushed) = match stream.kind {
        ShellStream::Stdout => (tentative_flushed, other_flushed),
        ShellStream::Stderr => (other_flushed, tentative_flushed),
    };
    let lag_bytes = lag.load(Ordering::Relaxed);
    let mut message = format!("stdout {stdout_flushed} B, stderr {stderr_flushed} B");
    if lag_bytes > 0 {
        message.push_str(&format!(", {lag_bytes} B not streamed"));
    }

    let now = crate::agent_loop::now_ts();
    let delta_event =
        runner.record_task_delta(session_id, 0, now, task_id, Delta::Blob(blob_ref), 1);
    let progress_event = runner.record_task_progress(
        session_id,
        0,
        now,
        task_id,
        Progress {
            message,
            fraction: None,
        },
        1,
    );
    match writer
        .append_batch_with_blobs(vec![delta_event, progress_event], state_dir.to_path_buf())
        .await
    {
        Ok(_) => {
            stream.flushed = tentative_flushed;
            Ok(())
        }
        Err(e) => {
            // The blob is already durably on disk (write_blob above
            // succeeded) but never indexed/referenced by this failed
            // append — an orphan file (this function's own doc comment,
            // M3/R17). From the delta STREAM's perspective, though,
            // nothing was ever recorded, so these bytes count as lag just
            // like any other unstreamed bytes.
            tracing::warn!(
                error = %e, dropped_bytes = cut,
                "shell delta append failed; counting the dropped bytes as lag"
            );
            lag.fetch_add(cut, Ordering::Relaxed);
            Err(ToolDispatchError::Isolation(format!(
                "shell delta append failed: {e}"
            )))
        }
    }
}

/// Appends a single `TaskProgress` marking a discontinuity (a budget drop or
/// the output cap) the instant it happens (fix round 1, security finding
/// M2) — distinct from, and in addition to, the ordinary per-flush
/// cumulative message `flush_stream` emits: that cumulative message only
/// ever rides the NEXT successful flush, which may be arbitrarily later, or
/// may never happen at all (e.g. a discontinuity that turns out to be the
/// very last thing this stream ever does, once its final buffer is empty).
/// `reason` is embedded in the message text (fix round 1 follow-up, finding
/// 8's note) so a caller — chiefly a test — can tell a `Cap` discontinuity
/// (at most one per stream, always its last event) apart from an arbitrary,
/// environment-dependent number of `Budget` ones. Best-effort like every
/// other streamed append here — a failure is not this call's problem to
/// propagate.
async fn emit_gap_progress(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    reason: GapReason,
    lag: &AtomicUsize,
) {
    let lag_bytes = lag.load(Ordering::Relaxed);
    let event = runner.record_task_progress(
        session_id,
        0,
        crate::agent_loop::now_ts(),
        task_id,
        Progress {
            message: format!(
                "shell output stream interrupted ({reason}) -- {lag_bytes} B not streamed so far"
            ),
            fraction: None,
        },
        1,
    );
    let _ = writer.append(event).await;
}

/// Drives both streams' [`StreamPumpState`] to completion: buffers each
/// received chunk, attempting a non-final [`flush_stream`] once a stream's
/// buffer reaches [`SHELL_FLUSH_CHUNK_BYTES`] or on every tick from
/// [`ShellDeltaSink::ticker`], and a final one the moment a stream's channel
/// closes (`recv()` returns `None` — [`drain_to_end`] dropping its sender,
/// either at real EOF or at the [`MAX_SHELL_OUTPUT_BYTES`] cap). Returns once
/// BOTH channels have closed and received their final flush — "the pump
/// returns after both drains drop their senders," per the brief.
///
/// `sink: None` (every call site until Task 9 wires this up) makes this an
/// immediate no-op — both `stdout_rx`/`stderr_rx` are `None` too in that
/// case (see [`run_isolated_shell_dispatch`]), so today's behavior
/// (single buffered `ShellOutput`, no deltas) is unchanged.
///
/// No `biased;` on the `select!` below (fix round 1, finding 11 — an
/// earlier version had one): with it, a stream that is continuously ready
/// (a fast, chatty producer) would deterministically starve its sibling
/// stream's branch and the ticker branch every single time, making the
/// ticker's cadence load-dependent instead of the fixed interval its own
/// name promises. Plain (unbiased) `select!` picks pseudo-randomly among
/// ready branches, so no branch can starve forever.
async fn run_shell_delta_pump(
    sink: Option<ShellDeltaSink>,
    stdout_rx: Option<mpsc::UnboundedReceiver<ShellChunk>>,
    stderr_rx: Option<mpsc::UnboundedReceiver<ShellChunk>>,
    in_flight: Arc<AtomicUsize>,
    lag: Arc<AtomicUsize>,
) {
    let Some(mut sink) = sink else {
        return;
    };
    let mut stdout = StreamPumpState::new(ShellStream::Stdout, stdout_rx);
    let mut stderr = StreamPumpState::new(ShellStream::Stderr, stderr_rx);

    loop {
        if stdout.rx.is_none() && stderr.rx.is_none() {
            return;
        }
        tokio::select! {
            chunk = recv_or_pending(&mut stdout.rx) => {
                handle_stream_event(
                    &sink.writer, sink.runner, sink.session_id, sink.task_id, &sink.state_dir,
                    &mut stdout, &mut stderr, chunk, &in_flight, &lag,
                ).await;
            }
            chunk = recv_or_pending(&mut stderr.rx) => {
                handle_stream_event(
                    &sink.writer, sink.runner, sink.session_id, sink.task_id, &sink.state_dir,
                    &mut stderr, &mut stdout, chunk, &in_flight, &lag,
                ).await;
            }
            () = sink.ticker.tick() => {
                let stderr_flushed = stderr.flushed;
                let _ = flush_stream(
                    &sink.writer, sink.runner, sink.session_id, sink.task_id, &sink.state_dir,
                    &mut stdout, stderr_flushed, false, &lag,
                ).await;
                let stdout_flushed = stdout.flushed;
                let _ = flush_stream(
                    &sink.writer, sink.runner, sink.session_id, sink.task_id, &sink.state_dir,
                    &mut stderr, stdout_flushed, false, &lag,
                ).await;
            }
        }
    }
}

/// One stream's reaction to a channel event.
///
/// - `Some(ShellChunk::Data(bytes))`: a genuinely contiguous chunk — buffered
///   (and its reserved budget released) and, once large enough, offered to
///   [`flush_stream`] as a non-final attempt.
/// - `Some(ShellChunk::Gap(reason))` (fix round 1, security finding I1): a
///   discontinuity — bytes existed on the real stream that will never reach
///   this buffer (`reason` says whether it was a budget drop or the output
///   cap — see [`GapReason`]). Whatever is currently
///   buffered is offered to [`flush_stream`] as a non-final attempt (WITH
///   holdback — this is deliberately never `final_flush = true`, so a
///   partial match still touching the tail is never released), and
///   whatever that flush does NOT safely release is then DISCARDED — added
///   to `lag` and dropped, never carried forward — so the NEXT bytes to
///   arrive (on the far side of the gap) start a genuinely fresh buffer
///   rather than getting silently concatenated onto a held-back tail that
///   was never actually adjacent to them in the real stream. A dedicated
///   `TaskProgress` (`emit_gap_progress`) marks the moment, independent of
///   whether anything was flushed or discarded.
/// - `None`: this stream's real end — `rx` is set to `None` (this stream no
///   longer participates in the pump's `select!`) and its final flush runs
///   unconditionally. Safe to release everything unconditionally
///   (`final_flush = true`) precisely because any discontinuity before this
///   point already went through the `Gap` arm above, which never leaves
///   `stream.buf` holding anything but a genuinely contiguous, gap-free
///   tail.
///
/// Flush failures are deliberately swallowed here (`let _ =`), matching
/// `flush_stream`'s own callers in [`run_shell_delta_pump`]'s tick arm: a
/// failed streamed-delta append must never fail the whole dispatched shell
/// call (whose own `ShellOutput`/exit code the drains/`wait()` already
/// captured independently) — streaming is a best-effort enrichment of the
/// task log, not the tool call's result. `flush_stream` itself already
/// counts a failure's bytes as lag before returning `Err`.
#[allow(clippy::too_many_arguments)]
async fn handle_stream_event(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    task_id: TaskId,
    state_dir: &Path,
    stream: &mut StreamPumpState,
    other: &mut StreamPumpState,
    chunk: Option<ShellChunk>,
    in_flight: &AtomicUsize,
    lag: &AtomicUsize,
) {
    match chunk {
        Some(ShellChunk::Data(bytes)) => {
            in_flight.fetch_sub(bytes.len(), Ordering::Relaxed);
            stream.buf.extend_from_slice(&bytes);
            if stream.buf.len() >= SHELL_FLUSH_CHUNK_BYTES {
                let other_flushed = other.flushed;
                let _ = flush_stream(
                    writer,
                    runner,
                    session_id,
                    task_id,
                    state_dir,
                    stream,
                    other_flushed,
                    false,
                    lag,
                )
                .await;
            }
        }
        Some(ShellChunk::Gap(reason)) => {
            let other_flushed = other.flushed;
            let _ = flush_stream(
                writer,
                runner,
                session_id,
                task_id,
                state_dir,
                stream,
                other_flushed,
                false,
                lag,
            )
            .await;
            if !stream.buf.is_empty() {
                // Whatever `flush_stream` just declined to release (a
                // held-back tail that might be a partial match) must never
                // be concatenated with bytes that arrive after this gap —
                // discard it, counted as lag, rather than releasing or
                // retaining it (finding I1).
                lag.fetch_add(stream.buf.len(), Ordering::Relaxed);
                stream.buf.clear();
            }
            emit_gap_progress(writer, runner, session_id, task_id, reason, lag).await;
        }
        None => {
            stream.rx = None;
            let other_flushed = other.flushed;
            let _ = flush_stream(
                writer,
                runner,
                session_id,
                task_id,
                state_dir,
                stream,
                other_flushed,
                true,
                lag,
            )
            .await;
        }
    }
}

/// Awaits the next chunk from `rx`, or pends forever once `rx` is already
/// `None` (this stream already closed and ran its final flush) — lets
/// [`run_shell_delta_pump`]'s `select!` keep polling a still-open sibling
/// stream without a closed one's branch ever winning again.
async fn recv_or_pending(
    rx: &mut Option<mpsc::UnboundedReceiver<ShellChunk>>,
) -> Option<ShellChunk> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// Runs an admitted shell command through the session-owned isolation handle.
/// The command and cwd have already been canonicalized before admission; this
/// function deliberately receives no raw model input so execution cannot drift
/// from what policy judged.
#[allow(clippy::too_many_arguments)]
async fn run_isolated_shell_dispatch(
    isolator: &dyn TaskIsolator,
    program: &str,
    argv: &[String],
    cwd: &Path,
    env: &[(String, String)],
    timeout: Duration,
    cancel: Option<watch::Receiver<SessionState>>,
    pre_spawned: Option<Child>,
    delta_sink: Option<ShellDeltaSink>,
) -> Result<roundhouse_tools::ShellOutput, ToolDispatchError> {
    let child = match pre_spawned {
        Some(child) => child,
        None => isolator
            .spawn_isolated(CommandSpec {
                program: program.to_string(),
                argv: argv.to_vec(),
                cwd: Some(cwd.to_string_lossy().into_owned()),
                env: env.to_vec(),
            })
            .await
            .map_err(|err: IsolationError| ToolDispatchError::Isolation(err.to_string()))?,
    };
    let (stdout, stderr) = child.take_stdio().await;
    let in_flight = Arc::new(AtomicUsize::new(0));
    let lag = Arc::new(AtomicUsize::new(0));
    let (stdout_channel, stdout_rx, stderr_channel, stderr_rx) = match &delta_sink {
        Some(_) => {
            let (stdout_tx, stdout_rx) = mpsc::unbounded_channel();
            let (stderr_tx, stderr_rx) = mpsc::unbounded_channel();
            (
                Some(DeltaChannel {
                    tx: stdout_tx,
                    in_flight: Arc::clone(&in_flight),
                    lag: Arc::clone(&lag),
                }),
                Some(stdout_rx),
                Some(DeltaChannel {
                    tx: stderr_tx,
                    in_flight: Arc::clone(&in_flight),
                    lag: Arc::clone(&lag),
                }),
                Some(stderr_rx),
            )
        }
        None => (None, None, None, None),
    };
    // Fix round 1, finding 10: the outer `tokio::select!` below races this
    // whole `completion` future (both drains AND the delta pump) against
    // `sleep(timeout)`/`wait_for_session_cancel`. If either of those wins,
    // `completion` — and everything it's still `join!`ing, including
    // `run_shell_delta_pump` — is dropped mid-flight: any bytes the pump
    // was still buffering (not yet flushed) are lost from the delta stream,
    // and no final flush ever runs for either stream. This is a silent,
    // by-design truncation relative to `ShellOutput` itself, which the
    // caller only sees indirectly (a `ShellCancelled`/`ShellSessionCancelled`
    // error, never an explicit "the delta stream stopped early" signal).
    // There is no happens-before relationship to preserve here beyond what
    // `select!` already gives: the delta stream is best-effort and is
    // allowed to be strictly less complete than the retained `ShellOutput`
    // buffer on a cancelled/timed-out call.
    let completion = async {
        let (status, stdout, stderr, ()) = tokio::join!(
            child.wait(),
            drain_to_end(stdout, MAX_SHELL_OUTPUT_BYTES, stdout_channel),
            drain_to_end(stderr, MAX_SHELL_OUTPUT_BYTES, stderr_channel),
            run_shell_delta_pump(delta_sink, stdout_rx, stderr_rx, in_flight, lag),
        );
        let status = status.map_err(|err| ToolDispatchError::Isolation(err.to_string()))?;
        Ok::<_, ToolDispatchError>(roundhouse_tools::ShellOutput {
            stdout,
            stderr,
            exit_code: status.code(),
        })
    };

    let mut cancel = cancel;
    // Phase 8 Task 25.4 Task 4: which branch won decides which
    // `ToolDispatchError` variant is returned below — `ShellCancelled` for
    // a wall-clock timeout, `ShellSessionCancelled` for §8.13's cooperative
    // cancel — so a caller (`dispatch_tool_for_workflow`) can tell "this
    // step ran out of its own declared time budget" apart from "a cancel
    // was observed" without parsing free text. The `child.cancel().await`
    // confirmation itself is identical either way, so it stays one call
    // below rather than being duplicated per branch.
    let (cancelled_by_session, cancel_reason) = tokio::select! {
        result = completion => return result,
        () = tokio::time::sleep(timeout) => {
            (false, format!("exceeded its {timeout:?} wall-clock bound"))
        }
        () = wait_for_session_cancel(&mut cancel) => {
            (true, "the owning session was cancelled/suspended/closed".to_string())
        }
    };

    match child.cancel().await {
        Ok(_) if cancelled_by_session => {
            Err(ToolDispatchError::ShellSessionCancelled(cancel_reason))
        }
        Ok(_) => Err(ToolDispatchError::ShellCancelled(cancel_reason)),
        Err(err) => Err(ToolDispatchError::Isolation(format!(
            "cancellation could not be confirmed: {err}"
        ))),
    }
}

/// Bound on how many bytes of stdout/stderr each `run_shell_dispatch` call
/// will **retain** (fix round B, ruling W1-R66 + carry-forward CF-7 item 4;
/// failure mode corrected in fix round C1, ruling W1-R71 — see
/// [`drain_to_end`]'s doc comment for why this is no longer a hard read
/// limit).
const MAX_SHELL_OUTPUT_BYTES: u64 = 10 * 1024 * 1024;

/// Runs a dispatched `shell` call through `roundhouse_tools::spawn_cancellable`
/// (never the uncancellable `run_shell` — fix round A, finding F6), racing
/// its natural completion against `timeout` and, when `cancel` is `Some`,
/// the owning session leaving `Created`/`Running`. Either losing condition
/// cancels the real process group (`cancel_running_shell`, SIGTERM
/// escalating to SIGKILL, confirmed via its own liveness probe) before
/// returning [`ToolDispatchError::ShellCancelled`] — this function never
/// reports success without the process having genuinely exited on its own.
///
/// **Fix round B, ruling W1-R66 (finding I1 — F6 was NOT actually closed):**
/// the direct child's own exit is not proof that its output is fully
/// buffered — a backgrounded grandchild that inherits the piped stdout/
/// stderr fds (e.g. `sh -c "sleep 900 & exit 0"`) keeps those pipes open
/// long after `wait()` resolves, and `read_to_end` does not return until
/// *every* writer closes. The previous version awaited the stdout/stderr
/// drain **inside** the `handle.wait()` branch body — i.e. AFTER the outer
/// `select!` had already committed to that branch — so once the direct
/// child exited, neither `sleep(timeout)` nor the cancellation watch could
/// still preempt the drain. Reproduced: such a script left this dispatch
/// running at 146s against a 120s `SHELL_TIMEOUT`, with the grandchild
/// never signalled. The fix: `wait()` and both drains are now one single
/// future (`tokio::join!` inside `completion`, below), so racing that ONE
/// future against `timeout`/cancellation in the outer `select!` preempts
/// the drain exactly the same way it already preempted `wait()` — dropping
/// `completion` when a sibling branch wins drops the in-progress drains
/// too. The size cap ([`MAX_SHELL_OUTPUT_BYTES`]) bounds how much of
/// stdout/stderr is **retained** in memory, independent of the outer race
/// — but, as of fix round C1 (ruling W1-R71), it does NOT bound how long a
/// still-producing stream keeps this dispatch running: [`drain_to_end`]
/// deliberately keeps reading (and discarding) past the cap until the
/// pipe reaches genuine EOF, rather than dropping the reader once the cap
/// is hit (see that function's own doc comment for why an early drop is
/// itself a bug, not a feature — it SIGPIPE-kills a child still writing).
/// A producer that never closes its own end is therefore bounded ONLY by
/// `timeout`/cancellation in the outer race, exactly like `wait()` always
/// was — the cap is a memory bound, not a time bound.
#[cfg(test)]
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

    let mut cancel = cancel;
    let completion = async {
        // A single future combining wait() with BOTH drains — see this
        // function's own doc comment for why this must be one future, not
        // three raced independently. `join!` polls all three concurrently
        // (never sequentially), which is also what avoids a chatty child
        // deadlocking against a full OS pipe buffer while `wait()` alone is
        // being awaited.
        let (status, stdout, stderr) = tokio::join!(
            handle.wait(),
            drain_to_end(stdout, MAX_SHELL_OUTPUT_BYTES, None),
            drain_to_end(stderr, MAX_SHELL_OUTPUT_BYTES, None),
        );
        status.map(|status| roundhouse_tools::ShellOutput {
            stdout,
            stderr,
            exit_code: status.code(),
        })
    };

    // See `run_isolated_shell_dispatch`'s identical split for why the
    // winning branch is tracked, not just its reason string.
    let (cancelled_by_session, cancel_reason) = tokio::select! {
        result = completion => {
            return result.map_err(ToolDispatchError::Tool);
        }
        () = tokio::time::sleep(timeout) => {
            (false, format!("exceeded its {timeout:?} wall-clock bound"))
        }
        () = wait_for_session_cancel(&mut cancel) => {
            (true, "the owning session was cancelled/suspended/closed".to_string())
        }
    };

    // Best-effort: cancellation failing to confirm is itself a real
    // condition (`CancelError::GroupStillAlive`), but this function's own
    // job is reporting the shell call as cancelled either way — a caller
    // that needs to know cancellation itself failed would need a different
    // return shape than "the tool call didn't succeed," which is all a
    // dispatched tool result can express today.
    let _ = roundhouse_tools::cancel_running_shell(&mut handle, SHELL_CANCEL_GRACE).await;
    if cancelled_by_session {
        Err(ToolDispatchError::ShellSessionCancelled(cancel_reason))
    } else {
        Err(ToolDispatchError::ShellCancelled(cancel_reason))
    }
}

/// Resolves once the watched session leaves `Created`/`Running`, or never
/// resolves at all (`cancel: None`, or the `SessionActor` — and with it the
/// `watch::Sender` — has been dropped, which only `None`'s sibling branches
/// in [`run_shell_dispatch`]'s `select!` can still make progress against).
/// `pub(crate)` as of fix round D: [`crate::agent_loop`]'s MCP arm needs the
/// identical "resolve as soon as this session leaves `Created`/`Running`"
/// future for its own cancellation `select!` (ruling W1-R81 finding I2
/// level 2), and reimplementing the `changed()`-error-means-pend subtlety a
/// second time is exactly how the two would drift apart.
pub(crate) async fn wait_for_session_cancel(cancel: &mut Option<watch::Receiver<SessionState>>) {
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

/// Reads a piped child stdio handle to its natural EOF, retaining at most
/// `cap` bytes (see [`MAX_SHELL_OUTPUT_BYTES`]) and discarding the rest —
/// or returns an empty buffer if the pipe was never present (stdio wasn't
/// piped, or `take_stdio` was never called). Never fails the whole
/// dispatch over a drain error.
///
/// **Fix round C1, ruling W1-R71 (finding invited by round B's own "cap
/// its size" instruction, which never specified the failure mode):** the
/// previous version used `AsyncReadExt::take(cap)` and dropped the limited
/// reader once `read_to_end` returned. `Take` simulates EOF for the
/// CALLER once the cap is hit, but does nothing to the underlying pipe —
/// dropping `io` while the writer is still mid-write **closes our read
/// end early**, which delivers `SIGPIPE` to a child still writing to it.
/// The default `SIGPIPE` disposition terminates the process, so the
/// child dies as an unannounced SIDE EFFECT of a cap meant to bound
/// OUTPUT, not to kill the PROCESS — `wait()` then reports `exit_code:
/// None` (signal-terminated) with exactly `cap` bytes of output and no
/// marker explaining why, indistinguishable from the command having
/// crashed on its own. It also directly contradicts this same fix
/// round's own M2 principle that truncation must be VISIBLE, not silent.
/// And a child that ignores `SIGPIPE` isn't bounded by the cap at all —
/// it would just keep blocking on a full OS pipe buffer forever, since
/// nothing is still reading from our end.
///
/// The fix: keep reading (and, once past the cap, discarding) until the
/// pipe reaches genuine EOF — i.e. until the writer itself closes it,
/// exactly as an uncapped drain would — so the child always gets to exit
/// on its own terms, and append an explicit, visible truncation marker to
/// whatever was retained. This costs nothing extra in the common case
/// (well under `cap` bytes): the loop still exits on the first natural
/// EOF, same as before.
///
/// `scratch` is heap-allocated (`vec![0u8; N]`), deliberately NOT a fixed
/// stack array (`[0u8; N]`): a byte array held across an `.await` point
/// inside a loop becomes part of this async fn's generated state machine,
/// which is itself nested several layers deep here (this future is
/// `tokio::join!`'d with `wait()` and a second `drain_to_end` inside
/// `run_shell_dispatch`'s `completion`, which is itself one arm of an
/// outer `tokio::select!`, called from `execute_builtin`, called from a
/// test's own `#[tokio::test]` future) — reproduced empirically: an
/// initial version of this fix used a 64 KiB stack array here and
/// overflowed the 2 MiB per-test thread stack on ANY shell call that ran
/// to natural completion (i.e. never hit the `select!`'s other branches),
/// even for something as small as `echo`. A `Vec`'s buffer lives on the
/// heap; only its 24-byte (ptr/len/cap) header is part of the future's
/// inline state, regardless of how deeply this future ends up nested.
/// `deltas`, when `Some`, receives a non-blocking copy of every chunk still
/// under `cap` (Phase 8 Task 19 lane B, Task 8) — see [`try_send_chunk`] for
/// the budget/lag accounting, and [`DeltaChannel`]'s own doc comment for why
/// this never awaits anything. The instant `cap` is reached — a chunk that
/// only partially fits, or a chunk that no longer fits at all because an
/// earlier one already exactly filled `cap` — a [`ShellChunk::Gap`] is sent
/// and `deltas` is dropped right here, in that SAME iteration, exactly once
/// (fix round 1, security finding I1; the off-by-one-iteration version this
/// replaced is finding 6): [`run_shell_delta_pump`] sees the `Gap`, flushes
/// and discards whatever is still buffered as a safety measure (see
/// [`handle_stream_event`]'s `Gap` arm), and only then sees the channel
/// close and runs its own ordinary final flush (with its accompanying
/// `TaskProgress`) over the genuinely-empty, gap-free remainder — the
/// brief's "deltas stop at the cap," now with an explicit signal rather than
/// a bare, indistinguishable-from-EOF channel drop. Reading (and discarding)
/// past `cap` for the underlying pipe's sake — see this function's own
/// truncation doc comment above — is unaffected: only the delta side stops
/// early.
async fn drain_to_end<R: tokio::io::AsyncRead + Unpin>(
    io: Option<R>,
    cap: u64,
    deltas: Option<DeltaChannel>,
) -> Vec<u8> {
    let Some(mut io) = io else {
        return Vec::new();
    };
    use tokio::io::AsyncReadExt;

    let cap = cap as usize;
    let mut buf = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    let mut truncated = false;
    let mut deltas = deltas;
    loop {
        let n = match io.read(&mut scratch).await {
            Ok(0) => break, // natural EOF -- the writer closed its end
            Ok(n) => n,
            Err(_) => break,
        };
        let remaining = cap.saturating_sub(buf.len());
        let take = remaining.min(n);
        if take > 0 {
            buf.extend_from_slice(&scratch[..take]);
            if let Some(channel) = deltas.as_ref() {
                try_send_chunk(channel, &scratch[..take]);
            }
        }
        if take < n {
            // The cap was reached on exactly this iteration (`take > 0` but
            // less than `n`) or had already been reached before it
            // (`take == 0`) — mark truncation and signal the discontinuity
            // in this SAME iteration, not a later one.
            truncated = true;
            if let Some(channel) = deltas.take() {
                let _ = channel.tx.send(ShellChunk::Gap(GapReason::Cap));
            }
        }
    }
    if truncated {
        buf.extend_from_slice(format!("\n[output truncated at {cap} bytes]").as_bytes());
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_sandbox::{Attestation, Child, CommandSpec};

    struct TestIsolator;

    #[async_trait::async_trait]
    impl TaskIsolator for TestIsolator {
        async fn spawn_isolated(&self, command: CommandSpec) -> Result<Child, IsolationError> {
            let mut process = tokio::process::Command::new(&command.program);
            process
                .args(&command.argv)
                .current_dir(command.cwd.as_deref().unwrap_or("."))
                .env_clear()
                .envs(command.env)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // A real process-group leader, matching production spawns — see
            // `Child::cancel`'s `signal_group` (`roundhouse-sandbox`), which
            // signals `-pid`. Without this, `pid` is never a real process
            // group id, `signal_group` is a silent no-op (ESRCH treated as
            // success), and cancellation falls all the way through to a 5s
            // wait plus a direct-pid-only `start_kill` — correct eventually,
            // but not what a timeout test wants to depend on.
            #[cfg(unix)]
            process.process_group(0);
            let child = process
                .spawn()
                .map_err(|err| IsolationError::Unsupported(err.to_string()))?;
            let pid = child
                .id()
                .ok_or_else(|| IsolationError::Unsupported("test child has no pid".into()))?;
            Ok(Child::from_process(pid, child))
        }

        fn isolation_attestation(&self) -> Attestation {
            Attestation {
                tier: roundhouse_core::Tier::None,
                digest: "test".into(),
                net_enforced: false,
            }
        }
    }

    fn test_isolator() -> TestIsolator {
        TestIsolator
    }

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
    fn relative_filesystem_paths_resolve_against_the_explicit_workspace_root() {
        let workspace = tempfile::tempdir().unwrap();
        let file = workspace.path().join("README.md");
        std::fs::write(&file, "workspace file").unwrap();

        let (params, _) = task_params_for_in_workspace(
            TaskKind::Read,
            &serde_json::json!({ "path": "README.md" }),
            workspace.path(),
        )
        .unwrap();

        match params {
            TaskParams::Fs { canonical, .. } => {
                assert_eq!(canonical.unwrap(), file.canonicalize().unwrap())
            }
            other => panic!("expected filesystem params, got {other:?}"),
        }
    }

    #[test]
    fn an_unresolvable_filesystem_path_is_rejected_instead_of_counting_as_inside() {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = outside.path().join("missing").join("secret.txt");

        let error = task_params_for_in_workspace(
            TaskKind::Read,
            &serde_json::json!({ "path": path }),
            workspace.path(),
        )
        .unwrap_err();

        assert!(matches!(error, ToolDispatchError::WorkspacePathRejected(_)));
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

    /// Fix round B, finding I2 (ruling W1-R67): resolving a relative
    /// program name must NOT resolve a symlink in the final component —
    /// `python3 -> python3.14` (or any interpreter-shaped basename symlink
    /// to a differently-named real binary) must still be admitted, and
    /// still judged, as `python3` — never silently rewritten to a name
    /// `is_interpreter`/`sealed_program`'s basename checks no longer
    /// recognize.
    #[test]
    fn task_params_for_shell_preserves_the_final_component_across_a_symlink_but_still_contains_its_directory(
    ) {
        let dir = workspace_temp_dir();
        // The symlink's TARGET has a completely different basename —
        // proving the returned program name comes from the ORIGINAL
        // string, not from resolving the link.
        let real_binary = dir.path().join("real-interpreter-binary");
        std::fs::write(&real_binary, "not a real binary").unwrap();
        let symlink_path = dir.path().join("python3");
        std::os::unix::fs::symlink(&real_binary, &symlink_path).unwrap();

        let (params, _extras) = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": "./python3",
                "argv": ["-c", "print('hi')"],
                "cwd": dir.path().to_string_lossy(),
            }),
        )
        .unwrap();

        let TaskParams::Shell(cmd) = params else {
            panic!("expected TaskParams::Shell");
        };
        assert_eq!(
            Path::new(&cmd.program).file_name().and_then(|n| n.to_str()),
            Some("python3"),
            "the final path component must be preserved verbatim across a symlink, not \
             resolved to the link's target basename — got {:?}",
            cmd.program
        );
        assert!(
            roundhouse_policy::shell::interpreter::is_interpreter(&cmd.program),
            "is_interpreter must still recognize this as `python3` after resolution, not \
             `real-interpreter-binary` — got {:?}",
            cmd.program
        );
        // The directory portion must still be the real, canonical one
        // (this is what actually defeats a model-controlled cwd — the
        // point of resolving at all).
        assert_eq!(
            Path::new(&cmd.program).parent(),
            Some(dir.path().canonicalize().unwrap().as_path())
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

    /// Fix round B, finding I3 (ruling W1-R68): a workspace root of `/`
    /// makes every containment `starts_with` check vacuously true — this is
    /// not a contrived setup (a systemd unit with no `WorkingDirectory=`
    /// defaults to `/`) — so it must fail closed rather than silently
    /// degrade to no boundary at all.
    #[test]
    fn a_workspace_root_of_slash_is_rejected_outright() {
        let err = reject_root_of_slash(PathBuf::from("/")).unwrap_err();
        assert!(matches!(
            err,
            ToolDispatchError::WorkspaceRootUnavailable(_)
        ));
    }

    #[test]
    fn an_ordinary_workspace_root_is_accepted() {
        let root = reject_root_of_slash(PathBuf::from("/tmp")).unwrap();
        assert_eq!(root, PathBuf::from("/tmp"));
    }

    #[test]
    fn task_params_for_shell_relative_program_escaping_the_workspace_root_is_rejected() {
        // The F2 vector itself: a relative, `/`-containing program name
        // whose resolution against `cwd` would land outside the workspace
        // root must be refused, not silently admitted with a
        // policy-invisible cwd deciding which binary that name means.
        // `workspace_temp_dir()` creates `cwd` one level directly under
        // `workspace_root()` (`crates/roundhouse-engine`, since that's this
        // test binary's own cwd), so `../../../Cargo.toml` from `cwd` lands
        // on the repo's own top-level `Cargo.toml` — a real, existing,
        // *regular file* definitely outside `workspace_root`.
        //
        // Deliberately NOT a directory (fix round B's own M4 review found
        // that this test previously used `program: "../.."`, which resolves
        // to a directory one level above `workspace_root` — since fix round
        // B also added the M4 is-a-regular-file check, and that check runs
        // *before* this containment check, the old test stopped exercising
        // containment at all and silently started exercising M4 instead,
        // without anyone noticing because the assertion only checked the
        // error variant, not which of the two reasons produced it).
        let cwd = workspace_temp_dir();

        let err = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": "../../../Cargo.toml",
                "argv": [],
                "cwd": cwd.path().to_string_lossy(),
            }),
        )
        .unwrap_err();
        match err {
            ToolDispatchError::ShellProgramRejected(msg) => assert!(
                msg.contains("outside the workspace root"),
                "expected a containment rejection, got: {msg}"
            ),
            other => panic!("expected ShellProgramRejected, got {other:?}"),
        }
    }

    #[test]
    fn task_params_for_shell_a_symlink_to_a_sealed_program_outside_root_is_rejected_by_containment_first(
    ) {
        // Fix round C2 (W1-R70 item 2): the `./shim` containment property
        // has existed only as a comment since fix round B (`resolve_shell_program`'s
        // own doc comment, "e.g. `./shim` symlinked to something outside
        // root"), never as a test — exactly the shape this lane's own M4
        // finding warned about ("a commented-but-untested property gets
        // silently absorbed by a later check"). The security lens verified
        // it holds by execution in round C1's review; this makes that a
        // standing regression test rather than a one-time manual check.
        //
        // The interesting case, not the trivial one: `./mytool` is a
        // symlink to a REAL, SEALED priv-escalation binary
        // (`/usr/bin/sudo` — `sealed_program`'s own basename list) sitting
        // OUTSIDE the workspace root. If containment ran after basename
        // matching, this would look identical to the already-covered
        // `a_fully_qualified_sealed_program_path_is_still_denied_by_the_sealed_floor`
        // case and prove nothing new. Containment must fire FIRST, before
        // `sealed_program`'s basename check ever gets a chance to matter —
        // proven here by asserting the rejection reason is explicitly
        // "outside the workspace root", not merely that `task_params_for`
        // returned some error.
        let sudo_path = Path::new("/usr/bin/sudo");
        assert!(
            sudo_path.is_file(),
            "this test needs a real binary outside the workspace root to symlink to; \
             /usr/bin/sudo is absent on this machine"
        );

        let cwd = workspace_temp_dir();
        std::os::unix::fs::symlink(sudo_path, cwd.path().join("mytool")).unwrap();

        let err = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": "./mytool",
                "argv": [],
                "cwd": cwd.path().to_string_lossy(),
            }),
        )
        .unwrap_err();
        match err {
            ToolDispatchError::ShellProgramRejected(msg) => assert!(
                msg.contains("outside the workspace root"),
                "expected containment to fire before basename matching ever runs, got: {msg}"
            ),
            other => panic!("expected ShellProgramRejected, got {other:?}"),
        }
    }

    #[test]
    fn task_params_for_shell_rejects_a_directory_as_program() {
        // Fix round B, finding M4 (ruling W1-R69): `program="/"` (the
        // finding's own example, generalized to any directory) must not
        // silently pass containment and then fail confusingly at exec time.
        // Uses an *absolute* directory path so that, pre-fix, it would skip
        // the containment check entirely (containment only applies to
        // relative programs) and fall straight through to a successful
        // `Ok(directory_path)` — a genuine discriminator, unlike `program:
        // "/"` itself, which has no `file_name()` and would already be
        // rejected (for an unrelated reason) even without the M4 check.
        let dir = tempfile::tempdir().unwrap();
        let cwd = workspace_temp_dir();

        let err = task_params_for(
            TaskKind::Shell,
            &serde_json::json!({
                "program": dir.path().to_string_lossy(),
                "argv": [],
                "cwd": cwd.path().to_string_lossy(),
            }),
        )
        .unwrap_err();
        match err {
            ToolDispatchError::ShellProgramRejected(msg) => assert!(
                msg.contains("does not resolve to a regular file"),
                "expected the M4 not-a-regular-file rejection, got: {msg}"
            ),
            other => panic!("expected ShellProgramRejected, got {other:?}"),
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
        let (params, extras) = task_params_for(TaskKind::Read, &input).unwrap();
        let parts = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
        execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
        execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
        let err = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
        let parts = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
        let parts = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
        .await
        .unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].text.contains("hello-from-shell"));
        assert!(parts[0].text.contains("exit_code=Some(0)"));
    }

    #[tokio::test]
    async fn an_extra_model_shell_command_field_cannot_change_shell_execution() {
        let dir = workspace_temp_dir();
        let cwd_str = dir.path().to_string_lossy().to_string();
        let input = serde_json::json!({
            "program": "echo",
            "argv": ["still-cancellable"],
            "cwd": cwd_str,
            "shell_command": true,
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();
        let parts = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
        .await
        .unwrap();
        assert!(parts[0].text.contains("still-cancellable"));
    }

    #[tokio::test]
    async fn execute_builtin_shell_times_out_a_runaway_process_and_confirms_cancellation() {
        // fix round A, finding F6: a process that never exits on its own
        // must be bounded, not left running forever. Uses a real, short
        // timeout override via `run_shell_dispatch` directly — a
        // lower-level analog of `execute_builtin`'s Shell arm that races the
        // identical `tokio::select!` shape over `spawn_cancellable` instead
        // of the isolator `execute_builtin` actually dispatches through (see
        // `execute_builtin_shell_timeout_parameter_is_a_real_process_group_kill`,
        // below, for the isolator-path version of this same claim, with a
        // real pid-liveness check).
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

    /// Phase 8 Task 25.4 Task 3: `execute_builtin`'s `timeout` parameter —
    /// not the module's [`SHELL_TIMEOUT`] constant — is what bounds the
    /// `Shell` arm, and an elapsed timeout is a real process-group kill, not
    /// merely this future returning. Proven through `execute_builtin` itself
    /// (via the isolator `TaskIsolator` path, exactly what
    /// `run_isolated_shell_dispatch` uses in production — unlike the test
    /// above, which goes through the separate `run_shell_dispatch`/
    /// `spawn_cancellable` path instead), with a real OS-level liveness
    /// check on the killed pid (`pid_is_dead_or_zombie`, the same check
    /// `execute_builtin_shell_is_bounded_even_when_a_backgrounded_grandchild_outlives_the_direct_child`
    /// uses below) — not merely trusting that the returned error names a
    /// timeout.
    #[tokio::test]
    async fn execute_builtin_shell_timeout_parameter_is_a_real_process_group_kill() {
        let dir = workspace_temp_dir();
        let pid_file = dir.path().join("shell.pid");
        let input = serde_json::json!({
            "program": "sh",
            "argv": ["-c", format!("echo $$ > {} ; sleep 30", pid_file.display())],
            "cwd": dir.path().to_string_lossy(),
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();

        // A tiny, non-zero timeout: `execute_builtin`'s own `timeout`
        // parameter, deliberately NOT `SHELL_TIMEOUT` (120s) — if the
        // module still silently used that constant internally instead of
        // the threaded value, this call would still be sleeping when the
        // outer 10s bound below elapses.
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            execute_builtin(
                &params,
                &extras,
                &input,
                None,
                None,
                &test_isolator(),
                Duration::from_millis(300),
                None,
            ),
        )
        .await
        .expect("execute_builtin must honor the threaded 300ms timeout, not SHELL_TIMEOUT's 120s");

        assert!(
            matches!(result, Err(ToolDispatchError::ShellCancelled(_))),
            "a shell call exceeding the threaded timeout must be cancelled and reported, got \
             {result:?}"
        );

        for _ in 0..50 {
            if pid_file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("the dispatched shell must have written its own pid before sleeping")
            .trim()
            .parse()
            .expect("pid file must contain a valid pid");

        let mut confirmed_dead = false;
        for _ in 0..100 {
            if pid_is_dead_or_zombie(pid) {
                confirmed_dead = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            confirmed_dead,
            "the timed-out process (pid {pid}) must actually be killed, not just reported as \
             cancelled while still running"
        );
    }

    /// Fix round B, finding I1 (ruling W1-R66): the round-A fix for F6 only
    /// raced `handle.wait()` against the timeout/cancellation — the
    /// stdout/stderr drain ran AFTER that race had already resolved, so a
    /// direct child that exits quickly but backgrounds a grandchild
    /// inheriting the piped stdio (an entirely ordinary shape: "start a dev
    /// server in the background") left the drain blocked on that
    /// grandchild's still-open pipe long past the wall-clock bound —
    /// reproduced pre-fix at 146s against a 120s timeout. This is the exact
    /// reproduction, scaled down: the direct `sh` exits in milliseconds,
    /// but a backgrounded `sleep 30` inherits the piped stdout/stderr, so
    /// pre-fix this test would take ~30s; post-fix it must return within a
    /// few hundred milliseconds of the timeout.
    #[tokio::test]
    async fn execute_builtin_shell_is_bounded_even_when_a_backgrounded_grandchild_outlives_the_direct_child(
    ) {
        let dir = workspace_temp_dir();
        let env = shell_env_allowlist();
        let pid_file = dir.path().join("grandchild.pid");

        let start = std::time::Instant::now();
        let result = run_shell_dispatch(
            "sh",
            &[
                "-c".to_string(),
                format!("sleep 30 & echo $! > {} ; exit 0", pid_file.display()),
            ],
            dir.path(),
            &env,
            Duration::from_millis(300),
            None,
        )
        .await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ToolDispatchError::ShellCancelled(_))),
            "must report cancellation, not silently hang or succeed, got {result:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "must return promptly once the wall-clock bound is exceeded, not block on a \
             backgrounded grandchild's still-open pipe — took {elapsed:?}"
        );

        // Confirm the grandchild was actually killed too, not just that
        // this function returned — cancel_running_shell's whole point is
        // process-GROUP-wide cancellation, not merely "stop waiting."
        for _ in 0..50 {
            if pid_file.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .expect("the backgrounded grandchild must have written its pid")
            .trim()
            .parse()
            .expect("pid file must contain a valid pid");

        // Fix round C1 (ruling W1-R72's second bullet): a fixed sleep-then-check-once
        // here flakes under load even when cancellation genuinely worked — after
        // SIGKILL, the grandchild is a ZOMBIE (its `/proc/{pid}/stat` entry still
        // exists, with state `Z`) until whatever reaps it (its re-parented-to
        // subreaper/init, since its direct parent `sh` already exited) actually does
        // so, which this test does not control and has no business waiting on. A
        // bounded retry loop that accepts "gone" OR "zombie" as proof of death avoids
        // both a fixed-sleep race AND a dependency on reaping timing — this lane
        // already carries one wall-clock flake (issue #12) and must not add a second.
        let mut confirmed_dead = false;
        for _ in 0..100 {
            if pid_is_dead_or_zombie(pid) {
                confirmed_dead = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            confirmed_dead,
            "the backgrounded grandchild (pid {pid}) must be killed along with the rest of \
             the process group, not left running"
        );
    }

    /// True once `pid` is either gone entirely from `/proc` or sitting as a zombie
    /// (state `Z`) awaiting reap by whatever process it was re-parented to — both
    /// count as "killed" for [`execute_builtin_shell_is_bounded_even_when_a_backgrounded_grandchild_outlives_the_direct_child`]'s
    /// purposes (fix round C1, ruling W1-R72): this test asserts the process GROUP
    /// was actually torn down, not that some unrelated reaper has already run.
    /// `/proc/{pid}/stat`'s format is `pid (comm) state ...` — `comm` itself may
    /// contain spaces or parentheses, so the state field is found by splitting on the
    /// LAST `)`, not the first.
    fn pid_is_dead_or_zombie(pid: i32) -> bool {
        let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => return true,
            Ok(s) => s,
        };
        match stat.rsplit_once(')') {
            Some((_, rest)) => rest.trim_start().starts_with('Z'),
            None => false,
        }
    }

    #[tokio::test]
    async fn drain_to_end_reads_past_the_cap_to_natural_eof_and_marks_truncation() {
        // Fix round C1 (ruling W1-R71): a small cap deliberately far below what `yes`
        // will produce, so the child is still writing well after the cap is hit. If
        // `drain_to_end` dropped the reader early (the round B bug), the child would
        // be SIGPIPE-killed and `status.success()` would be false.
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("yes | head -c 200000") // ~200 KB, far past the tiny cap below
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawning sh must succeed");
        let stdout = child.stdout.take();

        let cap = 10u64;
        let buf = drain_to_end(stdout, cap, None).await;
        let status = child
            .wait()
            .await
            .expect("waiting on the child must succeed");

        assert!(
            status.success(),
            "the child must exit normally (head closing its own stdout), not be \
             SIGPIPE-killed by us closing the read end early — got {status:?}"
        );
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains(&format!("[output truncated at {cap} bytes]")),
            "must contain a visible truncation marker, got {text:?}"
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
            matches!(result, Err(ToolDispatchError::ShellSessionCancelled(_))),
            "session cancellation must cancel the in-flight shell call and be reported as a \
             session cancellation, not an ordinary timeout, got {result:?}"
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

        let parts = execute_builtin(
            &params,
            &extras,
            &mismatched_input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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

        let parts = execute_builtin(
            &params,
            &extras,
            &decoy_input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            None,
        )
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
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
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
        let decision = policy.decide_sealed(&params, &ctx, roundhouse_policy::Taint::Trusted);
        assert_eq!(
            decision.outcome,
            roundhouse_policy::engine::Outcome::Deny,
            "a fully-qualified path to a sealed priv-escalation program must still be denied"
        );
    }

    // -----------------------------------------------------------------------------------
    // Fix round C1 — MUST 1 (ruling W1-R71): the bare-name branch was left fully
    // canonicalizing in round B, defeating basename-matching security controls and,
    // worse, making the bare-name and `/`-qualified forms of the identical binary
    // canonicalize to two DIFFERENT strings — letting the model dodge an exact-match
    // policy rule by choosing which spelling to send. `resolve_bare_program_on_path`
    // takes an injected `PATH` value (an `OsStr`, built from a tempdir) rather than
    // mutating the process-global `PATH` env var, which would race every other test in
    // this binary running in parallel.
    // -----------------------------------------------------------------------------------

    #[test]
    fn bare_name_program_preserves_the_final_component_across_a_symlink_but_still_canonicalizes_its_path_dir(
    ) {
        let path_dir = tempfile::tempdir().unwrap();
        let real_binary = path_dir.path().join("real-interpreter-binary");
        std::fs::write(&real_binary, "not a real binary").unwrap();
        let symlink_path = path_dir.path().join("python3");
        std::os::unix::fs::symlink(&real_binary, &symlink_path).unwrap();

        let path_var = std::ffi::OsString::from(path_dir.path());
        let resolved = resolve_bare_program_on_path("python3", &path_var).unwrap();

        assert_eq!(
            resolved.file_name().and_then(|n| n.to_str()),
            Some("python3"),
            "the final component must be the literal bare name, not the symlink's \
             target basename — got {resolved:?}"
        );
        assert!(
            roundhouse_policy::shell::interpreter::is_interpreter(&resolved.to_string_lossy()),
            "is_interpreter must still recognize this as `python3` after resolution — got \
             {resolved:?}"
        );
        assert_eq!(
            resolved.parent(),
            Some(path_dir.path().canonicalize().unwrap().as_path()),
            "the PATH directory portion must still be canonicalized"
        );
    }

    #[test]
    fn bare_name_program_named_sudo_is_still_denied_by_the_sealed_floor() {
        // Mirrors `a_fully_qualified_sealed_program_path_is_still_denied_by_the_sealed_floor`
        // above, but for the bare-name branch specifically — the branch round B's I2 fix
        // left untouched. Deliberately a SYMLINK named `sudo` (not a plain regular
        // file): a plain file's `canonicalize()` is a no-op regardless of whether this
        // fix exists, so it would not actually discriminate round B's bug from this
        // fix (a mistake this same round's own M4 test-coverage correction, and now
        // this one, both caught before landing) — the real property under test only
        // shows up when the final component is a symlink whose target has a different
        // basename.
        let path_dir = tempfile::tempdir().unwrap();
        let real_binary = path_dir.path().join("not-sudo-at-all");
        std::fs::write(&real_binary, "not a real binary").unwrap();
        std::os::unix::fs::symlink(&real_binary, path_dir.path().join("sudo")).unwrap();
        let path_var = std::ffi::OsString::from(path_dir.path());

        let resolved = resolve_bare_program_on_path("sudo", &path_var).unwrap();
        let params = TaskParams::Shell(ParsedCommand {
            program: resolved.to_string_lossy().to_string(),
            argv: vec![],
        });
        let policy = roundhouse_policy::engine::PolicyEngine::from_rules(vec![]);
        let ctx = roundhouse_policy::sealed::default_context();
        let decision = policy.decide_sealed(&params, &ctx, roundhouse_policy::Taint::Trusted);
        assert_eq!(
            decision.outcome,
            roundhouse_policy::engine::Outcome::Deny,
            "a bare-name invocation of a sealed priv-escalation program must still be denied"
        );
    }

    #[test]
    fn bare_name_and_relative_path_forms_of_the_same_program_canonicalize_to_the_same_string() {
        // The exact evasion the security lens named: round B's half-fix let
        // `program: "python3"` (bare) and `program: "./python3"` (path-qualified)
        // canonicalize to two DIFFERENT strings for the identical binary, so a model
        // could dodge an operator's exact-match `Predicate::Shell` rule (`Deny
        // /usr/bin/python3`) just by omitting the slash. Both forms must now agree,
        // using one directory as both the PATH entry and the shell's `cwd` — a real
        // workspace-root-contained tempdir (`workspace_temp_dir`, not a bare system
        // `/tmp` one), since the relative-path form's own containment check would
        // otherwise reject it before the two resolutions could even be compared.
        // `mytool` is deliberately a SYMLINK, not a plain file: a plain file's
        // `canonicalize()` is a no-op regardless of this fix, so it would not
        // actually discriminate round B's bug (both forms would trivially agree
        // either way) — this needs a symlinked final component to be a real test.
        let dir = workspace_temp_dir();
        let real_binary = dir.path().join("not-mytool-at-all");
        std::fs::write(&real_binary, "not a real binary").unwrap();
        std::os::unix::fs::symlink(&real_binary, dir.path().join("mytool")).unwrap();

        let path_var = std::ffi::OsString::from(dir.path());
        let via_bare_name = resolve_bare_program_on_path("mytool", &path_var).unwrap();

        let canonical_cwd = dir.path().canonicalize().unwrap();
        let via_relative_path =
            resolve_shell_program("./mytool", &canonical_cwd, &canonical_cwd).unwrap();

        assert_eq!(
            via_bare_name, via_relative_path,
            "the bare-name and `/`-qualified forms of the identical binary must \
             canonicalize to the same string, or an exact-match policy rule can be \
             evaded by choosing which spelling to send"
        );
    }

    /// Fix round 2: five of [`ToolDispatchError::unadmitted_refusal`]'s
    /// message literals shipped with their `\` line-continuations dropped,
    /// leaving an 18-space run mid-sentence in text that is returned
    /// verbatim to the model AND written into `TaskError.message` in a log
    /// that physically rejects `UPDATE`/`DELETE` — permanent, on both
    /// channels.
    ///
    /// **Nothing else in the pipeline can catch this class**, which is why
    /// it is worth a test of its own: `cargo fmt` passes because rustfmt
    /// does not reformat string CONTENTS, clippy has no lint for it, and
    /// the containment integration test asserts on `category` plus
    /// substring presence/absence — the right shape for the security
    /// property it pins, and structurally blind to whitespace inside the
    /// sentence.
    ///
    /// Constructs every variant rather than only the five reachable from
    /// [`task_params_for`]: these strings are cheap to get wrong and
    /// invisible when wrong, so the guard covers the whole rendering.
    #[test]
    fn every_unadmitted_refusal_message_is_clean_single_spaced_prose() {
        let all = [
            ToolDispatchError::BadArgs {
                tool: "shell",
                field: "cwd",
            },
            ToolDispatchError::UnsupportedKind {
                kind: TaskKind::Chat,
            },
            ToolDispatchError::UnresolvedPath(roundhouse_policy::PathErr("x".into())),
            ToolDispatchError::UnsupportedParams("x".into()),
            ToolDispatchError::WorkspaceRootUnavailable("x".into()),
            ToolDispatchError::ShellCwdRejected("x".into()),
            ToolDispatchError::ShellProgramRejected("x".into()),
            ToolDispatchError::MissingResolvedCwd,
            ToolDispatchError::ShellCancelled("x".into()),
            ToolDispatchError::ShellSessionCancelled("x".into()),
            ToolDispatchError::Tool(roundhouse_tools::ToolError::Glob("x".into())),
        ];

        for err in all {
            let (category, message) = err.unadmitted_refusal();
            assert!(
                !category.is_empty(),
                "every refusal needs a queryable category, {err:?} has none"
            );
            assert!(
                !message.contains("  "),
                "a doubled space in a refusal message is a dropped `\\` line-continuation — \
                 this text is returned to the model and written permanently to the event \
                 log. Category {category:?}: {message:?}"
            );
            assert!(
                !message.contains('\n') && !message.contains('\t'),
                "a refusal message must be one line of prose, category {category:?}: \
                 {message:?}"
            );
            assert_eq!(
                message.trim(),
                message,
                "a refusal message must not carry leading or trailing whitespace, category \
                 {category:?}"
            );
        }
    }

    // -----------------------------------------------------------------------------------
    // Phase 8 Task 19 lane B, Task 8 (plan 16): streamed shell stdout/stderr deltas.
    // -----------------------------------------------------------------------------------

    /// A `FlushTicker` a test drives explicitly, one `()` per desired tick —
    /// never a real sleep (AGENTS.md / `feedback_no_clock_timing_tests`).
    /// `tick()` pends forever once the paired sender is dropped, matching
    /// `wait_for_session_cancel`'s "no more signals coming" shape.
    struct ManualTicker {
        rx: mpsc::UnboundedReceiver<()>,
    }

    impl ManualTicker {
        fn new() -> (Self, mpsc::UnboundedSender<()>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (ManualTicker { rx }, tx)
        }
    }

    #[async_trait::async_trait]
    impl FlushTicker for ManualTicker {
        async fn tick(&mut self) {
            match self.rx.recv().await {
                Some(()) => {}
                None => std::future::pending::<()>().await,
            }
        }
    }

    /// Builds a `ShellDeltaSink` with a [`ManualTicker`] in place of the
    /// real, wall-clock `IntervalFlushTicker` — reaching into this struct's
    /// private fields directly, which only this module (a descendant of the
    /// module that defines them) can do. This is deliberately the ONE
    /// bypass of `ShellDeltaSink::new`'s "always the real ticker" contract:
    /// production code has no equivalent access.
    fn manual_shell_delta_sink(
        writer: EventWriter,
        runner: &'static TaskRunner,
        session_id: SessionId,
        task_id: TaskId,
        state_dir: PathBuf,
    ) -> (ShellDeltaSink, mpsc::UnboundedSender<()>) {
        let (ticker, tick_tx) = ManualTicker::new();
        (
            ShellDeltaSink {
                writer,
                runner,
                session_id,
                task_id,
                state_dir,
                ticker: Box::new(ticker),
            },
            tick_tx,
        )
    }

    /// A fresh, isolated event store plus the blob root the same
    /// `state_dir` value must point at — `(writer, db_path, state_dir,
    /// _guard)`; the returned `TempDir` must stay alive for as long as the
    /// caller still needs `db_path`/`state_dir` to resolve.
    async fn shell_delta_test_store() -> (EventWriter, PathBuf, PathBuf, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let store = roundhouse_store::open(&db_path).await.unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        let state_dir = dir.path().join("state");
        (writer, db_path, state_dir, dir)
    }

    /// Every `Delta::Blob` ref recorded for `task_id` whose mime matches
    /// `mime` (i.e. one stream's worth), in stored (seq) order.
    fn stream_blob_refs(
        events: &[roundhouse_store::StoredEvent],
        task_id: TaskId,
        mime: &str,
    ) -> Vec<roundhouse_core::BlobRef> {
        events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .filter_map(|e| match &e.payload {
                roundhouse_core::EventPayload::TaskDelta {
                    delta: Delta::Blob(blob_ref),
                } if blob_ref.mime.as_deref() == Some(mime) => Some(blob_ref.clone()),
                _ => None,
            })
            .collect()
    }

    /// Concatenates every blob a stream's deltas reference, reading each
    /// back through `read_verified_blob` (never a raw filesystem read) —
    /// test (a)'s own required round-trip path.
    fn concatenated_stream_bytes(
        events: &[roundhouse_store::StoredEvent],
        task_id: TaskId,
        state_dir: &Path,
        mime: &str,
    ) -> Vec<u8> {
        stream_blob_refs(events, task_id, mime)
            .iter()
            .flat_map(|blob_ref| {
                roundhouse_store::blobs::read_verified_blob(state_dir, blob_ref).unwrap()
            })
            .collect()
    }

    fn task_progress_count(events: &[roundhouse_store::StoredEvent], task_id: TaskId) -> usize {
        events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .filter(|e| {
                matches!(
                    e.payload,
                    roundhouse_core::EventPayload::TaskProgress { .. }
                )
            })
            .count()
    }

    /// How many of `task_id`'s `TaskProgress` events are `emit_gap_progress`'s
    /// own standalone discontinuity marker (identified by its distinctive
    /// message text) rather than an ordinary per-flush progress note paired
    /// with a `Delta::Blob` (fix round 1, BLOCKING finding 1 / security
    /// finding M2). A budget drop can fire zero, one, or many times over a
    /// real run depending on how far the pump falls behind a fast producer,
    /// so a test must count these by content, never assume a fixed number.
    fn gap_progress_count(events: &[roundhouse_store::StoredEvent], task_id: TaskId) -> usize {
        events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .filter(|e| match &e.payload {
                roundhouse_core::EventPayload::TaskProgress { progress } => {
                    progress.message.contains("shell output stream interrupted")
                }
                _ => false,
            })
            .count()
    }

    /// The strict subset of [`gap_progress_count`] that are specifically the
    /// [`GapReason::Cap`] discontinuity (fix round 1 follow-up, finding 8's
    /// note): at most one per stream, always that stream's LAST event before
    /// its channel closes — unlike [`GapReason::Budget`] gaps, which can fire
    /// an environment-dependent number of times. Distinguished by the
    /// `"(cap)"` tag `emit_gap_progress` embeds in the message per
    /// `GapReason`'s `Display` impl.
    fn cap_gap_progress_count(events: &[roundhouse_store::StoredEvent], task_id: TaskId) -> usize {
        events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .filter(|e| match &e.payload {
                roundhouse_core::EventPayload::TaskProgress { progress } => progress
                    .message
                    .contains("shell output stream interrupted (cap)"),
                _ => false,
            })
            .count()
    }

    /// (a) `seq 1 60000` on stdout, a DISJOINT `seq 60001 90000` on stderr
    /// (fix round 1, BLOCKING finding 3 — the previous version used the
    /// SAME sequence on both streams "told apart only by mime," which a
    /// mutation swapping `ShellStream::mime`'s two string literals would
    /// not have caught, since both streams' expected bytes were identical
    /// either way): every blob-backed `Delta` this run produces, concatenated
    /// and read back via `read_verified_blob`, must equal
    /// `ShellOutput.stdout`/`.stderr` exactly, and stdout/stderr's contents
    /// must never cross-contaminate. The mime literals themselves are
    /// spelled out directly here too, never routed back through
    /// `ShellStream::mime()`, so a mutation to that method's string
    /// constants is caught by THIS test rather than silently laundered
    /// through the same function on both the production and assertion
    /// sides. Uses `EventWriter`'s default (empty) redactor —
    /// `shell_delta_test_store` never calls `set_redactor` — so no bytes
    /// are ever substituted.
    #[tokio::test]
    async fn shell_stdout_and_stderr_deltas_round_trip_byte_for_byte_via_blobs() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let (sink, _tick_tx) =
            manual_shell_delta_sink(writer, runner, session_id, task_id, state_dir.clone());

        let cwd = workspace_temp_dir();
        let env = shell_env_allowlist();
        let output = run_isolated_shell_dispatch(
            &test_isolator(),
            "sh",
            &[
                "-c".to_string(),
                "seq 1 60000; seq 60001 90000 1>&2".to_string(),
            ],
            cwd.path(),
            &env,
            SHELL_TIMEOUT,
            None,
            None,
            Some(sink),
        )
        .await
        .unwrap();

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();

        let stdout_bytes = concatenated_stream_bytes(
            &events,
            task_id,
            &state_dir,
            "application/vnd.roundhouse.stdout",
        );
        assert_eq!(
            stdout_bytes, output.stdout,
            "concatenated stdout blob deltas must equal ShellOutput.stdout exactly"
        );

        let stderr_bytes = concatenated_stream_bytes(
            &events,
            task_id,
            &state_dir,
            "application/vnd.roundhouse.stderr",
        );
        assert_eq!(
            stderr_bytes, output.stderr,
            "concatenated stderr blob deltas must equal ShellOutput.stderr exactly"
        );
        assert_ne!(
            stdout_bytes, stderr_bytes,
            "the two streams' disjoint content must never cross-contaminate"
        );
        assert!(
            stdout_bytes.starts_with(b"1\n2\n3\n"),
            "stdout must hold the low sequence, unmistakably its own"
        );
        assert!(
            stderr_bytes.starts_with(b"60001\n60002\n60003\n"),
            "stderr must hold the high sequence, unmistakably its own"
        );
        assert!(
            stream_blob_refs(&events, task_id, "application/vnd.roundhouse.stdout").len() > 1,
            "60000 lines of output must have required more than one 64 KiB flush"
        );
    }

    /// (b) Every delta and progress event this dispatched call produces must
    /// already be committed by the time `execute_builtin` returns — proven
    /// here with output far too small (2 bytes) to ever hit the 64 KiB
    /// size trigger, and a `ManualTicker` whose sender is never used, so the
    /// ONLY thing that can have flushed it is the stream's final,
    /// close-triggered flush — which must therefore already have completed,
    /// synchronously, before `execute_builtin` returned. No poll/retry: a
    /// single direct read of the store immediately afterward is the point.
    #[tokio::test]
    async fn every_delta_and_progress_event_is_committed_before_execute_builtin_returns() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let (sink, _tick_tx) =
            manual_shell_delta_sink(writer, runner, session_id, task_id, state_dir.clone());

        let dir = workspace_temp_dir();
        let input = serde_json::json!({
            "program": "echo",
            "argv": ["-n", "hi"],
            "cwd": dir.path().to_string_lossy(),
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();
        execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            Some(sink),
        )
        .await
        .unwrap();

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();
        let stdout_bytes =
            concatenated_stream_bytes(&events, task_id, &state_dir, ShellStream::Stdout.mime());
        assert_eq!(
            stdout_bytes, b"hi",
            "the 2-byte payload must already be flushed (via the stream's close-triggered \
             final flush) by the time execute_builtin returned"
        );
        assert_eq!(
            task_progress_count(&events, task_id),
            1,
            "exactly one flush happened (the final one), so exactly one TaskProgress must \
             have been recorded alongside it"
        );
        let progress_texts: Vec<String> = events
            .iter()
            .filter(|e| e.task_id == Some(task_id))
            .filter_map(|e| match &e.payload {
                roundhouse_core::EventPayload::TaskProgress { progress } => {
                    Some(progress.message.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            progress_texts,
            vec!["stdout 2 B, stderr 0 B".to_string()],
            "fix round 1, MAJOR finding 5: the progress message's exact format must be \
             asserted, not just its count -- both byte totals, and no \", K B not streamed\" \
             suffix since nothing was ever dropped"
        );
    }

    /// (c) A `ManualTicker` drives a real, mid-stream (non-final) flush:
    /// the dispatched command writes a first chunk through a genuinely
    /// separate process (`/bin/echo`, never a shell builtin, whose own
    /// process exit is what guarantees its libc stdio buffer is flushed to
    /// the pipe — a builtin's buffering is not guaranteed to flush before
    /// the next command), then blocks in a poll loop until a gate file
    /// appears. The test repeatedly sends a tick and polls the STORE (never
    /// a fixed sleep-then-assert on the flush's own timing, which the tick
    /// alone drives deterministically) for the pre-gate bytes to show up —
    /// mirroring this file's own established bounded-retry idiom for
    /// synchronizing against a real child process's I/O
    /// (`execute_builtin_shell_timeout_parameter_is_a_real_process_group_kill`'s
    /// pid-file poll). Once seen, the gate is released and the run allowed
    /// to finish normally, proving the LATER close-triggered final flush
    /// still completes the rest.
    #[tokio::test]
    async fn manual_ticker_drives_a_flush_before_the_stream_closes() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let (sink, tick_tx) =
            manual_shell_delta_sink(writer, runner, session_id, task_id, state_dir.clone());

        let dir = workspace_temp_dir();
        let gate = dir.path().join("gate");
        let script = format!(
            "/bin/echo -n AAAA; while [ ! -f '{}' ]; do sleep 0.01; done; /bin/echo -n BBBB",
            gate.display(),
        );
        let input = serde_json::json!({
            "program": "sh",
            "argv": ["-c", script],
            "cwd": dir.path().to_string_lossy(),
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();

        let handle = tokio::spawn(async move {
            execute_builtin(
                &params,
                &extras,
                &input,
                None,
                None,
                &test_isolator(),
                SHELL_TIMEOUT,
                Some(sink),
            )
            .await
        });

        let mut saw_early_flush = false;
        for _ in 0..100 {
            let _ = tick_tx.send(());
            tokio::task::yield_now().await;
            let reopened = roundhouse_store::open(&db_path).await.unwrap();
            let events = roundhouse_store::session_events(&reopened, session_id)
                .await
                .unwrap();
            let bytes =
                concatenated_stream_bytes(&events, task_id, &state_dir, ShellStream::Stdout.mime());
            if bytes == b"AAAA" {
                saw_early_flush = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            saw_early_flush,
            "a manual tick must flush the buffered pre-gate bytes before the stream closes"
        );

        std::fs::write(&gate, b"go").unwrap();
        let parts = handle
            .await
            .expect("execute_builtin task must not panic")
            .expect("execute_builtin must succeed");
        assert!(parts[0].text.contains("AAAABBBB"));
    }

    /// (d) R4: asserted at the drain/pump seam directly, not through
    /// `execute_builtin`. The delta channel's receiver is kept ALIVE here
    /// but never polled — simulating a writer/pump that never makes
    /// progress — deliberately NOT dropped (fix round 1, BLOCKING finding
    /// 2): dropping the receiver makes `tx.send` fail and return
    /// immediately regardless of whether sending is truly non-blocking, so
    /// it cannot distinguish `try_send_chunk`'s real synchronous contract
    /// from a broken version that `.await`s a bounded sender — that exact
    /// mutation (an `async fn try_send_chunk` doing
    /// `tx.send(chunk).await` on a bounded channel of capacity 1) passed
    /// against the old drop-the-receiver version of this test. With the
    /// receiver alive-but-idle and total output driven well past
    /// `SHELL_DELTA_BUDGET_BYTES`, `drain_to_end` must still read a
    /// well-over-a-pipe-buffer child (6 MiB, `yes | head`) to its natural
    /// EOF and return the complete output, and the shared budget must have
    /// been exceeded — proving the budget-drop/lag path (also MAJOR finding
    /// 5) actually ran, not just that nothing panicked.
    #[tokio::test]
    async fn drain_to_end_completes_even_though_nothing_ever_drains_the_delta_channel() {
        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg("yes | head -c 6000000")
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawning sh must succeed");
        let stdout = child.stdout.take();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let lag = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::unbounded_channel();
        // Kept alive but never polled -- see this test's own doc comment
        // for why dropping it outright would make the test vacuous.
        let _rx = rx;
        let channel = DeltaChannel {
            tx,
            in_flight: Arc::clone(&in_flight),
            lag: Arc::clone(&lag),
        };

        let result = tokio::time::timeout(
            Duration::from_secs(10),
            drain_to_end(stdout, MAX_SHELL_OUTPUT_BYTES, Some(channel)),
        )
        .await
        .expect("drain_to_end must not stall even though nothing drains the delta channel");

        let status = child
            .wait()
            .await
            .expect("waiting on the child must succeed");
        assert!(status.success());
        assert_eq!(
            result.len(),
            6_000_000,
            "ShellOutput's own buffer must be complete regardless of delta-channel backpressure"
        );
        assert!(
            lag.load(Ordering::Relaxed) > 0,
            "once in-flight bytes exceed the shared SHELL_DELTA_BUDGET_BYTES budget with \
             nothing ever draining them, the excess must be counted as lag rather than \
             silently blocking or vanishing"
        );
    }

    /// (e) Output well past `MAX_SHELL_OUTPUT_BYTES` (10 MiB): the retained
    /// `ShellOutput` still shows the existing truncation marker (unchanged
    /// behavior), and the streamed stdout deltas never exceed the cap — an
    /// exact upper bound, not a loose one (fix round 1 follow-up, finding
    /// 8): `drain_to_end`'s `take = remaining.min(n)` means the drain never
    /// forwards a single byte past `cap`, so there is no "natural per-flush
    /// overshoot" to allow for (an earlier version of this comment/assertion
    /// claimed one, which the drain-seam-level
    /// `drain_to_end_forwards_exactly_up_to_the_cap_then_stops` test now
    /// proves false directly). Every flush pairs exactly one `Delta::Blob`
    /// with exactly one `TaskProgress`, and the cap being reached fires
    /// exactly one `GapReason::Cap` discontinuity marker — distinct from an
    /// arbitrary, environment-dependent number of `GapReason::Budget` ones a
    /// fast producer can also trigger before the cap is even reached.
    #[tokio::test]
    async fn output_over_the_cap_stops_deltas_and_emits_one_progress_note() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let sink = ShellDeltaSink::new(writer, runner, session_id, task_id, state_dir.clone());

        let dir = workspace_temp_dir();
        let over_cap = MAX_SHELL_OUTPUT_BYTES + 2 * 1024 * 1024;
        let input = serde_json::json!({
            "program": "sh",
            "argv": ["-c", format!("yes | head -c {over_cap}")],
            "cwd": dir.path().to_string_lossy(),
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();
        let parts = execute_builtin(
            &params,
            &extras,
            &input,
            None,
            None,
            &test_isolator(),
            SHELL_TIMEOUT,
            Some(sink),
        )
        .await
        .unwrap();
        assert!(
            parts[0].text.contains("[output truncated at"),
            "the existing truncation marker must be unaffected: {:?}",
            parts[0].text
        );

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();
        let stdout_refs = stream_blob_refs(&events, task_id, ShellStream::Stdout.mime());
        let stdout_bytes_len: u64 = stdout_refs
            .iter()
            .map(|blob_ref| {
                roundhouse_store::blobs::read_verified_blob(&state_dir, blob_ref)
                    .unwrap()
                    .len() as u64
            })
            .sum();
        assert!(
            stdout_bytes_len > 0,
            "streaming must have actually happened -- a pump that flushes nothing would \
             vacuously satisfy the upper-bound check below"
        );
        assert!(
            stdout_bytes_len <= MAX_SHELL_OUTPUT_BYTES,
            "deltas must never exceed the cap -- drain_to_end's `take = remaining.min(n)` \
             never forwards a byte past it, so there is no per-flush overshoot to allow for; \
             got {stdout_bytes_len} bytes of deltas against a {MAX_SHELL_OUTPUT_BYTES}-byte cap"
        );
        assert_eq!(
            task_progress_count(&events, task_id),
            stdout_refs.len() + gap_progress_count(&events, task_id),
            "every ordinary flush pairs exactly one Delta with exactly one TaskProgress, and \
             the only progress events NOT so paired are emit_gap_progress's own standalone \
             discontinuity markers -- no progress event may exist unaccounted for"
        );
        assert_eq!(
            cap_gap_progress_count(&events, task_id),
            1,
            "the cap being reached must fire EXACTLY ONE GapReason::Cap discontinuity marker \
             (fix round 1 follow-up, finding 8) -- distinct from the possibly-many \
             GapReason::Budget ones a fast producer can also trigger before the cap is even \
             reached"
        );
    }

    /// (e-2) Drain-seam-level, fix round 1 BLOCKING finding 1: the previous
    /// version of this test only bounded delta bytes loosely from ABOVE
    /// (`<= cap + one flush chunk`), which a completely different bug --
    /// forwarding a full extra 64 KiB read past the cap, or never stopping
    /// at all -- would also have passed. Here the boundary is exact and
    /// deterministic: `cap` is small, the source is an in-memory
    /// `tokio::io::duplex` (not a real, timing-sensitive child process), and
    /// its buffer is deliberately smaller than the total bytes written so
    /// the cap-crossing chunk is guaranteed to span more than one physical
    /// read -- exactly the multi-iteration scenario the pre-fix-round-1 code
    /// (finding 6) handled one iteration too late.
    #[tokio::test]
    async fn drain_to_end_forwards_exactly_up_to_the_cap_then_stops() {
        use tokio::io::AsyncWriteExt;

        let (mut tx_half, rx_half) = tokio::io::duplex(4);
        let cap: u64 = 10;
        let in_flight = Arc::new(AtomicUsize::new(0));
        let lag = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = mpsc::unbounded_channel();
        let channel = DeltaChannel {
            tx,
            in_flight: Arc::clone(&in_flight),
            lag: Arc::clone(&lag),
        };

        let write_task = tokio::spawn(async move {
            tx_half.write_all(b"ABCDEF").await.unwrap();
            tx_half.write_all(b"GHIJKLMNO").await.unwrap();
            tx_half.shutdown().await.unwrap();
        });

        let result = drain_to_end(Some(rx_half), cap, Some(channel)).await;
        write_task.await.expect("the writer task must not panic");

        let mut expected = b"ABCDEFGHIJ".to_vec();
        expected.extend_from_slice(format!("\n[output truncated at {cap} bytes]").as_bytes());
        assert_eq!(
            result, expected,
            "ShellOutput's own retained buffer must stop exactly at the cap (plus the \
             existing truncation marker)"
        );

        let mut forwarded = Vec::new();
        let mut gap_count = 0;
        while let Ok(chunk) = rx.try_recv() {
            match chunk {
                ShellChunk::Data(bytes) => forwarded.extend_from_slice(&bytes),
                ShellChunk::Gap(reason) => {
                    assert_eq!(
                        reason,
                        GapReason::Cap,
                        "the only discontinuity a cap-only scenario (no shared budget \
                         involved) can ever produce is a Cap gap"
                    );
                    gap_count += 1;
                }
            }
        }
        assert_eq!(
            forwarded, b"ABCDEFGHIJ",
            "deltas must be forwarded exactly up to the cap -- neither a partial-chunk's worth \
             less nor a full extra read past it"
        );
        assert_eq!(
            gap_count, 1,
            "crossing the cap must send exactly one Gap marker, in the same iteration it \
             happens, never zero (silently indistinguishable from a clean EOF) nor more than \
             one"
        );
    }

    /// (MAJOR 4a) fix round 1: the original test suite never once registered
    /// a real secret, so no test could have caught a bug in M4's
    /// split-then-redact race or in the holdback arithmetic itself. Exercised
    /// directly against `flush_stream` with a live, non-empty `Redactor` and
    /// a manually constructed `StreamPumpState`: a secret straddling an
    /// ordinary (non-final) flush boundary must never let any unredacted
    /// prefix of it survive in a stored blob, and once both halves are
    /// reassembled and flushed, the whole secret must come out fully
    /// redacted.
    #[tokio::test]
    async fn a_secret_straddling_a_flush_boundary_is_never_exposed_and_is_fully_redacted() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        writer.set_redactor(roundhouse_store::redact::Redactor::build(&[
            "SECRET123".to_string()
        ]));
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let lag = AtomicUsize::new(0);

        let mut stream = StreamPumpState::new(ShellStream::Stdout, None);
        // The secret's first 7 of its 9 bytes land in this non-final flush;
        // the live redactor's own holdback (`max_pattern_len() - 1` = 8
        // bytes) must keep them buffered rather than releasing a naked
        // "SECRET1" prefix.
        stream.buf.extend_from_slice(b"before-SECRET1");
        flush_stream(
            &writer,
            runner,
            session_id,
            task_id,
            &state_dir,
            &mut stream,
            0,
            false,
            &lag,
        )
        .await
        .unwrap();

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();
        let so_far = concatenated_stream_bytes(
            &events,
            task_id,
            &state_dir,
            "application/vnd.roundhouse.stdout",
        );
        assert!(
            !so_far.windows(7).any(|w| w == b"SECRET1"),
            "the live redactor's holdback must never release a naked, unredacted prefix of a \
             straddling secret: got {:?}",
            String::from_utf8_lossy(&so_far)
        );

        // The rest of the secret, plus trailing bytes, arrives -- then the
        // stream's real close runs the final, unconditional-release flush.
        stream.buf.extend_from_slice(b"23-after");
        flush_stream(
            &writer,
            runner,
            session_id,
            task_id,
            &state_dir,
            &mut stream,
            0,
            true,
            &lag,
        )
        .await
        .unwrap();

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();
        let full = concatenated_stream_bytes(
            &events,
            task_id,
            &state_dir,
            "application/vnd.roundhouse.stdout",
        );
        assert_eq!(
            full,
            b"before-[REDACTED]-after".to_vec(),
            "once both halves are reassembled and flushed, the secret must be fully redacted"
        );
        assert!(
            !full.windows(9).any(|w| w == b"SECRET123"),
            "the raw secret must never appear in any stored blob"
        );
    }

    /// (MAJOR 4b) The mirror image of the above, at the discontinuity path
    /// (fix round 1, security finding I1): a secret straddling a gap/cap
    /// discontinuity must never have any proper prefix of it survive
    /// unredacted, NOR reconstitute across the gap -- exercised directly
    /// against `handle_stream_event`'s `Gap` arm.
    #[tokio::test]
    async fn a_secret_straddling_a_discontinuity_never_leaks_a_partial_prefix() {
        let (writer, db_path, state_dir, _guard) = shell_delta_test_store().await;
        writer.set_redactor(roundhouse_store::redact::Redactor::build(&[
            "SECRET123".to_string()
        ]));
        let runner = crate::session_actor::test_runner();
        let session_id = SessionId::new();
        let task_id = TaskId::new();
        let in_flight = AtomicUsize::new(0);
        let lag = AtomicUsize::new(0);

        let mut stream = StreamPumpState::new(ShellStream::Stdout, None);
        let mut other = StreamPumpState::new(ShellStream::Stderr, None);
        // The secret is only half-received when a discontinuity (a budget
        // drop or the output cap) arrives.
        stream.buf.extend_from_slice(b"before-SECRET1");
        handle_stream_event(
            &writer,
            runner,
            session_id,
            task_id,
            &state_dir,
            &mut stream,
            &mut other,
            Some(ShellChunk::Gap(GapReason::Budget)),
            &in_flight,
            &lag,
        )
        .await;

        assert!(
            stream.buf.is_empty(),
            "the Gap arm must never carry a held-back buffer across the discontinuity -- \
             bytes on the far side of a gap were never actually adjacent to it in the real \
             stream"
        );
        assert!(
            lag.load(Ordering::Relaxed) > 0,
            "the discarded held-back tail must be counted as lag"
        );

        // Bytes that arrive AFTER the gap must never combine with the
        // discarded pre-gap tail to reconstitute the secret.
        stream.buf.extend_from_slice(b"23-after");
        handle_stream_event(
            &writer,
            runner,
            session_id,
            task_id,
            &state_dir,
            &mut stream,
            &mut other,
            None,
            &in_flight,
            &lag,
        )
        .await;

        let reopened = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&reopened, session_id)
            .await
            .unwrap();
        let full = concatenated_stream_bytes(
            &events,
            task_id,
            &state_dir,
            "application/vnd.roundhouse.stdout",
        );
        assert_eq!(
            full,
            b"before23-after".to_vec(),
            "the pre-gap tail must have been discarded entirely (never stored), and only the \
             genuinely gap-free segments -- \"before\" and \"23-after\" -- must ever reach a \
             blob"
        );
        assert!(
            !full.windows(9).any(|w| w == b"SECRET123"),
            "the secret must never reconstitute across the discontinuity"
        );
    }
}
