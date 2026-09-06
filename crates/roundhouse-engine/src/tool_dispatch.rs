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
//! already flags for the MCP arm's `StdioMcpTransport::spawn` stdout
//! reader. Pre-existing in
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
            Self::Tool(_) => (
                "tool_error",
                "the tool call failed".to_string(),
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
    pub shell_mode: ShellExecutionMode,
}

/// Trusted execution mode selected by the dispatch target, never by a model
/// input field. The classified string tool intentionally uses the simple
/// `execve_node` path; the legacy argv tool retains cancellation and output
/// bounds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ShellExecutionMode {
    #[default]
    Argv,
    Classified,
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
/// relative `/`-containing `program`, its containment check — never the
/// value actually stored, see [`resolve_shell_program`]) must stay inside
/// (ruling W1-R58). Nothing in the workspace today defines a per-session or
/// per-workspace filesystem root — `SessionSpec.workspace` is an opaque
/// `WorkspaceId`, not a path — so this dispatch uses the daemon process's
/// own current working directory as its stand-in: `round daemon` is meant
/// to be launched from within the project/repo it's operating on (the same
/// assumption `roundhouse-config`'s project-scope loading already makes),
/// so this is the most direct real boundary available without inventing
/// new session-wide state or touching `SessionActor::new`'s signature.
/// **This is a judgment call, not something W1-R58 ruled on directly —
/// flagged in the fix-round report for confirmation.** Read fresh on every
/// call rather than cached: nothing in this daemon ever calls
/// `std::env::set_current_dir`, so it is effectively invariant for the
/// process's lifetime, but reading it fresh costs nothing and doesn't rely
/// on that invariant silently.
///
/// **Fails closed at `/` (fix round B, finding I3 / ruling W1-R68).** A
/// root of `/` makes every `starts_with` check in [`resolve_shell_cwd`]/
/// [`resolve_shell_program`] vacuously true — measured: `root=/ cwd=/etc`
/// and `root=/ cwd=/home` both passed containment pre-fix. This is not a
/// contrived setup: a systemd unit with no `WorkingDirectory=` defaults to
/// `/`. Nothing in `roundhouse-policy` inspects a working directory at all
/// (confirmed: `grep -rn "cwd" crates/roundhouse-policy/src/` is zero
/// hits), so `resolve_shell_cwd` is the ONLY gate `cwd` ever passes through
/// — unlike `program`, where policy is still the real backstop even when
/// this boundary is weak. A vacuous boundary here is therefore
/// indistinguishable from no boundary at all, and must fail closed rather
/// than silently degrade. **A real per-session workspace root (CF-17)
/// remains the durable fix** — this is a floor, not a replacement for one.
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
            "the daemon's current working directory is '/' — refusing to use it as the shell \
             containment boundary, since that collapses cwd/program containment to no boundary \
             at all (fix round B, ruling W1-R68)"
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
        if !was_absolute {
            let root = workspace_root()?;
            if !fully_resolved.starts_with(&root) {
                return Err(ToolDispatchError::ShellProgramRejected(format!(
                    "resolved program {fully_resolved:?} is outside the workspace root {root:?}"
                )));
            }
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
            return Ok(canonical_dir.join(raw_program));
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
                    shell_mode: ShellExecutionMode::Argv,
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
            if extras.shell_mode == ShellExecutionMode::Classified {
                let node = roundhouse_policy::shell::pipeline::ResolvedNode {
                    resolved_program: cmd.program.clone(),
                    argv: cmd.argv.clone(),
                    redirections: Vec::new(),
                };
                let output = roundhouse_tools::execve_node(&node, cwd)
                    .await
                    .map_err(ToolDispatchError::Tool)?;
                let text = format!(
                    "exit_code={:?}\nstdout:\n{}\nstderr:\n{}",
                    output.exit_code,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
                return Ok(vec![ToolResultPart { text }]);
            }
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
            drain_to_end(stdout, MAX_SHELL_OUTPUT_BYTES),
            drain_to_end(stderr, MAX_SHELL_OUTPUT_BYTES),
        );
        status.map(|status| roundhouse_tools::ShellOutput {
            stdout,
            stderr,
            exit_code: status.code(),
        })
    };

    let cancel_reason = tokio::select! {
        result = completion => {
            return result.map_err(ToolDispatchError::Tool);
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
async fn drain_to_end<R: tokio::io::AsyncRead + Unpin>(io: Option<R>, cap: u64) -> Vec<u8> {
    let Some(mut io) = io else {
        return Vec::new();
    };
    use tokio::io::AsyncReadExt;

    let cap = cap as usize;
    let mut buf = Vec::new();
    let mut scratch = vec![0u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let n = match io.read(&mut scratch).await {
            Ok(0) => break, // natural EOF -- the writer closed its end
            Ok(n) => n,
            Err(_) => break,
        };
        if buf.len() < cap {
            let remaining = cap - buf.len();
            let take = remaining.min(n);
            buf.extend_from_slice(&scratch[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
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
    async fn an_extra_model_shell_command_field_cannot_select_classified_execution() {
        let dir = workspace_temp_dir();
        let cwd_str = dir.path().to_string_lossy().to_string();
        let input = serde_json::json!({
            "program": "echo",
            "argv": ["still-cancellable"],
            "cwd": cwd_str,
            "shell_command": true,
        });
        let (params, extras) = task_params_for(TaskKind::Shell, &input).unwrap();
        assert_eq!(extras.shell_mode, ShellExecutionMode::Argv);
        let parts = execute_builtin(&params, &extras, &input, None)
            .await
            .unwrap();
        assert!(parts[0].text.contains("still-cancellable"));
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
        let buf = drain_to_end(stdout, cap).await;
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
        let decision = policy.decide_sealed(&params, &ctx);
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
        let via_relative_path = resolve_shell_program("./mytool", &canonical_cwd).unwrap();

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
}
