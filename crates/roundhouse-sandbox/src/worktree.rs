//! Concrete, synchronous git-worktree materialization (Task 34, lane W5,
//! rulings W5-8/W5-22): the primitive that actually calls `git worktree
//! add`/`git worktree remove`, so that `roundhouse-flow`'s
//! `map.isolation: worktree` can give a workflow's fan-out items a real,
//! separate working directory each, instead of merely parsing to declared
//! data with nothing behind it (Phase 5 ruling P42). **Fix round 1, item
//! 5: not called "isolation" here** — see this crate's own top-level
//! module doc comment, and this module's "Config and hooks" section below,
//! for why a git worktree is a separate directory, not a confinement
//! boundary. This module has no idea what a workflow, a `map` step, or an
//! expression context is — it is two plain functions, [`add_worktree`] and
//! [`remove_worktree`], over a `repo_root` and a `worktree_path` the
//! caller supplies, exactly the same `roundhouse-flow`-never-a-dependency
//! shape [`crate::bounded_parse`] already established for this crate's
//! other spawn-a-child primitive.
//!
//! # Security: `base_ref` reaches `git` as one discrete argv element, after `--`
//!
//! `base_ref` is workflow-author-controlled text — `roundhouse-flow`'s
//! `parse/steps.rs::validate_git_ref` bounds its *shape* at parse time (no
//! control characters, no leading `-`, no `..`, etc. — see that function's
//! own doc comment for the full rule list and, importantly, what it does
//! **not** cover: what a `${{ }}` placeholder in it evaluates to at
//! runtime is not, and cannot be, validated by a parser). Neither layer is
//! a substitute for the other: parse-time shape rules reject an obviously
//! hostile *literal*, and this module's argv discipline is what keeps a
//! runtime-evaluated value — hostile or not, validated or not — from ever
//! being able to smuggle a second flag into `git`'s command line. `git
//! worktree add`'s own `--` end-of-options marker, placed immediately
//! before **both** positional arguments (`worktree_path` and `base_ref`,
//! fix round 1, item 4 — an earlier version placed it only before
//! `base_ref`, which left `worktree_path` unprotected too, code-derived
//! and therefore not exploitable today but with no reason to leave it
//! that way), is what makes that guarantee: everything after `--` is a
//! positional argument to git, never re-parsed as an option, no matter
//! what it contains (verified directly against this git binary: a
//! `base_ref` of `"--upload-pack=/tmp/evil"` after `--` is rejected by git
//! itself as `fatal: invalid reference`, not executed as a flag, and git
//! accepts `--` in the `worktree add --detach -- <path> <commit-ish>`
//! position identically for `remove --force -- <path>`). This module
//! never builds a shell string and never calls `sh -c` — `base_ref` is
//! always exactly one [`std::ffi::OsStr`] handed to one `.arg()` call.
//!
//! # Environment: `env_clear()` plus an explicit `PATH` allowlist, nothing else
//!
//! Same reasoning as [`crate::bounded_parse::run_bounded_subprocess`]
//! (ruling W5-25, finding 3, extended here per ruling W5-25's fix-round-2
//! note that a *new* spawn site in this lane's own crate does not inherit
//! that finding's "pre-existing residual" excuse): the caller of this
//! module — eventually the daemon — holds secrets like
//! `ANTHROPIC_API_KEY` in its process environment, and a `git` child (plus
//! whatever credential helper or hook `git` itself resolves and runs) has
//! no business inheriting any of it. `env_clear()` closes that.
//!
//! **The trap ruling W5-28 documents on `bounded_parse.rs` applies here
//! too, and is why this module does not simply `env_clear()` and move on.**
//! `std::process::Command` does not resolve a bare, slash-free program
//! name against the *caller's* `PATH` — it installs the cleared `envp` as
//! the child's `environ` before `execvp`, so `execvp` falls back to
//! glibc's `confstr(_CS_PATH)` default (`/bin:/usr/bin`), and `git` is
//! frequently installed somewhere else entirely (`/usr/local/bin`, a
//! Homebrew or nix prefix). This module resolves that deliberately: it
//! reads the *caller's* real `PATH` once, before clearing anything, and
//! sets it back explicitly with `.env("PATH", ..)` — never by skipping
//! `env_clear()`. `git` itself PATH-resolves its own credential helpers
//! and hooks, so this also governs those, which is a second, independent
//! reason to be explicit about `PATH` rather than to omit it and hope `git`
//! happens to live in the default path.
//!
//! No other environment variable is added back. `git worktree add`/
//! `remove` need no author identity and no `HOME` to be *supplied* — verified
//! directly (`env -i PATH="$PATH" git worktree add --detach <path> -- <ref>`
//! and the matching `remove` both succeed against a repository this process
//! owns). If a future caller of this module needs `git` to read
//! `~/.gitconfig` (a `safe.directory` entry, say), that is an explicit
//! addition to make there, not something this module provides speculatively.
//!
//! **This says nothing about what `git` reads and executes on its own,
//! regardless of environment — see "Config and hooks" below, which fix
//! round 1 added after an earlier version of this paragraph conflated the
//! two, and which fix round 2 corrected again after fix round 1's own
//! "Fix:" heading overclaimed what it actually closed.**
//!
//! # Config and hooks: a partial mitigation, not a fix (Task 34 fix rounds 1 and 2)
//!
//! A git worktree shares one `.git/config`, one `hooksPath`, and the
//! repository's own tracked `.gitattributes` with the repository it was
//! created from — worktrees are not independent repositories, and **this
//! module does not make them one.** This section used to be titled "`-c`
//! overrides ... close this" and said so under a "Fix:" heading; fix round
//! 2 corrected that after the security lens reproduced a second route past
//! it. **Read this alongside this crate's own top-level module doc
//! comment, which is the accurate framing: a git worktree is a separate
//! directory, not a security boundary. This section is the specific,
//! mechanical detail behind that same claim, not a competing one.**
//!
//! `git worktree add`/`remove` genuinely **run** repo-local hooks
//! (`post-checkout` on `add`, for one) as the invoking user, with whatever
//! `PATH` the process has, **regardless of `env_clear()`** — that bounds
//! what `git` inherits from *this process's environment*, not what `git`
//! reads from the repository's own on-disk config, which is a different
//! trust boundary entirely. Reproduced directly against this git binary: a
//! repo-local `core.hooksPath` pointing at a script touches a marker file
//! on a plain `env -i PATH="$PATH" git worktree add --detach -- <path>
//! <ref>`, with no environment variable involved at all.
//!
//! The security consequence is a real, chained one, not merely a stray
//! hook firing: because a worktree's `.git` is a write-through pointer back
//! at the *shared* config, anything with a shell inside one worktree (an
//! `agent`/`tool: shell` inner step, say) can write to that shared config
//! and have it apply to **every subsequent `git worktree add`/`remove`
//! call against that same `repo_root`** — including this module's own
//! calls for the *next* fan-out item. That is a cross-item escape from the
//! boundary a reader might otherwise assume this feature provides.
//!
//! **Partial mitigation, four `-c` overrides on every invocation, applied
//! to that one invocation only — never written to the repository's own
//! config file:** `-c core.hooksPath=/dev/null` (no hook path resolves to
//! anything runnable), `-c core.fsmonitor=false` (`core.fsmonitor` can also
//! name an arbitrary executable git runs), `-c core.attributesFile=/dev/null`
//! (closes one narrow variant — see exactly what it does and does not cover
//! below — reproduced separately), and `-c protocol.allow=never` (defense
//! in depth against any implicit network operation this or a future call
//! shape might trigger). None of the four change `add`/`remove`'s own
//! observable behavior — verified directly.
//!
//! **What remains open, named rather than left for a reader to
//! rediscover: `filter.<name>.smudge` (and, by the same mechanism,
//! `filter.<name>.clean`), through *any* of three independent routes —
//! fix round 3 corrected an earlier version of this section that named only
//! the first and stated the second imprecisely.**
//!
//! 1. **A repository-tracked `.gitattributes`** declaring `* filter=lfs` —
//!    ubiquitous in real-world repositories using Git LFS.
//! 2. **`.git/info/attributes`** — a file inside the repository's shared
//!    common `.git` directory (not inside any one worktree's own checkout),
//!    governed by **neither** `core.attributesFile` **nor** anything
//!    tracked in the tree. Reproduced directly, with **no** `.gitattributes`
//!    file anywhere in the tree at all. **Precision, corrected in the final
//!    round after an earlier version of this line said the write "is enough
//!    on its own":** it is enough on its own only where the repository
//!    already carries a matching `filter.<name>.smudge` entry in its local
//!    config. Measured: `* filter=evil` in `.git/info/attributes` with no
//!    `filter.*` config entry produced **0** executions; adding the config
//!    entry produced **1**. So this route needs **two** writes on a bare
//!    repository — but only **one** on a repository where such an entry
//!    already exists, which `git lfs install --local` writes as a matter of
//!    course, so the realistic case this section warns about stands
//!    unchanged. What is distinctive about route 2 is not the write count:
//!    it is that the attributes half lives outside both
//!    `core.attributesFile`'s reach and the tracked tree, so neither the
//!    `-c` override above nor a tree-level review sees it.
//! 3. A `core.attributesFile` entry written into the repository's own
//!    **shared, local** `.git/config` — the one thing `-c
//!    core.attributesFile=/dev/null` above actually closes, by overriding
//!    it for this invocation. (An earlier version of this section called
//!    this route "a *global* attributes file"; that was imprecise —
//!    `env_clear()` above means this module's own invocations never had a
//!    `$HOME`, so `~/.config/git/attributes` was never reachable through
//!    them in the first place. The real route this `-c` flag blocks is the
//!    *shared-config* write, identical in shape to the `filter.*` config
//!    write route 1 relies on.)
//!
//! One attacker write of `git config --local filter.lfs.smudge
//! /tmp/evil.sh` — against a repository whose tracked `.gitattributes`
//! already declares `* filter=lfs`, i.e. route 1, which is the ubiquitous
//! real-world case — causes the **next** `add_worktree` call, with this
//! module's full current argv, to execute `/tmp/evil.sh` during the
//! checkout `worktree add` performs by design. Route 2 reaches the same
//! place with one write against a repository that already has a `filter.*`
//! driver configured, and two otherwise (see route 2 above for the
//! measurement). Reproduced directly for all three routes, against
//! both the pre- and post-`core.attributesFile=/dev/null` argv where
//! applicable — routes 1 and 2 fire under **both**. There is no `filter.*`
//! wildcard `-c` override. The root cause — the shared, write-through
//! `.git/config` (and shared common `.git` directory) a worktree cannot be
//! given its own copy of — is not something any `-c` flag on this
//! module's own invocations can close; closing it for real needs a
//! mechanism this module does not have (a per-worktree config, or refusing
//! to run inner steps with a shell inside a materialized worktree at all).
//! Recorded here as a known, open route, not chased further this round.
//!
//! # What this bounds, and what it does not (final round, item A2)
//!
//! **An earlier version of this section declined any bound at all, on the
//! grounds that "there is no untrusted-input resource-exhaustion shape
//! here". That could not be true alongside the section above**, which
//! establishes the opposite: one attacker write to the shared
//! `.git/config` or `.git/info/attributes` makes the **next**
//! `add_worktree` call run attacker-chosen code during checkout. Both
//! final whole-branch review lenses found the contradiction
//! independently.
//!
//! The consequence does not even depend on that route ever being closed.
//! `Command::output()` returns only when **both** pipes reach EOF, so a
//! child that forks and backgrounds anything holding stdout blocks it
//! forever — the ordinary, non-adversarial `sh -c 'thing &'` shape. In
//! `roundhouse-flow` that wedges the executor thread running
//! `dispatch_map_step`, the item's `WorktreeGuard` never releases, and the
//! identical hang is reachable from `WorktreeGuard::drop` mid-unwind,
//! where it cannot even be reported.
//!
//! So `run_program` now spawns the child into **its own process group**
//! and enforces a wall-clock deadline (`WORKTREE_WALL_LIMIT`), tearing
//! the whole group down on **every** path out of the wait — including the
//! one where the direct child exited cleanly, which is precisely the
//! backgrounding shape above and the same conclusion ruling W5-26 reached
//! for [`crate::bounded_parse::run_bounded_subprocess`]. Descendants do
//! not outlive a call. Stdout and stderr are read capped-and-discarding so
//! a hook that floods output cannot turn the deadline into unbounded
//! memory growth.
//!
//! **What is deliberately still not bounded here, and why it differs from
//! `run_bounded_subprocess`:** no `RLIMIT_CPU`. That primitive bounds CPU
//! because it hands a child **untrusted third-party YAML** with a
//! genuinely adversarial cost profile (quadratic-cost anchor/alias
//! expansion) and a legitimate parse is cheap. Here a legitimate
//! `git worktree add` on a large repository is honestly CPU-heavy — a
//! checkout of every tracked file — so CPU is the wrong axis and a CPU
//! bound would fail real work. Wall-clock is the axis that separates
//! "still checking out" from "wedged", and it is generous for that reason.
//!
//! This module still does not route through
//! [`crate::bounded_parse::run_bounded_subprocess`] itself, which would
//! otherwise be preferable to two spawn conventions in one crate: that
//! function takes neither a working directory nor an environment (it is
//! `env_clear()` with no `PATH` — its own doc comment names "Task 34 is
//! the live case" for exactly this), and its `HelperCrashed` carries the
//! exit status as a `String`, where [`WorktreeError::CommandFailed`] and
//! [`WorktreeError::safe_summary`] hold a real `ExitStatus`. Adding two
//! parameters across thirteen call sites and weakening that type to reuse
//! the wait loop is a worse trade than the ~40 lines below.
//!
//! This module also never validates that `worktree_path` sits under
//! `repo_root`, or that the two calls forming one worktree's lifecycle
//! (`add_worktree` then `remove_worktree`) share the same path — that
//! discipline is the caller's, by contract (see each function's own doc
//! comment). `roundhouse-flow`'s adapter is the one caller today, and it
//! generates `worktree_path` itself; nothing here re-derives or validates
//! it, exactly as [`crate::bounded_parse::run_bounded_subprocess`] never
//! validates the `program`/`args` its own caller supplies.

use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// How long any one `git` invocation this module makes may run before its
/// whole process group is killed and the call fails with
/// [`WorktreeError::TimedOut`].
///
/// Deliberately generous: a legitimate `git worktree add` on a large
/// repository does a full checkout of every tracked file, and an LFS smudge
/// filter on top of that can take minutes on a slow network. This bound
/// exists to separate "wedged forever" from "still working", not to
/// second-guess how long a real checkout takes — see the module doc
/// comment's "What this bounds, and what it does not".
const WORKTREE_WALL_LIMIT: Duration = Duration::from_secs(300);

/// How often the wait loop polls the child. Same interval, for the same
/// reason (responsiveness against wakeup cost), as `bounded_parse`'s own
/// poll loop.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// How much of the child's stdout and stderr this module keeps. `git
/// worktree add`/`remove` emit a line or two; the cap exists so a
/// repository-controlled hook that floods a pipe cannot turn the wall-clock
/// bound into unbounded memory growth in this process.
const OUTPUT_CAP: usize = 64 * 1024;

/// Everything that can go wrong materializing or releasing a git worktree.
#[derive(Debug, thiserror::Error)]
pub enum WorktreeError {
    /// This process's own environment has no `PATH` at all, so there is
    /// nothing to hand the child for resolving `git` (or anything `git`
    /// itself resolves, e.g. a credential helper). Never silently falls
    /// back to spawning `git` under glibc's bare default path — see the
    /// module doc comment's "Environment" section for why that would be a
    /// silent, host-dependent failure mode rather than a loud one.
    #[error(
        "cannot resolve `git`: this process has no `PATH` in its own environment to hand the child"
    )]
    NoPath,
    /// The child could not be spawned at all (not found, not executable, …).
    #[error("failed to spawn `{program} {}` in {}: {source}", .args.join(" "), .repo_root.display())]
    Spawn {
        program: String,
        repo_root: PathBuf,
        args: Vec<String>,
        #[source]
        source: std::io::Error,
    },
    /// The child ran and exited non-zero.
    #[error(
        "`{program} {}` in {} exited with {status}: {stderr}",
        .args.join(" "),
        .repo_root.display()
    )]
    CommandFailed {
        program: String,
        repo_root: PathBuf,
        args: Vec<String>,
        status: std::process::ExitStatus,
        stderr: String,
    },
    /// The child (or something it forked) was still holding the call open
    /// once `WORKTREE_WALL_LIMIT` elapsed, and its whole process group was
    /// killed — see the module doc comment's "What this bounds" section.
    ///
    /// Separate from [`WorktreeError::CommandFailed`] rather than folded
    /// into it: there is no `ExitStatus` to report on this path (the child
    /// never produced one of its own), and inventing one would misreport a
    /// bound firing as `git` having decided something.
    ///
    /// Carries no text from outside this module, so
    /// [`WorktreeError::safe_summary`] has nothing to withhold from it.
    #[error(
        "`{program}` in {} exceeded the {wall_limit:?} wall-clock bound and its process group \
         was killed",
        .repo_root.display()
    )]
    TimedOut {
        program: String,
        repo_root: PathBuf,
        wall_limit: std::time::Duration,
    },
}

impl WorktreeError {
    /// A rendering that withholds every piece of text this module did not
    /// itself choose — the argv this call passed (which can contain
    /// `base_ref`), `git`'s own stderr, and the OS-level spawn error text —
    /// keeping only this crate's own fixed vocabulary: which variant fired,
    /// `program`/`repo_root` (never secret — this module's own caller-supplied,
    /// non-workflow-derived values), and, for [`WorktreeError::CommandFailed`],
    /// the exit status.
    ///
    /// # Why this exists (Task 34 fix round 3, ruling W5-36, superseding fix
    /// round 2's needle-based approach)
    ///
    /// `Display`'s ordinary rendering embeds `args`/`stderr`/`source`
    /// verbatim, and a caller that resolved `base_ref` from a workflow
    /// expression cannot assume those are safe to persist — `base_ref` may
    /// be secret-derived. Fix round 2 tried to close that by adding the
    /// resolved `base_ref` text as an extra needle to scrub out of the
    /// assembled message; fix round 3's security lens reproduced two ways
    /// that scrub misses: `git` does not always **echo a copy** of what it
    /// was given — `@{upstream}`-style branch-mark syntax makes `git` die
    /// mid-interpretation and report only the prefix before it (so the
    /// needle, the whole value, never matches the truncated echo), and
    /// `git`'s own `vreportf` stderr buffer silently truncates values past
    /// ~4KB (so a long secret's tail survives as a shorter, still-sensitive
    /// prefix a needle keyed on the *whole* value cannot match either).
    /// **No exact-match scrub can close a lossy transform** — the fix is to
    /// never scrub `git`'s free text at all when it might contain
    /// secret-derived material, and show this instead.
    pub fn safe_summary(&self) -> String {
        match self {
            WorktreeError::NoPath => {
                // No external free text of any kind — this variant's
                // ordinary `Display` is already exactly this crate's own
                // fixed sentence, so there is nothing to withhold.
                self.to_string()
            }
            WorktreeError::Spawn {
                program, repo_root, ..
            } => {
                format!(
                    "Spawn: failed to spawn `{program}` in {} (the OS's own error text is \
                     withheld here because it may contain secret-derived material)",
                    repo_root.display()
                )
            }
            WorktreeError::TimedOut {
                program,
                repo_root,
                wall_limit,
            } => {
                // Every field here is this module's own: the program name
                // it chose, the caller-supplied `repo_root`, and a constant.
                // No argv, no stderr — nothing to withhold.
                format!(
                    "TimedOut: `{program}` in {} exceeded the {wall_limit:?} wall-clock bound",
                    repo_root.display()
                )
            }
            WorktreeError::CommandFailed {
                program,
                repo_root,
                status,
                ..
            } => {
                format!(
                    "CommandFailed: `{program}` in {} exited with {status} (its stderr and \
                     argv are withheld here because they may contain secret-derived material)",
                    repo_root.display()
                )
            }
        }
    }
}

/// Runs `git` with `args` inside `repo_root`. Thin wrapper around
/// [`run_program`] naming `"git"` — see that function's own doc comment for
/// the env-handling contract, which is what actually matters here.
fn run_git(repo_root: &Path, args: &[&OsStr]) -> Result<(), WorktreeError> {
    run_program(repo_root, "git", args).map(|_stdout| ())
}

/// Runs `program` with `args` inside `repo_root`, under `env_clear()` plus
/// an explicit `PATH` (see the module doc comment's "Environment" section
/// for why both are required together), returning its captured stdout on
/// success. Synchronous, and bounded by [`WORKTREE_WALL_LIMIT`] — see the
/// module doc comment's "What this bounds, and what it does not" for why
/// this primitive spawns and waits by hand rather than calling
/// `Command::output()`, and why a wall-clock bound plus a process-group
/// teardown is the right pair here where `run_bounded_subprocess` also
/// bounds CPU. [`run_git`] (the only non-test caller) discards the returned
/// bytes — `git worktree add`/`remove`'s stdout carries nothing this crate
/// needs.
///
/// Generic over `program` (rather than hard-coding `"git"` inline in
/// [`run_git`]) purely so this module's own unit tests
/// (`tests::a_child_cannot_see_the_parents_environment` below) can drive
/// the exact same env-handling code path with `sh -c` instead of `git`,
/// and actually inspect what the child saw — `git` has no "print your own
/// environment" mode to assert against directly.
fn run_program(repo_root: &Path, program: &str, args: &[&OsStr]) -> Result<Vec<u8>, WorktreeError> {
    run_program_bounded(repo_root, program, args, WORKTREE_WALL_LIMIT)
}

/// [`run_program`] with the wall-clock bound as a parameter, so this
/// module's own tests can drive the bound in seconds rather than minutes.
/// Nothing else about the two differs — production always goes through
/// [`run_program`] and therefore always uses [`WORKTREE_WALL_LIMIT`].
fn run_program_bounded(
    repo_root: &Path,
    program: &str,
    args: &[&OsStr],
    wall_limit: Duration,
) -> Result<Vec<u8>, WorktreeError> {
    let path = std::env::var_os("PATH").ok_or(WorktreeError::NoPath)?;

    let mut command = Command::new(program);
    command.current_dir(repo_root);
    command.args(args);
    // See the module doc comment's "Environment" section: `env_clear()`
    // keeps this child (and anything IT execs — credential helpers, hooks)
    // from inheriting this process's whole environment, and the explicit
    // `.env("PATH", ..)` right after is what keeps that from also breaking
    // `git` itself when it does not happen to live on glibc's bare default
    // path.
    command.env_clear();
    command.env("PATH", &path);
    // `Command::output()` would set all three of these itself. Spawning by
    // hand does not, so they are explicit here — and `stdin(null)`
    // especially: inheriting the daemon's stdin would let a `git`
    // credential prompt block this call forever, which is a *new* stall of
    // exactly the kind this function now exists to prevent.
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    // Ruling W5-25's finding 2 and ruling W5-26, applied to this module's
    // spawn site: makes the child the leader of its own new process group
    // (pgid == its own pid) so the teardown below can reach everything it
    // forked, not just the one process `Child::kill()` names. Safe Rust —
    // no `unsafe` here, so `probe.rs` stays this crate's sole carve-out.
    // Gated the same way `bounded_parse` gates it (ruling W5-3's off-Linux
    // convention): off Linux the wall-clock bound still applies to the
    // direct child, just without group-wide reach.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let arg_strings: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    let mut child = command.spawn().map_err(|source| WorktreeError::Spawn {
        program: program.to_string(),
        repo_root: repo_root.to_path_buf(),
        args: arg_strings.clone(),
        source,
    })?;

    // Captured once, at spawn, rather than re-read at each kill site — the
    // same discipline (and for the same reason) as ruling W5-26's capture in
    // `bounded_parse`: every kill below is provably aimed at the group this
    // call created, not at whatever `child.id()` might return later.
    let pgid = child.id() as i32;
    debug_assert!(pgid > 0, "pgid must be a real, positive process-group id");

    let mut stdout_pipe = child.stdout.take().expect("stdout was requested as piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr was requested as piped");

    let (status, stdout_buf, stderr_buf) = thread::scope(|scope| {
        // Both pipes are read concurrently with the wait: a child that
        // fills one while this thread waits on the other would otherwise
        // deadlock, which is the same reason `bounded_parse` reads on
        // scoped threads.
        let stdout_reader = scope.spawn(|| read_capped_discarding(&mut stdout_pipe, OUTPUT_CAP));
        let stderr_reader = scope.spawn(|| read_capped_discarding(&mut stderr_pipe, OUTPUT_CAP));

        let status = wait_with_wall_limit(&mut child, pgid, wall_limit);

        // Joined only after the wait has torn the process group down, so
        // the readers see EOF even when a descendant inherited a pipe.
        (
            status,
            stdout_reader.join().unwrap_or_default(),
            stderr_reader.join().unwrap_or_default(),
        )
    });

    let Some(status) = status else {
        return Err(WorktreeError::TimedOut {
            program: program.to_string(),
            repo_root: repo_root.to_path_buf(),
            wall_limit,
        });
    };

    if !status.success() {
        return Err(WorktreeError::CommandFailed {
            program: program.to_string(),
            repo_root: repo_root.to_path_buf(),
            args: arg_strings,
            status,
            stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
        });
    }
    Ok(stdout_buf)
}

/// Polls `child` until it exits on its own or `wall_limit` elapses.
/// `Some(status)` is the child's own exit status; `None` means the bound
/// fired and the child (with its whole process group) was killed.
///
/// **Tears the process group down on both paths, including the one where
/// the direct child exited cleanly.** That second case is the whole point,
/// and it is ruling W5-26's finding transplanted to this module: a child
/// that forks, hands the descendant its inherited stdout, and exits itself
/// (`sh -c 'thing &'` — an ordinary backgrounding shell, no adversarial
/// behaviour required) leaves that orphan holding the pipe's write end with
/// nothing left to close it, and the reader in [`run_program_bounded`]
/// waits forever for an EOF that never comes. Killing the group is what
/// closes those inherited descriptors. Descendants do not outlive a call.
///
/// **Accepted residual, the same one `bounded_parse::wait_bounded`
/// documents:** `try_wait()` reaps the direct child before the group kill
/// is issued, so the kill targets a pgid whose leader is already gone. A
/// PID recycled into a new group leader inside that microseconds-wide
/// window would be signalled instead. Closing it needs a different wait
/// primitive (`waitid(..., WNOWAIT)`), not a bigger kill.
///
/// **Second accepted residual:** a descendant that calls `setsid` itself
/// leaves the group and escapes the kill, which then leaves the reader
/// blocked until... nothing. This is why the wall-clock bound and the group
/// kill are both needed and neither is sufficient alone — but a `setsid`
/// descendant holding a pipe still blocks the join after the timeout fires.
/// Closing that needs a PID namespace or cgroup, which this module does not
/// have; it is the same boundary `bounded_parse` records.
fn wait_with_wall_limit(child: &mut Child, pgid: i32, wall_limit: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            kill_process_group_or_child(child, pgid);
            return Some(status);
        }
        if start.elapsed() >= wall_limit {
            kill_process_group_or_child(child, pgid);
            // Reap, so a killed child is never left a zombie.
            let _ = child.wait();
            return None;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Kills `child`'s whole process group on Linux, falling back to the direct
/// child elsewhere — the same split, for the same reason, as
/// `bounded_parse`'s own kill helper (ruling W5-3's off-Linux convention:
/// no process-group reach off Linux, so the direct kill carries the load).
fn kill_process_group_or_child(child: &mut Child, pgid: i32) {
    #[cfg(target_os = "linux")]
    {
        // The group, not `child` itself, is what needs signalling here.
        let _ = &child;
        crate::probe::kill_process_group(pgid);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pgid;
        let _ = child.kill();
    }
}

/// Reads `pipe` to EOF, keeping at most `cap` bytes and discarding the
/// rest.
///
/// Draining rather than stopping at the cap matters: a reader that simply
/// stopped would leave the child blocked on a full pipe until the wall
/// limit, turning a chatty hook into a guaranteed timeout. Capping rather
/// than reading it all matters too: with a multi-minute wall limit, a hook
/// that floods stdout would otherwise be an unbounded-memory shape this
/// change itself introduced. Same shape as
/// `bounded_parse::read_stderr_draining`, which is private to that module.
///
/// The cap never becomes a verdict: nothing here can fail the call or kill
/// the child. It bounds what this process buffers, nothing more — the same
/// distinction ruling W5-28 drew between a caller-declared bound and an
/// internal capture-buffer size.
fn read_capped_discarding(pipe: &mut impl Read, cap: usize) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => return kept,
            Ok(n) => {
                if kept.len() < cap {
                    let room = cap - kept.len();
                    kept.extend_from_slice(&chunk[..n.min(room)]);
                }
            }
        }
    }
}

/// Creates a real git worktree at `worktree_path`, detached at `base_ref`,
/// against the repository rooted at `repo_root`.
///
/// `base_ref` crosses to `git` as exactly one argv element, after a `--`
/// separator — see the module doc comment's "Security" section. `--detach`
/// is unconditional: fan-out items materializing worktrees from the same
/// `base_ref` (the common case — many `map` items reviewing different
/// PRs but starting from the same `main`) would otherwise collide on `git`
/// refusing to check the same branch out twice, and this primitive has no
/// use for a named branch per item regardless.
pub fn add_worktree(
    repo_root: &Path,
    worktree_path: &Path,
    base_ref: &str,
) -> Result<(), WorktreeError> {
    run_git(
        repo_root,
        &[
            // Fix rounds 1 and 2: four discrete `-c` overrides, applied to
            // *this* invocation only (never written to the repo's own
            // config) — see the module doc comment's "Config and hooks"
            // section for what these do and do not close (a partial
            // mitigation, not a fix — `filter.<name>.smudge` is a known,
            // still-open route through the same shared config).
            OsStr::new("-c"),
            OsStr::new("core.hooksPath=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("core.fsmonitor=false"),
            OsStr::new("-c"),
            OsStr::new("core.attributesFile=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("protocol.allow=never"),
            OsStr::new("worktree"),
            OsStr::new("add"),
            OsStr::new("--detach"),
            // Fix round 1, item 4: `--` now precedes BOTH positionals, not
            // just `base_ref` — see the module doc comment's "Security"
            // section for why `worktree_path` needed it too even though
            // nothing exploits it today.
            OsStr::new("--"),
            worktree_path.as_os_str(),
            OsStr::new(base_ref),
        ],
    )
}

/// Removes a worktree previously created by [`add_worktree`]. **Must be
/// called with exactly the `worktree_path` that call was given** — this
/// function does not, and cannot, verify that on its own; see the module
/// doc comment. `--force` because a `map` item's inner steps may have left
/// untracked or modified files behind (nothing about this feature commits
/// on the caller's behalf), and cleanup must not fail just because the
/// item did real work in the worktree before it completed or failed.
pub fn remove_worktree(repo_root: &Path, worktree_path: &Path) -> Result<(), WorktreeError> {
    run_git(
        repo_root,
        &[
            // See `add_worktree`'s identical `-c` overrides and the module
            // doc comment's "Config and hooks" section.
            OsStr::new("-c"),
            OsStr::new("core.hooksPath=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("core.fsmonitor=false"),
            OsStr::new("-c"),
            OsStr::new("core.attributesFile=/dev/null"),
            OsStr::new("-c"),
            OsStr::new("protocol.allow=never"),
            OsStr::new("worktree"),
            OsStr::new("remove"),
            OsStr::new("--force"),
            OsStr::new("--"),
            worktree_path.as_os_str(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `bounded_parse.rs`'s own
    /// `a_child_cannot_see_the_parents_environment` (see that test's doc
    /// comment for why mutating a real, uniquely-named env var in a test is
    /// accepted practice in this crate already — no other test reads this
    /// name, and env vars are process-, not thread-, scoped, so this is safe
    /// under `cargo test`'s default multi-threaded execution). This module
    /// has no equivalent of that test through `git` itself (`git` has no
    /// "print your own environment" mode), so it drives the exact same
    /// `run_program` code path [`run_git`] uses, naming `sh` instead of
    /// `git` — see [`run_program`]'s own doc comment for why it is generic
    /// over the program name for exactly this reason.
    #[test]
    fn a_child_cannot_see_the_parents_environment() {
        const NAME: &str = "ROUNDHOUSE_SANDBOX_WORKTREE_ENV_CLEAR_PROBE";
        std::env::set_var(NAME, "a-secret-the-child-must-never-see");
        assert_eq!(
            std::env::var(NAME).as_deref(),
            Ok("a-secret-the-child-must-never-see"),
            "the parent must actually hold this variable, or the assertion below \
             would pass without proving anything"
        );

        let repo_root = std::env::temp_dir();
        let result = run_program(
            &repo_root,
            "sh",
            &[
                OsStr::new("-c"),
                OsStr::new("printf %s \"${ROUNDHOUSE_SANDBOX_WORKTREE_ENV_CLEAR_PROBE:-<unset>}\""),
            ],
        );
        std::env::remove_var(NAME);
        assert_eq!(
            result.expect("the probe child must run and exit cleanly"),
            b"<unset>".to_vec(),
            "the child inherited the parent's environment — `env_clear()` is not being \
             applied, and any secret in the daemon's environment (ANTHROPIC_API_KEY and \
             friends) is exposed to every `git` child this module spawns"
        );
    }

    /// Final round, item C3: [`WorktreeError::safe_summary`]'s `NoPath` and
    /// `Spawn` arms had no direct test — they were exercised only
    /// indirectly, through the flow crate's integration tests, which drive
    /// the `CommandFailed` arm for real. The match is exhaustive with no
    /// wildcard, so a new variant cannot silently default to permissive;
    /// this makes the guarantee local and self-evident as well.
    ///
    /// Every field a variant carries that this module did **not** itself
    /// choose gets the same marker planted in it. `program` and `repo_root`
    /// are deliberately excluded: they are this module's own hardcoded
    /// program name and its caller-supplied repository root, never
    /// workflow-derived, and `safe_summary` shows both on purpose.
    #[test]
    fn safe_summary_never_echoes_text_from_outside_this_module_for_any_variant() {
        use std::os::unix::process::ExitStatusExt;

        const MARKER: &str = "MARKER-SECRET-DERIVED-TEXT";
        let repo_root = PathBuf::from("/tmp/some-repo");
        let variants = [
            WorktreeError::NoPath,
            WorktreeError::Spawn {
                program: "git".to_string(),
                repo_root: repo_root.clone(),
                args: vec![MARKER.to_string()],
                source: std::io::Error::other(MARKER),
            },
            WorktreeError::TimedOut {
                program: "git".to_string(),
                repo_root: repo_root.clone(),
                wall_limit: Duration::from_secs(1),
            },
            WorktreeError::CommandFailed {
                program: "git".to_string(),
                repo_root: repo_root.clone(),
                args: vec![MARKER.to_string()],
                status: std::process::ExitStatus::from_raw(128 << 8),
                stderr: format!("fatal: invalid reference: {MARKER}"),
            },
        ];

        for error in &variants {
            let summary = error.safe_summary();
            assert!(
                !summary.contains(MARKER),
                "safe_summary() leaked text from outside this module: {summary}"
            );
            assert!(
                !summary.is_empty(),
                "every variant must still say something identifiable"
            );
        }

        // The marker must genuinely be reachable through the ordinary
        // rendering, or the loop above would pass without proving anything
        // (three of these four variants would leak it via `Display`).
        let leaking = variants
            .iter()
            .filter(|e| e.to_string().contains(MARKER))
            .count();
        assert_eq!(
            leaking, 2,
            "expected `Spawn` and `CommandFailed`'s own Display to embed the marker, so \
             the assertions above are testing something real"
        );
    }

    /// Final round, item A2 — the reason this module stopped using
    /// `Command::output()`. Both final whole-branch review lenses found this
    /// independently, and it is ruling W5-26's finding transplanted from
    /// `bounded_parse` to this module's own spawn site.
    ///
    /// `sh -c 'sleep 30 &'` backgrounds a descendant that inherits the
    /// stdout pipe's write end, then the shell itself exits 0 immediately
    /// (no foreground command is left to run) — leaving that descendant
    /// holding the pipe open with nothing left to close it. `output()`
    /// returns only when both pipes reach EOF, so pre-fix the call sat there
    /// for as long as the descendant lived. In `roundhouse-flow` that wedges
    /// the executor thread running `dispatch_map_step`, the item's
    /// `WorktreeGuard` never releases, and the same hang is reachable from
    /// `WorktreeGuard::drop` mid-unwind where it cannot even be reported.
    ///
    /// Shaped like `tests/bounded_parse.rs`'s sibling hang test: the call
    /// runs on its own thread under a **hard, test-level** `recv_timeout`
    /// ceiling, deliberately independent of the primitive's own
    /// `wall_limit` — the defect under test is "the bound never fires", so
    /// ending the test with that same bound would prove nothing. A
    /// regression fails at the ceiling rather than wedging the suite; the
    /// leaked thread is reaped when the test binary exits.
    ///
    /// **Verified by removal:** with the group kill deleted from
    /// `wait_with_wall_limit`'s exited path, this call blocks until the
    /// orphaned `sleep 30` exits on its own and the test fails at the 10s
    /// ceiling.
    #[test]
    fn a_backgrounded_descendant_cannot_wedge_the_call_when_the_direct_child_exits_cleanly() {
        let repo_root = std::env::temp_dir();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = run_program_bounded(
                &repo_root,
                "sh",
                &[OsStr::new("-c"), OsStr::new("sleep 30 &")],
                Duration::from_secs(5),
            );
            // The receiver is gone if the ceiling below already fired —
            // ignore the send failure rather than panicking on this thread.
            let _ = tx.send(result);
        });

        let result = rx.recv_timeout(Duration::from_secs(10)).expect(
            "run_program must return well within 10s even when the direct child exits \
             cleanly while a backgrounded descendant still holds the stdout pipe open — \
             a hang here is the `Command::output()` wedge item A2 closed",
        );
        assert_eq!(
            result.expect("a cleanly-exiting child must still succeed once its group is torn down"),
            Vec::<u8>::new(),
            "the shell itself writes nothing to stdout; expected empty stdout, not a hang"
        );
    }

    /// The other half of item A2's bound: a child that simply never exits is
    /// killed once `wall_limit` elapses and reported as
    /// [`WorktreeError::TimedOut`] — never as a `CommandFailed` with an
    /// invented exit status, and never as a hang.
    ///
    /// The `recv_timeout` ceiling is again the real assertion (a regression
    /// fails the suite instead of hanging CI); the returned variant is what
    /// pins the behaviour, so no wall-clock number is asserted beyond it.
    #[test]
    fn a_child_that_never_exits_is_killed_at_the_wall_limit_and_reported_as_timed_out() {
        let repo_root = std::env::temp_dir();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = run_program_bounded(
                &repo_root,
                "sh",
                &[OsStr::new("-c"), OsStr::new("sleep 30")],
                Duration::from_secs(2),
            );
            let _ = tx.send(result);
        });

        let result = rx.recv_timeout(Duration::from_secs(15)).expect(
            "a child that never exits must be killed at the wall limit, not waited on \
             forever",
        );
        assert!(
            matches!(result, Err(WorktreeError::TimedOut { .. })),
            "expected a TimedOut error, got {result:?}"
        );
    }

    /// `run_program` still resolves `PATH` for real (rather than leaving the
    /// child unable to find `sh` at all) — the counterpart to the test
    /// above, pinning that `env_clear()` does not also break the one
    /// variable this module deliberately keeps.
    #[test]
    fn the_child_can_still_resolve_its_own_program_via_the_real_path() {
        let repo_root = std::env::temp_dir();
        let result = run_program(&repo_root, "sh", &[OsStr::new("-c"), OsStr::new("exit 0")]);
        assert!(result.is_ok(), "expected success, got {result:?}");
    }
}
