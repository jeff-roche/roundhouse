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
//!    file anywhere in the tree at all: `* filter=evil` written there is
//!    enough on its own.
//! 3. A `core.attributesFile` entry written into the repository's own
//!    **shared, local** `.git/config` — the one thing `-c
//!    core.attributesFile=/dev/null` above actually closes, by overriding
//!    it for this invocation. (An earlier version of this section called
//!    this route "a *global* attributes file"; that was imprecise —
//!    `env_clear()` above means this module's own invocations never had a
//!    `$HOME`, so `~/.config/git/attributes` was never reachable through
//!    them in the first place. The real route this `-c` flag blocks is the
//!    *shared-config* write, identical in shape to every other single-write
//!    primitive this section describes.)
//!
//! One attacker write of `git config --local filter.lfs.smudge
//! /tmp/evil.sh` (or the `.git/info/attributes` write above, which needs no
//! companion `filter.*` config write reachable through the tree at all)
//! causes the **next** `add_worktree` call, with this module's full current
//! argv, to execute `/tmp/evil.sh` during the checkout `worktree add`
//! performs by design. Reproduced directly for all three routes, against
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
//! # What this does not attempt
//!
//! No CPU/wall-clock/output-size bound, unlike
//! [`crate::bounded_parse::run_bounded_subprocess`]. That primitive exists
//! because `roundhouse-flow` hands a bounded subprocess **untrusted
//! third-party YAML** to deserialize, with a genuinely adversarial cost
//! profile (quadratic-cost anchor/alias expansion). `git worktree add`/
//! `remove` run against a repository this process itself manages, with
//! fixed, small argument lists this module constructs — there is no
//! untrusted-input resource-exhaustion shape here to bound against, and
//! adding one would just be unexercised complexity.
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
use std::path::{Path, PathBuf};
use std::process::Command;

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
/// success. Synchronous; no bound of any kind — see the module doc
/// comment's "What this does not attempt". [`run_git`] (the only non-test
/// caller) discards the returned bytes — `git worktree add`/`remove`'s
/// stdout carries nothing this crate needs.
///
/// Generic over `program` (rather than hard-coding `"git"` inline in
/// [`run_git`]) purely so this module's own unit tests
/// (`tests::a_child_cannot_see_the_parents_environment` below) can drive
/// the exact same env-handling code path with `sh -c` instead of `git`,
/// and actually inspect what the child saw — `git` has no "print your own
/// environment" mode to assert against directly.
fn run_program(repo_root: &Path, program: &str, args: &[&OsStr]) -> Result<Vec<u8>, WorktreeError> {
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

    let arg_strings: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();

    let output = command.output().map_err(|source| WorktreeError::Spawn {
        program: program.to_string(),
        repo_root: repo_root.to_path_buf(),
        args: arg_strings.clone(),
        source,
    })?;

    if !output.status.success() {
        return Err(WorktreeError::CommandFailed {
            program: program.to_string(),
            repo_root: repo_root.to_path_buf(),
            args: arg_strings,
            status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(output.stdout)
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
