//! `round-landlock-exec`: Route B (Ruling W5-9) of real, per-process Landlock
//! enforcement on a bwrap-spawned child. See `roundhouse_sandbox::landlock_wrap`'s
//! module doc comment for why Route A (`pre_exec` on the bwrap `Command` itself)
//! is a dead end and why this binary exists instead.
//!
//! `isolate.rs::spawn()` rewrites the real `CommandSpec` so bwrap execs this
//! binary instead of the real program:
//!
//! ```text
//! bwrap <bwrap's own args> -- round-landlock-exec --allow <workspace> -- <program> <args...>
//! ```
//!
//! By the time this binary starts, bwrap's namespace, mounts, and `--proc`/
//! `--dev` setup already exist. It applies a real Landlock ruleset — `ReadFile`
//! and `Execute` on `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/etc` (enough
//! for the dynamic linker and any interpreter/shell to load and run);
//! `ReadFile`+`WriteFile` on `/dev` and `ReadFile`+`ReadDir` on `/proc` (fix
//! round 1, item 3 — bounded by bwrap's own curated `--dev`/`--proc` mounts,
//! never the real host device nodes or process table; without this, ordinary
//! tooling that touches `/dev/null` or `/proc/self/...` failed outright, e.g.
//! `git --version` exiting 128); full read/write on the workspace root
//! (`ABI::V1`, matching `probe.rs`'s existing baseline) — via the *safe*
//! `RulesetCreated::restrict_self()` (`probe.rs`'s module doc comment: this
//! call needs no `unsafe`), then `CommandExt::exec()`s the real program.
//! `CommandExt::exec` is also safe, so this binary needs **zero** `unsafe`
//! code and does not widen `probe.rs`'s carve-out as the crate's one
//! `unsafe_code`-permitted module.
//!
//! # Fail-closed: never execs the real program without a confirmed ruleset
//!
//! If the ruleset cannot be built, or the kernel does not report both
//! `RulesetStatus::FullyEnforced` and `no_new_privs` as actually enforced (fix
//! round 1, item 5), this binary exits `2` with a message on stderr and never
//! reaches `exec()` — a child that appeared sandboxed but silently wasn't
//! would be exactly the "fail-open hides" pattern this whole mechanism exists
//! to prevent (the same posture `isolate.rs::seccomp_bpf_for_spawn` already
//! takes for a seccomp compile failure).
//!
//! # Argument protocol
//!
//! `--allow <workspace-path> -- <program> [args...]`. No other flags. The `--`
//! separator is required so a `<program>`/`<args>` that itself looks like a
//! flag is never mistaken for one of this binary's own.
use roundhouse_sandbox::SYSTEM_READ_EXEC_DIRS;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("round-landlock-exec: {msg}");
            std::process::exit(2);
        }
    };

    if let Err(msg) = apply_landlock_ruleset(&parsed.workspace) {
        eprintln!("round-landlock-exec: failed to apply Landlock ruleset: {msg}");
        std::process::exit(2);
    }

    // `Command::exec` replaces this process's image on success and never
    // returns — reaching the line below always means it failed.
    let err = Command::new(&parsed.program)
        .args(&parsed.program_args)
        .exec();
    eprintln!(
        "round-landlock-exec: failed to exec {}: {err}",
        parsed.program
    );
    std::process::exit(127);
}

struct ParsedArgs {
    workspace: String,
    program: String,
    program_args: Vec<String>,
}

/// Parses `--allow <workspace> -- <program> [args...]`. Deliberately strict —
/// this binary has exactly one caller (`isolate.rs::spawn()`), so a malformed
/// invocation means an internal bug, not a user-facing usage error to be
/// forgiving about.
fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    if args.len() < 4 || args[0] != "--allow" || args[2] != "--" {
        return Err(
            "usage: round-landlock-exec --allow <workspace> -- <program> [args...]".to_string(),
        );
    }
    Ok(ParsedArgs {
        workspace: args[1].clone(),
        program: args[3].clone(),
        program_args: args[4..].to_vec(),
    })
}

// `SYSTEM_READ_EXEC_DIRS` (imported above): the directories granted `ReadFile`+
// `Execute` (never write) below — enough for the dynamic linker, an interpreter, or a
// shell to load and run, nothing more. Not every entry exists on every Linux layout
// (e.g. `/lib64` does not exist on most arm64 distributions) — a missing directory is
// tolerated (see the `NotFound` handling below), because there is no filesystem
// object to grant or deny access to in the first place. Any *other* open failure
// (permission denied, a path that exists but isn't a directory, ...) is still a hard
// error — only "doesn't exist" is tolerated. See its definition in
// `roundhouse_sandbox::landlock_wrap` for why this is a shared, not duplicated, list.

/// Fix round 1 (Ruling W5-40), item 3: `/dev`, granted `ReadFile`+`WriteFile` (never
/// `Execute` — nothing under it needs to run). Reproduced pre-fix: with `/dev` absent
/// from every rule, `ReadFile`+`WriteFile` on it are among the accesses `full_access`
/// (`AccessFs::from_all`) *handles* but no rule *grants* on this path, so the kernel
/// denies both — every `>/dev/null` redirect failed with `Permission denied`, and
/// `git --version` exited 128 (`fatal: could not open '/dev/null' for reading and
/// writing`). Granting access here is bounded, not a blind widening: `bwrap.rs`'s
/// `--dev /dev` has already replaced the host's real `/dev` with its own minimal,
/// curated tmpfs before `round-landlock-exec` ever runs, so this rule reaches only
/// that curated mount, never real host device nodes.
const DEV_READ_WRITE_DIR: &str = "/dev";

/// Fix round 1 (Ruling W5-40), item 3: `/proc`, granted `ReadFile`+`ReadDir` (never
/// write or execute). Same rationale as `DEV_READ_WRITE_DIR`: reproduced pre-fix,
/// `/proc/self/status`, `/proc/version`, and similar reads were all denied. Bounded the
/// same way — `bwrap.rs`'s `--proc /proc` has already replaced the host's real `/proc`
/// with its own pidns-isolated procfs, so this reaches only that curated view.
const PROC_READ_DIR: &str = "/proc";

#[cfg(target_os = "linux")]
fn apply_landlock_ruleset(workspace: &str) -> Result<(), String> {
    use landlock::{
        Access, AccessFs, PathBeneath, PathFd, PathFdError, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus, ABI,
    };

    // ABI::V1 (Linux 5.13+): the same widest-compatibility baseline
    // `probe.rs::landlock_probe_body` uses — do not silently pick a
    // different ABI (Ruling W5-9).
    let abi = ABI::V1;
    let read_exec = AccessFs::ReadFile | AccessFs::Execute;
    let dev_read_write = AccessFs::ReadFile | AccessFs::WriteFile;
    let proc_read = AccessFs::ReadFile | AccessFs::ReadDir;
    let full_access = AccessFs::from_all(abi);

    let ruleset = Ruleset::default()
        .handle_access(full_access)
        .map_err(|e| format!("handle_access failed: {e}"))?;
    let mut created = ruleset
        .create()
        .map_err(|e| format!("ruleset create() failed: {e}"))?;

    for dir in SYSTEM_READ_EXEC_DIRS {
        let fd = match PathFd::new(dir) {
            Ok(fd) => fd,
            Err(PathFdError::OpenCall { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                // Nothing to grant or deny: this layout simply has no such
                // directory (e.g. `/lib64` on arm64). Not a fail-open —
                // there is no filesystem object here for the restriction to
                // cover either way.
                continue;
            }
            Err(e) => return Err(format!("failed to open {dir} for the Landlock rule: {e}")),
        };
        created = created
            .add_rule(PathBeneath::new(fd, read_exec))
            .map_err(|e| format!("add_rule({dir}) failed: {e}"))?;
    }

    // `/dev` and `/proc` always exist under bwrap's own `--dev`/`--proc` mounts by the
    // time this binary runs (unlike the arm64-conditional entries above) — an open
    // failure here is a hard error, not tolerated as "this layout has none."
    let dev_fd = PathFd::new(DEV_READ_WRITE_DIR)
        .map_err(|e| format!("failed to open {DEV_READ_WRITE_DIR} for the Landlock rule: {e}"))?;
    created = created
        .add_rule(PathBeneath::new(dev_fd, dev_read_write))
        .map_err(|e| format!("add_rule({DEV_READ_WRITE_DIR}) failed: {e}"))?;

    let proc_fd = PathFd::new(PROC_READ_DIR)
        .map_err(|e| format!("failed to open {PROC_READ_DIR} for the Landlock rule: {e}"))?;
    created = created
        .add_rule(PathBeneath::new(proc_fd, proc_read))
        .map_err(|e| format!("add_rule({PROC_READ_DIR}) failed: {e}"))?;

    let workspace_fd = PathFd::new(workspace)
        .map_err(|e| format!("failed to open workspace {workspace} for the Landlock rule: {e}"))?;
    created = created
        .add_rule(PathBeneath::new(workspace_fd, full_access))
        .map_err(|e| format!("add_rule(workspace {workspace}) failed: {e}"))?;

    let status = created
        .restrict_self()
        .map_err(|e| format!("restrict_self() failed: {e}"))?;
    // Fix round 1 (Ruling W5-40), item 5: `restrict_self()`'s `RestrictSelfStatus` also
    // reports whether `no_new_privs` was actually enforced, and this crate treats an
    // unchecked enforcement claim as the defect class it exists to prevent (the same
    // posture as the `FullyEnforced` check on `status.ruleset` right below) — checking
    // only one of the two fields would leave that same class of gap open for the other.
    // Low risk in practice (the `landlock` crate sets NNP by default and `restrict_self()`
    // itself errors if it cannot), but the guard was one field short of complete.
    if !matches!(status.ruleset, RulesetStatus::FullyEnforced) || !status.no_new_privs {
        return Err(format!(
            "kernel did not fully enforce the requested ruleset (status: {:?}, no_new_privs: \
             {}) — refusing to exec the real program under a partial or absent restriction",
            status.ruleset, status.no_new_privs
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply_landlock_ruleset(_workspace: &str) -> Result<(), String> {
    Err(
        "Landlock is Linux-only — round-landlock-exec should never be invoked on this platform"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_expected_shape() {
        let args: Vec<String> = ["--allow", "/ws", "--", "echo", "hi", "there"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_args(&args).unwrap();
        assert_eq!(parsed.workspace, "/ws");
        assert_eq!(parsed.program, "echo");
        assert_eq!(parsed.program_args, vec!["hi", "there"]);
    }

    #[test]
    fn rejects_a_missing_separator() {
        let args: Vec<String> = ["--allow", "/ws", "echo"]
            .into_iter()
            .map(String::from)
            .collect();
        assert!(parse_args(&args).is_err());
    }

    #[test]
    fn allows_a_program_with_no_extra_args() {
        let args: Vec<String> = ["--allow", "/ws", "--", "echo"]
            .into_iter()
            .map(String::from)
            .collect();
        let parsed = parse_args(&args).unwrap();
        assert_eq!(parsed.program, "echo");
        assert!(parsed.program_args.is_empty());
    }
}
