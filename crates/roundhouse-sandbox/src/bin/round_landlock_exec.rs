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
//! for the dynamic linker and any interpreter/shell to load and run), full
//! read/write on the workspace root (`ABI::V1`, matching `probe.rs`'s existing
//! baseline) — via the *safe* `RulesetCreated::restrict_self()` (`probe.rs`'s
//! module doc comment: this call needs no `unsafe`), then
//! `CommandExt::exec()`s the real program. `CommandExt::exec` is also safe, so
//! this binary needs **zero** `unsafe` code and does not widen `probe.rs`'s
//! carve-out as the crate's one `unsafe_code`-permitted module.
//!
//! # Fail-closed: never execs the real program without a confirmed ruleset
//!
//! If the ruleset cannot be built, or the kernel does not report it as
//! `FullyEnforced`, this binary exits `2` with a message on stderr and never
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

/// Directories granted `ReadFile`+`Execute` (never write) — enough for the
/// dynamic linker, an interpreter, or a shell to load and run, nothing more.
/// Not every entry exists on every Linux layout (e.g. `/lib64` does not exist
/// on most arm64 distributions, which have no 64-bit-vs-32-bit split to name)
/// — a missing directory here is tolerated (see the `NotFound` handling
/// below), because there is no filesystem object to grant or deny access to
/// in the first place, so skipping it changes nothing about what the
/// restriction covers. Any *other* failure to open one of these (permission
/// denied, a path that exists but isn't a directory, ...) is still a hard
/// error — only "doesn't exist" is tolerated.
const SYSTEM_READ_EXEC_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

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

    let workspace_fd = PathFd::new(workspace)
        .map_err(|e| format!("failed to open workspace {workspace} for the Landlock rule: {e}"))?;
    created = created
        .add_rule(PathBeneath::new(workspace_fd, full_access))
        .map_err(|e| format!("add_rule(workspace {workspace}) failed: {e}"))?;

    let status = created
        .restrict_self()
        .map_err(|e| format!("restrict_self() failed: {e}"))?;
    if !matches!(status.ruleset, RulesetStatus::FullyEnforced) {
        return Err(format!(
            "kernel did not fully enforce the requested ruleset (status: {:?}) — refusing to \
             exec the real program under a partial or absent restriction",
            status.ruleset
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
