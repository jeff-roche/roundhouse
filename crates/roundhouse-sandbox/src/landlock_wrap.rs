//! Route B (Ruling W5-9) of real Landlock enforcement on the spawned child.
//!
//! # Why not `pre_exec` on the bwrap `Command` itself (Route A)
//!
//! `isolate.rs`'s `achieved_tier()` doc comment used to record Landlock as
//! "PROBED-availability only, not yet applied to the real spawned child":
//! `restrict_self()` ran only inside `probe.rs`'s throwaway forked probe
//! child, never on the process bwrap actually execs. The obvious-looking fix
//! — call `restrict_self()` from an `unsafe` `pre_exec` closure on the
//! **bwrap** `Command`, the same mechanism `probe.rs`'s `set_cpu_limit_pre_exec`
//! already uses for `RLIMIT_CPU` — was tried first, per Ruling W5-9, and is a
//! dead end. Landlock denies every handled access on any filesystem object
//! not covered by a rule added *before* `restrict_self()`, and that
//! restriction is inherited across `exec()` for the rest of the process's
//! life — including by bwrap's own subsequent setup work. Reproduced against
//! real `bwrap` 0.12.0: applying a ruleset granting `ReadFile`+`Execute` on
//! `/usr`/`/lib`/`/lib64`/`/bin`/`/sbin`/`/etc` plus full access on the
//! workspace, then `pre_exec`-restricting the bwrap process itself before
//! exec, makes bwrap fail during its *own* namespace setup —
//! `bwrap: Can't read /proc/sys/kernel/overflowuid: Permission denied`, and,
//! with `/proc` added to the allowed set, `bwrap: setting up uid map:
//! Permission denied` immediately after. bwrap's own privileged setup
//! (reading `/proc/sys/kernel/overflowuid`, writing `/proc/self/uid_map`,
//! creating `/newroot`, mounting `--proc`/`--dev`, binding the workspace)
//! needs broad filesystem access that a ruleset restrictive enough to be a
//! real security boundary must deny — restricting bwrap before it performs
//! its own mount setup does not work, exactly as Ruling W5-9 predicted.
//! Widening the ruleset enough for bwrap's setup to succeed would defeat the
//! restriction's entire purpose. **Not pursued further; this module
//! implements the pre-authorised Route B instead.**
//!
//! # Route B: a pre-exec wrapper binary run *inside* bwrap
//!
//! `round-landlock-exec` (`src/bin/round_landlock_exec.rs`) is a tiny
//! `[[bin]]` in this crate. `isolate.rs::spawn()` rewrites the real
//! `CommandSpec` so that bwrap execs it instead of the real program:
//!
//! ```text
//! bwrap <bwrap's own args> -- round-landlock-exec --allow <workspace> -- <program> <args...>
//! ```
//!
//! By the time `round-landlock-exec` starts, bwrap's namespace, mounts, and
//! `--proc`/`--dev` setup already exist — it applies the real Landlock
//! ruleset via the *safe* `RulesetCreated::restrict_self()` (see
//! `probe.rs`'s module doc comment: this call needs no `unsafe`), then
//! `std::os::unix::process::CommandExt::exec`s the real program.
//! `CommandExt::exec` is also safe — replacing the current process image is
//! not memory-unsafe — so `round-landlock-exec` needs **zero** `unsafe` code
//! and does not widen `probe.rs`'s carve-out as the crate's one
//! `unsafe_code`-permitted module.
use crate::IsolationError;
use std::path::{Path, PathBuf};

/// The `[[bin]] name` in this crate's `Cargo.toml` (ruling W5-4's `round-`
/// prefix convention, reused per Ruling W5-9).
pub(crate) const WRAPPER_BINARY_NAME: &str = "round-landlock-exec";

/// Resolves `round-landlock-exec`'s path: a sibling of
/// [`std::env::current_exe`], following the identical shape (and identical
/// rationale — no `$PATH` search, no environment-variable override in
/// production) as `roundhouse-flow`'s `helper_binary_path`
/// (`crates/roundhouse-flow/src/parse/helper.rs`, ruling W5-4). Cargo places
/// every workspace member's `[[bin]]` output in the same `target/<profile>/`
/// directory regardless of which crate declares it, so this resolves
/// correctly from whatever binary is actually running (`roundhouse-daemon` in
/// production).
///
/// Under this crate's `test-util` feature *only*, additionally falls back to
/// the **grandparent** of `current_exe()` — a `tests/*.rs` integration test
/// binary lives in `target/debug/deps/`, whose grandparent is `target/debug/`,
/// exactly where Cargo places `round-landlock-exec`. Gated by
/// [`is_inside_a_target_tree`], not `debug_assertions`, for the identical
/// reason `roundhouse-flow`'s copy is: `test-util` is not a default feature,
/// but `cargo build --release --all-features` is a plausible packaging
/// command that would still compile this branch in, and an absent sibling at
/// the fallback location must not resolve to an *installed* binary's own
/// grandparent (e.g. `/usr/local`, group/user-writable on Homebrew-style
/// installs) — the fallback declines rather than trusting a path outside a
/// `target` tree.
pub(crate) fn wrapper_binary_path() -> Result<PathBuf, IsolationError> {
    let exe = std::env::current_exe().map_err(|err| {
        IsolationError::Unsupported(format!("could not resolve current_exe(): {err}"))
    })?;
    let exe = std::fs::canonicalize(&exe).map_err(|err| {
        IsolationError::Unsupported(format!(
            "could not canonicalize current_exe() {}: {err}",
            exe.display()
        ))
    })?;
    let dir = exe.parent().ok_or_else(|| {
        IsolationError::Unsupported(format!(
            "{} has no parent directory; cannot locate {WRAPPER_BINARY_NAME}",
            exe.display()
        ))
    })?;

    let sibling = dir.join(WRAPPER_BINARY_NAME);
    if sibling.is_file() {
        return Ok(sibling);
    }

    #[cfg(feature = "test-util")]
    {
        if let Some(grandparent) = dir.parent() {
            let candidate = grandparent.join(WRAPPER_BINARY_NAME);
            if candidate.is_file() && is_inside_a_target_tree(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(IsolationError::Unsupported(format!(
        "{WRAPPER_BINARY_NAME} not found next to {} (or, under the test-util feature, in its \
         parent directory) — Landlock probed Available but the enforcement binary is missing, \
         refusing to spawn unprotected rather than silently downgrading",
        exe.display()
    )))
}

/// See `roundhouse-flow`'s identical helper (`parse/helper.rs`,
/// `is_inside_a_target_tree`, ruling W5-25) for the full rationale — copied
/// rather than shared across a crate boundary neither crate otherwise needs.
#[cfg(feature = "test-util")]
fn is_inside_a_target_tree(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == std::ffi::OsStr::new("target"))
}

/// Rewrites `cmd` so bwrap execs `round-landlock-exec --allow <workspace> --
/// <original program> <original argv...>` instead of the real program
/// directly. `workspace_root` is the same path `bwrap.rs::spawn_under_bwrap`
/// binds read-write into the sandbox, passed through unchanged as the one
/// directory `round-landlock-exec`'s ruleset grants full read/write access
/// to.
pub(crate) fn wrap_for_landlock(
    cmd: crate::CommandSpec,
    workspace_root: &Path,
    wrapper: &Path,
) -> crate::CommandSpec {
    let mut argv = Vec::with_capacity(cmd.argv.len() + 3);
    argv.push("--allow".to_string());
    argv.push(workspace_root.display().to_string());
    argv.push("--".to_string());
    argv.push(cmd.program);
    argv.extend(cmd.argv);
    crate::CommandSpec {
        program: wrapper.display().to_string(),
        argv,
        cwd: cmd.cwd,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_for_landlock_prepends_the_wrapper_and_allow_flag_ahead_of_the_real_program() {
        let cmd = crate::CommandSpec {
            program: "echo".into(),
            argv: vec!["hello".into(), "world".into()],
            cwd: Some("/workspace".into()),
        };
        let wrapped = wrap_for_landlock(
            cmd,
            Path::new("/workspace"),
            Path::new("/opt/round-landlock-exec"),
        );
        assert_eq!(wrapped.program, "/opt/round-landlock-exec");
        assert_eq!(
            wrapped.argv,
            vec!["--allow", "/workspace", "--", "echo", "hello", "world"]
        );
        assert_eq!(wrapped.cwd.as_deref(), Some("/workspace"));
    }
}
