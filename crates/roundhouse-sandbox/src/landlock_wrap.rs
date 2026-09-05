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

/// Mirrors `round_landlock_exec.rs`'s own `SYSTEM_READ_EXEC_DIRS` list (kept as a
/// separate copy rather than shared across the lib/bin crate boundary — `pub(crate)`
/// items in the library are not visible from a `[[bin]]` target, which links against
/// the library as an ordinary external dependency and only sees `pub` items; adding a
/// new `pub` export for six static strings was judged not worth the extra surface for
/// this fix round). Consulted only by [`validate_workspace_root`] below, to refuse a
/// workspace root that would swallow one of these directories under the workspace's
/// own, much broader grant. If `round_landlock_exec.rs`'s list ever changes, update
/// this copy too.
const SYSTEM_READ_EXEC_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

/// Task 27 fix round 1, item 1 (Ruling W5-40): refuses a `workspace_root` that would
/// make `round-landlock-exec`'s ruleset restrict nothing. `wrap_for_landlock_if_available`
/// (`isolate.rs`) grants `AccessFs::from_all(ABI::V1)` — every handled access — on
/// `workspace_root` verbatim, with no prior validation. Reproduced: with
/// `workspace_root == "/"`, that grant covers the entire filesystem hierarchy, so the
/// ruleset restricts nothing at all — and yet `restrict_self()` still reports
/// `FullyEnforced` (there is nothing inconsistent about "fully enforcing" a ruleset that
/// happens to grant everything), so `round_landlock_exec.rs`'s own fail-closed guard
/// does not catch this, and `isolate.rs::attest()` keeps claiming a real, restrictive
/// Landlock ruleset. The identical failure mode applies, one level narrower, if
/// `workspace_root` is (or contains as a descendant-of-itself relationship, i.e. is an
/// ancestor of) one of the six system directories: that directory would then also
/// receive the workspace's full read-write-execute grant instead of the deliberately
/// narrower read/execute-only one `round_landlock_exec.rs` gives it.
///
/// Canonicalizes `workspace_root` first (symlinks resolved, so a symlinked path aimed
/// at `/` or a system directory can't slip past a purely lexical check), then refuses
/// with an `IsolationError` — never emits a ruleset that grants everything. Also
/// refuses a non-UTF-8 canonical path explicitly (fix round 1, item 6): the wrapper
/// protocol threads `workspace_root` through as a `String` argv entry
/// (`wrap_for_landlock` below), and `Path::display()`'s lossy conversion would
/// otherwise silently hand `round-landlock-exec` a path that was never the real one,
/// which then fails downstream (a missing/wrong path) with an error naming the wrong
/// value instead of naming the actual problem.
pub(crate) fn validate_workspace_root(workspace_root: &Path) -> Result<PathBuf, IsolationError> {
    let canonical = std::fs::canonicalize(workspace_root).map_err(|err| {
        IsolationError::Unsupported(format!(
            "could not canonicalize workspace root {}: {err}",
            workspace_root.display()
        ))
    })?;

    if canonical == Path::new("/") {
        return Err(IsolationError::Unsupported(
            "refusing to apply Landlock: workspace root is \"/\" — a ruleset granting full \
             access there restricts nothing, which is the opposite of what Tier::Sandbox \
             attests"
                .to_string(),
        ));
    }
    for sys_dir in SYSTEM_READ_EXEC_DIRS {
        if let Ok(sys_canonical) = std::fs::canonicalize(sys_dir) {
            if sys_canonical.starts_with(&canonical) {
                return Err(IsolationError::Unsupported(format!(
                    "refusing to apply Landlock: workspace root {} contains the system \
                     directory {sys_dir}, which must stay read/execute-only under this \
                     ruleset rather than receive the workspace's full read-write grant",
                    canonical.display()
                )));
            }
        }
    }

    if canonical.to_str().is_none() {
        return Err(IsolationError::Unsupported(format!(
            "refusing to apply Landlock: workspace root {} is not valid UTF-8 — the wrapper \
             protocol passes it as a string argv entry, and a lossy conversion here would \
             silently hand round-landlock-exec a different path than the real one",
            canonical.display()
        )));
    }

    Ok(canonical)
}

/// Task 27 fix round 1, item 2 (Ruling W5-40): `true` if `wrapper` lies inside
/// `workspace_root` — both arguments are expected already canonicalized (`wrapper` by
/// [`wrapper_binary_path`], `workspace_root` by [`validate_workspace_root`]), so this is
/// a pure path-containment check with no filesystem access of its own.
///
/// Why this matters: `round_landlock_exec.rs`'s ruleset grants `workspace_root` full
/// read-write access, and `bwrap.rs::spawn_under_bwrap` binds it read-write into the
/// sandbox over an otherwise read-only `/` (`--ro-bind / /` then `--bind
/// <workspace_root> <workspace_root>`) — the *only* writable route to anything inside
/// the sandbox. In the ordinary dev layout (daemon at `<repo>/target/debug/`, wrapper at
/// its sibling `<repo>/target/debug/round-landlock-exec`, session workspace `<repo>`),
/// the wrapper sits inside the very directory its own ruleset makes writable. A child
/// correctly confined by that ruleset can still overwrite the wrapper binary itself; the
/// next session to resolve the same wrapper path execs attacker-controlled code
/// *before* any ruleset is ever applied. This is layer defeat (bwrap and seccomp are
/// unaffected) rather than full sandbox escape, but `attest()` has no way to see it, so
/// the escape would otherwise be invisible. The read-write workspace bind is the only
/// writable route to the wrapper inside the sandbox (`/` itself is read-only), so this
/// containment check alone is sufficient to close the hole, not merely necessary.
pub(crate) fn wrapper_is_inside_workspace(wrapper: &Path, workspace_root: &Path) -> bool {
    wrapper.starts_with(workspace_root)
}

/// Rewrites `cmd` so bwrap execs `round-landlock-exec --allow <workspace> --
/// <original program> <original argv...>` instead of the real program
/// directly. `workspace_root` is the same path `bwrap.rs::spawn_under_bwrap`
/// binds read-write into the sandbox, passed through unchanged as the one
/// directory `round-landlock-exec`'s ruleset grants full read/write access
/// to. Callers must pass an already-[`validate_workspace_root`]-checked path — this
/// function itself does no validation and is infallible.
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

    // Ruling W5-25/W5-40 precedent (`roundhouse-flow`'s `parse/helper.rs`): pins
    // `is_inside_a_target_tree`'s containment check directly, so a future edit can't
    // silently widen it back into trusting an arbitrary grandparent path. Raised
    // independently by both lenses in fix round 1's review.
    #[cfg(feature = "test-util")]
    #[test]
    fn a_target_tree_path_is_accepted() {
        assert!(is_inside_a_target_tree(Path::new(
            "/home/me/repo/target/debug/round-landlock-exec"
        )));
    }

    #[cfg(feature = "test-util")]
    #[test]
    fn an_installed_path_outside_any_target_tree_is_rejected() {
        assert!(!is_inside_a_target_tree(Path::new(
            "/usr/local/round-landlock-exec"
        )));
    }

    // Fix round 1, item 1: a workspace root of "/" must be refused rather than
    // silently producing a ruleset that grants everything.
    #[test]
    fn refuses_the_filesystem_root() {
        let err = validate_workspace_root(Path::new("/")).unwrap_err();
        match err {
            IsolationError::Unsupported(msg) => {
                assert!(
                    msg.contains('/'),
                    "message should reference the path: {msg}"
                )
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    // Fix round 1, item 1: a workspace root that IS one of the system directories
    // (the narrow, always-real-on-Linux case of "an ancestor of a system directory" —
    // a path is its own ancestor for `starts_with`'s purposes) must also be refused,
    // not just the bare filesystem root.
    #[test]
    fn refuses_a_workspace_root_that_is_a_system_directory() {
        let err = validate_workspace_root(Path::new("/usr")).unwrap_err();
        assert!(matches!(err, IsolationError::Unsupported(_)));
    }

    // Fix round 1, item 1: an ordinary workspace directory must still be accepted —
    // the fix must refuse the dangerous cases without becoming a blanket refusal.
    #[test]
    fn accepts_an_ordinary_workspace_directory() {
        let dir = std::env::temp_dir();
        let canonical = validate_workspace_root(&dir).expect("an ordinary tempdir is fine");
        assert_eq!(canonical, std::fs::canonicalize(&dir).unwrap());
    }

    // Fix round 1, item 6: a workspace root containing non-UTF-8 bytes must be refused
    // explicitly, rather than silently lossy-converted (`Path::display()`'s U+FFFD
    // replacement) into a value that is no longer the real path.
    #[test]
    fn refuses_a_non_utf8_workspace_root_rather_than_silently_lossy_converting_it() {
        use std::os::unix::ffi::OsStringExt;
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-nonutf8-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).expect("create base tempdir");
        let bad_name = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);
        let bad_path = base.join(bad_name);
        std::fs::create_dir(&bad_path).expect("create non-UTF-8-named subdirectory");

        let err = validate_workspace_root(&bad_path).unwrap_err();
        match err {
            IsolationError::Unsupported(msg) => {
                assert!(msg.contains("UTF-8"), "message was: {msg}")
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&base);
    }

    // Fix round 1, item 2: the wrapper-substitutability check itself, independent of
    // any real filesystem layout — `isolate_landlock_fix_round_1.rs` exercises the real
    // ordinary-dev-layout scenario end to end through the public `Isolate` API.
    #[test]
    fn detects_a_wrapper_that_lives_inside_the_workspace() {
        assert!(wrapper_is_inside_workspace(
            Path::new("/repo/target/debug/round-landlock-exec"),
            Path::new("/repo"),
        ));
    }

    #[test]
    fn does_not_flag_a_wrapper_outside_the_workspace() {
        assert!(!wrapper_is_inside_workspace(
            Path::new("/usr/libexec/roundhouse/round-landlock-exec"),
            Path::new("/home/user/workspace"),
        ));
    }
}
