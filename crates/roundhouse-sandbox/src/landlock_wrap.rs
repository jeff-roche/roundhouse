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
/// `target` tree. That decision lives in
/// [`resolve_grandparent_fallback`], which checks **both** the literal
/// `grandparent.join(name)` and the canonical path it resolves to; see its doc
/// comment for why checking only one of the two is a fail-open.
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

    if let Some(sibling) = resolve_existing_candidate(dir, WRAPPER_BINARY_NAME) {
        return Ok(sibling);
    }

    #[cfg(feature = "test-util")]
    {
        if let Some(grandparent) = dir.parent() {
            if let Some(candidate) = resolve_grandparent_fallback(grandparent, WRAPPER_BINARY_NAME)
            {
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

/// Resolves `dir.join(name)` to its **canonical** path if it exists as a file (symlinks
/// followed), `None` otherwise. Shared by both branches of [`wrapper_binary_path`]
/// above.
///
/// **Task 27 fix round 3, item 2 (Ruling W5-42):** `wrapper_binary_path` used to
/// return `dir.join(WRAPPER_BINARY_NAME)` *un*-canonicalized while `is_file()` follows
/// symlinks to decide whether that path exists — so a wrapper reached only through a
/// symlink was returned as the symlink's own path, not its real target.
/// [`wrapper_is_inside_workspace`]'s `starts_with` containment check operates on
/// whatever path string it is handed, so a symlink sitting *outside* the workspace
/// (passing that check) whose target sits *inside* it was never caught — reproduced
/// end to end by making the real sibling location a symlink into the workspace: the
/// spawn was allowed, a confined child overwrote the symlink's target, and the next
/// session exec'd attacker-controlled code. Canonicalizing here, at resolution time,
/// makes the doc claim on [`wrapper_is_inside_workspace`] ("both arguments are
/// expected already canonicalized") actually true for the `wrapper` side, for both the
/// production sibling lookup and the `test-util` grandparent fallback.
fn resolve_existing_candidate(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if candidate.is_file() {
        std::fs::canonicalize(&candidate).ok()
    } else {
        None
    }
}

/// The whole `test-util` grandparent fallback decision of [`wrapper_binary_path`],
/// extracted (Task 27 fix round 4, item 1 — Ruling W5-44) so the trust decision can be
/// exercised against a synthetic tempdir layout rather than only against whatever
/// `target/` tree the test binary happens to be built into.
///
/// Returns the **canonical** wrapper path only if `name` exists as a file under
/// `grandparent` *and* [`is_inside_a_target_tree`] holds for **both** the literal
/// `grandparent.join(name)` and the canonical path that resolves to.
///
/// **Why both, and not just one (the regression this restores).** Before fix round 3
/// the guard ran on the literal `grandparent.join(NAME)`, so it asked "does the
/// *candidate sit* inside a `target` tree" — which, since `grandparent` is already
/// canonical here (`wrapper_binary_path` canonicalizes `current_exe()` before taking
/// `.parent()`), is the same question as "is the fallback *directory* a `target`
/// tree", exactly the property the doc on [`wrapper_binary_path`] promises. Fix round
/// 3 moved canonicalization inside [`resolve_existing_candidate`], which silently
/// changed the guard's subject to "where does a symlink *point*". Reproduced through
/// the real `Isolate::spawn`: with the daemon at `<S>/bin/`, `<S>` containing no
/// `target` component but writable, a symlink `<S>/round-landlock-exec` aimed at an
/// attacker-owned `<X>/target/payload` was accepted and executed with no ruleset ever
/// applied, while `attest()` still reported `Tier::Sandbox`. That needs write access
/// only to the *grandparent* of the daemon's directory (`/usr/local` for a daemon at
/// `/usr/local/bin/` — the Homebrew-style case the doc names), which does not imply
/// write access to the daemon's own directory.
///
/// Checking both is strictly fail-closed relative to both prior shapes: it keeps fix
/// round 3's canonicalization (which closed a real symlink bypass — see
/// [`resolve_existing_candidate`]) and keeps the pre-round-3 meaning of the guard.
#[cfg(feature = "test-util")]
fn resolve_grandparent_fallback(grandparent: &Path, name: &str) -> Option<PathBuf> {
    // Where the candidate *sits*. `grandparent` is already canonical, so this asks
    // whether the fallback directory itself is inside a `target` tree.
    if !is_inside_a_target_tree(&grandparent.join(name)) {
        return None;
    }
    let canonical = resolve_existing_candidate(grandparent, name)?;
    // Where the candidate *points*. Redundant for a plain file; load-bearing when the
    // candidate is a symlink out of the target tree.
    if !is_inside_a_target_tree(&canonical) {
        return None;
    }
    Some(canonical)
}

/// See `roundhouse-flow`'s identical helper (`parse/helper.rs`,
/// `is_inside_a_target_tree`, ruling W5-25) for the full rationale — copied
/// rather than shared across a crate boundary neither crate otherwise needs.
#[cfg(feature = "test-util")]
fn is_inside_a_target_tree(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == std::ffi::OsStr::new("target"))
}

/// The system directories `round_landlock_exec.rs`'s ruleset grants `ReadFile`+
/// `Execute`+`ReadDir` on, and the same list [`validate_workspace_root`] below
/// consults to refuse a workspace root that would swallow one of them under the
/// workspace's own, much broader grant.
///
/// **Task 27 fix round 3, item 1 (Ruling W5-42): `ReadDir` was missing, so nothing
/// that enumerates a directory here could run — attribution, stated plainly.** Fix
/// round 1's own brief blamed a `python3 -c 'print(1)'` failure on the `/dev`/`/proc`
/// denial that round then fixed; that diagnosis came from the security lens's first
/// pass, was transcribed into the brief without independently isolating the cause,
/// and was wrong. The fix-round-1 implementation matched its brief's Definition of
/// Done exactly (`git --version`, a `/dev/null` consumer, was the stated bar, and it
/// was met) — the *finding as originally stated* ("no real session can run at Sandbox
/// tier") is what stayed open. Isolated cause: `AccessFs::ReadFile | AccessFs::Execute`
/// grants none of `ReadDir`, so `ls /usr/lib` — and CPython's `FileFinder`, which
/// calls `listdir()` on every `sys.path` entry to locate its own stdlib — both got
/// `Permission denied` even though every individual file underneath was already
/// readable. Adding `ReadDir` is bounded, not the careless widening item 3 of fix
/// round 1 warned against: it is strictly *weaker* than the `ReadFile` this list
/// already grants on these same trees — enumerating a directory whose every file you
/// may already read discloses nothing new.
///
/// **Task 27 fix round 2 (Ruling W5-40 item, escalated by Ruling W5-20's precedent):**
/// fix round 1 shipped this as two separately-maintained copies — one here (consulted
/// by the *validator*) and one in `round_landlock_exec.rs` (consulted by the
/// *ruleset-builder*) — with a comment asking a future editor to update both. That is
/// exactly the shape Ruling W5-20 (Task 14's `check_expansion`/`Verdict`, same
/// lib/`[[bin]]` visibility wall) already ruled out: "inventing a second copy of the
/// guard is not acceptable." Here the stakes are sharper than a maintenance nuisance —
/// the two copies don't merely mirror each other, they check *opposite sides of the
/// same fact*. If they drifted, a workspace root could pass validation (this copy)
/// while the ruleset still handed that same directory a broad grant (the other copy),
/// which is a fail-open path created purely by the duplication. `#[doc(hidden)] pub`
/// (the identical fix Ruling W5-20 applied) keeps this out of the crate's advertised
/// public API — it exists for exactly one external caller — while letting
/// `round_landlock_exec.rs`, a separate crate that links this library and can
/// therefore only reach `pub` items, use this single definition instead of a second
/// copy. Re-exported at the crate root (`lib.rs`) rather than left unreachable behind
/// the private `landlock_wrap` module, the same shape `roundhouse-flow`'s
/// `parse/mod.rs` uses for `check_expansion`/`Verdict`.
#[doc(hidden)]
pub const SYSTEM_READ_EXEC_DIRS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc"];

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
///
/// **Task 27 fix round 3, item 3 (Ruling W5-42):** the checks above compare
/// canonicalized *paths*, but Landlock's own rules key on the **inode** a `PathFd` was
/// opened against, not the path string used to open it. A bind-mount alias of `/` (or
/// of a system directory) is, to the kernel, indistinguishable from the real thing —
/// `PathFd::new("<alias>")` *is* a rule on `/` — while `realpath`/`canonicalize` of the
/// alias returns the alias's own path unchanged (canonicalize only resolves symlinks,
/// never bind mounts), so it is neither `"/"` nor a prefix of any system directory to
/// the checks above. Reproduced: with the workspace being a bind alias of `/`, reads
/// through the alias's sibling *real* paths (`/etc`, `~/.bashrc`, ...) all succeeded —
/// item 1's exact fail-open, just reached through the inode rather than the path.
/// [`same_inode`] below is the backstop: it compares `(st_dev, st_ino)` directly,
/// which a bind mount cannot hide. Kept *alongside* the path-based checks above, not
/// instead of them — those give a clearer, path-naming error message for the ordinary
/// (non-bind-mount) case that is the overwhelming majority of real refusals; this is
/// the inode-level guarantee underneath it.
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
    if same_inode(&canonical, Path::new("/")) {
        return Err(IsolationError::Unsupported(format!(
            "refusing to apply Landlock: workspace root {} is the same inode as \"/\" (e.g. a \
             bind-mount alias) — Landlock keys rules on the inode, not the path string, so a \
             grant here would restrict nothing even though the paths look unrelated",
            canonical.display()
        )));
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
            if same_inode(&canonical, &sys_canonical) {
                return Err(IsolationError::Unsupported(format!(
                    "refusing to apply Landlock: workspace root {} is the same inode as the \
                     system directory {sys_dir} (e.g. a bind-mount alias) — Landlock keys \
                     rules on the inode, not the path string, so the prefix check above cannot \
                     see this case",
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

/// `true` if `a` and `b` name the same underlying filesystem object — same device and
/// inode number — even when their paths are textually unrelated, which is exactly
/// what a bind-mount alias produces and a symlink-resolving [`std::fs::canonicalize`]
/// cannot see.
///
/// **`true`, not `false`, if either path's metadata can't be read (fix round 4, item 4
/// — Ruling W5-44).** Fix round 3 returned `false` there, reading an inconclusive
/// `stat` as "no evidence of aliasing". That is the fail-open direction: this function
/// exists only as a refusal predicate for [`validate_workspace_root`], so returning
/// `false` on missing evidence *permits* a workspace root the guard could not clear.
/// The architecture doc's position is that fail-open is structurally impossible in this
/// project, so an inconclusive stat refuses. Both call sites reach this only after
/// `canonicalize` has just succeeded on the same absolute path (and `/` cannot fail to
/// stat), so no reachable case changes behaviour today — the direction is what matters,
/// since the only route here is a TOCTOU race, and a race is precisely when you want
/// the guard to refuse rather than wave the root through.
fn same_inode(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(meta_a), Ok(meta_b)) => meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino(),
        _ => true,
    }
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
/// directly. `workspace_root` names the one directory
/// `round-landlock-exec`'s ruleset grants full read/write access to.
///
/// **It is the same *location* `bwrap.rs::spawn_under_bwrap` binds
/// read-write into the sandbox, not necessarily the same string.** An
/// earlier version of this sentence said "passed through unchanged", which
/// stopped being true in Task 27's fix round 1: `spawn()` hands bwrap the
/// **raw** `cmd.cwd`-derived path while this function receives the
/// **canonicalized** one. Harmless — the two resolve to the same real
/// directory at the OS level, which is what both the bind and the Landlock
/// rule key on (Landlock rules key on the inode a `PathFd` opened, not on
/// the path text) — but worth stating precisely, because
/// [`wrapper_is_inside_workspace`]'s "sufficient as well as necessary"
/// argument rests on the read-write bind and this grant covering the same
/// directory.
///
/// Callers must pass an already-[`validate_workspace_root`]-checked path — this
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
        env: cmd.env,
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
            env: vec![],
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

    // Fix round 3, item 2: `resolve_existing_candidate` (now used by both branches of
    // `wrapper_binary_path`) must canonicalize through a symlink, not just check
    // `is_file()` and return the symlink's own path — the exact bug that let a
    // workspace-contained symlink target evade `wrapper_is_inside_workspace`'s
    // `starts_with` check. This reproduces the real mechanism (a symlink whose target
    // sits inside a workspace) using a self-contained temp directory rather than the
    // shared `target/debug/` build output, so this test never mutates build state
    // other tests depend on.
    #[test]
    fn resolve_existing_candidate_follows_a_symlink_to_its_canonical_target() {
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-symlink-{}",
            uuid::Uuid::new_v4()
        ));
        let workspace = base.join("workspace");
        std::fs::create_dir_all(&workspace).expect("create workspace dir");
        let real_wrapper = workspace.join("real-wrapper");
        std::fs::write(&real_wrapper, b"stand-in binary").expect("write real wrapper");
        // The symlink itself sits in `base`, a sibling of (not inside) `workspace` —
        // exactly the ordinary-dev-layout shape (wrapper sibling of the daemon binary)
        // — but its *target* is inside `workspace`.
        std::os::unix::fs::symlink(&real_wrapper, base.join(WRAPPER_BINARY_NAME))
            .expect("create symlink");

        let resolved = resolve_existing_candidate(&base, WRAPPER_BINARY_NAME)
            .expect("the symlink resolves to a real file");
        let canonical_workspace = std::fs::canonicalize(&workspace).unwrap();

        assert_eq!(
            resolved,
            std::fs::canonicalize(&real_wrapper).unwrap(),
            "must return the symlink's real target, not the symlink's own path"
        );
        assert!(
            wrapper_is_inside_workspace(&resolved, &canonical_workspace),
            "the canonicalized wrapper path must be detected as inside the workspace"
        );
        // Sanity: the un-resolved symlink path itself is NOT lexically inside the
        // workspace — this is exactly the gap that canonicalizing at resolution time
        // closes. Before this fix, `wrapper_binary_path` returned this un-resolved
        // path and this containment check would have missed the real hazard entirely.
        assert!(!wrapper_is_inside_workspace(
            &base.join(WRAPPER_BINARY_NAME),
            &canonical_workspace
        ));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn resolve_existing_candidate_returns_none_when_nothing_exists_there() {
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-missing-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).expect("create base dir");
        assert!(resolve_existing_candidate(&base, WRAPPER_BINARY_NAME).is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    // Fix round 3, item 3: `same_inode` is the backstop for a bind-mount alias, which
    // Landlock (and the kernel generally) resolves by inode rather than by path.
    // Directory hard links are refused by the kernel itself (`EPERM`), so this
    // exercises the exact comparison `same_inode` performs using a **file** hard link,
    // which the kernel does allow — `dev()`/`ino()` equality is file-type-agnostic.
    //
    // **Fix round 4, item 2 (Ruling W5-44) corrects what this comment used to claim.**
    // It said a real bind-mount alias of `/` could not be produced in this environment,
    // citing `unshare --user --map-root-user --mount` with `mount --bind / <dir>`. That
    // was wrong by one character: `--bind` fails on `/` (`wrong fs type, bad option,
    // bad superblock`) but **`--rbind` succeeds**, unprivileged, no bwrap. So this test
    // is no longer the only reachable evidence — see
    // `validate_workspace_root_refuses_a_bind_mount_alias_of_the_filesystem_root`
    // below, which drives the real call site with a real alias. This one stays as the
    // cheap, namespace-free unit check of the comparison itself.
    #[test]
    fn same_inode_detects_two_distinct_canonical_paths_sharing_one_inode() {
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-inode-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).expect("create base dir");
        let original = base.join("original");
        std::fs::write(&original, b"x").expect("write original");
        let alias = base.join("alias");
        std::fs::hard_link(&original, &alias).expect("create hard link");

        let canonical_original = std::fs::canonicalize(&original).unwrap();
        let canonical_alias = std::fs::canonicalize(&alias).unwrap();
        assert_ne!(
            canonical_original, canonical_alias,
            "a hard link keeps two textually distinct paths — canonicalize() has no \
             symlink to resolve here, which is exactly why the path-based checks above \
             cannot see this case on their own"
        );
        assert!(same_inode(&canonical_original, &canonical_alias));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn same_inode_is_false_for_two_genuinely_unrelated_paths() {
        assert!(!same_inode(Path::new("/"), &std::env::temp_dir()));
    }

    // Fix round 3, item 3: wiring — `validate_workspace_root` refuses "/" via the
    // inode backstop as well as the literal-path check above it (both fire for this
    // exact input; this pins that the inode branch alone, in isolation, agrees).
    // Fix round 4, item 4: an inconclusive `stat` must refuse, not permit — this is a
    // refusal predicate, so returning `false` on missing evidence is the fail-open
    // direction.
    #[test]
    fn same_inode_treats_an_unreadable_path_as_aliased_rather_than_as_not_aliased() {
        let missing = std::env::temp_dir().join(format!(
            "roundhouse-landlock-absent-{}",
            uuid::Uuid::new_v4()
        ));
        assert!(!missing.exists());
        assert!(same_inode(&missing, Path::new("/")));
    }

    #[test]
    fn same_inode_confirms_the_filesystem_root_is_its_own_inode() {
        assert!(same_inode(Path::new("/"), Path::new("/")));
    }

    // ---------------------------------------------------------------------------
    // Task 27 fix round 4, item 1 (Ruling W5-44): the `test-util` grandparent trust
    // decision, exercised against synthetic tempdir layouts.
    //
    // These deliberately drive `resolve_grandparent_fallback` — the whole decision —
    // rather than `is_inside_a_target_tree` alone. The pre-existing
    // `an_installed_path_outside_any_target_tree_is_rejected` above calls that helper
    // directly and never the call site, which is why it stayed green straight through
    // fix round 3 silently changing the guard's subject from "where the candidate
    // sits" to "where a symlink points".
    // ---------------------------------------------------------------------------

    /// A canonical, freshly-created base directory with no `target` component of its
    /// own — asserted, not assumed, so a `TMPDIR` that happened to sit under a
    /// `target/` tree fails these tests loudly instead of passing them vacuously.
    #[cfg(feature = "test-util")]
    fn grandparent_case_base(label: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&base).expect("create base dir");
        let base = std::fs::canonicalize(&base).expect("canonicalize base dir");
        assert!(
            !is_inside_a_target_tree(&base),
            "precondition: the temp dir used to build these layouts must not itself sit \
             inside a `target` tree, or every case below passes for the wrong reason: {}",
            base.display()
        );
        base
    }

    /// Case D from the fix-round-4 brief, reproduced end to end through the real
    /// `Isolate::spawn` by the security lens: an install-style grandparent with **no**
    /// `target` component, holding a symlink named `round-landlock-exec` whose target
    /// *does* sit under a `target` tree. Accepted at HEAD `6debf7e` (payload executed,
    /// no ruleset applied, `attest()` still claiming `Tier::Sandbox`); must be refused.
    ///
    /// **This is the test whose failure the literal-path check in
    /// `resolve_grandparent_fallback` is responsible for.** Removing that check must
    /// make this test fail.
    #[cfg(feature = "test-util")]
    #[test]
    fn a_grandparent_outside_any_target_tree_is_refused_even_when_the_symlink_points_into_one() {
        let base = grandparent_case_base("grandparent-case-d");
        // The install location: `<base>/usr-local/bin`'s parent, no `target` anywhere.
        let install_grandparent = base.join("usr-local");
        std::fs::create_dir_all(&install_grandparent).expect("create install grandparent");
        // The attacker-owned payload, deliberately under a `target` component.
        let payload_dir = base.join("attacker/target");
        std::fs::create_dir_all(&payload_dir).expect("create payload dir");
        let payload = payload_dir.join("payload");
        std::fs::write(&payload, b"stand-in payload").expect("write payload");
        std::os::unix::fs::symlink(&payload, install_grandparent.join(WRAPPER_BINARY_NAME))
            .expect("create symlink");

        // Sanity: the symlink really does resolve, so `None` below is the guard's
        // decision and not merely a missing file.
        assert!(
            resolve_existing_candidate(&install_grandparent, WRAPPER_BINARY_NAME).is_some(),
            "the symlink must resolve to a real file, or this test proves nothing"
        );
        assert_eq!(
            resolve_grandparent_fallback(&install_grandparent, WRAPPER_BINARY_NAME),
            None,
            "a wrapper reached from a grandparent outside any `target` tree must be \
             refused however target-ish the symlink's destination looks"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Case D2: the same install-style grandparent, but the symlink's destination has
    /// no `target` component either. Refused at both `722be5b` and HEAD; pinned here as
    /// the control that makes case D's contrast meaningful.
    #[cfg(feature = "test-util")]
    #[test]
    fn a_grandparent_outside_any_target_tree_is_refused_when_the_symlink_also_points_outside_one() {
        let base = grandparent_case_base("grandparent-case-d2");
        let install_grandparent = base.join("usr-local");
        std::fs::create_dir_all(&install_grandparent).expect("create install grandparent");
        let payload_dir = base.join("attacker/plain");
        std::fs::create_dir_all(&payload_dir).expect("create payload dir");
        let payload = payload_dir.join("payload");
        std::fs::write(&payload, b"stand-in payload").expect("write payload");
        std::os::unix::fs::symlink(&payload, install_grandparent.join(WRAPPER_BINARY_NAME))
            .expect("create symlink");

        assert_eq!(
            resolve_grandparent_fallback(&install_grandparent, WRAPPER_BINARY_NAME),
            None
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The mirror image of case D, and the check the *canonical* half is responsible
    /// for: the grandparent is a genuine `target/debug`, but the wrapper there is a
    /// symlink out to a path with no `target` component. Recorded in the fix-round-4
    /// brief as "fail-closed, breaks only a plausible dev layout rather than a
    /// boundary" — it was accepted at `722be5b`, is refused at HEAD, and stays refused.
    ///
    /// Removing the canonical-path check must make this test fail.
    #[cfg(feature = "test-util")]
    #[test]
    fn a_target_tree_grandparent_is_refused_when_its_wrapper_symlinks_out_of_the_target_tree() {
        let base = grandparent_case_base("grandparent-case-out");
        let grandparent = base.join("target/debug");
        std::fs::create_dir_all(&grandparent).expect("create target/debug");
        let payload_dir = base.join("elsewhere");
        std::fs::create_dir_all(&payload_dir).expect("create payload dir");
        let payload = payload_dir.join("payload");
        std::fs::write(&payload, b"stand-in payload").expect("write payload");
        std::os::unix::fs::symlink(&payload, grandparent.join(WRAPPER_BINARY_NAME))
            .expect("create symlink");

        assert!(
            is_inside_a_target_tree(&grandparent.join(WRAPPER_BINARY_NAME)),
            "the literal path must pass, so `None` below is the canonical check's doing"
        );
        assert_eq!(
            resolve_grandparent_fallback(&grandparent, WRAPPER_BINARY_NAME),
            None
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The layout the fallback exists for: a `tests/*.rs` binary in
    /// `target/debug/deps/` finding the real `round-landlock-exec` at its grandparent
    /// `target/debug/`. Both checks must pass, and the canonical path comes back — the
    /// both-sides guard must not become a blanket refusal.
    #[cfg(feature = "test-util")]
    #[test]
    fn the_ordinary_target_debug_grandparent_layout_is_still_accepted() {
        let base = grandparent_case_base("grandparent-case-ok");
        let grandparent = base.join("target/debug");
        std::fs::create_dir_all(&grandparent).expect("create target/debug");
        let wrapper = grandparent.join(WRAPPER_BINARY_NAME);
        std::fs::write(&wrapper, b"stand-in binary").expect("write wrapper");

        assert_eq!(
            resolve_grandparent_fallback(&grandparent, WRAPPER_BINARY_NAME),
            Some(std::fs::canonicalize(&wrapper).unwrap())
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Fix round 4, item 2 (Ruling W5-44): the libtest path of the test below. Passed
    /// to the re-exec'd child as `--exact`, which **exits 0 having run nothing** if it
    /// matches no test — so the outer half asserts on `1 passed`, not just on the exit
    /// status. Keep in sync with the function name.
    const RBIND_ALIAS_TEST_NAME: &str = "landlock_wrap::tests::\
                                         validate_workspace_root_refuses_a_bind_mount_alias_of_the_filesystem_root";

    /// Set by the outer half on the re-exec'd child, carrying the directory that is a
    /// bind-mount alias of `/` inside the child's mount namespace.
    const RBIND_ALIAS_ENV: &str = "ROUNDHOUSE_LANDLOCK_RBIND_ALIAS_DIR";

    /// Fix round 4, item 2 (Ruling W5-44): drives `validate_workspace_root` — the real
    /// call site — against a real bind-mount alias of `/`.
    ///
    /// Why this had to be wired at all: deleting **both** `same_inode(...)` call sites
    /// from `validate_workspace_root` left the whole suite green, because all three
    /// `same_inode` tests call the function directly and nothing drove the validator
    /// with an aliased root. That is structurally the same blind spot as item 1's, in
    /// the same commit.
    ///
    /// The alias makes the two path-based checks above `same_inode` miss by
    /// construction: `canonicalize` resolves symlinks but never bind mounts, so the
    /// alias canonicalizes to its own ordinary tempdir path — neither `"/"` nor a
    /// prefix of any system directory. Only the inode comparison sees it, which is why
    /// removing the `same_inode` call sites makes this test fail.
    ///
    /// The test re-execs its own binary under
    /// `unshare --user --map-root-user --mount` with `mount --rbind / <dir>` (`--bind`
    /// fails on `/`; `--rbind` succeeds, unprivileged) and runs only itself there,
    /// taking the inner branch via `RBIND_ALIAS_ENV`.
    #[test]
    fn validate_workspace_root_refuses_a_bind_mount_alias_of_the_filesystem_root() {
        if let Ok(alias) = std::env::var(RBIND_ALIAS_ENV) {
            // Inner half: we are inside the mount namespace, `alias` *is* `/`.
            let alias = PathBuf::from(alias);
            let canonical = std::fs::canonicalize(&alias).expect("canonicalize the alias");
            assert_ne!(
                canonical,
                Path::new("/"),
                "the alias must canonicalize to its own path, not to \"/\" — otherwise \
                 the literal-root check above `same_inode` would be what refuses it and \
                 this test would prove nothing about the inode backstop"
            );
            let err = validate_workspace_root(&alias)
                .expect_err("a bind-mount alias of \"/\" must be refused");
            match err {
                IsolationError::Unsupported(msg) => assert!(
                    msg.contains("same inode as \"/\""),
                    "the refusal must come from the inode backstop; message was: {msg}"
                ),
                other => panic!("expected Unsupported, got {other:?}"),
            }
            return;
        }

        // Outer half.
        let base = std::env::temp_dir().join(format!(
            "roundhouse-landlock-rbind-{}",
            uuid::Uuid::new_v4()
        ));
        let probe_dir = base.join("probe");
        let alias_dir = base.join("alias");
        std::fs::create_dir_all(&probe_dir).expect("create probe dir");
        std::fs::create_dir_all(&alias_dir).expect("create alias dir");

        const RBIND_SCRIPT: &str = r#"mount --rbind / "$1""#;
        const RBIND_AND_EXEC_SCRIPT: &str =
            r#"mount --rbind / "$1" && exec "$2" --exact "$3" --nocapture --test-threads=1"#;

        // Capability probe, so an environment without user namespaces skips cleanly
        // instead of failing — and so that a failure of the real run below is a real
        // failure rather than an environment gap.
        let probe = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sh", "-c"])
            .arg(RBIND_SCRIPT)
            .arg("sh")
            .arg(&probe_dir)
            .output();
        match &probe {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                eprintln!(
                    "skipping {RBIND_ALIAS_TEST_NAME}: `unshare --user --map-root-user --mount` \
                     with `mount --rbind /` is unavailable here ({}): {}",
                    out.status,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                let _ = std::fs::remove_dir_all(&base);
                return;
            }
            Err(err) => {
                eprintln!("skipping {RBIND_ALIAS_TEST_NAME}: could not run `unshare`: {err}");
                let _ = std::fs::remove_dir_all(&base);
                return;
            }
        }

        let exe = std::env::current_exe().expect("resolve this test binary");
        let out = std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "--mount", "sh", "-c"])
            .arg(RBIND_AND_EXEC_SCRIPT)
            .arg("sh")
            .arg(&alias_dir)
            .arg(&exe)
            .arg(RBIND_ALIAS_TEST_NAME)
            .env(RBIND_ALIAS_ENV, &alias_dir)
            .output()
            .expect("re-exec this test binary inside a mount namespace");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "the re-exec'd inner half failed ({})\n--- child stdout ---\n{stdout}\n--- child \
             stderr ---\n{stderr}",
            out.status
        );
        assert!(
            stdout.contains("1 passed"),
            "libtest exits 0 when `--exact` matches no test, so the exit status alone \
             proves nothing — the inner half must actually have run\n--- child stdout \
             ---\n{stdout}\n--- child stderr ---\n{stderr}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }
}
