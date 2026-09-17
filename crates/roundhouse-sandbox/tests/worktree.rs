//! Integration tests for `roundhouse_sandbox::worktree` (Task 34, lane W5) —
//! against a **real** `git`, in a **real** temp repository this test
//! creates with `git init`. Every test that spawns `git` skips cleanly (with
//! an explanatory `eprintln!` and an early `return`) when `git` is not on
//! this host's `PATH` — matching the crate's existing OS/mechanism-gating
//! convention (see `isolate_fix_round_1.rs`'s `bwrap_and_python_available`).
//! CI is `ubuntu-latest`, where `git` exists, so this is not how these tests
//! pass there.

use roundhouse_sandbox::worktree::{add_worktree, remove_worktree, WorktreeError};
use std::path::{Path, PathBuf};
use std::process::Command;

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// `git init`s a fresh repo in a fresh temp dir, with one commit on the
/// default branch, plus a `mybranch` ref pointing at it. Returns the repo's
/// path; the caller is responsible for cleaning up the returned `TempRepo`'s
/// directory (via `Drop`).
struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "roundhouse-sandbox-worktree-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&path).expect("create temp repo dir");

        let run = |args: &[&str]| {
            let status = Command::new("git")
                .args(args)
                .current_dir(&path)
                .status()
                .expect("spawn git for test fixture setup");
            assert!(status.success(), "git {args:?} failed during test setup");
        };
        run(&["init", "-q"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "test"]);
        std::fs::write(path.join("f.txt"), "hello\n").expect("write fixture file");
        run(&["add", "f.txt"]);
        run(&["commit", "-q", "-m", "init"]);
        run(&["branch", "mybranch"]);

        TempRepo { path }
    }

    fn worktree_list(&self) -> String {
        let output = Command::new("git")
            .args(["worktree", "list"])
            .current_dir(&self.path)
            .output()
            .expect("git worktree list");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn worktree_path(repo: &TempRepo, name: &str) -> PathBuf {
    repo.path
        .parent()
        .expect("repo path has a parent")
        .join(format!(
            "{}-{name}",
            repo.path.file_name().unwrap().to_string_lossy()
        ))
}

#[test]
fn add_worktree_creates_a_real_git_worktree() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = worktree_path(&repo, "wt1");

    add_worktree(&repo.path, &wt, "mybranch").expect("add_worktree must succeed");

    assert!(
        wt.is_dir(),
        "worktree directory must exist after add_worktree"
    );
    assert!(
        repo.worktree_list().contains(wt.to_str().unwrap()),
        "git worktree list must show the new worktree"
    );

    let _ = remove_worktree(&repo.path, &wt);
    let _ = std::fs::remove_dir_all(&wt);
}

#[test]
fn remove_worktree_removes_it() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = worktree_path(&repo, "wt2");

    add_worktree(&repo.path, &wt, "mybranch").expect("add_worktree must succeed");
    assert!(wt.is_dir(), "sanity: worktree must exist before removal");

    remove_worktree(&repo.path, &wt).expect("remove_worktree must succeed");

    assert!(
        !wt.exists(),
        "worktree directory must be gone after remove_worktree"
    );
    assert!(
        !repo.worktree_list().contains(wt.to_str().unwrap()),
        "git worktree list must no longer show the removed worktree"
    );
}

#[test]
fn remove_worktree_force_removes_a_dirty_worktree() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = worktree_path(&repo, "wt3");
    add_worktree(&repo.path, &wt, "mybranch").expect("add_worktree must succeed");

    // A map item's inner steps may write files without committing them —
    // cleanup must not fail just because the item did real, uncommitted
    // work in the worktree. See `remove_worktree`'s own doc comment for why
    // this uses `--force`.
    std::fs::write(wt.join("untracked.txt"), "left behind\n").expect("write untracked file");

    remove_worktree(&repo.path, &wt)
        .expect("remove_worktree must succeed even with untracked files present");
    assert!(!wt.exists());
}

/// Security regression: `base_ref` crosses to git as one discrete argv
/// element after `--`, so a value shaped like a git flag is read by git as
/// a (rejected) literal ref, never as an option. This does not duplicate
/// `roundhouse-flow`'s parse-time `validate_git_ref` — it pins the *other*
/// half of the two-layer guarantee described in `worktree.rs`'s own module
/// doc comment: even a value the parser did not (or could not) reject still
/// cannot inject a flag at the point it actually reaches `git`.
#[test]
fn a_leading_dash_base_ref_cannot_inject_a_git_flag() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = worktree_path(&repo, "wt-injection");

    let result = add_worktree(&repo.path, &wt, "--upload-pack=/tmp/evil");

    assert!(
        matches!(result, Err(WorktreeError::CommandFailed { .. })),
        "a flag-shaped base_ref must be rejected by git as an invalid ref, not accepted \
         as an option — got {result:?}"
    );
    assert!(
        !wt.exists(),
        "no worktree may be created from a rejected base_ref"
    );
}

/// Security regression (fix round 1, item 2): a repo-local `post-checkout`
/// hook (set via repo-local `core.hooksPath`, which `env_clear()` cannot
/// touch — it lives in `.git/config`, not the process environment) must not
/// run when `add_worktree` checks a new worktree out. Reproduced against
/// this exact git binary before the fix: without the `-c core.hooksPath=
/// /dev/null` override, the identical hook fired on a plain
/// `env -i PATH="$PATH" git worktree add`.
#[test]
fn add_worktree_does_not_run_the_repos_post_checkout_hook() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = worktree_path(&repo, "wt-hook");

    let hooks_dir = repo.path.join("my-hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");
    let marker = repo.path.join("HOOK_RAN");
    let hook_path = hooks_dir.join("post-checkout");
    std::fs::write(
        &hook_path,
        format!("#!/bin/sh\ntouch {:?}\n", marker.to_str().unwrap()),
    )
    .expect("write hook script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
            .expect("make hook executable");
    }
    let status = Command::new("git")
        .args(["config", "core.hooksPath", hooks_dir.to_str().unwrap()])
        .current_dir(&repo.path)
        .status()
        .expect("set core.hooksPath for test setup");
    assert!(status.success());

    add_worktree(&repo.path, &wt, "mybranch").expect("add_worktree must still succeed");

    assert!(
        !marker.exists(),
        "the repo-local post-checkout hook must not run during add_worktree \
         (core.hooksPath must be overridden to /dev/null for this invocation)"
    );

    let _ = remove_worktree(&repo.path, &wt);
    let _ = std::fs::remove_dir_all(&wt);
}

/// Security regression (fix round 1, item 4): `--` now precedes both
/// positionals, so a `worktree_path` shaped like a flag also cannot be
/// misread as an option — even though this argument is code-derived, not
/// workflow-author-controlled, today.
#[test]
fn a_leading_dash_worktree_path_cannot_inject_a_git_flag() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    let repo = TempRepo::new();
    let wt = repo.path.parent().unwrap().join("-f");

    let result = add_worktree(&repo.path, &wt, "mybranch");

    // Whatever git makes of a literal `-f`-named path after `--`, it must
    // not be read as git's own `-f`/`--force` flag — the call must not
    // silently succeed against some *other* path than the one requested.
    assert!(
        result.is_ok(),
        "a flag-shaped worktree_path after `--` must be treated as a literal path, got {result:?}"
    );
    assert!(
        wt.is_dir(),
        "the worktree must have been created at the literal `-f` path, not misread as a flag"
    );

    let _ = remove_worktree(&repo.path, &wt);
    let _ = std::fs::remove_dir_all(&wt);
}

/// **Concurrent `add_worktree`/`remove_worktree` against the same repository
/// must all succeed** (Phase 8 Task 25.7 Task 8).
///
/// Per-item worktree *paths* cannot collide — `SandboxWorktreeProvider` mints
/// a fresh uuid subdirectory per call — but `git worktree add` and `git
/// worktree remove` both mutate, and both enumerate, the repository's shared
/// `<repo>/.git/worktrees/` administrative directory. That is a different
/// question from path collision, and empirically (git 2.55.0, this host) it
/// is **not** safe: with no serialization, a `git worktree remove` deleting
/// worktree *A*'s admin directory makes a concurrent `git worktree add`, or a
/// concurrent `git worktree remove` of some unrelated worktree *B*, die with
///
/// ```text
/// fatal: Invalid path '<repo>/.git/worktrees/A': No such file or directory
/// fatal: failed to read .git/worktrees/A/commondir: No such file or directory
/// ```
///
/// — a hard failure of an operation that has nothing to do with *A*. See
/// `roundhouse_sandbox::worktree`'s module doc comment, section "Concurrency:
/// one `git worktree` mutation at a time per repository", for the measured
/// failure rates and for what the serialization added there does and does not
/// cover.
///
/// The shape below is the one that reproduces it: adds running concurrently
/// with removes, which is what a fan-out does as soon as one item releases
/// its worktree while another materializes one. Both halves are asserted
/// `Ok`, because the harm is not corruption of the repository — git's own
/// junk cleanup unwinds a failed `add` — but a *spurious failure* of the
/// sibling operation, which reaches a workflow as an item that failed for
/// something another item did.
#[test]
fn concurrent_add_and_remove_against_one_repo_all_succeed() {
    if !git_available() {
        eprintln!("skipping: git not available on this host");
        return;
    }
    // Sized to reproduce reliably rather than minimally, because the window
    // is narrow: every `git worktree` invocation enumerates
    // `<repo>/.git/worktrees/` and then resolves each entry it found, and the
    // race is a concurrent removal landing between those two. `BALLAST`
    // worktrees stay registered for the whole test purely to widen that
    // enumeration, `WAVE` adds then race `WAVE` removes on top, and `ROUNDS`
    // repeats the race. Measured on this host at git 2.55.0, by deleting the
    // serialization and running this test sixteen times: 8 of 16 runs failed
    // without it and 16 of 16 passed with it. At `BALLAST: 0, WAVE: 40,
    // ROUNDS: 1` only 1 run in 8 failed, which is why the ballast is here.
    const BALLAST: usize = 40;
    const WAVE: usize = 16;
    const ROUNDS: usize = 3;

    let repo = TempRepo::new();
    let repo_root: &Path = &repo.path;
    for i in 0..BALLAST {
        let path = worktree_path(&repo, &format!("ballast{i}"));
        add_worktree(repo_root, &path, "HEAD").expect("seeding a ballast worktree must succeed");
    }

    // The wave that is *removed* during round 0; each round's adds become the
    // next round's removes, which is the shape a fan-out actually has.
    let mut live: Vec<PathBuf> = (0..WAVE)
        .map(|i| worktree_path(&repo, &format!("r0-{i}")))
        .collect();
    for path in &live {
        add_worktree(repo_root, path, "HEAD").expect("seeding the first wave must succeed");
    }

    for round in 1..=ROUNDS {
        let fresh: Vec<PathBuf> = (0..WAVE)
            .map(|i| worktree_path(&repo, &format!("r{round}-{i}")))
            .collect();
        let results: Vec<(&'static str, &PathBuf, Result<(), WorktreeError>)> =
            std::thread::scope(|scope| {
                let mut handles = Vec::new();
                for path in &fresh {
                    handles.push(
                        scope.spawn(move || ("add", path, add_worktree(repo_root, path, "HEAD"))),
                    );
                }
                for path in &live {
                    handles.push(
                        scope.spawn(move || ("remove", path, remove_worktree(repo_root, path))),
                    );
                }
                handles
                    .into_iter()
                    .map(|h| h.join().expect("no worktree thread may panic"))
                    .collect()
            });

        for (op, path, result) in &results {
            assert!(
                result.is_ok(),
                "round {round}: concurrent {op} of {path:?} failed: {result:?}"
            );
        }

        let listing = repo.worktree_list();
        for path in &fresh {
            assert!(
                listing.contains(path.to_str().unwrap()),
                "round {round}: every concurrently added worktree must be registered, missing \
                 {path:?}:\n{listing}"
            );
            assert!(path.is_dir(), "{path:?} must exist on disk");
        }
        for path in &live {
            assert!(
                !listing.contains(path.to_str().unwrap()),
                "round {round}: every concurrently removed worktree must be gone, still listed \
                 {path:?}:\n{listing}"
            );
            assert!(!path.exists(), "{path:?} must be gone from disk");
        }
        live = fresh;
    }

    // Releasing a whole wave at once is the other half of the shape: a fan-out
    // finishing together is all-removes, with no add to interleave with.
    std::thread::scope(|scope| {
        let handles: Vec<_> = live
            .iter()
            .map(|path| scope.spawn(move || (path, remove_worktree(repo_root, path))))
            .collect();
        for handle in handles {
            let (path, result) = handle.join().expect("no worktree thread may panic");
            assert!(
                result.is_ok(),
                "concurrent remove of {path:?} failed: {result:?}"
            );
        }
    });

    let listing = repo.worktree_list();
    assert_eq!(
        listing.lines().count(),
        1 + BALLAST,
        "only the repository's own primary worktree and the ballast may remain:\n{listing}"
    );
}

#[test]
fn add_worktree_defaults_are_reasonable_when_git_is_unavailable() {
    // Not gated on `git_available()` — this asserts behaviour when `git`
    // itself cannot be found at all (a `NoPath`/`Spawn`-shaped failure, not
    // a panic), by pointing PATH resolution failure. Constructed without
    // touching the real `PATH`: pass a repo_root that does not exist, which
    // is a spawn/command failure regardless of whether git is installed.
    let missing_repo = Path::new("/definitely/does/not/exist/roundhouse-sandbox-test");
    let wt = missing_repo.join("wt");
    let result = add_worktree(missing_repo, &wt, "HEAD");
    assert!(
        result.is_err(),
        "add_worktree against a nonexistent repo_root must fail, not silently succeed"
    );
}
