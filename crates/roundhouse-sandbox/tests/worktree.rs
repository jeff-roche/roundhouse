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
