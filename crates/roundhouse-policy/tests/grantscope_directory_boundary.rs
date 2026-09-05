//! Task 24 (W4): `GrantScope::Directory` grants are clamped to the session's
//! workspace boundary. `fs_predicate_for_directory_grant`
//! (`approval.rs`) special-cased only the literal filesystem root — any
//! other shallow ancestor (e.g. `/home` for a task under
//! `/home/alice/project`) produced an unbounded `Predicate::FsPrefix`
//! reaching every other user's home directory.
//!
//! Per Ruling W4-4, `fs_predicate_for_directory_grant` stays private (this
//! bundle's Task 23 narrows this crate's public surface; widening it here
//! would contradict that) and there is no `Predicate::matches_path` — this
//! drives the same security property through the real public
//! `synthesize_grant` + `PolicyEngine::decide` path instead. The
//! function-level unit tests against `fs_predicate_for_directory_grant`
//! itself live in an in-module `#[cfg(test)]` block in `approval.rs`.

use roundhouse_core::{SessionId, TaskId, Timestamp};
use roundhouse_policy::approval::{synthesize_grant, GrantProvenance, GrantScope};
use roundhouse_policy::engine::{Outcome, PolicyEngine};
use roundhouse_policy::FsOp;
use std::path::{Path, PathBuf};

fn provenance() -> GrantProvenance {
    GrantProvenance {
        session_id: SessionId::new(),
        task_id: TaskId::new(),
        ts: Timestamp::from_unix_nanos(0),
    }
}

/// The headline security property: a human approving a shallow ancestor
/// directory (`/home`) for a task that only ever touched
/// `/home/alice/project/src/main.rs` must not produce a grant reaching
/// another user's home directory — the grant is clamped to the workspace
/// boundary (`/home/alice/project`) regardless of how shallow the requested
/// ancestor was.
#[test]
fn a_shallow_ancestor_directory_grant_is_clamped_to_the_workspace_boundary() {
    let boundary = PathBuf::from("/home/alice/project");
    let task_path = PathBuf::from("/home/alice/project/src/main.rs");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home"),
        },
        provenance(),
        &boundary,
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let other_users_key = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/bob/.ssh/id_rsa"),
        canonical: Ok(PathBuf::from("/home/bob/.ssh/id_rsa")),
    };
    assert_ne!(
        engine.decide(&other_users_key).outcome,
        Outcome::Allow,
        "a /home-shallow grant under a /home/alice/project boundary must not \
         reach another user's home directory"
    );

    let within_the_boundary = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/alice/project/src/main.rs"),
        canonical: Ok(PathBuf::from("/home/alice/project/src/main.rs")),
    };
    assert_eq!(
        engine.decide(&within_the_boundary).outcome,
        Outcome::Allow,
        "the grant must still cover the workspace it was clamped to"
    );
}

/// The workspace boundary itself is not widened when the requested ancestor
/// is already at or below it — no clamping should occur in the common case.
#[test]
fn a_directory_grant_at_or_below_the_boundary_is_unaffected() {
    let boundary = PathBuf::from("/home/alice/project");
    let task_path = PathBuf::from("/home/alice/project/sub/notes.txt");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home/alice/project/sub"),
        },
        provenance(),
        &boundary,
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let sibling = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/alice/project/sub/other.txt"),
        canonical: Ok(PathBuf::from("/home/alice/project/sub/other.txt")),
    };
    assert_eq!(engine.decide(&sibling).outcome, Outcome::Allow);

    let outside_sub = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/alice/project/other.txt"),
        canonical: Ok(PathBuf::from("/home/alice/project/other.txt")),
    };
    assert_ne!(engine.decide(&outside_sub).outcome, Outcome::Allow);
}

/// Disjoint trees: the requested ancestor is not an ancestor of the
/// workspace boundary at all, in either direction. Fail closed — no
/// directory-wide grant, only the task's own exact path.
#[test]
fn a_directory_grant_disjoint_from_the_workspace_boundary_fails_closed() {
    let task_path = PathBuf::from("/home/alice/project/notes.txt");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    // `/home/alice/project` (task's canonical path's real ancestor) is
    // requested as the directory, but the workspace boundary handed in is a
    // completely unrelated tree — a caller bug, or a compromised/buggy UI
    // layer, must not be trusted to widen the grant regardless.
    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home/alice/project"),
        },
        provenance(),
        Path::new("/var/other-workspace"),
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    // The task's own exact write is still allowed (never narrower than the
    // task itself).
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);

    // But nothing else under the requested (disjoint-from-boundary)
    // directory is granted.
    let sibling = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/alice/project/other.txt"),
        canonical: Ok(PathBuf::from("/home/alice/project/other.txt")),
    };
    assert_ne!(
        engine.decide(&sibling).outcome,
        Outcome::Allow,
        "a directory request disjoint from the workspace boundary must not \
         produce any directory-wide grant"
    );
}

/// B2 (review round 2): `Path::starts_with` returns `true` for both `/` and
/// `""` against any absolute path — so before this fix, a `workspace_boundary`
/// of either degenerate value made the "dir at or below the boundary" branch
/// always taken, restoring exact pre-Task-24 behaviour with no error and no
/// log: a shallow ancestor like `/home`, granted for a task that only ever
/// touched one file under it, would produce an unbounded `FsPrefix` reaching
/// every other user's home directory. All three degenerate boundaries below
/// must instead fail closed to the exact-path downgrade.
#[test]
fn a_root_workspace_boundary_does_not_disable_the_clamp() {
    let task_path = PathBuf::from("/home/alice/project/src/main.rs");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home"),
        },
        provenance(),
        Path::new("/"),
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let other_users_key = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/bob/.ssh/id_rsa"),
        canonical: Ok(PathBuf::from("/home/bob/.ssh/id_rsa")),
    };
    assert_ne!(
        engine.decide(&other_users_key).outcome,
        Outcome::Allow,
        "a `/` workspace boundary must not be treated as \"no clamp\" and let a shallow \
         /home grant reach another user's home directory"
    );

    // The task's own write is still Allow — the downgrade to FsExact never
    // makes the grant narrower than what was actually approved.
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);
}

#[test]
fn an_empty_workspace_boundary_does_not_disable_the_clamp() {
    let task_path = PathBuf::from("/home/alice/project/src/main.rs");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home"),
        },
        provenance(),
        Path::new(""),
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let other_users_key = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/bob/.ssh/id_rsa"),
        canonical: Ok(PathBuf::from("/home/bob/.ssh/id_rsa")),
    };
    assert_ne!(
        engine.decide(&other_users_key).outcome,
        Outcome::Allow,
        "an empty workspace boundary must not be treated as \"no clamp\" either"
    );
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);
}

#[test]
fn a_relative_workspace_boundary_does_not_disable_the_clamp() {
    let task_path = PathBuf::from("/home/alice/project/src/main.rs");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/home"),
        },
        provenance(),
        Path::new("workspace"),
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let other_users_key = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/home/bob/.ssh/id_rsa"),
        canonical: Ok(PathBuf::from("/home/bob/.ssh/id_rsa")),
    };
    assert_ne!(
        engine.decide(&other_users_key).outcome,
        Outcome::Allow,
        "a relative workspace boundary can't meaningfully bound an absolute path and must \
         not be treated as \"no clamp\""
    );
    assert_eq!(engine.decide(&params).outcome, Outcome::Allow);
}

/// The literal filesystem-root special case (finding 3, Task 15) must keep
/// working under the new boundary-aware code path.
#[test]
fn filesystem_root_directory_request_still_downgrades_to_exact() {
    let boundary = PathBuf::from("/workspace");
    let task_path = PathBuf::from("/workspace/notes.txt");
    let params = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: task_path.clone(),
        canonical: Ok(task_path.clone()),
    };

    let grant = synthesize_grant(
        &params,
        GrantScope::Directory {
            path: PathBuf::from("/"),
        },
        provenance(),
        &boundary,
    );
    let engine = PolicyEngine::from_rules(vec![grant
        .into_rule_for_installation()
        .expect("Directory scope installs cleanly")]);

    let unrelated = roundhouse_policy::TaskParams::Fs {
        op: FsOp::Write,
        path: PathBuf::from("/etc/shadow"),
        canonical: Ok(PathBuf::from("/etc/shadow")),
    };
    assert_ne!(engine.decide(&unrelated).outcome, Outcome::Allow);
}
