//! `WorktreeProvider`: the narrow trait `Executor::dispatch_map_step`
//! depends on to materialize and release a real git worktree per fan-out
//! item, plus the one adapter this crate ships that implements it over
//! `roundhouse-sandbox::worktree` (Task 34, lane W5, rulings W5-1/W5-8/
//! W5-22 — the answer to Phase 5 ruling P42, "`map.isolation: worktree` is
//! declared data with no materialization anywhere").
//!
//! # Why the trait lives here, not in `roundhouse-sandbox` (ruling W5-1)
//!
//! `roundhouse-sandbox` exposes concrete, synchronous, dependency-light
//! primitives and never learns what a workflow, a `map` step, or an
//! expression context is — see `roundhouse_sandbox::worktree`'s own module
//! doc comment. This trait is shaped by exactly one caller,
//! [`crate::exec::map_step::Executor::dispatch_map_step`], and expresses
//! precisely what that caller needs: materialize a worktree for one item,
//! release it. Putting the trait in `roundhouse-sandbox` and implementing
//! it here would invert the `flow -> sandbox` dependency edge (`sandbox`
//! would have to know about a "provider" abstraction that exists only for
//! `flow`'s benefit); putting it here and adapting over the sandbox
//! primitive keeps the edge pointing the one way it already does.
//!
//! # Why `repo_root` is explicit, not resolved from a `WorkspaceId` (Task 34 lane boundary)
//!
//! No `WorkspaceId -> path` resolver exists anywhere in this workspace
//! today — `roundhouse_sandbox::isolate`'s own comment records this same
//! finding for the identical reason, and `Isolate::spawn` uses
//! `CommandSpec::cwd` rather than resolving one. [`SandboxWorktreeProvider`]
//! therefore takes `repo_root` as a plain constructor argument. Populating
//! it from daemon config (or from whatever eventually maps a `Job`/
//! `Session` to a real checkout on disk) is `roundhouse-daemon`'s job —
//! lane W1's crate — not this one's; this module provides the seam and the
//! adapter, nothing upstream of it.
use std::path::{Path, PathBuf};

/// Exactly what [`crate::exec::map_step::Executor::dispatch_map_step`]
/// needs from a git-worktree backend: materialize one for a fan-out item,
/// release it afterward. Nothing else — no listing, no locking, no
/// knowledge of `map` or `${{ }}`.
///
/// `Send + Sync` because [`crate::exec::RunContext::worktree_provider`]
/// holds this behind an `Arc<dyn WorktreeProvider>` (so `RunContext` stays
/// `Clone` without requiring every implementation to be `Clone` itself —
/// `Arc<T>: Clone` regardless of `T`).
pub trait WorktreeProvider: Send + Sync {
    /// Creates a new, real worktree checked out at `base_ref` and returns
    /// its absolute path.
    ///
    /// `base_ref` must already be the **fully resolved** ref text — any
    /// `${{ }}` placeholder the workflow author wrote has already been
    /// substituted by the caller before this method is invoked. This
    /// method's own obligation, and the one
    /// [`SandboxWorktreeProvider`] discharges via
    /// `roundhouse_sandbox::worktree::add_worktree`, is to hand `base_ref`
    /// to `git` as a single, discrete argv element — never interpolated
    /// into a shell string — regardless of what it contains. See that
    /// function's own doc comment for the full guarantee.
    fn materialize(&self, base_ref: &str) -> Result<PathBuf, WorktreeProviderError>;

    /// Removes a worktree previously returned by [`Self::materialize`].
    ///
    /// **Callers must pass back exactly the path [`Self::materialize`]
    /// returned** — never a path read from the workflow document or
    /// computed independently. This trait does not and cannot enforce that
    /// on its own (see `roundhouse_sandbox::worktree`'s own module doc
    /// comment, "What this does not attempt"); the one caller in this crate
    /// ([`crate::exec::map_step::Executor::dispatch_map_step`]) holds the
    /// path in a guard it never reconstructs from other data — see that
    /// function's own doc comment for how it guarantees this.
    fn release(&self, worktree_path: &Path) -> Result<(), WorktreeProviderError>;
}

/// A [`WorktreeProvider`] failure. Deliberately a single string-carrying
/// type, not a re-export of `roundhouse_sandbox::worktree::WorktreeError` —
/// the trait is meant to be implementable by something other than
/// [`SandboxWorktreeProvider`] without that implementation needing to name
/// a `roundhouse-sandbox`-specific type. The message is diagnostic text
/// only (never a resolved secret — nothing this trait's one implementation
/// touches is secret-shaped), and callers that log it are expected to
/// treat it exactly like any other `StepStatus::Failed` message.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct WorktreeProviderError(String);

impl WorktreeProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// The one [`WorktreeProvider`] implementation this crate ships: a thin
/// adapter over `roundhouse_sandbox::worktree`'s free functions, rooted at
/// one fixed `repo_root` supplied at construction (see this module's own
/// doc comment for why that argument is explicit rather than resolved).
///
/// Generates a fresh, unique subdirectory per [`WorktreeProvider::materialize`]
/// call — never a path taken from the workflow document, and never reused
/// across calls — so that concurrent or sequential fan-out items never
/// collide on the same worktree path.
pub struct SandboxWorktreeProvider {
    repo_root: PathBuf,
}

impl SandboxWorktreeProvider {
    /// `repo_root` must be the root of a real git repository (i.e.
    /// `git worktree add` run from inside it must succeed) — this
    /// constructor performs no validation of its own; the first
    /// [`WorktreeProvider::materialize`] call surfaces any problem as a
    /// [`WorktreeProviderError`].
    pub fn new(repo_root: PathBuf) -> Self {
        Self { repo_root }
    }
}

/// Where generated worktrees live under `repo_root`, kept out of the way
/// of the repository's own tracked tree. Not `.git/roundhouse-worktrees`:
/// `git worktree add` refuses a path inside `.git`.
const WORKTREE_SUBDIR: &str = ".roundhouse-worktrees";

impl WorktreeProvider for SandboxWorktreeProvider {
    fn materialize(&self, base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        let worktree_path = self
            .repo_root
            .join(WORKTREE_SUBDIR)
            .join(uuid::Uuid::new_v4().to_string());
        roundhouse_sandbox::worktree::add_worktree(&self.repo_root, &worktree_path, base_ref)
            .map_err(|e| {
                WorktreeProviderError::new(format!(
                    "materializing a worktree at {}: {e}",
                    worktree_path.display()
                ))
            })?;
        Ok(worktree_path)
    }

    fn release(&self, worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        roundhouse_sandbox::worktree::remove_worktree(&self.repo_root, worktree_path).map_err(|e| {
            WorktreeProviderError::new(format!(
                "releasing the worktree at {}: {e}",
                worktree_path.display()
            ))
        })
    }
}
