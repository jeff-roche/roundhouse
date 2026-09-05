//! `WorktreeProvider`: the narrow trait `Executor::dispatch_map_step`
//! depends on to materialize and release a real git worktree per fan-out
//! item, plus the one adapter this crate ships that implements it over
//! `roundhouse-sandbox::worktree` (Task 34, lane W5, rulings W5-1/W5-8/
//! W5-22 — the answer to Phase 5 ruling P42, "`map.isolation: worktree` is
//! declared data with no materialization anywhere", **for an explicitly
//! declared `worktree` tier** — fix round 2, item 3, ruling W5-33: a `map`
//! step that leaves `isolation:` unset inherits `Defaults.isolation`
//! without this trait ever being consulted at all, which is P42's shape
//! again, for that one case, not yet fixed — see
//! `crate::exec::Executor::dispatch_map_step`'s own doc comment,
//! "Task 34", for the full qualification).
//!
//! # Why the trait lives here, not in `roundhouse-sandbox` (ruling W5-1)
//!
//! `roundhouse-sandbox` exposes concrete, synchronous, dependency-light
//! primitives and never learns what a workflow, a `map` step, or an
//! expression context is — see `roundhouse_sandbox::worktree`'s own module
//! doc comment. This trait is shaped by exactly one caller,
//! `crate::exec::Executor::dispatch_map_step`, and expresses
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

/// Exactly what `crate::exec::Executor::dispatch_map_step`
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
    /// (`crate::exec::Executor::dispatch_map_step`) holds the
    /// path in a guard it never reconstructs from other data — see that
    /// function's own doc comment for how it guarantees this.
    fn release(&self, worktree_path: &Path) -> Result<(), WorktreeProviderError>;
}

/// A [`WorktreeProvider`] failure. Deliberately not a re-export of
/// `roundhouse_sandbox::worktree::WorktreeError` — the trait is meant to be
/// implementable by something other than [`SandboxWorktreeProvider`]
/// without that implementation needing to name a `roundhouse-sandbox`-
/// specific type.
///
/// Carries **two** renderings, not one (Task 34 fix round 3, ruling
/// W5-36) — see [`Self::safe_summary`]'s own doc comment for why a single
/// message cannot serve both a caller that knows the failing call involved
/// no secret-derived input and one that cannot make that assumption.
#[derive(Debug)]
pub struct WorktreeProviderError {
    /// The full message — for a caller that has established the inputs to
    /// the failing call carry no secret-derived material. May embed
    /// whatever free text the underlying failure carried (a subprocess's
    /// stderr, an OS error message, an echoed argv).
    full: String,
    /// A message that never embeds any text this crate did not itself
    /// choose — see [`Self::safe_summary`].
    safe: String,
}

impl WorktreeProviderError {
    /// Constructs an error with no daylight between the two renderings —
    /// for a failure this implementation knows carries no text from
    /// outside its own control (nothing derived from a workflow-authored,
    /// possibly-secret-influenced value).
    pub fn new(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            safe: message.clone(),
            full: message,
        }
    }

    /// Constructs an error whose full rendering may embed free text from
    /// outside this crate's control, alongside a `safe_summary` that never
    /// does — see [`Self::safe_summary`]'s own doc comment.
    pub fn with_safe_summary(full: impl Into<String>, safe_summary: impl Into<String>) -> Self {
        Self {
            full: full.into(),
            safe: safe_summary.into(),
        }
    }

    /// A rendering safe to persist **even when the input that produced
    /// this failure might be secret-derived** — never embeds a
    /// subprocess's stderr, an OS error message, or an echoed argv; only
    /// this crate's own fixed vocabulary plus non-secret context (a path,
    /// an exit status).
    ///
    /// **Why this exists, not a needle-based scrub of [`Self`]'s
    /// `Display`:** fix round 2 tried scrubbing the *full* rendering by
    /// adding the resolved (potentially secret-derived) value as an extra
    /// redaction needle. Fix round 3's security lens reproduced two ways
    /// that fails: `git`'s own stderr does not always echo a **copy** of
    /// what it was given — `@{upstream}`-style syntax makes `git` die
    /// mid-interpretation and report only a prefix, and `git`'s stderr
    /// buffer silently truncates values past ~4KB — so an exact-match
    /// needle keyed on the whole original value can miss a still-sensitive
    /// transformed or truncated echo entirely. No amount of cleverness in
    /// the scrub closes a *lossy* transform of the input; the only thing
    /// that reliably closes it is never showing that free text at all when
    /// the input might be secret-derived. See
    /// `roundhouse_sandbox::worktree::WorktreeError::safe_summary`'s own
    /// doc comment for the sandbox-crate half of this same reasoning.
    pub fn safe_summary(&self) -> &str {
        &self.safe
    }
}

impl std::fmt::Display for WorktreeProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full)
    }
}

impl std::error::Error for WorktreeProviderError {}

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
///
/// **Recorded, not fixed, this round (Task 34 fix round 1's "Record, do not
/// fix" list):** this directory lives *inside* the main repository's
/// working tree, so from that repository's own point of view it is an
/// ordinary untracked directory — nothing here adds a `.gitignore` entry
/// for it. A workflow step that runs `git clean -ffdx` or `git add -A`
/// against `repo_root` itself (as opposed to inside one of the per-item
/// worktrees) would therefore delete or stage live, in-use worktrees.
/// Whoever wires a real `repo_root` in (`roundhouse-daemon`, lane W1) should
/// account for this — a `.gitignore` line, or relocating this directory
/// outside the tracked tree entirely — rather than this module silently
/// assuming it away. Relocating it is a design change, deliberately not
/// made in this fix round.
///
/// **Also recorded:** under `on_item_error: continue`, an item whose
/// [`WorktreeProvider::release`] call fails leaves its checkout behind and
/// the fan-out keeps going, so repeated release failures across many items
/// accumulate checkouts under this directory rather than being bounded.
/// `remove_worktree`'s `--force` makes an ordinary (non-git-level) release
/// failure unlikely, but it is not eliminated — see
/// `roundhouse_sandbox::worktree::remove_worktree`'s own doc comment for
/// what `--force` does and does not cover.
const WORKTREE_SUBDIR: &str = ".roundhouse-worktrees";

impl WorktreeProvider for SandboxWorktreeProvider {
    fn materialize(&self, base_ref: &str) -> Result<PathBuf, WorktreeProviderError> {
        let worktree_path = self
            .repo_root
            .join(WORKTREE_SUBDIR)
            .join(uuid::Uuid::new_v4().to_string());
        roundhouse_sandbox::worktree::add_worktree(&self.repo_root, &worktree_path, base_ref)
            .map_err(|e| {
                // `e`'s own `Display` can embed `git`'s stderr and this
                // call's argv, either of which can carry `base_ref`
                // verbatim — `safe_summary()` never does. See
                // `WorktreeProviderError::safe_summary`'s own doc comment
                // for why the caller (not this adapter) decides which
                // rendering it may persist.
                WorktreeProviderError::with_safe_summary(
                    format!(
                        "materializing a worktree at {}: {e}",
                        worktree_path.display()
                    ),
                    format!(
                        "materializing a worktree at {}: {}",
                        worktree_path.display(),
                        e.safe_summary()
                    ),
                )
            })?;
        Ok(worktree_path)
    }

    fn release(&self, worktree_path: &Path) -> Result<(), WorktreeProviderError> {
        roundhouse_sandbox::worktree::remove_worktree(&self.repo_root, worktree_path).map_err(|e| {
            WorktreeProviderError::with_safe_summary(
                format!("releasing the worktree at {}: {e}", worktree_path.display()),
                format!(
                    "releasing the worktree at {}: {}",
                    worktree_path.display(),
                    e.safe_summary()
                ),
            )
        })
    }
}
