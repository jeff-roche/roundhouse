//! Real, persisted `Suspended{AwaitingApproval}` (Task 15) — closes §1.1 bug
//! #2, where "Suspended" was treated as an in-memory-only future rather than
//! a real, restart-surviving state. `suspend_for_approval` mints and
//! persists the `TaskSuspended{AwaitingApproval}` event through the real
//! `TaskRunner`/`EventWriter` pair (the source of truth across restarts) and
//! registers the same fact live in an `ApprovalRegistry` in the same call —
//! the two were previously separate concerns with nothing joining them,
//! which is exactly how audit finding 6's empty re-arm loop happened:
//! persistence worked, but nothing live ever got told.
//!
//! `synthesize_grant` turns an approved decision into a policy rule, and is
//! total over every `TaskParams` kind — audit finding 5: it previously
//! panicked with `unimplemented!()` on every kind except `Fs`, meaning the
//! single dominant approval path (a human clicking "allow" on a shell
//! command) crashed the moment anyone actually exercised it.

use crate::engine::{ArgMatcher, CompiledRule, Outcome, Predicate, RuleId, Scope};
use crate::registry::{ApprovalRegistry, PendingApproval};
use crate::{FsOp, PathErr, TaskParams};
use roundhouse_core::{SessionId, TaskId, TaskRunner, Timestamp};
use roundhouse_store::{EventWriter, StoreError};
use std::path::PathBuf;

/// How broadly a synthesized [`Grant`] is meant to apply, from the caller's
/// (a human clicking "allow") point of view — see [`synthesize_grant`] for
/// how each variant maps onto a [`CompiledRule`]'s predicate.
///
/// **Security fix round 1, finding 5:** none of these variants currently has
/// real lifetime enforcement (a TTL, a use-count, or session-binding) inside
/// `PolicyEngine` itself — that machinery does not exist yet anywhere in this
/// crate. `Once`/`Session`/`ExactArgv` are semantically supposed to expire
/// (after one use, at session end, or after one exact-argv match
/// respectively), but nothing currently enforces that expiry once a
/// `CompiledRule` is installed into a live `PolicyEngine`. Use
/// [`Grant::into_rule_for_installation`] rather than reading [`Grant::rule`]
/// directly — it refuses to hand back a rule for these three variants,
/// specifically so a future caller can't silently turn a one-time approval
/// into a standing rule by grabbing the obvious field.
#[derive(Debug, Clone)]
pub enum GrantScope {
    /// Meant to authorize exactly one more matching task, then expire.
    /// **Not enforced yet** — see the type doc comment.
    Once,
    /// Meant to authorize matching tasks for the remainder of the
    /// originating session, then expire. **Not enforced yet.**
    Session,
    /// Meant to authorize only the exact argv whose digest is `hash`, for
    /// some caller-defined lifetime. **Not enforced yet.**
    ExactArgv { hash: [u8; 32] },
    /// A standing rule scoped to everything under `path` (validated to be an
    /// ancestor of the originating task's own canonical path — see
    /// [`synthesize_grant`]'s finding-3 fix). Meant to be durable, so this
    /// one and `Always` are the two variants [`Grant::into_rule_for_installation`]
    /// actually hands back a rule for.
    Directory { path: PathBuf },
    /// A standing, workspace-wide rule. Meant to be durable — see `Directory`.
    Always,
}

/// Who approved a [`Grant`], and when — carried on the synthesized
/// [`CompiledRule`]'s `id` (as `"grant:<session>:<task>"`) and echoed back on
/// the `Grant` itself for audit/debug purposes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GrantProvenance {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub ts: Timestamp,
}

/// The output of [`synthesize_grant`]: a policy rule generalised from one
/// approved task, plus the scope and provenance that produced it.
///
/// Task 23 (W4): `rule` is `pub(crate)`, not `pub` — it used to be `pub`
/// specifically so tests (and [`Grant::into_rule_for_installation`] itself)
/// could inspect the synthesized predicate directly, but that made
/// `into_rule_for_installation`'s loud `Once`/`Session`-scope error trivially
/// bypassable by reading `.rule` directly, which this crate's own test suite
/// did. A caller that wants to actually **install** this grant into a live
/// `PolicyEngine` must go through [`Grant::into_rule_for_installation`]; a
/// caller (in-crate or, via [`Grant::predicate`], out-of-crate) that only
/// needs to inspect what was synthesized — never install it — has that
/// narrower accessor instead.
pub struct Grant {
    pub scope: GrantScope,
    pub(crate) rule: CompiledRule,
    pub provenance: GrantProvenance,
}

/// Returned by [`Grant::into_rule_for_installation`] when a grant's scope has
/// no real lifetime enforcement built yet — see that method's doc comment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantInstallError {
    #[error(
        "GrantScope::{0} has no real lifetime enforcement (TTL/use-count/session-binding) \
         built yet in the policy engine — installing its CompiledRule directly into a live \
         PolicyEngine would silently turn a one-time or session-scoped approval into a \
         permanent standing rule. Do not install this grant's rule until real enforcement \
         exists for this scope."
    )]
    UnenforcedLifetime(&'static str),
}

/// A standing grant that Task 23 may persist and reload. Its rule is private
/// so callers cannot bypass the scope check by replacing it before install.
#[derive(Debug, Clone)]
pub struct RememberedGrant {
    scope: RememberedGrantScope,
    rule: CompiledRule,
    provenance: GrantProvenance,
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
enum RememberedGrantScope {
    Directory,
    Always,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RememberedGrantWire {
    scope: RememberedGrantScope,
    rule: RememberedRule,
    provenance: GrantProvenance,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct RememberedRule {
    scope: Scope,
    outcome: Outcome,
    predicate: Predicate,
    id: RuleId,
}

/// A grant cannot be remembered unless its scope is a real standing scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RememberedGrantError {
    #[error("GrantScope::{0} has no lifetime enforcement and cannot be remembered")]
    UnenforcedLifetime(&'static str),
}

impl RememberedGrant {
    /// Returns the validated, policy-owned rule for engine assembly after a
    /// persisted record has been loaded by Task 23.
    pub fn into_rule(self) -> CompiledRule {
        self.rule
    }

    /// Preserves the original approval metadata for audit and storage layers.
    pub fn provenance(&self) -> &GrantProvenance {
        &self.provenance
    }
}

impl<'de> serde::Deserialize<'de> for RememberedGrant {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = RememberedGrantWire::deserialize(deserializer)?;
        let scope_matches = matches!(
            (wire.scope, wire.rule.scope),
            (RememberedGrantScope::Directory, Scope::Grant)
                | (RememberedGrantScope::Always, Scope::Workspace)
        );
        if !scope_matches || wire.rule.outcome != Outcome::Allow {
            return Err(serde::de::Error::custom(
                "remembered grants require an Allow rule at their durable scope",
            ));
        }
        let expected_id = format!(
            "grant:{}:{}",
            wire.provenance.session_id.as_uuid(),
            wire.provenance.task_id.as_uuid()
        );
        if wire.rule.id.0 != expected_id {
            return Err(serde::de::Error::custom(
                "remembered grant rule id does not match its provenance",
            ));
        }
        Ok(Self {
            scope: wire.scope,
            rule: CompiledRule::new(
                wire.rule.scope,
                wire.rule.outcome,
                wire.rule.predicate,
                0,
                wire.rule.id,
            ),
            provenance: wire.provenance,
        })
    }
}

impl serde::Serialize for RememberedGrant {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        RememberedGrantWire {
            scope: self.scope,
            rule: RememberedRule {
                scope: self.rule.scope(),
                outcome: self.rule.outcome(),
                predicate: self.rule.predicate().clone(),
                id: self.rule.id().clone(),
            },
            provenance: self.provenance.clone(),
        }
        .serialize(serializer)
    }
}

impl Grant {
    /// Whether this grant's synthesized rule covers a filesystem task with
    /// the given `op`/`path`. **`Fs`-specific only** — for any grant
    /// synthesized from a `Shell`/`Http`/`Mcp`/`Git`/`Agent` task (i.e. the
    /// predicate is not `FsPrefix`/`FsExact`), this always returns `false`;
    /// it is not a general-purpose "does this grant cover this task" check
    /// for those kinds. Callers working with non-`Fs` `TaskParams` must use
    /// [`Grant::predicate`] and match on it directly instead (Task 23 (W4):
    /// `self.rule.predicate` is no longer reachable from outside this crate).
    ///
    /// **Security fix round 1, finding 4:** now also checks `op` (previously
    /// only compared the path, so e.g. a grant synthesized for `FsOp::Read`
    /// wrongly reported `true` for a `Write` on the same path — the real
    /// `Predicate::matches` in `engine.rs` has always gated on `op`, this
    /// helper just hadn't matched that).
    pub fn rule_covers_path(&self, op: FsOp, path: &PathBuf) -> bool {
        match self.rule.predicate() {
            Predicate::FsPrefix { op: pop, prefix } => *pop == op && path.starts_with(prefix),
            Predicate::FsExact { op: pop, path: p } => *pop == op && path == p,
            _ => false,
        }
    }

    /// The synthesized predicate this grant's `CompiledRule` was built with —
    /// read-only inspection, never installation. Task 23 (W4): added
    /// alongside narrowing `Grant.rule` to `pub(crate)`, specifically for
    /// callers (this crate's own non-`Fs` tests, chiefly) that need to see
    /// what [`synthesize_grant`] produced regardless of the grant's
    /// [`GrantScope`] — `into_rule_for_installation` is *not* a substitute
    /// here, because it errors for `Once`/`Session`/`ExactArgv` scopes (see
    /// its own doc comment), and inspecting the synthesized predicate is a
    /// legitimate thing to want to do even for a scope with no installable
    /// rule yet.
    ///
    /// **This is narrower than a guarantee, not a guarantee itself (B1,
    /// review round 2):** narrowing `Grant.rule` to `pub(crate)` removes the
    /// *convenient* bypass of reading `.rule` directly, but `Predicate`
    /// derives `Clone` and `CompiledRule`'s fields (including `test_new`,
    /// `pub fn`) are all `pub`, so three lines from outside this crate can
    /// still do `CompiledRule::test_new(scope, outcome,
    /// grant.predicate().clone())` and hand the result to
    /// `PolicyEngine::from_rules`, reconstructing an installable rule from a
    /// `Once`/`Session`/`ExactArgv` grant without ever going through
    /// [`Grant::into_rule_for_installation`]. Note this accessor is not
    /// *required* for that bypass either — `Predicate` is a fully public
    /// enum, so a determined caller could hand-construct an equivalent
    /// predicate without `Grant` at all — so removing `predicate()` would
    /// not close anything either. What narrowing `rule` and keeping this
    /// accessor read-only-typed actually buys is removing the one-line
    /// bypass and making the intended path (`into_rule_for_installation`)
    /// the obvious one; it is a known limit of this crate's current
    /// enforcement, not a guarantee that a determined out-of-crate caller
    /// cannot reconstruct an installable rule.
    pub fn predicate(&self) -> &Predicate {
        self.rule.predicate()
    }

    /// The only sanctioned way to obtain this grant's `CompiledRule` for
    /// installation into a live `PolicyEngine`. **Security fix round 1,
    /// finding 5:** errors loudly, rather than silently handing back a rule
    /// that outlives what the human actually approved, for scopes this crate
    /// has no real lifetime enforcement for yet (`Once`/`Session`/
    /// `ExactArgv` — see [`GrantScope`]'s doc comment: nothing tracks TTL,
    /// use-count, or session-binding for those, and `PolicyEngine` has no
    /// such concept at all today). `Directory`/`Always` are the two scopes
    /// that are genuinely meant to become standing rules, so those pass
    /// through unchanged.
    ///
    /// Task 23 (W4) closed the hole this method's earlier doc comment
    /// flagged: `Grant.rule` is now `pub(crate)`, not `pub`, so a caller
    /// outside this crate reaching for the obvious thing, `grant.rule`, to
    /// install into `PolicyEngine::from_rules` gets a compile error instead
    /// of silently reproducing the "one-time approval becomes a permanent
    /// rule" bug this synthesis module exists to prevent — this method is
    /// now the *only* way to obtain a `CompiledRule` from a `Grant` at all,
    /// in-crate or out. Real TTL/use-count/session-binding *enforcement*
    /// inside `PolicyEngine` itself remains out of scope for this task —
    /// this method only makes the current absence of that enforcement
    /// impossible to silently misuse.
    pub fn into_rule_for_installation(&self) -> Result<CompiledRule, GrantInstallError> {
        match standing_scope(&self.scope) {
            Ok(_) => Ok(self.rule.clone()),
            Err(scope) => Err(GrantInstallError::UnenforcedLifetime(scope)),
        }
    }

    /// Converts a standing grant to the only serializable representation Task
    /// 23 may persist. One-shot and session-scoped grants are rejected before
    /// they can be mistaken for standing policy.
    pub fn into_remembered(self) -> Result<RememberedGrant, RememberedGrantError> {
        let scope =
            standing_scope(&self.scope).map_err(RememberedGrantError::UnenforcedLifetime)?;
        Ok(RememberedGrant {
            scope,
            rule: self.rule,
            provenance: self.provenance,
        })
    }
}

fn standing_scope(scope: &GrantScope) -> Result<RememberedGrantScope, &'static str> {
    match scope {
        GrantScope::Once => Err("Once"),
        GrantScope::Session => Err("Session"),
        GrantScope::ExactArgv { .. } => Err("ExactArgv"),
        GrantScope::Directory { .. } => Ok(RememberedGrantScope::Directory),
        GrantScope::Always => Ok(RememberedGrantScope::Always),
    }
}

/// A grant is generalised strictly downward from the task that produced it —
/// never broader (§6.4) — for **every** `TaskParams` kind, not just `Fs`.
/// Fixes audit finding 5: this previously panicked with `unimplemented!()`
/// for Shell/Http/Mcp/Git/Agent, meaning the single dominant approval path
/// (a human approving a shell command) crashed the moment anyone actually
/// clicked "allow."
///
/// Per kind: `Fs` under `Directory` scope becomes a path-prefix rule bounded
/// at that directory — but only when `path` is actually an ancestor of the
/// task's own canonical path (security fix round 1, finding 3: previously
/// any caller-supplied `Directory{path}` was trusted verbatim, so a bug
/// upstream that passed e.g. `path: "/"` for a task that wrote
/// `/workspace/notes.txt` would silently produce a filesystem-wide grant;
/// see `fs_predicate_for_directory_grant`'s doc comment for the downgrade
/// behavior when `path` is not an ancestor). Every other combination —
/// including `Fs` under any other scope — pins to the exact **canonical**
/// value (security fix round 1, finding 9: previously pinned to the raw,
/// possibly-uncanonicalized `path` field, which the real matcher never
/// compares against, so it was dead-on-arrival whenever the two differed):
/// `Shell` binds the exact argv (never a wildcard program-only rule),
/// `Http`/`Git` bind the exact URL / exact subcommand+argv (security fix
/// round 1, findings 1/2: previously these produced `starts_with`-style
/// prefix predicates that a model could trivially widen — appending a query
/// string to an approved URL, or extra flags to an approved git invocation —
/// now they set the new `Predicate::Http`/`Predicate::Git` `exact: true`
/// field so the underlying match requires full equality, not merely a
/// prefix), `Mcp` binds server+tool+exact args (Task 22 (W4) added
/// `Predicate::Mcp`'s `args: Option<ArgsPattern>` field; this arm defaults to
/// `ArgsPattern::Exact` so approving one call never covers a future call
/// with different arguments), and `Agent` pins `max_tier` to the tier
/// actually requested (Task 21
/// (W4) flipped that field's comparison to a floor rather than a ceiling —
/// see its doc comment in `engine.rs` — so pinning it here means the grant
/// never generalizes *below* the isolation actually requested).
/// Task 24 (W4): `workspace_boundary` is the session's real workspace root,
/// threaded in by the caller — never derived from `params` (which is
/// entirely caller/task-supplied and must not be trusted to bound itself).
/// Only consulted for the `GrantScope::Directory` + `TaskParams::Fs` arm; see
/// `fs_predicate_for_directory_grant`'s doc comment for what it does with it.
/// B2 (review round 2): this parameter itself is not further validated by
/// `synthesize_grant` — it is still trusted to actually be the caller's real
/// workspace root — but `effective_directory_prefix` (reached from the arm
/// above) does now refuse to treat a degenerate value (`/`, `""`, or a
/// relative path) as "no boundary"; see its doc comment.
/// Orchestrator Ruling W4-7: this is a plain parameter, not a `SealedContext`
/// field — `synthesize_grant` has no callers outside this crate, so the
/// signature change is free, and `SealedContext` is lane W1's actively-edited
/// file.
pub fn synthesize_grant(
    params: &TaskParams,
    scope: GrantScope,
    provenance: GrantProvenance,
    workspace_boundary: &std::path::Path,
) -> Grant {
    let predicate = match (&scope, params) {
        (
            GrantScope::Directory { path },
            TaskParams::Fs {
                op,
                path: task_path,
                canonical,
            },
        ) => fs_predicate_for_directory_grant(op, task_path, canonical, path, workspace_boundary),
        (
            _,
            TaskParams::Fs {
                op,
                path,
                canonical,
            },
        ) => Predicate::FsExact {
            op: clone_op(op),
            path: canonical_or_raw(canonical, path),
        },
        (_, TaskParams::Shell(cmd)) => Predicate::Shell {
            program: cmd.program.clone(),
            matcher: ArgMatcher::Exact(cmd.argv.clone()),
            allow_interpreter: false,
        },
        (_, TaskParams::Http { method, url, .. }) => Predicate::Http {
            method: Some(*method),
            url_prefix: url.clone(),
            exact: true, // finding 1: exact URL, never a starts_with-widenable prefix
        },
        // Task 22 (W4): defaults to `ArgsPattern::Exact` binding, per the
        // least-privilege principle every other grant type in this file
        // already follows — a human approving one specific MCP call must
        // not also grant every future call to that tool regardless of
        // arguments.
        (_, TaskParams::Mcp { server, tool, args }) => Predicate::Mcp {
            server: server.clone(),
            tool: Some(tool.clone()),
            args: Some(crate::engine::ArgsPattern::Exact(args.clone())),
        },
        (
            _,
            TaskParams::Git {
                subcommand, argv, ..
            },
        ) => Predicate::Git {
            subcommand: subcommand.clone(),
            argv_prefix: argv.clone(),
            exact: true, // finding 2: exact argv, never a starts_with-widenable prefix
        },
        (
            _,
            TaskParams::Agent {
                provider,
                model,
                tier_request,
            },
        ) => Predicate::Agent {
            provider: Some(provider.clone()),
            model: Some(model.clone()),
            // Task 21 (W4): `max_tier` is now a floor, not a ceiling (see its
            // doc comment in `engine.rs`) — pinning it to the tier actually
            // requested means the grant never generalizes *below* the
            // isolation actually requested, i.e. it covers only requests at
            // or above what this task asked for, never a less-isolated one.
            //
            // That framing is safe only on the isolation axis, not the
            // egress axis (see `Predicate::Agent::max_tier`'s doc comment in
            // `engine.rs` for the full argument): `Tier::Remote` ships the
            // `CommandSpec` over the network
            // (`docs/architecture/03-security-and-sandboxing.md:213`), a
            // property `Tier::None` lacks. Pinning `max_tier` to an approved
            // `Tier::None` request covers all five tiers, including
            // `Remote`, because `None` is the universal floor — so a human
            // approving one local, unisolated spawn would, once agent-spawn
            // policy wiring lands, silently authorize a `Tier::Remote` spawn
            // too. Tracked as defect (A), not implemented here (orchestrator
            // Ruling W4-23 — see `engine.rs`): an `exact: bool` on
            // `Predicate::Agent`, matching `Predicate::Http`/`Predicate::Git`,
            // where matching would become `tier_request == max_tier`.
            //
            // A second, separate tracked defect (B, orchestrator Ruling
            // W4-24) also touches this field: `max_tier` is excluded from
            // `matches`'s specificity `bound`, so two `Agent` rules
            // differing only in floor tie-break by `file_order` instead of
            // by specificity. Its fix component is making the floor
            // `Option<Tier>`. (A) and (B) are distinct bugs — closing one
            // does not close the other; see `Predicate::Agent::max_tier`'s
            // doc comment in `engine.rs` for the full argument.
            max_tier: *tier_request,
        },
        // Task 20 (W4): exact scope+op bind, same least-privilege contract as
        // every other arm. Fix round 1 (Ruling W4-11): also binds the exact
        // requesting `session` (`Some(session)`, never `None`) — a grant
        // synthesized from one session's approved request must not also
        // match a different session's identical request, since
        // `PolicyEngine` is shared across every session actor behind an
        // `Arc`. Inert for `Team` scope regardless of what grant is
        // synthesized here — `PolicyEngine::decide` never consults rules for
        // `MemoryScope::Team` Allow, only `TeamMembership` (see
        // `Predicate::Memory`'s doc comment in `engine.rs`).
        (_, TaskParams::Memory { scope, op, session }) => Predicate::Memory {
            scope: scope.clone(),
            op: *op,
            session: Some(*session),
        },
    };
    let rule = CompiledRule::new(
        grant_rule_scope(&scope),
        Outcome::Allow,
        predicate,
        0,
        RuleId(format!(
            "grant:{}:{}",
            provenance.session_id.as_uuid(),
            provenance.task_id.as_uuid()
        )),
    );
    Grant {
        scope,
        rule,
        provenance,
    }
}

/// Builds the `Fs` predicate for a `GrantScope::Directory { path }` grant.
/// **Security fix round 1, finding 3.** `path` is caller-supplied and, prior
/// to this fix, was trusted verbatim — nothing checked it was actually an
/// ancestor of the task's own (canonical) path, so a caller bug (or a future
/// compromised/buggy UI layer) that constructed e.g.
/// `GrantScope::Directory { path: "/".into() }` for a task that only wrote
/// `/workspace/notes.txt` would silently produce a filesystem-wide grant —
/// directly contradicting `synthesize_grant`'s own "never broader" contract.
///
/// Fix: only build the wide `FsPrefix` when ALL of the following hold:
/// `canonical` is `Ok`, `canonical` is actually prefixed by `dir` (a genuine
/// ancestor relationship, not an unrelated tree), AND `dir` is not the
/// filesystem root itself. The root check is necessary in addition to the
/// ancestor check because `Path::starts_with` treats `/` as a (trivial)
/// ancestor of every absolute path — an ancestor check alone does **not**
/// reject `GrantScope::Directory { path: "/" }`, which is exactly the
/// literal reproduction the security auditor used. Any of these checks
/// failing **downgrades** to an `FsExact` bound to the task's own canonical
/// path (or, if canonicalization itself failed, to the raw observed `path`
/// — `decide` hard-Denies `canonical: Err` tasks upstream, so this arm
/// should be unreachable in practice, but must still fail closed rather than
/// panic or fabricate a wide grant if it somehow is reached). A downgrade is
/// always at least as narrow as what was actually approved — it can never be
/// broader — so this never violates the "never broader" contract even when
/// it silently narrows a caller's mistaken request.
///
/// **Task 24 (W4) closed the residual gap this comment used to flag:** the
/// checks above rejected the literal filesystem root and genuinely unrelated
/// (non-ancestor) directories, but a caller could still request a
/// shallow-but-non-root ancestor that is technically a real ancestor of the
/// task's path yet still far broader than what a human plausibly meant to
/// approve (e.g. `path: "/home"` for a task that wrote
/// `/home/alice/project/notes.txt` — a genuine ancestor, not the filesystem
/// root, but still covers every other user's home directory). Now that
/// `synthesize_grant` threads `workspace_boundary` through, this function
/// clamps the effective prefix to whichever of `{dir, workspace_boundary}` is
/// deeper **by real containment**, not depth arithmetic — a path can be
/// deeper without being inside another, so this uses `starts_with` in both
/// directions rather than counting path components. See
/// [`effective_directory_prefix`] for the three-way case analysis (dir at/
/// below the boundary; dir a shallower ancestor of the boundary; disjoint
/// trees, which fail closed).
fn fs_predicate_for_directory_grant(
    op: &FsOp,
    task_path: &std::path::Path,
    canonical: &Result<PathBuf, PathErr>,
    dir: &std::path::Path,
    workspace_boundary: &std::path::Path,
) -> Predicate {
    // `/`'s parent is `None`; every non-root absolute directory has `Some`
    // parent. This is the targeted check that closes the literal
    // reproduction (`Directory { path: "/" }`) an ancestor check alone
    // cannot, since `/` is trivially an ancestor of everything.
    let is_filesystem_root = dir.parent().is_none();
    match canonical {
        Ok(c) if !is_filesystem_root && c.starts_with(dir) => {
            match effective_directory_prefix(dir, workspace_boundary, c) {
                Some(prefix) => Predicate::FsPrefix {
                    op: clone_op(op),
                    prefix,
                },
                None => Predicate::FsExact {
                    op: clone_op(op),
                    path: c.clone(),
                },
            }
        }
        Ok(c) => Predicate::FsExact {
            op: clone_op(op),
            path: c.clone(),
        },
        Err(_) => Predicate::FsExact {
            op: clone_op(op),
            path: task_path.to_path_buf(),
        },
    }
}

/// Clamps a requested directory-grant ancestor `dir` to never be shallower
/// than `workspace_boundary`, using real path containment (`starts_with`) in
/// both directions rather than component-count depth arithmetic — a path can
/// have more components without being an ancestor/descendant of another at
/// all (e.g. `/home/alice/other-project` has as many components as
/// `/home/alice/project/src` but is not "deeper" in any meaningful sense).
/// Called only after the caller has already verified `dir` is a genuine
/// ancestor of the task's own canonical path `canonical_task_path` — this
/// function only decides how far `dir` may be widened relative to the
/// workspace boundary, not whether `dir` itself is valid at all.
///
/// `workspace_boundary` itself IS validated here, and is the caller's one
/// piece of trusted input this function does check before using it (B2,
/// review round 2): a boundary that is not absolute, or whose `parent()` is
/// `None` (i.e. `/` or `""`, the only two paths for which `Path::starts_with`
/// is trivially true against everything), fails closed to `None` rather than
/// silently acting as "no clamp" — see the guard at the top of the function
/// body.
///
/// Otherwise, three cases, by real containment:
/// - `dir` is already at or below `workspace_boundary`
///   (`dir.starts_with(workspace_boundary)`, which is also true when they're
///   equal): no widening beyond the workspace is possible through this path
///   anyway, so `dir` is used as-is — this is the common case for a
///   legitimately-scoped directory grant.
/// - `dir` is a shallower ancestor of `workspace_boundary`
///   (`workspace_boundary.starts_with(dir)`): clamp **up** to
///   `workspace_boundary` itself, never granting the shallower `dir`.
///   Additionally verified that `canonical_task_path` is actually inside
///   `workspace_boundary` — the task's own path should always be inside its
///   own workspace, but this function never trusts a caller-supplied `dir`
///   (or a mismatched boundary) to imply that on its own; if it somehow
///   isn't, this fails closed to `None` rather than granting a boundary the
///   task itself isn't even under.
/// - Disjoint trees — neither is an ancestor of the other. `dir` cannot be
///   trusted at all relative to this workspace: fails closed to `None`
///   (the caller downgrades to `FsExact` on the task's own canonical path),
///   the same fail-closed choice `fs_predicate_for_directory_grant` already
///   makes when `dir` isn't even an ancestor of the task's path.
fn effective_directory_prefix(
    dir: &std::path::Path,
    workspace_boundary: &std::path::Path,
    canonical_task_path: &std::path::Path,
) -> Option<PathBuf> {
    // B2 (review round 2): `Path::starts_with` returns `true` for both `/`
    // and `""` against any absolute path, so an unvalidated `workspace_boundary`
    // of either makes the first branch below always taken, restoring exact
    // pre-Task-24 behaviour — an ancestor as shallow as `/home` yields an
    // unbounded `FsPrefix` over every user's home directory — with no error
    // and no log. A relative boundary can't meaningfully contain an absolute
    // canonical path either. Guard all three degenerate forms here, at the
    // one place every caller in this crate funnels through, and fail closed
    // to `None` — the same downgrade-to-`FsExact` choice the disjoint-trees
    // case below already makes — rather than trust an unvalidated boundary.
    let boundary_is_degenerate =
        !workspace_boundary.is_absolute() || workspace_boundary.parent().is_none();
    if boundary_is_degenerate {
        return None;
    }

    if dir.starts_with(workspace_boundary) {
        Some(dir.to_path_buf())
    } else if workspace_boundary.starts_with(dir) {
        if canonical_task_path.starts_with(workspace_boundary) {
            Some(workspace_boundary.to_path_buf())
        } else {
            None
        }
    } else {
        None
    }
}

/// The real `Predicate::matches` (`engine.rs`) always compares against
/// `canonical`, never the raw `path` — see finding 9. Prefers `canonical`
/// when it's `Ok`; falls back to the raw path only in the (per `decide`'s
/// upstream hard-Deny on `canonical: Err`, practically unreachable) case
/// where canonicalization failed, so this never panics.
fn canonical_or_raw(canonical: &Result<PathBuf, PathErr>, raw: &std::path::Path) -> PathBuf {
    match canonical {
        Ok(c) => c.clone(),
        Err(_) => raw.to_path_buf(),
    }
}

fn grant_rule_scope(scope: &GrantScope) -> Scope {
    match scope {
        GrantScope::Always => Scope::Workspace, // §6.2: Always writes to Workspace/UserGlobal explicitly
        _ => Scope::Grant,
    }
}

fn clone_op(op: &FsOp) -> FsOp {
    match op {
        FsOp::Read => FsOp::Read,
        FsOp::Write => FsOp::Write,
        FsOp::Edit => FsOp::Edit,
        FsOp::Find => FsOp::Find,
    }
}

/// Persists the `TaskSuspended{AwaitingApproval}` event (source of truth
/// across restarts, via the real `TaskRunner`/`EventWriter` pair — see
/// `roundhouse-core/src/task_runner.rs`'s `record_task_suspended` and
/// `roundhouse-store/src/writer.rs`'s `EventWriter::append`) AND registers
/// it live in the `ApprovalRegistry` in the same call. `seq` is a
/// placeholder: `EventWriter::append` ignores the `seq` field on the `Event`
/// it's handed and assigns the real monotonic-per-session sequence number
/// itself (see `writer.rs`'s `append`/`append_batch` doc comments) — every
/// real call site in this codebase (e.g. `roundhouse-store/tests/suspended.rs`)
/// passes `0` for exactly this reason.
///
/// `rule` is the policy engine's human-readable `RuleId` (`crate::engine::RuleId`,
/// a `String`) — what a real `PolicyEngine::decide` call actually produces on
/// `Outcome::Ask`. `SuspendReason::AwaitingApproval` needs the frozen
/// `roundhouse_core::RuleId(u64)` instead (see that type's doc comment: it's
/// deliberately a different type, since `roundhouse-core` cannot depend on
/// `roundhouse-policy`), so this function converts via
/// `core_rule_id_from_policy_rule_id` — a lossy, one-way provenance pointer,
/// not a reversible mapping.
pub async fn suspend_for_approval(
    writer: &EventWriter,
    runner: &TaskRunner,
    registry: &ApprovalRegistry,
    session_id: SessionId,
    task_id: TaskId,
    rule: Option<RuleId>,
    params: &TaskParams,
) -> Result<(), StoreError> {
    let digest = params_digest(params);
    let ts = now_ts();
    let core_rule = rule.as_ref().map(core_rule_id_from_policy_rule_id);
    let event = runner.record_task_suspended(
        session_id,
        0, // placeholder seq — EventWriter::append assigns the real one
        ts,
        task_id,
        roundhouse_core::SuspendReason::AwaitingApproval {
            rule: core_rule,
            params_digest: digest,
        },
        1, // schema_v
    );
    writer.append(event).await?;
    registry.register(PendingApproval {
        session_id,
        task_id,
        rule,
        params_digest: digest,
        since: ts,
    });
    Ok(())
}

/// **Lossy, one-way provenance pointer as a stopgap** (Ruling 3): converts a
/// policy-engine `RuleId` (a human-readable `String`, e.g.
/// `"grant:<session>:<task>"` or a config-file rule name) into the frozen
/// `roundhouse_core::RuleId(u64)` that `SuspendReason::AwaitingApproval`
/// actually persists, via the first 8 bytes of a `blake3` hash of the
/// string reinterpreted as a little-endian `u64`.
///
/// This is deliberately **not** a real interning table: two different rule-id
/// strings could in principle collide to the same `u64` (astronomically
/// unlikely for blake3, but not structurally impossible), and — more
/// importantly — there is no way to recover the original string from the
/// `u64` alone. A later task that needs to go from a persisted
/// `SuspendReason`'s `RuleId(u64)` back to a human-readable rule name must
/// build a real bidirectional interning table (assigned once when a
/// `CompiledRule` is compiled from config, stable across reloads) — that is
/// explicitly out of scope here, per the addendum.
pub fn core_rule_id_from_policy_rule_id(rule: &RuleId) -> roundhouse_core::RuleId {
    let hash = blake3::hash(rule.0.as_bytes());
    let bytes: [u8; 8] = hash.as_bytes()[..8]
        .try_into()
        .expect("blake3 digest is at least 8 bytes");
    roundhouse_core::RuleId(u64::from_le_bytes(bytes))
}

fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// Hashes `params` via its **canonicalized** JSON encoding, not `Debug`
/// formatting: `TaskParams::Mcp.args` is an arbitrary caller-supplied
/// `serde_json::Value`, and with `serde_json`'s `preserve_order` feature
/// forced on workspace-wide (the pinned ACP SDK requires it), a
/// `Value::Object`'s `Debug`/`Serialize` order reflects insertion order,
/// not a sorted one. Two semantically identical MCP tool calls whose JSON
/// arguments were built with keys in a different order would then digest
/// differently, breaking this function's whole purpose: matching a
/// re-submitted request against a previously recorded grant. Recursively
/// sorting object keys before hashing restores the order-independence a
/// `BTreeMap`-backed `Value` gave for free before that feature was forced
/// on. Mirrored verbatim in `roundhouse-mcp::executor::params_digest` —
/// keep both in sync, since a grant recorded by one must match a digest
/// computed by the other.
fn params_digest(params: &TaskParams) -> [u8; 32] {
    let value = serde_json::to_value(params).expect("TaskParams serialization cannot fail");
    let canonical = canonicalize_json(value);
    let bytes =
        serde_json::to_vec(&canonical).expect("canonicalized value serialization cannot fail");
    *blake3::hash(&bytes).as_bytes()
}

/// Recursively sorts JSON object keys so two values that differ only in
/// object-key insertion order serialize identically.
fn canonicalize_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, canonicalize_json(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(canonicalize_json).collect())
        }
        other => other,
    }
}

/// Task 24 (W4) direct-unit tests against the private
/// `fs_predicate_for_directory_grant`/`effective_directory_prefix` — kept
/// in-module rather than widening the crate's public surface to reach them
/// (Ruling W4-4: Task 23 in this same bundle exists to *narrow* this crate's
/// public surface, so widening it elsewhere here would contradict the
/// bundle's own point). `grantscope_directory_boundary.rs` covers the same
/// security property through the public `synthesize_grant` +
/// `PolicyEngine::decide` path.
#[cfg(test)]
mod directory_boundary_tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn dir_at_or_below_the_boundary_is_used_as_is() {
        let dir = Path::new("/workspace/sub");
        let boundary = Path::new("/workspace");
        let task_path = Path::new("/workspace/sub/notes.txt");
        assert_eq!(
            effective_directory_prefix(dir, boundary, task_path),
            Some(dir.to_path_buf())
        );
    }

    #[test]
    fn dir_equal_to_the_boundary_is_used_as_is() {
        let dir = Path::new("/workspace");
        let boundary = Path::new("/workspace");
        let task_path = Path::new("/workspace/notes.txt");
        assert_eq!(
            effective_directory_prefix(dir, boundary, task_path),
            Some(dir.to_path_buf())
        );
    }

    #[test]
    fn a_shallower_dir_is_clamped_up_to_the_boundary() {
        let dir = Path::new("/home");
        let boundary = Path::new("/home/alice/project");
        let task_path = Path::new("/home/alice/project/src/main.rs");
        assert_eq!(
            effective_directory_prefix(dir, boundary, task_path),
            Some(boundary.to_path_buf()),
            "a shallow ancestor must clamp up to the workspace boundary, never grant the shallower dir"
        );
    }

    #[test]
    fn a_shallower_dir_fails_closed_when_the_task_path_is_outside_the_boundary() {
        // The workspace boundary is deeper than `dir`, but the task's own
        // canonical path isn't even inside that boundary — never trust `dir`
        // to imply that on its own.
        let dir = Path::new("/home");
        let boundary = Path::new("/home/alice/project");
        let task_path = Path::new("/home/bob/other.txt");
        assert_eq!(effective_directory_prefix(dir, boundary, task_path), None);
    }

    #[test]
    fn disjoint_trees_fail_closed() {
        let dir = Path::new("/home/alice/project");
        let boundary = Path::new("/var/other-workspace");
        let task_path = Path::new("/home/alice/project/notes.txt");
        assert_eq!(
            effective_directory_prefix(dir, boundary, task_path),
            None,
            "neither tree is an ancestor of the other — must fail closed, not guess"
        );
    }

    /// B2 (review round 2): a `workspace_boundary` of `/` must not be treated
    /// as "no clamp" — `Path::starts_with` is trivially true against `/` for
    /// any absolute path, so without this guard `dir` (however shallow) would
    /// always be used as-is, silently restoring exact pre-Task-24 behaviour.
    #[test]
    fn a_root_boundary_is_degenerate_and_fails_closed() {
        let dir = Path::new("/home");
        let boundary = Path::new("/");
        let task_path = Path::new("/home/alice/project/src/main.rs");
        assert_eq!(
            effective_directory_prefix(dir, boundary, task_path),
            None,
            "a `/` boundary must be treated as unvalidated input, not as an unbounded workspace"
        );
    }

    /// B2 (review round 2): an empty `workspace_boundary` behaves exactly
    /// like `/` under `Path::starts_with` (`Path::new("").parent()` is also
    /// `None`), so it must be caught by the same guard.
    #[test]
    fn an_empty_boundary_is_degenerate_and_fails_closed() {
        let dir = Path::new("/home");
        let boundary = Path::new("");
        let task_path = Path::new("/home/alice/project/src/main.rs");
        assert_eq!(effective_directory_prefix(dir, boundary, task_path), None);
    }

    /// B2 (review round 2): a relative `workspace_boundary` cannot
    /// meaningfully bound an absolute canonical path at all.
    #[test]
    fn a_relative_boundary_is_degenerate_and_fails_closed() {
        let dir = Path::new("/home");
        let boundary = Path::new("workspace");
        let task_path = Path::new("/home/alice/project/src/main.rs");
        assert_eq!(effective_directory_prefix(dir, boundary, task_path), None);
    }

    #[test]
    fn filesystem_root_request_still_downgrades_to_fs_exact_regardless_of_boundary() {
        let canonical: Result<PathBuf, PathErr> = Ok(PathBuf::from("/workspace/notes.txt"));
        let predicate = fs_predicate_for_directory_grant(
            &FsOp::Write,
            Path::new("/workspace/notes.txt"),
            &canonical,
            Path::new("/"),
            Path::new("/workspace"),
        );
        match predicate {
            Predicate::FsExact { path, .. } => {
                assert_eq!(path, PathBuf::from("/workspace/notes.txt"));
            }
            other => panic!("expected FsExact downgrade for the filesystem root, got {other:?}"),
        }
    }

    #[test]
    fn shallow_ancestor_beyond_the_boundary_produces_an_fs_prefix_clamped_to_the_boundary() {
        let canonical: Result<PathBuf, PathErr> =
            Ok(PathBuf::from("/home/alice/project/src/main.rs"));
        let predicate = fs_predicate_for_directory_grant(
            &FsOp::Write,
            Path::new("/home/alice/project/src/main.rs"),
            &canonical,
            Path::new("/home"),
            Path::new("/home/alice/project"),
        );
        match predicate {
            Predicate::FsPrefix { prefix, .. } => {
                assert_eq!(prefix, PathBuf::from("/home/alice/project"));
            }
            other => panic!("expected FsPrefix clamped to the boundary, got {other:?}"),
        }
    }
}
