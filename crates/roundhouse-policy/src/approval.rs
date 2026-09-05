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
#[derive(Debug, Clone)]
pub struct GrantProvenance {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub ts: Timestamp,
}

/// The output of [`synthesize_grant`]: a policy rule generalised from one
/// approved task, plus the scope and provenance that produced it.
///
/// `rule` is `pub` so tests (and [`Grant::into_rule_for_installation`]
/// itself) can inspect the synthesized predicate directly, but a caller that
/// wants to actually **install** this grant into a live `PolicyEngine`
/// should go through [`Grant::into_rule_for_installation`], not read `rule`
/// directly — see that method's doc comment and finding 5's fix.
pub struct Grant {
    pub scope: GrantScope,
    pub rule: CompiledRule,
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

impl Grant {
    /// Whether this grant's synthesized rule covers a filesystem task with
    /// the given `op`/`path`. **`Fs`-specific only** — for any grant
    /// synthesized from a `Shell`/`Http`/`Mcp`/`Git`/`Agent` task (i.e. the
    /// predicate is not `FsPrefix`/`FsExact`), this always returns `false`;
    /// it is not a general-purpose "does this grant cover this task" check
    /// for those kinds. Callers working with non-`Fs` `TaskParams` must
    /// match on `self.rule.predicate` directly instead.
    ///
    /// **Security fix round 1, finding 4:** now also checks `op` (previously
    /// only compared the path, so e.g. a grant synthesized for `FsOp::Read`
    /// wrongly reported `true` for a `Write` on the same path — the real
    /// `Predicate::matches` in `engine.rs` has always gated on `op`, this
    /// helper just hadn't matched that).
    pub fn rule_covers_path(&self, op: FsOp, path: &PathBuf) -> bool {
        match &self.rule.predicate {
            Predicate::FsPrefix { op: pop, prefix } => *pop == op && path.starts_with(prefix),
            Predicate::FsExact { op: pop, path: p } => *pop == op && path == p,
            _ => false,
        }
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
    /// This exists because `Grant.rule` is `pub` (kept so tests and this
    /// method itself can inspect the synthesized predicate) — a future
    /// caller reaching for the obvious thing, `grant.rule`, to install into
    /// `PolicyEngine::from_rules` would otherwise silently reproduce exactly
    /// the "one-time approval becomes a permanent rule" bug this synthesis
    /// module exists to prevent. Real TTL/use-count/session-binding
    /// *enforcement* inside `PolicyEngine` itself is out of scope for this
    /// task — this method only makes the current absence of that
    /// enforcement impossible to silently misuse.
    pub fn into_rule_for_installation(&self) -> Result<CompiledRule, GrantInstallError> {
        match &self.scope {
            GrantScope::Once => Err(GrantInstallError::UnenforcedLifetime("Once")),
            GrantScope::Session => Err(GrantInstallError::UnenforcedLifetime("Session")),
            GrantScope::ExactArgv { .. } => Err(GrantInstallError::UnenforcedLifetime("ExactArgv")),
            GrantScope::Directory { .. } | GrantScope::Always => Ok(self.rule.clone()),
        }
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
/// prefix), `Mcp` binds server+tool (`args` binding is a known, out-of-scope
/// gap — `Predicate::Mcp` has no field for it; tracked separately, not fixed
/// here), and `Agent` pins `max_tier` to the tier actually requested (Task 21
/// (W4) flipped that field's comparison to a floor rather than a ceiling —
/// see its doc comment in `engine.rs` — so pinning it here means the grant
/// never generalizes *below* the isolation actually requested).
pub fn synthesize_grant(
    params: &TaskParams,
    scope: GrantScope,
    provenance: GrantProvenance,
) -> Grant {
    let predicate = match (&scope, params) {
        (
            GrantScope::Directory { path },
            TaskParams::Fs {
                op,
                path: task_path,
                canonical,
            },
        ) => fs_predicate_for_directory_grant(op, task_path, canonical, path),
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
        (_, TaskParams::Mcp { server, tool, .. }) => Predicate::Mcp {
            server: server.clone(),
            tool: Some(tool.clone()),
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
    let rule = CompiledRule {
        scope: grant_rule_scope(&scope),
        outcome: Outcome::Allow,
        predicate,
        file_order: 0,
        id: RuleId(format!(
            "grant:{}:{}",
            provenance.session_id.as_uuid(),
            provenance.task_id.as_uuid()
        )),
    };
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
/// **Residual gap, not closed here:** this only rejects the literal
/// filesystem root and genuinely unrelated (non-ancestor) directories. A
/// caller could still request a shallow-but-non-root ancestor that is
/// technically a real ancestor of the task's path yet still far broader than
/// what a human plausibly meant to approve (e.g. `path: "/home"` for a task
/// that wrote `/home/alice/project/notes.txt` — a genuine ancestor, not the
/// filesystem root, but still covers every other user's home directory).
/// Fully closing that requires threading a workspace/session boundary into
/// `synthesize_grant` (so directory grants can be bounded to "at or below
/// the session's workspace root," not just "somewhere above the task's own
/// path") — no such parameter exists on this function today, and adding one
/// is a real signature/caller-surface change beyond this fix round's scope.
/// Flagged here loudly, and in the Task 15 fix-round report, rather than
/// silently left implicit.
fn fs_predicate_for_directory_grant(
    op: &FsOp,
    task_path: &std::path::Path,
    canonical: &Result<PathBuf, PathErr>,
    dir: &std::path::Path,
) -> Predicate {
    // `/`'s parent is `None`; every non-root absolute directory has `Some`
    // parent. This is the targeted check that closes the literal
    // reproduction (`Directory { path: "/" }`) an ancestor check alone
    // cannot, since `/` is trivially an ancestor of everything.
    let is_filesystem_root = dir.parent().is_none();
    match canonical {
        Ok(c) if !is_filesystem_root && c.starts_with(dir) => Predicate::FsPrefix {
            op: clone_op(op),
            prefix: dir.to_path_buf(),
        },
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
