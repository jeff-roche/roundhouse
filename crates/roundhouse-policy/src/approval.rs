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
use crate::{FsOp, TaskParams};
use roundhouse_core::{SessionId, TaskId, TaskRunner, Timestamp};
use roundhouse_store::{EventWriter, StoreError};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum GrantScope {
    Once,
    Session,
    ExactArgv { hash: [u8; 32] },
    Directory { path: PathBuf },
    Always,
}

#[derive(Debug, Clone)]
pub struct GrantProvenance {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub ts: Timestamp,
}

pub struct Grant {
    pub scope: GrantScope,
    pub rule: CompiledRule,
    pub provenance: GrantProvenance,
}

impl Grant {
    pub fn rule_covers_path(&self, path: &PathBuf) -> bool {
        match &self.rule.predicate {
            Predicate::FsPrefix { prefix, .. } => path.starts_with(prefix),
            Predicate::FsExact { path: p, .. } => path == p,
            _ => false,
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
/// at that directory (never wider); every other combination — including
/// `Fs` under any other scope — pins to the exact observed value: `Shell`
/// binds the exact argv (never a wildcard program-only rule), `Http`/`Git`/
/// `Mcp` bind the exact URL/subcommand+argv/server+tool, and `Agent` caps
/// `max_tier` at the tier that was actually requested, never a higher one.
pub fn synthesize_grant(
    params: &TaskParams,
    scope: GrantScope,
    provenance: GrantProvenance,
) -> Grant {
    let predicate = match (&scope, params) {
        (GrantScope::Directory { path }, TaskParams::Fs { op, .. }) => Predicate::FsPrefix {
            op: clone_op(op),
            prefix: path.clone(),
        },
        (_, TaskParams::Fs { op, path, .. }) => Predicate::FsExact {
            op: clone_op(op),
            path: path.clone(),
        },
        (_, TaskParams::Shell(cmd)) => Predicate::Shell {
            program: cmd.program.clone(),
            matcher: ArgMatcher::Exact(cmd.argv.clone()),
            allow_interpreter: false,
        },
        (_, TaskParams::Http { method, url, .. }) => Predicate::Http {
            method: Some(*method),
            url_prefix: url.clone(), // exact URL, never a host-wide wildcard
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
            max_tier: *tier_request, // never generalized above the tier actually requested
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

fn params_digest(params: &TaskParams) -> [u8; 32] {
    *blake3::hash(format!("{params:?}").as_bytes()).as_bytes()
}
