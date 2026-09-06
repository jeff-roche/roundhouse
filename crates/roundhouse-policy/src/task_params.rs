use roundhouse_core::{MemoryScope, SessionId, TaskId, Tier};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// §6.2 — a real shell-grammar parse result, never a raw string (see §6.3:
/// "We do not exec through a shell"). Phase 0 stubs this with the minimal
/// shape the policy engine needs to compile against; the actual
/// `brush-parser` integration is Phase 2 work (§6.3, §6.12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedCommand {
    pub program: String,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsOp {
    Read,
    Write,
    Edit,
    Find,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathErr(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Method {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Head,
    Options,
}

/// Bare-`pub` tuple id, deliberately unlike the four private-field core ids
/// (`SessionId`/`TaskId`/`WorkspaceId`/`TeamId`) — see `RuleId`'s doc
/// comment in `roundhouse-core/src/task_meta.rs` for the rationale: this
/// names an externally-sourced value (an MCP server's configured name),
/// not an identity this system mints and must guard against collision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerId(pub String);

/// See `ServerId`'s doc comment above.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderId(pub String);

/// The four operations a memory task can perform on a `MemoryScope`. `Read`
/// is gated separately from `Write`/`Append`/`Delete` in
/// `PolicyEngine::decide`'s `Team`-scope handling (§15.2's read/write
/// asymmetry) — see `TeamMembership`.
///
/// Orchestrator Ruling W4-13: this is deliberately a **keyless** policy-side
/// projection of §15.1's own, keyed `MemoryOp` (`Read { key }`,
/// `Write { key, content }`, `Append { key, .. }`, `Delete { key }`, `List`).
/// Do not add a `key` field here. Consequence a future memory-executor
/// author must know: because this type carries no key, `PolicyEngine`
/// cannot distinguish which memory key a request touches — an `Allow`
/// decision for a given `(scope, op)` authorizes **every** key in that
/// scope, not the one key the underlying request actually names. That gap
/// is intentional and out of scope for this task; a future unit that wants
/// per-key policy will need to widen this type (and `TaskParams::Memory`,
/// and every `Predicate::Memory`/`TeamMembership` call site) deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryOp {
    Read,
    Write,
    Append,
    Delete,
}

/// §6.2 — every task passes through `Policy::decide` matched on these
/// typed, parsed parameters, never raw strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskParams {
    Shell(ParsedCommand),
    Fs {
        op: FsOp,
        path: PathBuf,
        canonical: Result<PathBuf, PathErr>,
    },
    Http {
        method: Method,
        url: String,
        body_len: usize,
    },
    Mcp {
        server: ServerId,
        tool: String,
        args: serde_json::Value,
    },
    Git {
        subcommand: String,
        argv: Vec<String>,
        remote: Option<String>,
    },
    Agent {
        provider: ProviderId,
        model: String,
        tier_request: Tier,
    },
    /// Orchestrator Ruling W4-6: `session` is required here even though the
    /// plan's field list omits it. `PolicyEngine::decide(&self, params:
    /// &TaskParams)` has no session in reach, neither `PolicyInput` nor
    /// `SealedContext` carries one, and none of those may gain one here (their
    /// callers live in other lanes' crates) — so `TeamMembership::can_read`/
    /// `can_write` would have no session to check without this field.
    /// Fabricating a placeholder session id would be a fail-closed violation;
    /// this variant is brand new, so carrying its own session breaks nothing.
    ///
    /// **SECURITY INVARIANT (fix round 1, Ruling W4-6 follow-up):** `session`
    /// is the sole *who* — the only input `TeamMembership::can_read`/
    /// `can_write` are given to decide identity — inside an object this
    /// crate otherwise treats as pure *what* (every other `TaskParams`
    /// variant describes only an action, never an actor). `TaskParams`
    /// derives `Deserialize`, so nothing at the type level stops a caller
    /// from populating this field from attacker-reachable input. `session`
    /// MUST be the dispatching `SessionActor`'s own session id, as that actor
    /// holds it — **never** a value taken from task input, model output, or
    /// anything read off the wire. Passing a client-supplied or
    /// model-supplied session id straight through hands a non-member
    /// session's forged identity to `can_read`/`can_write` and gets `Allow`
    /// — a classic confused-deputy bypass of the membership gate this
    /// variant exists to enforce. (Compare
    /// `roundhouse-engine`'s `TaskCreateRequest::params` SECURITY INVARIANT
    /// on `TaskParams::Fs.canonical`, the same shape of "this field must be
    /// derived by the trusted dispatcher, never passed through" contract.)
    ///
    /// The same caller-trust gap applies to `MemoryScope::Project
    /// { workspace }`: `PolicyEngine` has no session→workspace membership
    /// mapping and cannot itself verify that the requesting `session`
    /// actually belongs to `workspace`. That binding, too, is entirely
    /// caller-trusted — whoever constructs a `Project`-scoped `TaskParams::
    /// Memory` is responsible for having already verified the requesting
    /// session's workspace membership before this type is ever built.
    Memory {
        scope: MemoryScope,
        op: MemoryOp,
        session: SessionId,
    },
}

/// §6.8 — `PolicyInput.taint` gates autonomy for irreversible/exfiltrating
/// kinds. Only two trust levels exist by design — "no semi-trusted."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Taint {
    Trusted,
    Tainted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub params: TaskParams,
    pub taint: Taint,
}

#[doc(hidden)]
pub type _TaskIdRef = TaskId; // keeps roundhouse_core::TaskId a live import for future rule-provenance fields
