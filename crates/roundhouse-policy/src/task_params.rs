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
