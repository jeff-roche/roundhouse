use roundhouse_core::{TaskId, Tier};
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
