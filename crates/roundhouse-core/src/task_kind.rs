use serde::{Deserialize, Serialize};

/// §4.2 — core kinds are flat identifiers; plugin-provided kinds are
/// namespaced `vendor:verb` so the enum stays closed for the core and open
/// for extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskKind {
    Chat,
    Infer,
    Shell,
    Read,
    Write,
    Edit,
    Find,
    Http,
    Web,
    Mcp,
    Git,
    Memory,
    Agent,
    Message,
    Compact,
    Checkpoint,
    Plan,
    Elicit,
    Flow,
    /// The mandatory terminal task of every workflow/job run (§8.6, §8.8). Added
    /// 2026-08-28 as an explicit frozen-contract amendment — it was used throughout
    /// §8's prose and by the Phase 5 plan before this table actually had it (audit
    /// finding A2); this is the fix, not a later addition layered on top.
    Report,
    /// `vendor:verb` — plugin-provided task kinds.
    Plugin { vendor: String, verb: String },
}
