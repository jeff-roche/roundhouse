//! The MCP host: connects to Model Context Protocol servers and exposes
//! their tools to the rest of the system as ordinary
//! `TaskParams`/policy-gated actions, so an MCP tool call is subject to the
//! same permission and event-sourcing rules as any built-in executor. The
//! current stdio adapter (`transport/stdio.rs`) hand-rolls
//! newline-delimited JSON-RPC framing; the future `rmcp` reconciliation is
//! isolated to that one file.
//!
//! Task 1 (Phase 3) scaffolds the crate: the workspace wiring, the
//! dependency set later tasks build on, and a placeholder
//! `fake-mcp-stdio-server` binary (Task 9 fills it in). Every later Phase 3
//! task adds a module declared here. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `07-protocols-acp-mcp.md`.
#![forbid(unsafe_code)]

pub mod config;
pub mod executor;
pub mod host;
pub mod namespace;
pub mod transport;
pub mod wire;

#[cfg(test)]
pub mod testing;

#[cfg(test)]
mod smoke {
    #[test]
    fn crate_links_and_forbids_unsafe() {
        // If this compiles at all, #![forbid(unsafe_code)] is active and the
        // crate is wired into the workspace. Nothing to assert at runtime.
        assert_eq!(2 + 2, 4);
    }
}
