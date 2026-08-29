//! The daemon binary: wiring, API server, and lifecycle for `round daemon`
//! — the long-running process every `roundhouse-cli` client attaches to or
//! sends requests through. Depends on nearly every other crate in the
//! workspace (it's one of only two crates — the other is
//! `roundhouse-cli` — allowed to; nothing else may depend on either).
//!
//! Phase 0 only proves the full dependency graph actually compiles and
//! links into one binary; real supervisor/API-server/lifecycle wiring is
//! Phase 1+ work. See `docs/architecture/02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    // Phase 0 proves the dependency graph compiles; real daemon wiring
    // (supervisor, API server, lifecycle) is Phase 1+.
    let _ = roundhouse_engine::EngineHandles::bootstrap;
    let _layers = roundhouse_config::default_layers(None);
    Ok(())
}
