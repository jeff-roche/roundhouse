#![forbid(unsafe_code)]

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    // Phase 0 proves the dependency graph compiles; real daemon wiring
    // (supervisor, API server, lifecycle) is Phase 1+.
    let _ = roundhouse_engine::EngineHandles::bootstrap;
    Ok(())
}
