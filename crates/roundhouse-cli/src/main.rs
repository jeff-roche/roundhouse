//! The `round` binary: TUI attach, headless/one-shot runs, and `round
//! daemon` (the same binary, invoked as a subprocess — not a Cargo
//! dependency edge; see §5.2's dependency table note on why this crate
//! deliberately doesn't depend on `roundhouse-daemon` despite the table
//! listing that edge).
//!
//! Phase 0 only proves this crate compiles against `roundhouse-tui`'s
//! schema emission; real CLI behavior is Phase 1+ work. See
//! `docs/architecture/02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let _schema = roundhouse_tui::client_schema();
    Ok(())
}
