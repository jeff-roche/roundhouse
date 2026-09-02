//! Library half of the `round` CLI: the argument-parsing scaffold (`cli`)
//! and subcommand implementations (`commands`) that `src/main.rs` dispatches
//! to.
//!
//! Split out of `main.rs` (Task A8/G6 — see the module docs on `cli` and
//! `commands` for the "why") so both halves are unit-testable without
//! spawning the real `round` binary: `cli` is pure `clap` parsing, and each
//! `commands::*` module keeps its filesystem/process side effects behind a
//! narrow, tempdir-friendly seam.
#![forbid(unsafe_code)]

pub mod cli;
pub mod commands;
