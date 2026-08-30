//! Shell command parsing and classification.
//!
//! Uses the real `brush-parser` crate to parse shell syntax, resolves plain
//! variable expansions, and hard-denies irreducibly opaque constructs before
//! any per-node policy matching happens.

pub mod classify;
pub mod opaque;

pub use classify::ParsedShellAst;
