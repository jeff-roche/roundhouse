//! Isolation tiers behind one trait (`Isolate`): the sandbox a task runs
//! in — from no isolation up through containers — chosen and attested to
//! independently of which executor or provider is running the task.
//!
//! Phase 0 shipped only the `Isolate` trait signature and its supporting data
//! types (`Tier` — re-exported from `roundhouse-core`, since `Tier` had to
//! move there so `EventPayload::TaskStarted` could reference it without
//! `roundhouse-core` depending on this crate — `Attestation`, `CommandSpec`,
//! `ProbeResult`). The *behavioral* half is now substantially built by Phase 2
//! (`probe` module: real syscall probes per mechanism; `isolate`/`bwrap`
//! modules: `BwrapLandlockIsolate`, a real `Isolate` impl that fails closed —
//! errors rather than warns — when the achieved tier is below what a session
//! requested, and that genuinely applies bwrap namespace isolation and, on
//! Linux when probed available, a real seccomp-BPF filter to every spawned
//! child). It is not yet complete: real per-process Landlock enforcement on
//! the spawned child (as opposed to Landlock's own probe, which is real) is a
//! tracked follow-up — see `isolate::BwrapLandlockIsolate::achieved_tier`'s doc
//! comment for exactly what each mechanism does and doesn't enforce today. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `03-security-and-sandboxing.md` (S-ISO-1/2).
//!
//! Task 14 (lane W5) added [`bounded_parse`], a second and unrelated kind of
//! confinement: a generic, synchronous, resource-bounded subprocess
//! primitive (CPU time on Linux, wall clock and output size everywhere),
//! consumed by `roundhouse-flow` to run third-party YAML deserialization
//! out of process rather than trust an in-process byte cap against a
//! quadratic-cost parser. This crate takes no dependency on `roundhouse-flow`
//! or anything YAML-shaped in return — see that module's doc comment.

// NOTE: unsafe_code is `deny`, not `forbid`, at the crate level — see
// Cargo.toml. The only module permitted to use it is `probe` (Phase 2:
// raw fork/pipe/waitpid/syscall calls needed to run the real
// Landlock/seccomp enforcement probes in a throwaway forked child — see
// `src/probe.rs`'s module doc comment), which locally re-enables it with
// `#![allow(unsafe_code)]` on that module alone.
#![deny(unsafe_code)]

pub mod bounded_parse;
pub mod bwrap;
pub mod isolate;
mod isolate_trait;
pub mod probe; // the only module permitted unsafe_code — see probe.rs's module-level allow
mod types;

pub use isolate_trait::Isolate;
pub use roundhouse_core::Tier;
pub use types::{Attestation, Child, CommandSpec, Handle, IsolationError, ProbeResult};
