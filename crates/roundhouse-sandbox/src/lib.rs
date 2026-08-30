//! Isolation tiers behind one trait (`Isolate`): the sandbox a task runs
//! in — from no isolation up through containers — chosen and attested to
//! independently of which executor or provider is running the task.
//!
//! Phase 0 ships only the `Isolate` trait signature and its supporting data
//! types (`Tier` — re-exported from `roundhouse-core`, since `Tier` had to
//! move there so `EventPayload::TaskStarted` could reference it without
//! `roundhouse-core` depending on this crate — `Attestation`, `CommandSpec`,
//! `ProbeResult`). The *behavioral* half (probing real syscalls, refusing to
//! start below the requested tier) is Phase 2 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `03-security-and-sandboxing.md` (S-ISO-1/2).

// NOTE: unsafe_code is `deny`, not `forbid`, at the crate level — see
// Cargo.toml. The only module permitted to use it is `probe` (Phase 2:
// raw fork/pipe/waitpid/syscall calls needed to run the real
// Landlock/seccomp enforcement probes in a throwaway forked child — see
// `src/probe.rs`'s module doc comment), which locally re-enables it with
// `#![allow(unsafe_code)]` on that module alone.
#![deny(unsafe_code)]

mod isolate_trait;
pub mod probe; // the only module permitted unsafe_code — see probe.rs's module-level allow
mod types;

pub use isolate_trait::Isolate;
pub use roundhouse_core::Tier;
pub use types::{Attestation, Child, CommandSpec, Handle, IsolationError, ProbeResult};
