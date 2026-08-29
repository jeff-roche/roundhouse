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
// Cargo.toml. The only module permitted to use it is a future
// `enforce::unsafe_ops` (Phase 2 work: raw Landlock/seccomp/bwrap-exec
// syscalls), which will locally re-enable it with
// `#[allow(unsafe_code)]` on that module alone. Phase 0 contains no
// unsafe code anywhere in this crate yet.
#![deny(unsafe_code)]

mod isolate_trait;
mod types;

pub use isolate_trait::Isolate;
pub use roundhouse_core::Tier;
pub use types::{Attestation, Child, CommandSpec, Handle, IsolationError, ProbeResult};
