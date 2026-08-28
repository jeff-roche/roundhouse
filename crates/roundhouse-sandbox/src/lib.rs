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
