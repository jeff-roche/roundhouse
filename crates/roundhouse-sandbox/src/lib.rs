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
//! child). Task 27 (lane W5, ruling W5-9) closed the one remaining gap: real
//! per-process Landlock enforcement on the spawned child itself, not just
//! Landlock's own probe (which was always real) — see `landlock_wrap`'s
//! module doc comment for the pre-exec wrapper mechanism this needed (bwrap
//! has no native Landlock flag, unlike its native `--seccomp FD`) and why the
//! more obvious `pre_exec`-on-bwrap approach is a dead end, and
//! `isolate::BwrapLandlockIsolate::achieved_tier`'s doc comment for exactly
//! what each mechanism enforces today. See
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
//!
//! Task 34 (lane W5, rulings W5-8/W5-22) added [`worktree`], a generic,
//! synchronous `git worktree add`/`remove` primitive, consumed by
//! `roundhouse-flow`'s `map.isolation: worktree` to give each fan-out item
//! its own working directory (a separate checkout, bound into the
//! expression context as `${{ worktree.path }}`). **Reworded in fix round
//! 1, item 5 — this is deliberately not called "confinement" or
//! "isolation" here, the way [`bounded_parse`] above genuinely is one:**
//! nothing in this crate or `roundhouse-flow` sets an inner step's working
//! directory to the materialized path, no enforcer confines any process to
//! it, and every worktree it creates shares one `.git/config` and one
//! `hooksPath` with the repository it came from — a worktree is a separate
//! *directory*, not a separate *repository* or a security boundary.
//! **Fix round 2 confirmed this the hard way:** [`worktree`]'s own `-c`
//! overrides mitigate the `hooksPath`/`fsmonitor` routes through that
//! shared config but do not, and cannot, close it as a class — a
//! repo-tracked `.gitattributes` plus one config write to
//! `filter.<name>.smudge` still reaches code execution through it, which is
//! exactly what "not a security boundary" means here, not a residual bug in
//! the mitigation. See [`worktree`]'s own module doc comment, "Config and
//! hooks", for the mechanism. Like
//! [`bounded_parse`], this module knows nothing about workflows or `map`
//! steps — see its own module doc comment, and see
//! `roundhouse_flow::exec::map_step::Executor::dispatch_map_step`'s doc
//! comment for what "isolation" means in the workflow-YAML vocabulary this
//! feature is named after versus what this primitive actually delivers.

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
mod landlock_wrap; // Task 27 (ruling W5-9): Route B, the round-landlock-exec pre-exec wrapper — no unsafe
pub mod probe; // the only module permitted unsafe_code — see probe.rs's module-level allow
mod types;
pub mod worktree;

pub use isolate_trait::Isolate;
pub use roundhouse_core::Tier;
pub use types::{Attestation, Child, CommandSpec, Handle, IsolationError, ProbeResult};

// Task 27 fix round 2 (Ruling W5-40, following Ruling W5-20's precedent):
// `round-landlock-exec` (`src/bin/round_landlock_exec.rs`) is a separate crate that
// links this crate's *library* and can therefore only reach `pub` items, so this is
// re-exported here rather than duplicated as a second copy — see
// `landlock_wrap::SYSTEM_READ_EXEC_DIRS`'s own doc comment for why the two prior
// copies (one validating, one granting) were a fail-open hazard, not just a
// maintenance nuisance. `#[doc(hidden)]` keeps it out of this crate's advertised
// public API — it exists for exactly one external caller.
#[doc(hidden)]
pub use landlock_wrap::SYSTEM_READ_EXEC_DIRS;
