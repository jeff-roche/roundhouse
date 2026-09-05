//! The daemon's library half: the pieces of `round daemon` that are worth
//! testing without spawning the binary.
//!
//! `roundhouse-daemon` was binary-only through Phase 0, when it existed only to
//! prove the full dependency graph links. Phase 1's exit criterion needs the
//! wiring itself under test — an integration test can drive
//! [`demo::run_demo_session`] and [`socket_server::serve`] directly, but
//! it cannot drive a `main`. Hence this lib target; `src/main.rs` is now a thin
//! startup shell over it. See `docs/architecture/02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

pub mod boot;
/// Phase 1's scripted, single-session exit-criterion fixture. Phase 7 Task 7
/// retires it as BOOT behavior (`main.rs` no longer calls
/// `run_demo_session` — see that file's own module doc) — this module stays
/// `pub`, unconditionally, only because `tests/exit_criterion_demo.rs` (an
/// external integration test, which cannot see a `#[cfg(test)]`-gated item
/// in the library it depends on — `cfg(test)` is local to each compilation
/// unit) drives it directly to prove the demo wiring itself still works,
/// same as Task 21 of Phase 1 originally used it. `real_boot_smoke.rs`
/// separately asserts this module's symbols are absent from `main.rs`'s own
/// source, i.e. from the real boot path.
pub mod demo;
pub mod mcp_config;
pub mod session_bootstrap;
pub mod session_registry;
pub mod socket_server;

/// One `TaskRunner::bootstrap()` shared by every `#[cfg(test)] mod tests`
/// in this crate's LIBRARY test binary — `session_registry`'s and
/// `session_bootstrap`'s own test modules both need a `&'static TaskRunner`
/// to build a real `SessionActor`, and `cargo test -p roundhouse-daemon
/// --lib` runs every `#[cfg(test)]` module in this crate inside ONE process.
/// `TaskRunner::bootstrap()` panics on a second call per process (S-LOG-1),
/// so each module having its own independent `static RUNNER` would panic
/// the moment both modules' tests ran in the same test binary — this is the
/// one shared instance both reach for instead.
#[cfg(test)]
pub(crate) mod test_support {
    static RUNNER: std::sync::OnceLock<roundhouse_core::TaskRunner> = std::sync::OnceLock::new();

    pub(crate) fn runner() -> &'static roundhouse_core::TaskRunner {
        RUNNER.get_or_init(roundhouse_core::TaskRunner::bootstrap)
    }
}
