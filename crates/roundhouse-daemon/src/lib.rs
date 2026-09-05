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
    use std::sync::Arc;

    use roundhouse_core::{OnDegrade, SessionId, SessionSpec, SessionState, Tier};
    use roundhouse_engine::SessionActor;
    use roundhouse_policy::engine::PolicyEngine;
    use roundhouse_sandbox::isolate::BwrapLandlockIsolate;
    use roundhouse_sandbox::probe::{MechanismProbeReport, MechanismStatus};
    use roundhouse_sandbox::Isolate;

    static RUNNER: std::sync::OnceLock<roundhouse_core::TaskRunner> = std::sync::OnceLock::new();

    pub(crate) fn runner() -> &'static roundhouse_core::TaskRunner {
        RUNNER.get_or_init(roundhouse_core::TaskRunner::bootstrap)
    }

    /// A `BwrapLandlockIsolate` that deterministically achieves `Tier::Sandbox`
    /// with no real bwrap/landlock syscalls (`test_with_probe`).
    pub(crate) fn available_isolate() -> Arc<dyn Isolate> {
        Arc::new(BwrapLandlockIsolate::test_with_probe(
            MechanismProbeReport {
                landlock: MechanismStatus::Available,
                bwrap: MechanismStatus::Available,
                seccomp: MechanismStatus::Available,
                seatbelt: MechanismStatus::Unavailable {
                    reason: "n/a".into(),
                },
            },
        ))
    }

    /// A minimal but fully real `SessionActor`, constructed with
    /// `initial_state` rather than always `Running` — needed by
    /// `socket_server`'s `spawn_session_reaper` test, which has no other way
    /// to observe a `Closed` actor (nothing in production code transitions
    /// one there yet — see that test's own doc comment).
    pub(crate) async fn real_actor_with_state(
        dir: &std::path::Path,
        initial_state: SessionState,
    ) -> Arc<SessionActor> {
        let store = roundhouse_store::open(&dir.join("events.db"))
            .await
            .unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;
        let policy = Arc::new(PolicyEngine::from_rules(vec![]));
        let isolate = available_isolate();
        let spec = SessionSpec::test_requesting(Tier::Sandbox, OnDegrade::Refuse);
        let handle = isolate.prepare(&spec).await.unwrap();
        Arc::new(SessionActor::new(
            SessionId::new(),
            writer,
            initial_state,
            runner(),
            policy,
            dir.join("state"),
            dir.join("daemon-binary"),
            isolate,
            handle,
            spec,
            vec![],
        ))
    }

    /// [`real_actor_with_state`] with the ordinary `Running` initial state —
    /// what every session actually starts as.
    pub(crate) async fn real_actor(dir: &std::path::Path) -> Arc<SessionActor> {
        real_actor_with_state(dir, SessionState::Running).await
    }
}
