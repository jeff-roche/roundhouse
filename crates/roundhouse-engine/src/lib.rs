//! The agent loop: session actor, supervision, and context management —
//! the crate that actually drives a session forward, holding the
//! `TaskRunner` authority plus `Arc<dyn Bus>`/`Arc<dyn Provider>` handles
//! for everything a running session needs to talk to.
//!
//! Phase 0 only proves this crate compiles against every trait it will
//! hold a handle to (`EngineHandles::bootstrap` below is the intended
//! single call site for `TaskRunner::bootstrap()`, per Task 4's design —
//! `roundhouse-daemon` calls it exactly once at startup); no real session
//! actor or supervision exists yet — that's Phase 1 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `00-overview.md` §3.1.
#![forbid(unsafe_code)]

use roundhouse_bus::Bus;
use roundhouse_core::TaskRunner;
use roundhouse_provider::Provider;
use std::sync::Arc;

/// Proves roundhouse-engine — the intended caller of
/// `TaskRunner::bootstrap()` per Task 4's design — compiles against every
/// Phase 0 trait it will hold an `Arc<dyn ...>` of in Phase 1.
pub struct EngineHandles {
    pub task_runner: TaskRunner,
    pub bus: Arc<dyn Bus>,
    pub providers: Vec<Arc<dyn Provider>>,
}

impl EngineHandles {
    pub fn bootstrap(bus: Arc<dyn Bus>, providers: Vec<Arc<dyn Provider>>) -> Self {
        EngineHandles { task_runner: TaskRunner::bootstrap(), bus, providers }
    }
}
