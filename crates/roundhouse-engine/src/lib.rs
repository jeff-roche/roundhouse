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
