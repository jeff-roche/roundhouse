//! The agent loop: session actor, supervision, and context management —
//! the crate that actually drives a session forward, holding the
//! `TaskRunner` authority plus `Arc<dyn Bus>`/`Arc<dyn Provider>` handles
//! for everything a running session needs to talk to.
//!
//! Phase 1 built the real chat turn: [`run_chat_turn`] drives a `chat`→`infer`
//! task pair against a `&dyn Provider`, records every step through a
//! `TaskRunner`, and folds the provider's stream into `ContentBlock`s via
//! [`fold_stream_to_blocks`]. `EngineHandles::bootstrap` below is Phase 0
//! scaffolding proving this crate compiles against every trait it will hold a
//! handle to; it is *not* what `roundhouse-daemon` actually calls today —
//! `main.rs` calls `TaskRunner::bootstrap()` directly at its own startup site
//! instead, since `EngineHandles::bootstrap` also demands an `Arc<dyn Bus>`
//! and no concrete `Bus` implementation exists yet. Full session
//! actor/supervision beyond one scripted chat turn is Phase 2+ work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `00-overview.md` §3.1.
#![forbid(unsafe_code)]

mod chat;
mod context;
mod infer;

pub use chat::{run_chat_turn, AgentError};
pub use context::assemble_context;
pub use infer::fold_stream_to_blocks;

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
        EngineHandles {
            task_runner: TaskRunner::bootstrap(),
            bus,
            providers,
        }
    }
}
