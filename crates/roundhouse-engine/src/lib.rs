//! The agent loop: session actor, supervision, and context management —
//! the crate that actually drives a session forward, holding the
//! `TaskRunner` authority plus `Arc<dyn Bus>`/`Arc<dyn Provider>` handles
//! for everything a running session needs to talk to.
//!
//! Phase 1 built the real chat turn: [`run_chat_turn`] drives a `chat`→`infer`
//! task pair against a `&dyn Provider`, records every step through a
//! `TaskRunner`, and folds the provider's stream into `ContentBlock`s via
//! [`fold_stream_to_blocks`]. Phase 2 hardened the session actor
//! ([`SessionActor`]) with fail-closed admission, sandbox isolation, and egress
//! boundaries. Phase 4 added sub-agent spawning ([`agent_spawn`]) and
//! break-glass operations ([`break_glass`]), driven over a real
//! `roundhouse-bus` `LocalBus` — so `EngineHandles::bootstrap` below is the
//! Phase 0 compile-proof scaffolding it always was, not what
//! `roundhouse-daemon` calls at startup today. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `00-overview.md` §3.1.
#![forbid(unsafe_code)]

pub mod agent_spawn;
pub mod break_glass;

/// §7.7's depth/fan-out/team-size constants and their predicates, re-exported
/// verbatim from `roundhouse-bus`.
///
/// `roundhouse-engine` already depends on `roundhouse-bus` and enforces these
/// on every sub-agent spawn ([`agent_spawn`]). Crates whose §5.2 dependency
/// row grants `engine` but not `bus` — `roundhouse-flow`'s is
/// `core, engine, store` — need the *same* constants to bound the `call:`
/// chain, which §8.12 makes a chain of nested Sessions exactly as sub-agent
/// spawning is. Re-exporting over the `flow -> engine` edge §5.2 already
/// grants means one definition rather than two ceilings that agree only by
/// coincidence (ruling P76 §2).
pub use roundhouse_bus::limits;

mod chat;
pub mod compact;
mod context;
mod infer;
pub mod mcp_spawner;
pub mod message_render;
mod session_actor;
mod working_context;

pub use chat::{run_chat_turn, AgentError};
// `compact` is `pub mod` so tests can use the path `roundhouse_engine::compact::*`.
// Re-export the common items at crate root for convenience.
pub use compact::{execute_compact, CompactError, CompactInput, CompactOutput, CompactStrategy};
pub use context::assemble_context;
pub use infer::fold_stream_to_blocks;
pub use session_actor::{
    create_session_isolation, create_session_with_egress, AdmitError, CreateSessionError,
    FinallySpec, FinallyStepError, SessionActor, TaskCreateRequest,
};
pub use working_context::{ContextStateId, TokenBudget, WorkingContext};

pub mod system_prompt;
pub mod test_support;
pub mod tool_catalog;
pub mod tools;

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
