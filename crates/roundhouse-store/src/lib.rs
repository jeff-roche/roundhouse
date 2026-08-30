//! The SQLite-backed event log: schema and migrations, the append-only
//! `events` table (S-LOG-2, enforced by `BEFORE UPDATE`/`BEFORE DELETE`
//! triggers that `RAISE(ABORT, ...)` — never by application-level
//! discipline alone), FTS5 full-text search, and content-addressed blob
//! storage (§4.5) for payloads too large to keep inline in an event row.
//!
//! Phase 0 gives this crate real content: the migration harness
//! (`rusqlite_migration`), the append-only triggers, and `write_blob`/
//! `read_blob`/reference-counted GC-eligibility for blobs. Task 1 adds
//! a production-ready WAL-mode connection pool (`open()`) with automatic
//! migration application. Materialized views over the event log are Phase 1 work.
//! See `docs/architecture/01-data-model.md` and `02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

pub mod blobs;
mod fold;
mod migrations;
mod pool;
mod recovery;
mod replay;
mod session_events;
mod suspended;
mod tasks_view;
mod txn;
mod writer;

// Phase 0 exports
pub use migrations::migrations;
pub use pool::{open_memory_connection, open_pool};
pub use txn::begin_immediate;

// Task 1 exports
pub use pool::{open, StoreError, StorePool, MIGRATIONS};

// Task 2 exports
pub use writer::{serialize_payload, spawn_writer, EventWriter};

// Task 3 exports
pub use fold::{fold_task, Task, TaskState};

// Task 4 exports
pub use recovery::recover_interrupted_tasks;

// Task 2 (Phase 2) exports: suspended-task enumeration
pub use suspended::{suspended_tasks, SuspendedTask};

// Task 18 (Phase 2) exports: session-scoped event reads (used by
// roundhouse-secrets' keyring-fallback Degradation visibility test).
pub use session_events::session_events;

// CQRS read-model exports (storage replay / fold)
pub use replay::StoredEvent;
pub use roundhouse_core::EventFields;
