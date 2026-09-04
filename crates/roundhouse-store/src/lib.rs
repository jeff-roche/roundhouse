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

pub mod attention;
pub mod blobs;
pub mod cost;
mod fold;
mod migrations;
mod pool;
mod recovery;
pub mod redact;
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

// Phase 5 Task 34 (fix round 2): a name for a checked-out connection, so a
// caller can hold one in a struct without declaring a `deadpool-sqlite` edge.
//
// Phase 5 Task 35 (fix round 3, ruling P103): and names for the two types in
// `interact`'s signature, so a caller can *forward* it — rather than inherit it
// through a `Deref` that also inherits everything else `deadpool` puts on
// `Object` — still without declaring a `rusqlite` or `deadpool-sqlite` edge.
pub use pool::{InteractError, PooledConnection, SqliteConnection};

// Task 2 exports
pub use writer::{serialize_payload, spawn_writer, EventWriter};

// Task 3 exports
pub use fold::{fold_task, Task, TaskState};

// Task 4 exports
pub use recovery::recover_interrupted_tasks;

// Task 2 (Phase 2) exports: suspended-task enumeration
pub use suspended::{suspended_tasks, SuspendedTask};

// Task 21 (Phase 2) exports: the blocked-anywhere query (S-OBS-4)
pub use attention::{blocked_anywhere, BlockedTask};

// Task 18 (Phase 2) exports: session-scoped event reads (used by
// roundhouse-secrets' keyring-fallback Degradation visibility test).
pub use session_events::session_events;

// CQRS read-model exports (storage replay / fold)
pub use replay::StoredEvent;
pub use roundhouse_core::EventFields;
