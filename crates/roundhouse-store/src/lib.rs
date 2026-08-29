//! The SQLite-backed event log: schema and migrations, the append-only
//! `events` table (S-LOG-2, enforced by `BEFORE UPDATE`/`BEFORE DELETE`
//! triggers that `RAISE(ABORT, ...)` — never by application-level
//! discipline alone), FTS5 full-text search, and content-addressed blob
//! storage (§4.5) for payloads too large to keep inline in an event row.
//!
//! Phase 0 gives this crate real content: the migration harness
//! (`rusqlite_migration`), the append-only triggers, and `write_blob`/
//! `read_blob`/reference-counted GC-eligibility for blobs. Materialized
//! views over the event log are Phase 1 work. See
//! `docs/architecture/01-data-model.md` and `02-system-architecture.md` §5.2.
#![forbid(unsafe_code)]

mod migrations;
mod pool;
mod txn;
pub mod blobs;

pub use migrations::migrations;
pub use pool::{open_memory_connection, open_pool};
pub use txn::begin_immediate;
