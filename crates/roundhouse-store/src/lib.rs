#![forbid(unsafe_code)]

mod migrations;
mod pool;
mod txn;
pub mod blobs;

// Phase 0 exports
pub use migrations::migrations;
pub use pool::{open_memory_connection, open_pool};
pub use txn::begin_immediate;

// Task 1 exports
pub use pool::{open, StoreError, StorePool, MIGRATIONS};
