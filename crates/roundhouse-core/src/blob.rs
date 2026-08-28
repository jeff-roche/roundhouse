use serde::{Deserialize, Serialize};

/// A blake3 content hash, hex-encoded. `roundhouse-core` does not depend on
/// the `blake3` crate itself (keeping core's dependency list to
/// serde/uuid/thiserror/bytes/serde_json/schemars, all pure-data/derive
/// concerns, no hashing algorithm) — `roundhouse-store` computes the digest
/// and constructs this from its hex string; core only needs the resulting
/// fixed-shape value to be nameable in `BlobRef`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Blake3Hash(pub String);

/// §4.5 — content-addressed pointer to a blob stored outside the event log.
/// Identical bytes always collide to the same blob (content addressing),
/// which is what makes reference counting — not mark-and-sweep — the
/// steady-state GC strategy: a `blobs` row's `ref_count` is bumped in the
/// same transaction as the event append that references it (never a
/// separate transaction), so a blob can never be referenced by an event
/// that isn't durably recorded, and vice versa.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BlobRef {
    pub hash: Blake3Hash,
    pub len: u64,
    pub mime: Option<String>,
}

/// §4.5 — "nothing large lives inline in an event row." Below this size (in
/// serialized bytes) a `TaskInput`/`TaskOutput`/`Delta` payload stays
/// inline; at or above it — or unconditionally, for `shell` stdout/stderr,
/// `read`/`edit` content and diffs, `http`/`web`/`mcp` bodies, and
/// checkpoint snapshots, which always route through the blob store
/// regardless of size — it moves to the blob store and the event row
/// carries a `BlobRef` in its place instead.
pub const BLOB_INLINE_THRESHOLD: usize = 4096;
