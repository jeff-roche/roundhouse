use serde::{Deserialize, Serialize};
use std::fmt;

/// blake3's own hex digest length: 32 bytes, hex-encoded as 2 chars/byte.
const BLAKE3_HEX_LEN: usize = 64;

/// A validated blake3 content hash, hex-encoded. `roundhouse-core` does not
/// depend on the `blake3` crate itself (keeping core's dependency list to
/// serde/uuid/thiserror/bytes/serde_json/schemars, all pure-data/derive
/// concerns, no hashing algorithm) — `roundhouse-store` computes the digest
/// and constructs this from its hex string; core only needs the resulting
/// fixed-shape value to be nameable in `BlobRef`.
///
/// Deliberately *not* a bare-`pub` tuple struct, unlike this crate's other
/// externally-sourced wrapper types (`RuleId`, `ServerId`, `ModelId`,
/// `ProviderId`, `ToolCallId`): `roundhouse-store::blobs::blob_path` joins
/// this value directly onto a filesystem path
/// (`state_dir/blobs/<hash[..2]>/<hash>`) to read a blob back off disk. An
/// unvalidated string reaching that join — e.g. one deserialized from
/// persisted or externally-supplied `TaskInput`/`TaskOutput`/`Delta`/event
/// data containing `../` sequences — is a path-traversal vector, so this
/// type validates on every path into existence: `from_hex`/`TryFrom<String>`
/// for construction, and a hand-written `Deserialize` impl (routing through
/// `from_hex`) so `serde_json::from_str` can't manufacture one unvalidated
/// either.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, schemars::JsonSchema)]
pub struct Blake3Hash(String);

/// A string failed to validate as a blake3 hex digest (exactly 64 lowercase
/// hex characters).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid blake3 hash: {0:?} is not exactly {BLAKE3_HEX_LEN} lowercase hex characters")]
pub struct InvalidHashError(String);

impl Blake3Hash {
    /// The only way to construct a `Blake3Hash`: rejects anything that
    /// isn't exactly 64 lowercase ASCII hex characters.
    pub fn from_hex(s: impl Into<String>) -> Result<Self, InvalidHashError> {
        let s = s.into();
        let is_valid = s.len() == BLAKE3_HEX_LEN
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if is_valid {
            Ok(Blake3Hash(s))
        } else {
            Err(InvalidHashError(s))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Blake3Hash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Blake3Hash {
    type Error = InvalidHashError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Blake3Hash::from_hex(s)
    }
}

impl<'de> Deserialize<'de> for Blake3Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Blake3Hash::from_hex(s).map_err(serde::de::Error::custom)
    }
}

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
