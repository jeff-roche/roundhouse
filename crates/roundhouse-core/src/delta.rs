use crate::ids::SessionId;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// §4.1 — deliberately typed rather than `String`: a `shell` task streams
/// stdout/stderr bytes, a `chat` task streams text/thinking/tool-call
/// fragments, an `agent` task streams child-session progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Delta {
    Text { text: String },
    /// Must round-trip verbatim — see §9.3 on thinking signatures.
    Thinking { text: String, signature: Option<String> },
    #[serde(with = "bytes_as_vec")]
    Stdout { bytes: Bytes },
    #[serde(with = "bytes_as_vec")]
    Stderr { bytes: Bytes },
    /// Partial JSON from a streaming tool call.
    ToolArgs { fragment: String },
    /// Pointer to a child session's event.
    Child { session: SessionId, seq: u64 },
}

// serde has no built-in Bytes support without pulling in `serde_bytes`;
// Phase 0 keeps roundhouse-core dependency-light and defines the minimal
// shim needed for the two variants that carry raw bytes.
mod bytes_as_vec {
    use bytes::Bytes;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Bytes, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
        let v: Vec<u8> = serde::Deserialize::deserialize(d)?;
        Ok(Bytes::from(v))
    }
}
