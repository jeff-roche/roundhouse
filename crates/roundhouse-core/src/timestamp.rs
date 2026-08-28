use serde::{Deserialize, Serialize};

/// UTC, monotonic-corrected, stored as nanoseconds since the Unix epoch.
/// A plain integer newtype (not `std::time::SystemTime`) so this stays
/// trivially `Copy`/`Serialize` with no platform-clock dependency at all —
/// the clock read itself is engine/store's job, not core's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(i64);

impl Timestamp {
    pub fn from_unix_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    pub fn as_unix_nanos(&self) -> i64 {
        self.0
    }
}
