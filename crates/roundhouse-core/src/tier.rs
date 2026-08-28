use serde::{Deserialize, Serialize};

/// §6.5 — lives in `roundhouse-core` (not `roundhouse-sandbox`) because
/// `IsolationAttestation`, which is part of `EventPayload`, needs it and
/// core has zero dependencies. `roundhouse-sandbox` re-exports this type
/// rather than redefining it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    None,
    Worktree,
    Sandbox,
    Container,
    Remote,
}
