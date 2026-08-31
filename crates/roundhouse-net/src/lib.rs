//! The daemon-owned network egress boundary (§6.6, §6.1) — one of the design's
//! "exactly two real boundaries." §6.6's two-lane model: the **control lane**
//! (provider APIs, `web` search backends, ACP transports, telemetry) is the
//! daemon's own — credentials live only there and the sandbox has no route to
//! it. The **agent lane** (everything an agent-initiated task originates) exits
//! solely through a per-session [`proxy::LoopbackProxy`] with a bearer token,
//! filtered by [`policy::ConnectFilter`] against a per-session
//! [`policy::EgressPolicy`] allowlist, with the cloud-metadata IP
//! ([`policy::METADATA_IP`]) denied unconditionally on every code path —
//! checked first, before any allowlist logic, matched-first and not editable,
//! the same shape as the policy engine's sealed floor.
//!
//! This task (Task 23, Phase 2) builds the subsystem itself: the two-lane
//! model, the allowlist matcher, and a real per-session loopback CONNECT
//! proxy with hermetic tests. Task 24 wires it into `net_enforced`, the
//! isolation tiers, and the `http`/`web` task kinds; Task 25's integration
//! test exercises it from the real task-admission path.
#![forbid(unsafe_code)]

pub mod policy;
pub mod proxy;

pub use policy::{ConnectFilter, EgressDecision, EgressPolicy, HostPattern, Lane, METADATA_IP};
pub use proxy::{LoopbackProxy, SessionEgressContext};
