//! Triggers and scheduling: what starts a session or workflow run — a cron
//! schedule, a webhook, a file-system watch, another session's message —
//! decoupled from the session/workflow logic itself.
//!
//! Phase 0 only proves this crate compiles and gives downstream crates one
//! named constant to depend on; no real trigger/scheduling implementation
//! exists yet — that's Phase 5 work. See
//! `docs/architecture/02-system-architecture.md` §5.2 and
//! `05-scheduling-and-workflows.md`.
#![forbid(unsafe_code)]

pub fn schema_version_floor() -> u16 {
    // S-CFG-1 (§12.7): layered config's schema-version floor lives here in
    // Phase 0 only as a named constant downstream crates can already
    // depend on; the real layered-config resolution is Phase 5 work.
    1
}
