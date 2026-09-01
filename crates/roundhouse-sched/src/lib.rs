//! Triggers and scheduling: what starts a session or workflow run — a cron
//! schedule, a webhook, a file-system watch, another session's message —
//! decoupled from the session/workflow logic itself.
//!
//! Phase 5, Subsystem A, Task 1 lands the core trigger/binding/event types
//! (`trigger` module) that every later scheduling task builds on: cron
//! next-fire computation (A2), the min-heap scheduler (A3),
//! `trigger_event` persistence + dedupe (A4), and overlap-policy admission
//! (A5). See `docs/architecture/02-system-architecture.md` §5.2 and
//! `05-scheduling-and-workflows.md`.
#![forbid(unsafe_code)]

pub mod trigger;

pub fn schema_version_floor() -> u16 {
    // S-CFG-1 (§12.7): layered config's schema-version floor lives here in
    // Phase 0 only as a named constant downstream crates can already
    // depend on; the real layered-config resolution is Phase 5 work.
    1
}
