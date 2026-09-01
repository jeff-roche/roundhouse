//! Inter-agent messaging, teams, and break-glass operations.
//!
//! Implements the routed registry (`Bus`) that session runtimes use to address
//! each other, the `LocalBus` concrete implementation with bounded mailboxes,
//! wait-graph deadlock refusal, rate limiting, and team management per
//! `docs/architecture/04-messaging-and-teams.md` §7.
#![forbid(unsafe_code)]

pub mod artifact_grant;
pub mod bus_trait;
pub mod event_sink;
pub mod handle_registry;
pub mod human_notifications;
pub mod limits;
pub mod local_bus;
pub mod mailbox;
pub mod rate_limit;
pub mod restart;
pub mod spawn_tree;
pub mod teams;
pub mod types;
pub mod wait_graph;

pub use bus_trait::Bus;
pub use types::*;
