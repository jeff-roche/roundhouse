//! `peers` tool executor (Task 14).

use roundhouse_bus::teams::{Membership, TeamRegistry};
use roundhouse_core::TeamId;

/// §7.6: "peers gives the live detailed view (state, mailbox depth, who is blocked on
/// whom)." Mailbox depth and wait-graph edges are read from `Bus`/`LocalBus` at the
/// call site (roundhouse-daemon's tool dispatcher); this function is the pure
/// roster-shaping part that does not need a live Bus handle to unit test.
pub fn peers(registry: &TeamRegistry, team: TeamId) -> Vec<Membership> {
    registry.roster(team).unwrap_or_default()
}
