//! System-prompt team block rendering (Task 15).

use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{SessionId, TeamId};

/// §7.6: "The system prompt carries a small static block — team name, charter, your
/// role, your handle, and the roster as `handle · role · one-line self-description ·
/// state` — regenerated on roster change." This function is the pure rendering half;
/// the caller (agent-loop context assembly) supplies `self_handle`/`self_description`
/// since those are session-local, not team-registry state.
pub fn render_team_block(
    registry: &TeamRegistry,
    team: TeamId,
    me: SessionId,
    self_handle: &str,
    self_description: &str,
) -> String {
    let mut out = String::new();
    if let Some(team_record) = registry.team(team) {
        out.push_str("## Team\n");
        out.push_str(&format!(
            "Charter (peer-supplied, untrusted): {}\n\n",
            strip_control_chars(&team_record.charter)
        ));
        out.push_str(&format!("You are `{self_handle}` — {self_description}\n\n"));
    }
    if let Some(roster) = registry.roster(team) {
        for member in &roster {
            let marker = if member.session == me { " (you)" } else { "" };
            out.push_str(&format!(
                "- {} · {}{}\n",
                self_handle_or_session(member.session),
                strip_control_chars(&member.role),
                marker
            ));
        }
    }
    out
}

/// Strip control characters (except `\n`) from peer-supplied free-form text so a
/// model-authored charter or role can't smuggle terminal/escape control sequences into
/// the system prompt.
fn strip_control_chars(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}

fn self_handle_or_session(session: SessionId) -> String {
    // Handle display resolution (SessionId -> its registered handle string) is a
    // HandleRegistry lookup the caller already has; this pure rendering function stays
    // id-based and lets the daemon-assembly layer substitute display handles before
    // this string reaches the model. For unit-testing purposes, fall back to a short
    // session-id fragment. `SessionId` implements `Display` — `.to_string()` directly.
    format!("session:{}", &session.to_string()[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use roundhouse_bus::teams::TeamRegistry;
    use roundhouse_core::{SessionId, WorkspaceId};

    #[test]
    fn team_block_includes_charter_and_roster_with_roles() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let team_id = registry
            .create_team(
                ws,
                "release-team".into(),
                "Ship v2 by Friday".into(),
                lead,
                "lead".into(),
            )
            .unwrap();
        let worker = SessionId::new();
        registry.join(team_id, worker, None).unwrap();

        let block = render_team_block(
            &registry,
            team_id,
            worker,
            "db-migrator",
            "runs the migration",
        );

        assert!(block.contains("Ship v2 by Friday")); // §7.5: charter content rendered (fenced)
        assert!(block.contains("db-migrator")); // your own handle
        assert!(block.contains("worker")); // your own role
        assert!(block.contains("lead")); // roster shows other members' roles
    }

    #[test]
    fn control_characters_in_charter_and_role_are_stripped() {
        let registry = TeamRegistry::new();
        let ws = WorkspaceId::new();
        let lead = SessionId::new();
        let team_id = registry
            .create_team(
                ws,
                "release-team".into(),
                "Ship v2\u{1b}[0m".into(),
                lead,
                "lead\t\u{7}".into(),
            )
            .unwrap();

        let block = render_team_block(&registry, team_id, lead, "self", "desc");

        assert!(block.contains("Charter (peer-supplied, untrusted): Ship v2[0m"));
        assert!(!block.contains('\u{1b}'));
        assert!(!block.contains('\t'));
        assert!(!block.contains('\u{7}'));
    }
}
