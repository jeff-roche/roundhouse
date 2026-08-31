//! §6.6's egress allowlist matcher and the `ConnectFilter` decision point.
//! See `crate` root docs for the two-lane model this module's `Lane`
//! documents.

/// §6.6's two physically separated lanes. The control lane (provider APIs,
/// `web` search backends, ACP transports, telemetry) is the daemon's own;
/// credentials live only here and the sandbox has no route to it. The agent
/// lane (everything an agent initiates) exits solely through a
/// [`crate::proxy::LoopbackProxy`] with a bearer token. This enum documents
/// the distinction at the type level in call-site signatures; it carries no
/// data of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Control,
    Agent,
}

/// Exact match or a leading `*.` wildcard suffix — **never** substring or
/// prefix matching on the raw host string, the same rule §6.3 states for
/// shell argv matching and for the same reason: substring matching is how
/// every published bypass works.
///
/// Concretely: an exact pattern for `"crates.io"` matches only the literal
/// string `"crates.io"` — it does not match `"evil-crates.io"` (Rust string
/// equality is exact, not `contains`/`ends_with`). A wildcard pattern for
/// `"*.example.com"` matches `"example.com"` itself and any host ending in
/// the *dotted* suffix `".example.com"` (e.g. `"api.example.com"`) — it does
/// not match `"evilexample.com"`, because that host has no `.` immediately
/// before `"example.com"`, so `ends_with(".example.com")` is false.
#[derive(Debug, Clone)]
pub struct HostPattern(String);

impl HostPattern {
    pub fn exact(host: &str) -> Self {
        Self(host.to_string())
    }

    pub fn wildcard_suffix(suffix: &str) -> Self {
        Self(format!("*.{suffix}"))
    }

    pub fn matches(&self, host: &str) -> bool {
        match self.0.strip_prefix("*.") {
            Some(suffix) => {
                host == suffix || host.ends_with(&format!(".{suffix}")) || suffix.is_empty()
            }
            None => host == self.0,
        }
    }
}

/// A session's egress allowlist — the set of hosts an agent-lane connection
/// through a [`crate::proxy::LoopbackProxy`] may reach.
pub struct EgressPolicy {
    pub allowed_hosts: Vec<HostPattern>,
}

impl EgressPolicy {
    pub fn matches(&self, host: &str) -> bool {
        self.allowed_hosts.iter().any(|p| p.matches(host))
    }
}

/// The cloud-metadata endpoint every SSRF chain reaches for. Denied always,
/// checked before any allowlist logic runs — matched-first and not editable
/// from config, the same shape as the policy engine's sealed floor (Task
/// 10).
pub const METADATA_IP: &str = "169.254.169.254";

#[derive(Debug, Clone)]
pub enum EgressDecision {
    Allow,
    Deny { host: String, reason: String },
}

/// The single decision point every real connection attempt must pass
/// through. `evaluate` checks [`METADATA_IP`] first, unconditionally, on
/// every call — before consulting the policy's allowlist at all — so no
/// allowlist configuration, however permissive, can ever route a connection
/// to the metadata endpoint.
pub struct ConnectFilter;

impl ConnectFilter {
    pub fn evaluate(policy: &EgressPolicy, target_host: &str) -> EgressDecision {
        let bare_host = target_host
            .rsplit_once(':')
            .map(|(h, _)| h)
            .unwrap_or(target_host);
        // Checked first, unconditionally — before any allowlist logic on
        // this or any other code path that reaches a real connection
        // attempt.
        if bare_host == METADATA_IP {
            return EgressDecision::Deny {
                host: target_host.to_string(),
                reason: "cloud metadata endpoint is denied always, regardless of allowlist".into(),
            };
        }
        if policy.matches(bare_host) {
            EgressDecision::Allow
        } else {
            EgressDecision::Deny {
                host: target_host.to_string(),
                reason: "not on the session's egress allowlist".into(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_pattern_never_substring_matches() {
        let pattern = HostPattern::exact("crates.io");
        assert!(pattern.matches("crates.io"));
        // `"evil-crates.io"` contains `"crates.io"` as a substring but must
        // not be treated as a match — exact means exact.
        assert!(!pattern.matches("evil-crates.io"));
        assert!(!pattern.matches("crates.io.evil.example"));
    }

    #[test]
    fn wildcard_suffix_requires_a_literal_dot_boundary() {
        let pattern = HostPattern::wildcard_suffix("example.com");
        assert!(pattern.matches("example.com"));
        assert!(pattern.matches("api.example.com"));
        // `"evilexample.com"` ends with the raw string `"example.com"` but
        // has no `.` immediately before it — must not match.
        assert!(!pattern.matches("evilexample.com"));
    }

    #[test]
    fn egress_policy_matches_any_allowed_host() {
        let policy = EgressPolicy {
            allowed_hosts: vec![
                HostPattern::exact("crates.io"),
                HostPattern::wildcard_suffix("example.com"),
            ],
        };
        assert!(policy.matches("crates.io"));
        assert!(policy.matches("sub.example.com"));
        assert!(!policy.matches("evil-crates.io"));
        assert!(!policy.matches("evilexample.com"));
    }

    #[test]
    fn connect_filter_denies_metadata_ip_before_allowlist_even_when_wide_open() {
        let policy = EgressPolicy {
            allowed_hosts: vec![HostPattern::wildcard_suffix("")],
        };
        let decision = ConnectFilter::evaluate(&policy, &format!("{METADATA_IP}:80"));
        assert!(matches!(decision, EgressDecision::Deny { .. }));
    }

    #[test]
    fn connect_filter_denies_host_not_on_allowlist() {
        let policy = EgressPolicy {
            allowed_hosts: vec![HostPattern::exact("crates.io")],
        };
        let decision = ConnectFilter::evaluate(&policy, "evil.example:443");
        assert!(matches!(decision, EgressDecision::Deny { .. }));
    }

    #[test]
    fn connect_filter_allows_host_on_allowlist() {
        let policy = EgressPolicy {
            allowed_hosts: vec![HostPattern::exact("crates.io")],
        };
        let decision = ConnectFilter::evaluate(&policy, "crates.io:443");
        assert!(matches!(decision, EgressDecision::Allow));
    }
}
