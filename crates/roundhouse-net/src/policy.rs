//! §6.6's egress allowlist matcher and the `ConnectFilter` decision point.
//! See `crate` root docs for the two-lane model this module's `Lane`
//! documents.
//!
//! **Fix-round-1 architecture note (security review findings, both
//! confirmed by live end-to-end reproduction against a real
//! `LoopbackProxy`):** the original version of this module compared the
//! *string* the CONNECT client sent against `METADATA_IP` (also a string),
//! and the allowlist likewise matched on the raw hostname string, with
//! `TcpStream::connect` independently re-resolving that same string later.
//! That has zero IP-level enforcement: `TcpStream::connect`'s resolver
//! (`getaddrinfo`/`inet_aton`) accepts at least nine different textual
//! spellings of the metadata IP alone (a root-anchored trailing dot,
//! decimal-dword, octal, multiple hex forms, a truncated 3-part form, and
//! two IPv4-mapped-IPv6 spellings) that all compare unequal to the literal
//! string `"169.254.169.254"` but resolve to the exact same address — every
//! one of them sailed straight through the old string check. Worse, any
//! allowlisted *hostname* that resolves (now, or later via a DNS record
//! change) to an internal or metadata address sailed through too, since the
//! old code never looked at an actual `IpAddr` at all.
//!
//! The fix: `proxy.rs` now resolves the CONNECT target to real
//! `SocketAddr`s exactly once (`tokio::net::lookup_host`), and this
//! module's checks operate on the resulting, canonicalized `IpAddr` — never
//! a string — for the parts of the decision that are genuinely about *which
//! address* a connection would reach. The hostname-string allowlist match
//! remains a legitimate, separate check (operators allow by hostname, not
//! by IP), but it is layered *on top of* the IP-level metadata check, never
//! a substitute for it. See `proxy.rs`'s `gate_connect` for the full
//! resolve-check-connect-to-the-checked-address pipeline this enables
//! (never re-resolving at connect time, closing the DNS-rebinding-shaped
//! TOCTOU the string-only design had no defense against at all).

use std::net::{IpAddr, Ipv4Addr};

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

/// Lowercases and strips a single trailing `.` (the DNS root-anchor form,
/// e.g. `"crates.io."`) — applied once, uniformly, before both the
/// allowlist match and (in `proxy.rs`) the DNS resolution step, so neither
/// check can be bypassed by case or trailing-dot variation alone.
pub(crate) fn normalize_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

/// Whether a host matched an allowlist entry via an **exact** pattern or a
/// **wildcard-suffix** one. `proxy.rs`'s `gate_connect` uses this
/// distinction to decide whether to additionally deny a private/loopback/
/// link-local resolved address: an exact entry (e.g. an operator literally
/// allowlisting `"127.0.0.1"`) is explicit, deliberate operator intent and
/// is trusted as-is; a wildcard entry (e.g. `"*.example.com"`) only ever
/// expresses trust in a *hostname*, and a hostname unexpectedly resolving
/// into the daemon host's internal network (accidentally, or via a
/// DNS-rebinding-shaped record change) is exactly the shape of bug/attack
/// this distinction exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchKind {
    Exact,
    Wildcard,
}

#[derive(Debug, Clone)]
enum HostPatternKind {
    Exact(String),
    WildcardSuffix(String),
}

/// Exact match or a leading `*.` wildcard suffix — **never** substring or
/// prefix matching on the raw host string, the same rule §6.3 states for
/// shell argv matching and for the same reason: substring matching is how
/// every published bypass works.
///
/// Concretely: an exact pattern for `"crates.io"` matches only the literal
/// (normalized) string `"crates.io"` — it does not match `"evil-crates.io"`
/// (string equality is exact, not `contains`/`ends_with`). A wildcard
/// pattern for `"*.example.com"` matches `"example.com"` itself and any
/// host ending in the *dotted* suffix `".example.com"` (e.g.
/// `"api.example.com"`) — it does not match `"evilexample.com"`, because
/// that host has no `.` immediately before `"example.com"`.
///
/// **Fix-round-1 note:** the original version stored both kinds as a bare
/// `String` and detected "is this a wildcard" by checking whether the
/// stored string started with `"*."` — which meant `HostPattern::exact("*.
/// foo")` was silently treated as a wildcard despite being constructed
/// through the exact-match constructor. Storing the kind explicitly (this
/// enum) makes `exact()` genuinely, unconditionally exact regardless of
/// its input.
#[derive(Debug, Clone)]
pub struct HostPattern(HostPatternKind);

impl HostPattern {
    pub fn exact(host: &str) -> Self {
        Self(HostPatternKind::Exact(normalize_host(host)))
    }

    pub fn wildcard_suffix(suffix: &str) -> Self {
        Self(HostPatternKind::WildcardSuffix(normalize_host(suffix)))
    }

    pub fn matches(&self, host: &str) -> bool {
        self.match_kind(host).is_some()
    }

    pub(crate) fn match_kind(&self, host: &str) -> Option<MatchKind> {
        let host = normalize_host(host);
        match &self.0 {
            HostPatternKind::Exact(exact) => (host == *exact).then_some(MatchKind::Exact),
            HostPatternKind::WildcardSuffix(suffix) => {
                let matched =
                    host == *suffix || host.ends_with(&format!(".{suffix}")) || suffix.is_empty();
                matched.then_some(MatchKind::Wildcard)
            }
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

    /// Prefers `MatchKind::Exact` if *any* pattern matches exactly, even if
    /// a wildcard pattern also matches the same host — an explicit exact
    /// entry is always at least as trusted as a wildcard one covering the
    /// same host, never less.
    pub(crate) fn match_kind(&self, host: &str) -> Option<MatchKind> {
        let mut wildcard_matched = false;
        for pattern in &self.allowed_hosts {
            match pattern.match_kind(host) {
                Some(MatchKind::Exact) => return Some(MatchKind::Exact),
                Some(MatchKind::Wildcard) => wildcard_matched = true,
                None => {}
            }
        }
        wildcard_matched.then_some(MatchKind::Wildcard)
    }
}

/// The cloud-metadata endpoint every SSRF chain reaches for, as a *string*
/// — kept for display/formatting/test convenience (e.g. building a CONNECT
/// target). **Never compared directly against another string** for the
/// actual deny decision; see `METADATA_IPV4` and
/// [`ConnectFilter::deny_reason_for_metadata_ip`], which compare a real,
/// resolved, canonicalized `IpAddr` instead. (Fix-round-1: this is exactly
/// the string-vs-string comparison the security review found bypassable by
/// at least nine alternate textual encodings of the same address.)
pub const METADATA_IP: &str = "169.254.169.254";

/// The metadata endpoint's parsed `Ipv4Addr` — the real, canonical
/// representation every deny decision in this crate compares a resolved
/// address against. A unit test below asserts this stays in sync with
/// [`METADATA_IP`].
const METADATA_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

#[derive(Debug, Clone)]
pub enum EgressDecision {
    Allow,
    Deny { host: String, reason: String },
}

/// The IP-level decision points every real connection attempt must pass
/// through, operating on an already-resolved, already-canonicalized
/// `IpAddr` (never a string) — see `proxy.rs`'s `gate_connect` for where
/// resolution and canonicalization happen, exactly once, before any of
/// these are consulted.
pub struct ConnectFilter;

impl ConnectFilter {
    /// Denied always, unconditionally, on every resolved candidate address
    /// for a CONNECT target — before, and independently of, any allowlist
    /// logic. No allowlist configuration, however permissive, can ever
    /// cause this to return `None` for the metadata endpoint: matched-first
    /// and not editable, the same shape as the policy engine's sealed
    /// floor (Task 10).
    ///
    /// `ip` must already be canonicalized (`IpAddr::to_canonical()`) by the
    /// caller so that an IPv4-mapped-IPv6 spelling of the metadata address
    /// (e.g. `::ffff:169.254.169.254`) is caught exactly the same as the
    /// plain IPv4 form — canonicalization collapses both to the same
    /// comparison.
    pub fn deny_reason_for_metadata_ip(ip: IpAddr) -> Option<String> {
        if ip == IpAddr::V4(METADATA_IPV4) {
            Some("cloud metadata endpoint is denied always, regardless of allowlist".to_string())
        } else {
            None
        }
    }

    /// Denies loopback/private/link-local ranges. Only consulted by
    /// `proxy.rs`'s `gate_connect` when the matching allowlist entry was a
    /// **wildcard**, not an exact host — an operator who explicitly
    /// allowlists `"127.0.0.1"` (or any other specific host) by its exact
    /// name has given deliberate, specific consent that this check does
    /// not second-guess; a broad `"*.example.com"`-shaped entry has only
    /// ever expressed trust in a *hostname*, and that hostname resolving
    /// into the daemon host's own internal network is exactly the
    /// SSRF/DNS-rebinding shape this exists to catch. `ip` must already be
    /// canonicalized by the caller, same as
    /// [`Self::deny_reason_for_metadata_ip`].
    pub fn deny_reason_for_private_range(ip: IpAddr) -> Option<String> {
        let denied = match ip {
            IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
        denied.then(|| {
            format!(
                "{ip} is in a private/loopback/link-local range, only reachable via an \
                 explicit exact-host allowlist entry, not a wildcard match"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_ip_str_and_parsed_constant_stay_in_sync() {
        assert_eq!(METADATA_IP.parse::<Ipv4Addr>().unwrap(), METADATA_IPV4);
    }

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
    fn exact_pattern_with_wildcard_looking_input_stays_exact() {
        // Fix-round-1 regression: `exact("*.foo")` must not be silently
        // reinterpreted as a wildcard pattern.
        let pattern = HostPattern::exact("*.foo");
        assert_eq!(pattern.match_kind("*.foo"), Some(MatchKind::Exact));
        assert_eq!(pattern.match_kind("bar.foo"), None);
        assert_eq!(pattern.match_kind("foo"), None);
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
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        let pattern = HostPattern::exact("crates.io");
        assert!(pattern.matches("CRATES.IO"));
        assert!(pattern.matches("crates.io."));
        assert!(pattern.matches("Crates.Io."));
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
    fn egress_policy_match_kind_prefers_exact_over_wildcard() {
        let policy = EgressPolicy {
            allowed_hosts: vec![
                HostPattern::wildcard_suffix("example.com"),
                HostPattern::exact("api.example.com"),
            ],
        };
        assert_eq!(policy.match_kind("api.example.com"), Some(MatchKind::Exact));
        assert_eq!(
            policy.match_kind("other.example.com"),
            Some(MatchKind::Wildcard)
        );
        assert_eq!(policy.match_kind("unrelated.example"), None);
    }

    #[test]
    fn deny_reason_for_metadata_ip_matches_canonical_ipv4_mapped_ipv6() {
        let mapped: IpAddr = "::ffff:169.254.169.254".parse().unwrap();
        assert!(ConnectFilter::deny_reason_for_metadata_ip(mapped.to_canonical()).is_some());
        assert!(ConnectFilter::deny_reason_for_metadata_ip(IpAddr::V4(METADATA_IPV4)).is_some());
        let benign: IpAddr = "93.184.216.34".parse().unwrap();
        assert!(ConnectFilter::deny_reason_for_metadata_ip(benign).is_none());
    }

    #[test]
    fn deny_reason_for_private_range_covers_loopback_private_and_link_local() {
        assert!(
            ConnectFilter::deny_reason_for_private_range("127.0.0.1".parse().unwrap()).is_some()
        );
        assert!(
            ConnectFilter::deny_reason_for_private_range("10.0.0.5".parse().unwrap()).is_some()
        );
        assert!(
            ConnectFilter::deny_reason_for_private_range("169.254.1.1".parse().unwrap()).is_some()
        );
        assert!(ConnectFilter::deny_reason_for_private_range("::1".parse().unwrap()).is_some());
        assert!(
            ConnectFilter::deny_reason_for_private_range("93.184.216.34".parse().unwrap())
                .is_none()
        );
    }
}
