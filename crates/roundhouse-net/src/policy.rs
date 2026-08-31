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
use std::str::FromStr;

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

/// Whether, and how, a host matched an allowlist entry. `proxy.rs`'s
/// `gate_connect` uses this to decide whether to additionally deny a
/// private/loopback/link-local resolved address:
///
/// - `ExactIpLiteral` — the matching pattern's own text parses as a raw
///   `IpAddr` (e.g. `exact("127.0.0.1")`). An operator who explicitly typed
///   a literal IP address is consenting to *that specific address*, full
///   stop — this is the only case the private-range check does not
///   second-guess.
/// - `ExactHostname` — the matching pattern's text does *not* parse as an
///   `IpAddr` (e.g. `exact("internal.example.com")`), even though the
///   match itself was exact. **Fix-round-2 correction:** an earlier version
///   of this distinction exempted every exact match, including hostnames —
///   but an operator typing a *name* is consenting to that name, not to
///   whatever address it happens to resolve to now or after a later DNS
///   change. Only a literal-IP exact match is exempt; an exact-matched
///   hostname is treated the same as a wildcard for the private-range
///   check.
/// - `Wildcard` — matched via a `*.`-suffix pattern. Only ever expresses
///   trust in a *hostname*, and a hostname unexpectedly resolving into the
///   daemon host's internal network (accidentally, or via a
///   DNS-rebinding-shaped record change) is exactly the shape of bug/attack
///   this distinction exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchKind {
    ExactIpLiteral,
    ExactHostname,
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
            HostPatternKind::Exact(exact) => (host == *exact).then(|| {
                if IpAddr::from_str(exact).is_ok() {
                    MatchKind::ExactIpLiteral
                } else {
                    MatchKind::ExactHostname
                }
            }),
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

    /// Returns the highest-trust `MatchKind` among every pattern that
    /// matches `host`, in priority order `ExactIpLiteral` >
    /// `ExactHostname` > `Wildcard` — an explicit exact-IP-literal entry is
    /// always at least as trusted as any other kind of match covering the
    /// same host, never less.
    pub(crate) fn match_kind(&self, host: &str) -> Option<MatchKind> {
        let mut best: Option<MatchKind> = None;
        for pattern in &self.allowed_hosts {
            let Some(kind) = pattern.match_kind(host) else {
                continue;
            };
            best = Some(match (best, kind) {
                (Some(MatchKind::ExactIpLiteral), _) | (_, MatchKind::ExactIpLiteral) => {
                    MatchKind::ExactIpLiteral
                }
                (Some(MatchKind::ExactHostname), _) | (_, MatchKind::ExactHostname) => {
                    MatchKind::ExactHostname
                }
                _ => MatchKind::Wildcard,
            });
        }
        best
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

    /// Denies unspecified/loopback/private/link-local ranges. Only
    /// consulted by `proxy.rs`'s `gate_connect` when the matching allowlist
    /// entry's `MatchKind` is not `ExactIpLiteral` — an operator who
    /// explicitly typed a literal IP address (e.g. `exact("127.0.0.1")`)
    /// has given deliberate, specific consent to that exact address, which
    /// this check does not second-guess; anything else (a hostname, even
    /// via an exact match, or a wildcard) has only ever expressed trust in
    /// a *name*, and that name resolving into the daemon host's own
    /// internal network is exactly the SSRF/DNS-rebinding shape this
    /// exists to catch. `ip` must already be canonicalized by the caller,
    /// same as [`Self::deny_reason_for_metadata_ip`].
    ///
    /// **Fix-round-2 addition:** `is_unspecified()` — on Linux, connecting
    /// to the unspecified address (`0.0.0.0`, or any of its equivalent
    /// spellings: `0`, `0x0`, decimal/octal/hex forms, or the
    /// IPv4-mapped-IPv6 `::ffff:0.0.0.0`) actually connects to
    /// `127.0.0.1` — a real, live bypass the original loopback/private/
    /// link-local checks alone did not catch, confirmed by an
    /// end-to-end byte-tunnel reproduction against all four listed
    /// spellings.
    pub fn deny_reason_for_private_range(ip: IpAddr) -> Option<String> {
        let denied = match ip {
            IpAddr::V4(v4) => {
                v4.is_unspecified() || v4.is_loopback() || v4.is_private() || v4.is_link_local()
            }
            IpAddr::V6(v6) => {
                v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_unique_local()
                    || v6.is_unicast_link_local()
            }
        };
        denied.then(|| {
            format!(
                "{ip} is unspecified/loopback/private/link-local, only reachable via an \
                 allowlist entry that is itself an exact, literal IP address"
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
        assert_eq!(pattern.match_kind("*.foo"), Some(MatchKind::ExactHostname));
        assert_eq!(pattern.match_kind("bar.foo"), None);
        assert_eq!(pattern.match_kind("foo"), None);
    }

    #[test]
    fn exact_pattern_distinguishes_ip_literal_from_hostname() {
        assert_eq!(
            HostPattern::exact("127.0.0.1").match_kind("127.0.0.1"),
            Some(MatchKind::ExactIpLiteral)
        );
        assert_eq!(
            HostPattern::exact("::1").match_kind("::1"),
            Some(MatchKind::ExactIpLiteral)
        );
        assert_eq!(
            HostPattern::exact("internal.example.com").match_kind("internal.example.com"),
            Some(MatchKind::ExactHostname)
        );
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
        assert_eq!(
            policy.match_kind("api.example.com"),
            Some(MatchKind::ExactHostname)
        );
        assert_eq!(
            policy.match_kind("other.example.com"),
            Some(MatchKind::Wildcard)
        );
        assert_eq!(policy.match_kind("unrelated.example"), None);
    }

    #[test]
    fn egress_policy_match_kind_prefers_exact_ip_literal_over_everything() {
        let policy = EgressPolicy {
            allowed_hosts: vec![
                HostPattern::wildcard_suffix(""),
                HostPattern::exact("127.0.0.1"),
            ],
        };
        assert_eq!(
            policy.match_kind("127.0.0.1"),
            Some(MatchKind::ExactIpLiteral)
        );
        assert_eq!(
            policy.match_kind("other.example"),
            Some(MatchKind::Wildcard)
        );
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

    /// Fix-round-2 Critical: on Linux, connecting to the unspecified
    /// address (in any of its equivalent spellings — `0.0.0.0`, `0`,
    /// `0x0`, and the IPv4-mapped-IPv6 `::ffff:0.0.0.0`) actually connects
    /// to `127.0.0.1` — a live bypass the re-review confirmed with a real,
    /// byte-tunnel-verified connection through the proxy under a wildcard
    /// allow-all policy. Every one of those textual spellings resolves
    /// (via `tokio::net::lookup_host`, per `proxy.rs`'s
    /// `nine_alternate_encodings...`-style resolution) to one of the two
    /// canonical `IpAddr` values this test checks directly — this is the
    /// pure decision-logic test; `tests/proxy_hermetic.rs` has the
    /// end-to-end wire-level regression test using the literal alternate
    /// spellings.
    #[test]
    fn deny_reason_for_private_range_covers_unspecified_address_in_every_spelling() {
        // `0.0.0.0`, `0`, and `0x0` all resolve to this canonical IPv4
        // value.
        assert!(ConnectFilter::deny_reason_for_private_range("0.0.0.0".parse().unwrap()).is_some());
        // `[::ffff:0.0.0.0]`, canonicalized (as every caller in this crate
        // is required to do before calling this function), collapses to
        // the same IPv4 value above.
        let mapped: IpAddr = "::ffff:0.0.0.0".parse().unwrap();
        assert!(ConnectFilter::deny_reason_for_private_range(mapped.to_canonical()).is_some());
        // The plain IPv6 unspecified address.
        assert!(ConnectFilter::deny_reason_for_private_range("::".parse().unwrap()).is_some());
    }
}
