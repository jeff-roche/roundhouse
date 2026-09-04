//! The DNS-rebinding defence on the `/api` nest: a `Host`-header check derived
//! from the bind, layered inside [`crate::api_router`] so it is always on
//! (ruling P93 §A).
//!
//! # What this defends, and why nothing else can
//!
//! The loopback bind is **ungated by design** ([`crate::lan_auth`] §2): a
//! same-uid local process can already read the state dir, the socket and the
//! database directly, so authenticating one would only add the login system
//! §11.3 forbids. That argument covers a local *process*. It does not cover a
//! remote *web page*.
//!
//! The abuse path is DNS rebinding. A victim visits `evil.com`; the attacker
//! answers with a short-TTL record, then re-answers `127.0.0.1`; the page issues
//! `fetch("http://evil.com:PORT/api/runs")`. The **browser** considers that
//! same-origin — same scheme, same name, same port as the document — so it
//! hands the response body to the page. The one thing that does not change
//! under rebinding is the `Host` header: it still says `evil.com`, because that
//! is the name in the URL.
//!
//! So the check is: **the request must address us by a name we actually bind
//! to.** The three alternatives were considered and rejected in ruling P93 §A,
//! recorded here so they are not re-derived:
//!
//! - **CORS** — inapplicable. After a rebind the request is not cross-origin,
//!   so no CORS header is consulted at all. ([`crate::lan_auth`] also forbids
//!   adding one.)
//! - **`Origin` / `Sec-Fetch-Site`** — a rebound same-origin `GET` sends no
//!   `Origin` and `Sec-Fetch-Site: same-origin`. Both *confirm* the attacker.
//! - **Requiring the token on loopback** — §6.4's stricter reading, which
//!   [`crate::lan_auth`] §2 already rejects because §11.3 forbids a login
//!   system.
//!
//! # A missing `Host` is rejected
//!
//! `Host` is mandatory in HTTP/1.1, but an in-process `oneshot` request omits
//! it unless the test sets it — so "absent" must fail closed, or the check has
//! a hole exactly where the tests live. Every `/api` request in this crate's
//! test suite therefore carries a `Host`, and that churn is the check working.
//!
//! HTTP/2 and HTTP/3 have no `Host` header at all: they carry `:authority`,
//! which `hyper` puts in the request URI. That authority is checked against the
//! same allow-list, so a future h2 listener is not silently 403ed — and it is
//! not a bypass, because it has to match the same names.
//!
//! # What it costs on the LAN arm
//!
//! An operator who browses to a *hostname* (`http://nas.local:PORT/`) is
//! refused, because the bind knows only an address. That is accepted rather
//! than worked around: the LAN arm is token-gated regardless, so the `Host`
//! check there is defence in depth. **Residual:** hostname-based LAN access
//! needs a config item naming the expected host, not a loosened check — a
//! wildcard here would give the rebinding page back exactly what this takes
//! from it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Which `Host` values the bound surface answers to.
///
/// Derived from [`crate::lan_auth::BindConfig`] — the same value that decides
/// the address and the token — so there is no second place to configure this
/// and no way to bind one thing while admitting another.
#[derive(Debug, Clone)]
pub(crate) enum AllowedHosts {
    /// Exactly these names, compared case-insensitively (hostnames are
    /// case-insensitive, and an attacker's name fails whatever its case), each
    /// accepted with or without a `:port` suffix. The port is not checked
    /// because [`crate::lan_auth::BindConfig`] does not carry one; the name is
    /// what rebinding cannot change.
    Named(Arc<[String]>),
    /// Any IP literal, for a bind to the **unspecified** address (`0.0.0.0` or
    /// `::`), which is how a LAN bind is realistically spelled: the operator's
    /// address is whatever DHCP handed the machine, and it is not in the
    /// config.
    ///
    /// This is not a hole. DNS rebinding needs a *name* — the attack is
    /// precisely that a name the browser considers the page's own origin
    /// resolves to us. A page served from `http://192.168.1.40:PORT` is one the
    /// operator typed an address into; a page served from `evil.com` sends
    /// `Host: evil.com`, which is not an IP literal and is refused here. A
    /// cross-origin `fetch` to a bare IP is not rebinding at all and is stopped
    /// by the absent CORS headers.
    ///
    /// **And a second reason, which does not depend on the first** (ruling P94
    /// addendum): this variant is structurally unreachable without the LAN
    /// token. [`crate::lan_auth::BindConfig::allowed_hosts`] yields it only
    /// under `Bind::Lan`, `BindConfig::gate` returns `Some` for **every**
    /// `Bind::Lan`, and `BindConfig::lan` cannot be constructed without a
    /// `LanToken`. So the loosest arm of this check is never the ungated arm,
    /// and admitting it cannot weaken the loopback property at all — loopback
    /// never reaches it. The argument above rests on
    /// [`is_ip_literal`]'s name/literal discrimination being exact; this one
    /// holds even if that discrimination were buggy, which is what makes it the
    /// better of the two to lead with.
    AnyIpLiteral,
}

impl AllowedHosts {
    /// Whether `host` — a raw `Host` header value or `:authority` — addresses
    /// this bind.
    fn admits(&self, host: &str) -> bool {
        let Some(name) = host_without_port(host) else {
            return false;
        };
        match self {
            Self::Named(names) => names
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name)),
            Self::AnyIpLiteral => is_ip_literal(name),
        }
    }
}

/// The host part of a `Host` value, or `None` if the port suffix is not a port.
///
/// A malformed port is a refusal rather than something to strip leniently: this
/// runs in front of an ungated surface, and a parser that shrugs at input it
/// does not understand is how "`127.0.0.1.evil.com`"-shaped tricks get through
/// somewhere else.
fn host_without_port(host: &str) -> Option<&str> {
    // An IPv6 literal is bracketed in a `Host` value (`[::1]:8080`), which is
    // what makes its own colons unambiguous. Find the bracket first, or the
    // `split_once(':')` below would cut `[::1]` in half.
    if host.starts_with('[') {
        let end = host.find(']')?;
        let (literal, rest) = host.split_at(end + 1);
        let port_ok = rest.is_empty() || rest.strip_prefix(':').is_some_and(is_port);
        return port_ok.then_some(literal);
    }
    match host.split_once(':') {
        None => Some(host),
        // `a:b:c` leaves `b:c` here, which is not a port — so it is refused
        // rather than treated as a name of `a`.
        Some((name, port)) => is_port(port).then_some(name),
    }
}

fn is_port(port: &str) -> bool {
    !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `name` is an IP literal in `Host` form: a bare IPv4 address, or a
/// **bracketed** IPv6 one. A bare IPv6 address is not legal in a `Host` value
/// and is refused, which is the fail-closed direction.
fn is_ip_literal(name: &str) -> bool {
    match name
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        Some(inner) => inner.parse::<Ipv6Addr>().is_ok(),
        None => name.parse::<Ipv4Addr>().is_ok(),
    }
}

/// Refuses any request that does not address this bind by a name it answers to.
///
/// Layered by [`crate::api_router`] onto the API routes **and their fallback**,
/// so an `/api` path that matches no route is checked too. It sits *inside*
/// [`crate::lan_auth`]'s gate, so on a LAN bind an unauthenticated request is
/// `401` before it is `403` — the order that tells an unauthenticated caller
/// the least.
pub(crate) async fn require_expected_host(
    State(allowed): State<AllowedHosts>,
    request: Request,
    next: Next,
) -> Response {
    let addressed_correctly = match request.headers().get(header::HOST) {
        // A `Host` value that is not ASCII is not a name we bind to.
        Some(host) => host.to_str().is_ok_and(|host| allowed.admits(host)),
        // No `Host` header: either HTTP/2+, where the authority is in the URI,
        // or an HTTP/1.1 request that omitted a mandatory header. The first is
        // checked against the same list; the second has no authority and is
        // refused.
        None => request
            .uri()
            .authority()
            .is_some_and(|authority| allowed.admits(authority.as_str())),
    };

    if addressed_correctly {
        next.run(request).await
    } else {
        forbidden()
    }
}

/// `403` — the request reached the right process by the wrong name.
///
/// Not `401`: nothing the caller can present fixes it, so a challenge would be
/// a lie. Not `404`: the path exists. The body says which header is wrong,
/// because the operator hitting this legitimately (a hostname on the LAN arm —
/// see this module's docs) has no other way to find out.
fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        crate::api_error("this API answers only to the host it is bound to; check the Host header"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> AllowedHosts {
        AllowedHosts::Named(
            vec![
                "127.0.0.1".to_string(),
                "[::1]".to_string(),
                "localhost".to_string(),
            ]
            .into(),
        )
    }

    /// The three spellings a browser uses for the loopback bind, each with and
    /// without a port. The port is not part of the decision, so both forms of
    /// each name must be admitted — a check that compared the whole `Host`
    /// value would reject every real request, since a non-80 port is always
    /// present in practice.
    #[test]
    fn every_loopback_spelling_is_admitted_with_and_without_a_port() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
            "localhost",
            "localhost:8080",
            // Hostnames are case-insensitive, and accepting a shouted one
            // weakens nothing: `evil.com` fails in every case.
            "LOCALHOST:8080",
        ] {
            assert!(
                loopback().admits(host),
                "{host} addresses the loopback bind"
            );
        }
    }

    /// The attack this exists for: after a rebind the request is same-origin
    /// and carries no `Origin`, but the `Host` is still the attacker's name.
    #[test]
    fn a_rebound_attacker_name_is_refused() {
        for host in [
            "evil.com",
            "evil.com:8080",
            // The two near-misses a `contains`/`starts_with` check would let
            // through, which is why the comparison is on the whole name.
            "127.0.0.1.evil.com",
            "evil.com:8080/127.0.0.1",
            "notlocalhost",
            "localhost.evil.com",
        ] {
            assert!(!loopback().admits(host), "{host} is not a name we bind to");
        }
    }

    /// A port that is not a port is a refusal, not something to strip. `a:b:c`
    /// must not be read as the name `a`.
    #[test]
    fn a_malformed_port_is_refused_rather_than_stripped() {
        for host in [
            "localhost:",
            "localhost:80a",
            "localhost:80:80",
            "127.0.0.1:evil",
            "[::1]:",
            "[::1]x",
            "[::1",
        ] {
            assert!(!loopback().admits(host), "{host} has no usable port");
        }
    }

    /// The LAN arm admits the address it was bound to, and nothing else — not
    /// the loopback names, which are what a rebinding page reaches for.
    #[test]
    fn a_lan_bind_admits_its_own_literal_and_not_the_loopback_names() {
        let allowed = AllowedHosts::Named(vec!["192.168.1.40".to_string()].into());

        assert!(allowed.admits("192.168.1.40"));
        assert!(allowed.admits("192.168.1.40:8080"));
        assert!(!allowed.admits("127.0.0.1"));
        assert!(!allowed.admits("localhost"));
        assert!(!allowed.admits("192.168.1.41"));
    }

    /// The unspecified bind admits any *literal* — because the operator's
    /// address is not in the config — and still refuses every name, which is
    /// the half that stops rebinding.
    #[test]
    fn an_unspecified_bind_admits_literals_and_still_refuses_names() {
        let allowed = AllowedHosts::AnyIpLiteral;

        for host in ["192.168.1.40", "192.168.1.40:8080", "127.0.0.1", "[::1]:80"] {
            assert!(allowed.admits(host), "{host} is an IP literal");
        }
        for host in ["evil.com", "localhost", "nas.local:8080", "::1"] {
            assert!(
                !allowed.admits(host),
                "{host} is a name, and a name is what rebinding controls"
            );
        }
    }
}
