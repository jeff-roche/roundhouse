//! Ruling P93 §A's DNS-rebinding defence, exercised through the real router.
//!
//! The unit tests in `src/host_guard.rs` cover the predicate — which names are
//! admitted, and what a malformed port does. What can only be checked here is
//! the part that was actually wrong before this existed: **that the check is
//! mounted, over the whole `/api` nest including its fallback, on the ungated
//! loopback arm as well as the gated LAN one.** A predicate that is correct and
//! never layered is the failure P84 §E and P88 §A are both about.
//!
//! Two properties every test here rests on, stated once:
//!
//! - The check is **inside** `api_router`, so the asset surface is untouched.
//!   That is not a leniency: `assets/dist/` is compile-time-constant public
//!   content (see `assets`' module docs), and a rebinding page reading the app
//!   shell learns what the open port already told it. What it must not reach is
//!   `/api`.
//! - A **missing** `Host` is refused. HTTP/1.1 makes the header mandatory, so
//!   nothing legitimate omits it — but an in-process `oneshot` does, which is
//!   exactly where a lenient check would have its hole.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use roundhouse_web::lan_auth::{BindConfig, LanToken};
use roundhouse_web::{build_router, AppState};
use tempfile::TempDir;
use tower::ServiceExt;

/// A session id shaped like the one `sse.rs` parses, so a request that gets
/// past the check reaches a handler rather than a parse failure.
const SESSION_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

/// The `/api` paths this file probes: a real route, the *other* real route, and
/// a path no route will ever match.
///
/// The third is the load-bearing one, for P88 §A's reason one layer down: a
/// check applied with `route_layer` instead of `layer` would cover the two
/// routes and leave `api_not_found` — the fallback that answers everything else
/// under `/api` — outside it. Then a rebinding page could not read `/api/runs`
/// but the *next* route added would be a coin flip.
const API_PATHS: [&str; 3] = [
    "/api/runs",
    "/api/sessions/{id}/events",
    "/api/no-such-route",
];

fn api_paths() -> Vec<String> {
    API_PATHS
        .iter()
        .map(|path| path.replace("{id}", SESSION_ID))
        .collect()
}

async fn status_of(router: axum::Router, request: Request<Body>) -> StatusCode {
    router
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

fn with_host(uri: &str, host: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("Host", host)
        .body(Body::empty())
        .expect("the request builds")
}

fn without_host(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .body(Body::empty())
        .expect("the request builds")
}

fn loopback_router() -> axum::Router {
    build_router(AppState::default(), &BindConfig::loopback())
}

/// A `0700` state dir, which is what `LanToken::load_or_create` demands.
fn state_dir() -> TempDir {
    let dir = tempfile::tempdir().expect("a temp dir is creatable");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("the mode is settable");
    dir
}

fn lan_router(dir: &Path, addr: IpAddr) -> (axum::Router, String) {
    let token = LanToken::load_or_create(dir).expect("a fresh 0700 dir yields a token");
    let text = std::fs::read_to_string(roundhouse_web::lan_auth::token_path(dir))
        .expect("the token file exists")
        .trim()
        .to_string();
    (
        build_router(AppState::default(), &BindConfig::lan(addr, token)),
        text,
    )
}

fn bearer(uri: &str, host: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("Host", host)
        .header("Authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("the request builds")
}

/// **The attack, end to end.** The victim visits `evil.com`, the attacker
/// rebinds it to `127.0.0.1`, and the page fetches `http://evil.com:PORT/api/runs`
/// — which the browser treats as same-origin, so no CORS header is consulted
/// and nothing else in this crate would have stopped it. The one thing rebinding
/// cannot change is the name in the URL, and therefore the `Host`.
///
/// Every `/api` path, not just the routed ones: the fallback has to be behind
/// the check too, or the next route added lands outside it.
#[tokio::test]
async fn a_rebound_page_is_refused_on_every_api_path() {
    for path in api_paths() {
        assert_eq!(
            status_of(loopback_router(), with_host(&path, "evil.com:7777")).await,
            StatusCode::FORBIDDEN,
            "{path} must refuse a request addressed to a name this process does not bind"
        );
    }
}

/// The three names a browser reaches the loopback bind by, each with the port
/// it will actually carry. Without this the check could be "refuse everything"
/// and the suite above would still pass — the local UI would simply never work.
#[tokio::test]
async fn the_loopback_bind_answers_to_the_names_a_browser_uses() {
    for host in [
        "127.0.0.1:7777",
        "[::1]:7777",
        "localhost:7777",
        "localhost",
    ] {
        assert_eq!(
            status_of(loopback_router(), with_host("/api/runs", host)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{host} addresses the loopback bind, so the request must reach the handler — which \
             answers 503 for a router with no store"
        );
    }
}

/// A missing `Host` fails closed. HTTP/1.1 requires the header, so nothing
/// legitimate omits it; what does omit it is an in-process `oneshot`, which is
/// why "absent is allowed" would put the hole exactly where the tests are.
#[tokio::test]
async fn a_request_with_no_host_header_is_refused() {
    for path in api_paths() {
        assert_eq!(
            status_of(loopback_router(), without_host(&path)).await,
            StatusCode::FORBIDDEN,
            "{path} with no Host must fail closed"
        );
    }
}

/// HTTP/2 and HTTP/3 carry `:authority` instead of a `Host` header, and `hyper`
/// puts it in the request URI. Checking only the header would 403 every request
/// from an h2 client — a listener-shaped trap this crate cannot yet trip,
/// because it binds nothing. The authority is held to the same list, so it
/// admits nothing the header form would not.
#[tokio::test]
async fn an_authority_in_the_uri_stands_in_for_a_missing_host_header() {
    assert_eq!(
        status_of(
            loopback_router(),
            without_host("http://127.0.0.1:7777/api/runs")
        )
        .await,
        StatusCode::SERVICE_UNAVAILABLE,
        "an h2 request addressing the bind by its authority must reach the handler"
    );
    assert_eq!(
        status_of(
            loopback_router(),
            without_host("http://evil.com:7777/api/runs")
        )
        .await,
        StatusCode::FORBIDDEN,
        "the authority is checked against the same names, not trusted for existing"
    );
}

/// The asset surface is deliberately outside the check — it is compile-time
/// constant public content, and a whole-surface `Host` check would break the
/// shell for the same reason the whole-surface *token* gate did (`build_router`
/// records that at length). What a rebinding page gets from the shell is the
/// client code from an open-source repository.
#[tokio::test]
async fn the_asset_surface_is_not_host_checked() {
    for path in ["/", "/index.html", "/w/default/inbox"] {
        assert_eq!(
            status_of(loopback_router(), with_host(path, "evil.com")).await,
            StatusCode::OK,
            "{path} is public content and must not depend on the Host"
        );
    }
}

/// The LAN arm answers to the literal it was bound to and to nothing else —
/// including the loopback names, which are what a rebinding page reaches for.
/// The token is presented so the `401` cannot be what is being observed.
#[tokio::test]
async fn a_lan_bind_answers_only_to_its_own_address() {
    let dir = state_dir();
    let addr = Ipv4Addr::new(192, 168, 1, 40);
    let (router, token) = lan_router(dir.path(), IpAddr::V4(addr));

    assert_eq!(
        status_of(router, bearer("/api/runs", "192.168.1.40:7777", &token)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "the bound address is the name the LAN arm answers to"
    );

    for host in ["127.0.0.1:7777", "localhost:7777", "nas.local:7777"] {
        let (router, token) = lan_router(dir.path(), IpAddr::V4(addr));
        assert_eq!(
            status_of(router, bearer("/api/runs", host, &token)).await,
            StatusCode::FORBIDDEN,
            "{host} is not the address this router is bound to"
        );
    }
}

/// A bind to the unspecified address names no interface, so the operator's own
/// address is not in the config and cannot be compared against. Any IP literal
/// is admitted there; every *name* is still refused, which is the half that
/// stops rebinding — the attack needs a name the browser will call same-origin.
#[tokio::test]
async fn an_unspecified_bind_admits_a_literal_and_still_refuses_a_name() {
    let dir = state_dir();
    let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    for host in ["192.168.1.40:7777", "10.0.0.5", "[::1]:7777"] {
        let (router, token) = lan_router(dir.path(), unspecified);
        assert_eq!(
            status_of(router, bearer("/api/runs", host, &token)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "{host} is an IP literal, which is the only thing an unspecified bind can accept"
        );
    }

    for host in ["evil.com", "localhost:7777", "nas.local"] {
        let (router, token) = lan_router(dir.path(), unspecified);
        assert_eq!(
            status_of(router, bearer("/api/runs", host, &token)).await,
            StatusCode::FORBIDDEN,
            "{host} is a name, and a name is what a rebinding page controls"
        );
    }
}

/// A bind to an IPv6 address answers to the bracketed form, which is how RFC
/// 3986 §3.2.2 spells one in a `Host` — the bare form's colons are
/// indistinguishable from the port separator, so it is refused.
#[tokio::test]
async fn an_ipv6_bind_answers_to_the_bracketed_form() {
    let dir = state_dir();
    let addr = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));

    let (router, token) = lan_router(dir.path(), addr);
    assert_eq!(
        status_of(router, bearer("/api/runs", "[fd00::1]:7777", &token)).await,
        StatusCode::SERVICE_UNAVAILABLE
    );

    let (router, token) = lan_router(dir.path(), addr);
    assert_eq!(
        status_of(router, bearer("/api/runs", "fd00::1", &token)).await,
        StatusCode::FORBIDDEN,
        "an unbracketed IPv6 address is not a legal Host value"
    );
}

/// The order of the two `/api` layers, pinned because it is a disclosure
/// decision rather than an accident of how `build_router` is written: on a LAN
/// bind, a request that is *both* unauthenticated and wrongly addressed is
/// answered `401`. The gate is outermost, so the caller learns "you need a
/// token" and not "this host is wrong", which is the less useful of the two to
/// someone who has neither.
#[tokio::test]
async fn the_token_gate_answers_before_the_host_check() {
    let dir = state_dir();
    let (router, _) = lan_router(dir.path(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)));

    assert_eq!(
        status_of(router, with_host("/api/runs", "evil.com")).await,
        StatusCode::UNAUTHORIZED
    );
}
