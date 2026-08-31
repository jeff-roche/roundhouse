//! The `http` task executor (Task 24, closing G1's "every task attests to
//! `net_enforced` but nothing enforces it" finding).
//!
//! [`HttpTaskExecutor`] has **no public constructor other than
//! [`HttpTaskExecutor::via_proxy`]**, which requires a real
//! `roundhouse_net::ProxyHandle` — the same type-level guarantee Task 18 gives
//! `ControlLaneToken`. There is no code path in this type that can reach the network
//! directly, bypassing Task 23's `LoopbackProxy` allowlist and metadata-IP hard-deny:
//! every request this executor sends is tunnelled through the proxy, authenticated
//! with the session's bearer token.

use std::time::Duration;

use roundhouse_net::ProxyHandle;

/// How long to wait for the CONNECT tunnel handshake through the loopback proxy
/// before giving up. Matches `roundhouse-provider`'s `reqwest_transport.rs`
/// `CONNECT_TIMEOUT` (generous enough for a cold TLS handshake over a slow link,
/// short enough that an unroutable/blackholed host fails the task instead of
/// hanging it indefinitely — security-review finding, fix-round-1: a request to a
/// blackholed allowlisted host previously hung 30+ seconds with no configured
/// timeout at all).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read inactivity timeout, same rationale and value as
/// `roundhouse-provider`'s `reqwest_transport.rs` `READ_TIMEOUT`: resets on every
/// chunk received, so a slow-but-real response is never cut off, while a peer
/// that accepts and then goes silent is.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// An `http` task executor that can only ever route through
/// [`roundhouse_net::LoopbackProxy`] — see the module docs for why that's a
/// structural, not just conventional, guarantee.
pub struct HttpTaskExecutor {
    client: reqwest::Client,
}

impl HttpTaskExecutor {
    /// The only way to construct an `HttpTaskExecutor`. Requires a real
    /// [`ProxyHandle`] (minted only by `LoopbackProxy::register_session`), so an
    /// `http` task cannot be executed without going through the loopback proxy.
    pub fn via_proxy(handle: &ProxyHandle) -> Self {
        let proxy_url = format!("http://{}", handle.addr());
        let auth_header = format!("Bearer {}", handle.token());
        let proxy = reqwest::Proxy::all(&proxy_url)
            .expect("proxy URL is always well-formed — built from a real SocketAddr")
            .custom_http_auth(
                reqwest::header::HeaderValue::from_str(&auth_header)
                    // Genuinely unreachable, not just unlikely: `ProxyHandle`'s only
                    // constructor is `LoopbackProxy::register_session` (fix-round-1
                    // made its fields private, see `roundhouse-net`'s
                    // `tests/compile_fail.rs`), which always mints the token as
                    // `format!("rh-{}", Uuid::new_v4())` — never attacker-influenced,
                    // never containing CRLF or other invalid header bytes.
                    .expect("a session bearer token is always a valid header value"),
            );
        let client = reqwest::Client::builder()
            .proxy(proxy)
            // Security-review finding (fix-round-1): explicit, not left to
            // reqwest's default — a second, silently-inconsistent
            // `reqwest::Client` construction site (see `reqwest_transport.rs`'s
            // module doc on being "the one place... allowed to construct a
            // `reqwest::Client`" for provider adapters; this is a deliberately
            // separate one for the `http` task domain, but it must not drift on
            // the safety-relevant settings).
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .expect("client construction with a single proxy never fails");
        Self { client }
    }

    /// `http` tasks execute through the same proxy and policy as shell-initiated
    /// traffic (§6.6), so they share one audit stream and get URL-level rules for
    /// free.
    pub async fn execute(&self, url: &str) -> Result<reqwest::Response, reqwest::Error> {
        self.client.get(url).send().await
    }
}
