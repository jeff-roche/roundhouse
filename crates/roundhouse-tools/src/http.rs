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

use roundhouse_net::ProxyHandle;

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
        let proxy_url = format!("http://{}", handle.addr);
        let auth_header = format!("Bearer {}", handle.token);
        let proxy = reqwest::Proxy::all(&proxy_url)
            .expect("proxy URL is always well-formed — built from a real SocketAddr")
            .custom_http_auth(
                reqwest::header::HeaderValue::from_str(&auth_header)
                    .expect("a session bearer token is always a valid header value"),
            );
        let client = reqwest::Client::builder()
            .proxy(proxy)
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
