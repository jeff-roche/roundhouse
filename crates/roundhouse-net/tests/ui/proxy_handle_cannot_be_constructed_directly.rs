use roundhouse_net::ProxyHandle;
use std::net::SocketAddr;

fn main() {
    // must fail: ProxyHandle's fields are private, so an external crate cannot
    // forge one pointing at an arbitrary address — the only real constructor is
    // `LoopbackProxy::register_session`, in the same crate.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _handle = ProxyHandle {
        token: "forged".to_string(),
        addr,
    };
}
