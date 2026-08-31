use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_net::policy::EgressPolicy;
use roundhouse_core::SessionId;
use std::net::SocketAddr;

fn main() {
    // must fail: even a legitimately registered ProxyHandle's `addr` field
    // cannot be reassigned from outside `roundhouse-net` — a session must not be
    // able to redirect its own handle at an arbitrary address after registering
    // with a real (possibly deny-all) policy.
    let proxy = LoopbackProxy::new();
    let policy = EgressPolicy { allowed_hosts: vec![] };
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let mut handle = proxy.register_session(SessionId::new(), policy, addr);
    let rogue: SocketAddr = "127.0.0.1:2".parse().unwrap();
    handle.addr = rogue;
}
