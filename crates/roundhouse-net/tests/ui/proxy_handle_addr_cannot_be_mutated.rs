use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_net::policy::EgressPolicy;
use roundhouse_core::SessionId;
use std::net::SocketAddr;

fn main() {
    // must fail: even a legitimately registered ProxyHandle's `addr` field
    // cannot be reassigned from outside `roundhouse-net` — a session must not be
    // able to redirect its own handle at an arbitrary address after registering
    // with a real (possibly deny-all) policy. `register_session` (fix-round-2) no
    // longer takes a caller-supplied `addr` at all — it reads the proxy's own bound
    // address — but this case is purely a compile-time check of field privacy, so
    // the `.unwrap()` on `register_session`'s `Result` (which would be `Err` at
    // runtime, since this proxy is never `serve()`d) is never actually executed;
    // trybuild only needs this to fail to *compile*, on the line below.
    let proxy = LoopbackProxy::new();
    let policy = EgressPolicy { allowed_hosts: vec![] };
    let mut handle = proxy.register_session(SessionId::new(), policy).unwrap();
    let rogue: SocketAddr = "127.0.0.1:2".parse().unwrap();
    handle.addr = rogue;
}
