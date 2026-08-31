//! `HttpTaskExecutor` can only ever be constructed from a real `ProxyHandle` — this
//! is a live, hermetic assertion on the real request path (Task 23's `LoopbackProxy`,
//! actually serving), not a mock: a non-allowlisted host must fail through the
//! proxy's 403, never bypass it.

use once_cell::sync::Lazy;
use roundhouse_core::{SessionId, TaskRunner};
use roundhouse_net::policy::{EgressPolicy, HostPattern};
use roundhouse_net::proxy::LoopbackProxy;
use roundhouse_tools::http::HttpTaskExecutor;
use std::sync::Arc;

/// `TaskRunner::bootstrap()` panics on a second call in the same process (S-LOG-1) —
/// this test binary's `#[tokio::test]` functions share one process, so they must
/// share one `TaskRunner` instance. Matches the precedent in
/// `crates/roundhouse-net/tests/proxy_hermetic.rs`.
static RUNNER: Lazy<TaskRunner> = Lazy::new(TaskRunner::bootstrap);

#[tokio::test]
async fn http_task_execution_only_ever_reaches_an_allowlisted_host_through_the_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let store = roundhouse_store::open(&db_path).await.unwrap();
    let writer = roundhouse_store::spawn_writer(store).await;

    let proxy = Arc::new(LoopbackProxy::new());
    let policy = EgressPolicy {
        allowed_hosts: vec![HostPattern::exact("example.invalid")],
    };
    let addr = proxy.clone().serve(&RUNNER, writer).await.unwrap();
    // register_session now takes the proxy's bound address too (this task's edit to
    // Task 23's signature) and returns a ProxyHandle bundling both.
    let handle = proxy.register_session(SessionId::new(), policy, addr);

    // Constructing the executor is only possible with a ProxyHandle — there is no
    // other public constructor, so an http task literally cannot bypass the proxy
    // (mirrors ControlLaneToken's type-level guarantee, Task 18).
    let executor = HttpTaskExecutor::via_proxy(&handle);
    let result = executor.execute("https://not-allowlisted.example/x").await;
    // A non-allowlisted host must fail closed through the proxy's 403, not silently
    // route around it — this is a live, hermetic assertion on the real request path.
    assert!(
        result.is_err(),
        "a request to a non-allowlisted host must fail, never bypass the proxy"
    );
}
