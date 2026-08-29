use roundhouse_core::Tier;
use roundhouse_sandbox::{Attestation, CommandSpec, Handle, Isolate, IsolationError, ProbeResult};
use std::sync::Arc;

struct NoopIsolate;

#[async_trait::async_trait]
impl Isolate for NoopIsolate {
    fn declared(&self) -> Tier {
        Tier::None
    }

    async fn probe(&self) -> ProbeResult {
        ProbeResult {
            achieved: Tier::None,
            degradations: vec![],
        }
    }

    async fn prepare(
        &self,
        _spec: &roundhouse_core::SessionSpec,
    ) -> Result<Handle, IsolationError> {
        Ok(Handle { id: "noop".into() })
    }

    async fn spawn(
        &self,
        _h: &Handle,
        _cmd: CommandSpec,
    ) -> Result<roundhouse_sandbox::Child, IsolationError> {
        Err(IsolationError::Unsupported(
            "NoopIsolate never actually spawns".into(),
        ))
    }

    fn attest(&self, h: &Handle) -> Attestation {
        Attestation {
            tier: Tier::None,
            digest: format!("noop:{}", h.id),
            net_enforced: false,
        }
    }

    async fn teardown(&self, _h: Handle) -> Result<(), IsolationError> {
        Ok(())
    }
}

#[tokio::test]
async fn isolate_trait_is_object_safe_and_declares_a_tier() {
    let isolate: Arc<dyn Isolate> = Arc::new(NoopIsolate);
    assert_eq!(isolate.declared(), Tier::None);
    let probe = isolate.probe().await;
    assert_eq!(probe.achieved, Tier::None);
}

#[test]
fn tier_ordering_matches_spec_ascending_strength() {
    assert!(Tier::None < Tier::Worktree);
    assert!(Tier::Worktree < Tier::Sandbox);
    assert!(Tier::Sandbox < Tier::Container);
    assert!(Tier::Container < Tier::Remote);
}
