//! Real `Isolate` implementation over Task 16's real probe results.
//!
//! §6.5 rule 2: `prepare()` errors (never warns) when the achieved tier is below what
//! was requested. §6.5 rule 4: `attest()` is written on every task row, not once per
//! session, because the achieved tier can change mid-session.
use crate::probe::{MechanismProbeReport, MechanismStatus};
use crate::{Attestation, Child, CommandSpec, Handle, Isolate, IsolationError};
use dashmap::DashMap;
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) struct HandleMeta {
    pub tier: Tier,
    pub bwrap_pid: Option<u32>,
    pub workspace_root: PathBuf,
    /// Kept alive here (not dropped) so tokio can still reap the process; a bare `pid:
    /// u32` on the frozen `Child` type has nowhere else for the live handle to live.
    pub child_handle: Option<tokio::process::Child>,
}

pub struct BwrapLandlockIsolate {
    probe_report: MechanismProbeReport,
    bwrap_path: PathBuf,
    handles: DashMap<String, HandleMeta>,
    last_shortfall: Mutex<Option<(Tier, Tier)>>,
}

impl BwrapLandlockIsolate {
    pub fn test_with_probe(probe_report: MechanismProbeReport) -> Self {
        Self {
            probe_report,
            bwrap_path: PathBuf::from("/usr/libexec/roundhouse/bwrap"),
            handles: DashMap::new(),
            last_shortfall: Mutex::new(None),
        }
    }

    /// §6.5's macOS Sandbox tier is Seatbelt + bwrap, not Landlock + bwrap — consulting
    /// only Landlock (as an earlier draft did) made Sandbox tier structurally
    /// unreachable on macOS even when Seatbelt probed Available (audit finding 11).
    fn achieved_tier(&self) -> Tier {
        let bwrap_ok = matches!(self.probe_report.bwrap, MechanismStatus::Available);
        let landlock_ok = matches!(self.probe_report.landlock, MechanismStatus::Available);
        let seatbelt_ok = matches!(self.probe_report.seatbelt, MechanismStatus::Available);
        if bwrap_ok && (landlock_ok || seatbelt_ok) {
            Tier::Sandbox
        } else if bwrap_ok || landlock_ok || seatbelt_ok {
            Tier::Worktree
        } else {
            Tier::None
        }
    }

    /// The frozen `IsolationError::DegradedBelowRequested` carries no fields, so the
    /// specific (achieved, requested) pair a caller needs to log as a `Degradation`
    /// event lives here instead — read immediately after a `prepare()` call errors.
    pub fn last_shortfall(&self) -> Option<(Tier, Tier)> {
        *self.last_shortfall.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl Isolate for BwrapLandlockIsolate {
    fn declared(&self) -> Tier {
        Tier::Sandbox
    }

    async fn probe(&self) -> crate::ProbeResult {
        crate::probe::probe_cached(&std::env::temp_dir())
            .await
            .to_probe_result()
    }

    /// §6.5 rule 2: errors, does not warn, when achieved < requested. The session does
    /// not start; only an explicit SessionSpec.on_degrade = AllowDownTo(Tier) — set by
    /// the human at creation and recorded — permits continuing at a lower tier.
    async fn prepare(&self, spec: &SessionSpec) -> Result<Handle, IsolationError> {
        let achieved = self.achieved_tier();
        let requested = spec.requested_tier;
        if achieved < requested {
            *self.last_shortfall.lock().unwrap() = Some((achieved, requested));
            match spec.on_degrade {
                OnDegrade::Refuse => return Err(IsolationError::DegradedBelowRequested),
                OnDegrade::AllowDownTo(floor) if achieved >= floor => {
                    // recorded Degradation event is appended by the caller (session
                    // actor), which has the Store handle; this trait stays I/O-minimal.
                }
                OnDegrade::AllowDownTo(_) => return Err(IsolationError::DegradedBelowRequested),
            }
        }
        let tier = achieved.min(requested);
        let id = format!("bwrap:{}", uuid::Uuid::new_v4());
        self.handles.insert(
            id.clone(),
            HandleMeta {
                tier,
                bwrap_pid: None,
                workspace_root: PathBuf::from(spec.workspace.to_string()),
                child_handle: None,
            },
        );
        Ok(Handle { id })
    }

    async fn spawn(&self, h: &Handle, cmd: CommandSpec) -> Result<Child, IsolationError> {
        let workspace_root = self
            .handles
            .get(&h.id)
            .ok_or_else(|| IsolationError::Unsupported(format!("unknown handle {}", h.id)))?
            .workspace_root
            .clone();
        let (child, live_handle) =
            crate::bwrap::spawn_under_bwrap(&self.bwrap_path, &workspace_root, cmd).await?;
        if let Some(mut meta) = self.handles.get_mut(&h.id) {
            meta.bwrap_pid = Some(child.pid);
            meta.child_handle = Some(live_handle); // keeps tokio able to reap the process
        }
        Ok(child)
    }

    /// Written on every task row, not once per session — tiers can change mid-session
    /// (§6.5 rule 4).
    fn attest(&self, h: &Handle) -> Attestation {
        let meta = self.handles.get(&h.id);
        let (tier, bwrap_pid) = meta
            .map(|m| (m.tier, m.bwrap_pid))
            .unwrap_or((Tier::None, None));
        let digest = blake3::hash(format!("{}:{tier:?}:{bwrap_pid:?}", h.id).as_bytes())
            .to_hex()
            .to_string();
        Attestation {
            tier,
            digest,
            net_enforced: matches!(tier, Tier::Sandbox | Tier::Container | Tier::Remote),
        }
    }

    async fn teardown(&self, h: Handle) -> Result<(), IsolationError> {
        self.handles.remove(&h.id);
        Ok(())
    }
}
