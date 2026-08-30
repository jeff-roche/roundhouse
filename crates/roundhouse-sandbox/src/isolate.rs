//! Real `Isolate` implementation over Task 16's real probe results.
//!
//! §6.5 rule 2: `prepare()` errors (never warns) when the achieved tier is below what
//! was requested. §6.5 rule 4: `attest()` is written on every task row, not once per
//! session, because the achieved tier can change mid-session.
use crate::probe::MechanismProbeReport;
use crate::{Attestation, Child, CommandSpec, Handle, Isolate, IsolationError};
use dashmap::DashMap;
use roundhouse_core::{OnDegrade, SessionSpec, Tier};
use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) struct HandleMeta {
    pub tier: Tier,
    pub bwrap_pid: Option<u32>,
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

    /// Test-only: like `test_with_probe`, but with a caller-supplied `bwrap_path` —
    /// needed by fix-round-1's `spawn()`/`teardown()` regression tests, which spawn a
    /// real process under the real `bwrap` binary on `$PATH` rather than the
    /// production install path baked into `test_with_probe`.
    pub fn test_with_probe_and_bwrap_path(
        probe_report: MechanismProbeReport,
        bwrap_path: PathBuf,
    ) -> Self {
        Self {
            probe_report,
            bwrap_path,
            handles: DashMap::new(),
            last_shortfall: Mutex::new(None),
        }
    }

    /// §6.5's macOS Sandbox tier is Seatbelt + bwrap, not Landlock + bwrap — consulting
    /// only Landlock (as an earlier draft did) made Sandbox tier structurally
    /// unreachable on macOS even when Seatbelt probed Available (audit finding 11).
    ///
    /// Fix-round-1 finding 4: this used to duplicate `MechanismProbeReport::
    /// to_probe_result()`'s tier-fold with its own (correct, 3-way) logic, while
    /// `to_probe_result()` itself (in `probe.rs`) only considered `(landlock, bwrap)`
    /// — so `probe()` and `prepare()` could disagree about the achieved tier on a
    /// Seatbelt-only host. Now delegates to `to_probe_result()` so the two
    /// structurally cannot disagree again; `to_probe_result()` carries the real
    /// 3-way `bwrap && (landlock || seatbelt)` logic as the single source of truth.
    ///
    /// **What "Sandbox tier" actually enforces today, per mechanism (fix-round-1
    /// finding 1 — read this before trusting an `Attestation.tier == Sandbox` as a
    /// complete security boundary):**
    /// - bwrap: real — every spawned child actually runs under a real bwrap
    ///   namespace sandbox (`bwrap.rs::spawn_under_bwrap`).
    /// - seccomp: real, as of fix-round-1 — when `self.probe_report.seccomp` is
    ///   `Available`, `spawn()` compiles a real filter
    ///   (`probe::compile_baseline_seccomp_bpf`) and passes it to bwrap's native
    ///   `--seccomp FD`, genuinely applied to the spawned child (see that function's
    ///   doc comment for exactly what it restricts and why).
    ///  - Seatbelt: real — `MechanismStatus::Available` for Seatbelt already means
    ///    `sandbox-exec` was actually run and its enforcement actually observed
    ///    (`probe.rs`'s Seatbelt probe).
    ///  - **Landlock: PROBED-availability only, not yet applied to the real spawned
    ///    child.** `restrict_self()` today runs only inside `probe.rs`'s throwaway
    ///    forked probe child, never on the process bwrap actually execs. So a session
    ///    that reaches `Tier::Sandbox` via this OR's Landlock branch (rather than via
    ///    Seatbelt, or via the now-real seccomp path) is running under bwrap alone
    ///    plus whatever real seccomp filter was applied — Landlock contributes
    ///    nothing real yet, despite the probe reporting it `Available`. Real
    ///    per-process Landlock enforcement on a bwrap-spawned child needs a pre-exec
    ///    wrapper mechanism (bwrap has no native Landlock flag, unlike its native
    ///    `--seccomp FD`) — this is a tracked, hard-prerequisite follow-up, not yet
    ///    built. The OR-logic itself is intentionally unchanged this round: the
    ///    regression test `seatbelt_alone_achieves_sandbox_tier_on_a_landlock_less_host`
    ///    depends on it (audit finding 11), and narrowing it to exclude the
    ///    not-yet-real Landlock branch would make Linux hosts without a real
    ///    Landlock-enforcement path unable to reach `Sandbox` tier via seccomp alone,
    ///    which is not this round's fix.
    fn achieved_tier(&self) -> Tier {
        self.probe_report.to_probe_result().achieved
    }

    /// The frozen `IsolationError::DegradedBelowRequested` carries no fields, so the
    /// specific (achieved, requested) pair a caller needs to log as a `Degradation`
    /// event lives here instead — read immediately after a `prepare()` call errors.
    pub fn last_shortfall(&self) -> Option<(Tier, Tier)> {
        *self.last_shortfall.lock().unwrap()
    }

    /// Compiles the real seccomp-BPF program to apply on the real spawn path when the
    /// host's seccomp probe reported `Available` — `None` on hosts where seccomp
    /// isn't real (not Linux, or the probe reported `Degraded`/`Unavailable`), so
    /// `spawn_under_bwrap` is never asked to pass a filter that was never actually
    /// verified. See `probe::compile_baseline_seccomp_bpf`'s doc comment for what the
    /// compiled filter actually restricts.
    #[cfg(target_os = "linux")]
    fn seccomp_bpf_for_spawn(&self) -> Option<Vec<u8>> {
        use crate::probe::MechanismStatus;
        if matches!(self.probe_report.seccomp, MechanismStatus::Available) {
            crate::probe::compile_baseline_seccomp_bpf().ok()
        } else {
            None
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn seccomp_bpf_for_spawn(&self) -> Option<Vec<u8>> {
        None
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
                child_handle: None,
            },
        );
        Ok(Handle { id })
    }

    /// Fix-round-1 finding 2: `workspace_root` used to be derived from `spec.workspace`
    /// (a bare `WorkspaceId` UUID with no path-resolution mechanism anywhere in this
    /// codebase) at `prepare()` time, so real invocations passed `--bind <uuid>
    /// <uuid>` to bwrap, which fails immediately ("Can't find source path") —
    /// reproduced against real bwrap 0.12.0. There is still no `WorkspaceId` → real
    /// path resolver anywhere in this workspace (confirmed: grepping for one turns up
    /// nothing), so this now uses `cmd.cwd` — the real, caller-supplied working
    /// directory, actually available at `spawn()` time rather than `prepare()` time —
    /// and refuses up front if it's absent, rather than silently proceeding with
    /// something meaningless.
    async fn spawn(&self, h: &Handle, cmd: CommandSpec) -> Result<Child, IsolationError> {
        if !self.handles.contains_key(&h.id) {
            return Err(IsolationError::Unsupported(format!(
                "unknown handle {}",
                h.id
            )));
        }
        let workspace_root = cmd.cwd.clone().map(PathBuf::from).ok_or_else(|| {
            IsolationError::Unsupported(
                "spawn requires a real working directory to sandbox into".into(),
            )
        })?;
        let seccomp_bpf = self.seccomp_bpf_for_spawn();
        let (child, live_handle) =
            crate::bwrap::spawn_under_bwrap(&self.bwrap_path, &workspace_root, cmd, seccomp_bpf)
                .await?;
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
            // Aspirational pending the real network-policy work (§6.6): `--unshare-all`
            // today fully cuts network for every tier's spawned child (see the comment
            // on `--unshare-all` in `bwrap.rs::spawn_under_bwrap`), which happens to
            // make this `true` non-misleading in practice right now (no network reaches
            // the sandbox at all), but it is not backed by the bound loopback-proxy
            // enforcement §6.6 actually calls for — do not read this field as "a real
            // proxy is enforcing policy," only as "network is currently fully cut."
            net_enforced: matches!(tier, Tier::Sandbox | Tier::Container | Tier::Remote),
        }
    }

    /// Fix-round-1 finding 3: this used to just `self.handles.remove(&h.id)`, dropping
    /// `HandleMeta` (and the `tokio::process::Child` inside it) without killing
    /// anything — tokio's `Child` has `kill_on_drop = false` by default, so the
    /// sandboxed process stayed alive after "teardown" (reproduced: still running
    /// 800ms later). Now actually kills the live child, if there is one, before
    /// dropping the bookkeeping.
    async fn teardown(&self, h: Handle) -> Result<(), IsolationError> {
        if let Some((_, mut meta)) = self.handles.remove(&h.id) {
            if let Some(mut child) = meta.child_handle.take() {
                // Best-effort: `start_kill()` errors only if the process has already
                // exited (nothing left to kill, not a real failure) — ignored
                // deliberately. `wait()` afterward reaps it so tokio doesn't leave a
                // zombie behind.
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
        Ok(())
    }
}
