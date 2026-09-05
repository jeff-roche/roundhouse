//! Real `Isolate` implementation over Task 16's real probe results.
//!
//! §6.5 rule 2: `prepare()` errors (never warns) when the achieved tier is below what
//! was requested. §6.5 rule 4: `attest()` is written on every task row, not once per
//! session, because the achieved tier can change mid-session.
use crate::probe::MechanismProbeReport;
use crate::{Attestation, Child, CommandSpec, Handle, Isolate, IsolationError};
use dashmap::DashMap;
use roundhouse_core::{net_enforced_for, NetworkMechanism, OnDegrade, SessionSpec, Tier};
use std::path::PathBuf;
use std::sync::Mutex;

pub(crate) struct HandleMeta {
    pub tier: Tier,
    pub bwrap_pid: Option<u32>,
    /// `true` only if bwrap's own `--info-fd` mechanism confirmed namespace/mount
    /// setup actually completed for this handle's spawned process (fix-round-2
    /// security-review finding: `bwrap_pid.is_some()` alone only proves fork/exec of
    /// the bwrap binary succeeded, not that its `unshare(2)` calls did — see
    /// `bwrap::spawn_under_bwrap`'s doc comment for the full rationale). `attest()`
    /// keys `net_enforced` off this, not `bwrap_pid.is_some()`.
    pub bwrap_namespace_confirmed: bool,
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
    ///  - **Landlock: real, as of Task 27 (lane W5, ruling W5-9).** When
    ///    `self.probe_report.landlock` is `Available`, `spawn()` rewrites the
    ///    spawned command so bwrap execs `round-landlock-exec` instead of the real
    ///    program (`landlock_wrap::wrap_for_landlock`); that binary applies the real
    ///    ruleset — via the safe `RulesetCreated::restrict_self()` — *after* bwrap's
    ///    own namespace/mount setup already exists, then `exec()`s the real program.
    ///    See `landlock_wrap`'s module doc comment for why this pre-exec-wrapper
    ///    shape was needed (bwrap has no native Landlock flag, unlike its native
    ///    `--seccomp FD`) and for the empirically-verified reason the more obvious
    ///    `pre_exec`-on-bwrap approach is a dead end. This is independent of which
    ///    OR-branch reached `Tier::Sandbox`, the same as seccomp above: it applies
    ///    whenever the probe says Landlock is `Available`, regardless of whether
    ///    Seatbelt or seccomp is what actually got a given host to `Sandbox` tier.
    ///    The OR-logic itself is unchanged: the regression test
    ///    `seatbelt_alone_achieves_sandbox_tier_on_a_landlock_less_host` still
    ///    depends on it (audit finding 11), and narrowing it is out of this task's
    ///    scope.
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
    /// host's seccomp probe reported `Available` — `Ok(None)` on hosts where seccomp
    /// isn't real (not Linux, or the probe reported `Degraded`/`Unavailable`), so
    /// `spawn_under_bwrap` is never asked to pass a filter that was never actually
    /// verified. See `probe::compile_baseline_seccomp_bpf`'s doc comment for what the
    /// compiled filter actually restricts.
    ///
    /// Fix-round-2 bug fix: this used to discard a compile failure with `.ok()`,
    /// which meant that if compilation ever failed (e.g. an unsupported target arch,
    /// or any other real failure), `spawn()` would proceed with **no filter applied
    /// at all** while the probe still reported seccomp `Available` and `attest()`
    /// still claimed `Tier::Sandbox` as if the filter had actually been built —
    /// exactly the "fail-open hides" pattern this whole module exists to prevent,
    /// newly introduced by fix-round-1's own fix for that same pattern. Now returns
    /// `Result` and propagates the failure as a real `IsolationError` so `spawn()`
    /// fails closed instead of silently spawning under a weaker-than-attested tier.
    #[cfg(target_os = "linux")]
    fn seccomp_bpf_for_spawn(&self) -> Result<Option<Vec<u8>>, IsolationError> {
        use crate::probe::MechanismStatus;
        if matches!(self.probe_report.seccomp, MechanismStatus::Available) {
            crate::probe::compile_baseline_seccomp_bpf()
                .map(Some)
                .map_err(|e| {
                    IsolationError::Unsupported(format!(
                        "seccomp probed Available but compiling the real enforcement filter \
                         failed ({e}) — refusing to spawn with Tier::Sandbox attested but no \
                         seccomp filter actually applied"
                    ))
                })
        } else {
            Ok(None)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn seccomp_bpf_for_spawn(&self) -> Result<Option<Vec<u8>>, IsolationError> {
        Ok(None)
    }

    /// Task 27 (lane W5, ruling W5-9): when `self.probe_report.landlock` is
    /// `Available` (Linux-only in practice — see `probe::probe_landlock`), rewrites
    /// `cmd` so bwrap execs `round-landlock-exec` instead of the real program,
    /// applying a real Landlock ruleset to the process bwrap actually execs. See
    /// `landlock_wrap`'s module doc comment for the full mechanism and why this
    /// pre-exec-wrapper shape is needed instead of `pre_exec` on bwrap itself.
    ///
    /// Fails closed, mirroring `seccomp_bpf_for_spawn` above: if the probe reported
    /// Landlock `Available` but the wrapper binary cannot be located, this returns
    /// `Err` rather than silently spawning the real program directly — a `Tier::
    /// Sandbox` attestation reached via Landlock's OR-branch must not silently
    /// degrade to "bwrap namespace isolation only" without the caller finding out.
    fn wrap_for_landlock_if_available(
        &self,
        cmd: CommandSpec,
        workspace_root: &std::path::Path,
    ) -> Result<CommandSpec, IsolationError> {
        if matches!(
            self.probe_report.landlock,
            crate::probe::MechanismStatus::Available
        ) {
            let wrapper = crate::landlock_wrap::wrapper_binary_path()?;
            Ok(crate::landlock_wrap::wrap_for_landlock(
                cmd,
                workspace_root,
                &wrapper,
            ))
        } else {
            Ok(cmd)
        }
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
                bwrap_namespace_confirmed: false,
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
        let seccomp_bpf = self.seccomp_bpf_for_spawn()?;
        let cmd = self.wrap_for_landlock_if_available(cmd, &workspace_root)?;
        let (child, live_handle, namespace_confirmed) =
            crate::bwrap::spawn_under_bwrap(&self.bwrap_path, &workspace_root, cmd, seccomp_bpf)
                .await?;
        if let Some(mut meta) = self.handles.get_mut(&h.id) {
            meta.bwrap_pid = Some(child.pid);
            meta.bwrap_namespace_confirmed = namespace_confirmed;
            meta.child_handle = Some(live_handle); // keeps tokio able to reap the process
        }
        Ok(child)
    }

    /// Written on every task row, not once per session — tiers can change mid-session
    /// (§6.5 rule 4).
    ///
    /// **Read this before trusting `Attestation.tier == Sandbox` as a complete
    /// security boundary:** as of Task 27 (lane W5, ruling W5-9), bwrap, seccomp
    /// (when the probe reported `Available`), Seatbelt, and Landlock (when the
    /// probe reported `Available`) are all genuinely enforced on the real spawned
    /// child. A `Tier::Sandbox` attestation reached via `achieved_tier()`'s OR
    /// because Landlock probed `Available` — rather than because Seatbelt or
    /// seccomp did — really is bwrap namespace isolation plus a real,
    /// kernel-confirmed Landlock ruleset restricting the spawned child to
    /// `ReadFile`+`Execute` on the system directories and read/write on the
    /// workspace root, applied via `round-landlock-exec` (`landlock_wrap`'s module
    /// doc comment has the full mechanism and why it's a pre-exec wrapper binary
    /// rather than `pre_exec` on bwrap itself). See `achieved_tier()`'s doc
    /// comment for the full per-mechanism breakdown.
    fn attest(&self, h: &Handle) -> Attestation {
        // Mutable borrow (not just `get`): fix-round-2 security-review finding —
        // attestation must reflect whether the sandboxed child is *still actually
        // running* at the moment this specific `attest()` call happens, not just
        // whatever was true when `spawn()` returned. A task row written after the
        // child has already exited (on its own, not via `teardown()`, which would
        // have removed this handle from `self.handles` entirely) must not keep
        // claiming live network enforcement that no longer exists. `try_wait()` is a
        // cheap, non-blocking, synchronous liveness check — `Ok(None)` means still
        // running, anything else (exited, or no live handle to check at all) means
        // there is nothing left to attest enforcement for.
        let mut meta = self.handles.get_mut(&h.id);
        let (tier, bwrap_pid, bwrap_namespace_confirmed, still_running) =
            if let Some(m) = meta.as_mut() {
                let still_running = match m.child_handle.as_mut() {
                    Some(child) => matches!(child.try_wait(), Ok(None)),
                    None => false, // never spawned (prepare()-only handle) — nothing to be running
                };
                (
                    m.tier,
                    m.bwrap_pid,
                    m.bwrap_namespace_confirmed,
                    still_running,
                )
            } else {
                (Tier::None, None, false, false)
            };
        drop(meta); // release the DashMap shard lock before the rest of this synchronous call

        let digest = blake3::hash(format!("{}:{tier:?}:{bwrap_pid:?}", h.id).as_bytes())
            .to_hex()
            .to_string();

        // §6.6's honesty table, driven by which mechanism actually achieved THIS
        // HANDLE's network posture — not by `Tier` alone. `tier` is set once at
        // `prepare()` time and reflects the *probed capability* of the host, not
        // whether bwrap has actually run for this handle: a handle that was
        // `prepare()`d but never `spawn()`ed, or whose `spawn()` failed (missing
        // bwrap binary etc.), still carries `Tier::Sandbox` with `bwrap_pid: None`.
        // Security-review finding (fix-round-1): mapping tier alone to a mechanism
        // made `net_enforced` definitionally identical to the old
        // `matches!(tier, Sandbox | Container | Remote)` line for exactly that
        // reason — a rename, not an honesty fix.
        //
        // Security-review finding (fix-round-2): gating on bare `bwrap_pid.is_some()`
        // only proved a fork/exec succeeded, not that bwrap's own namespace setup
        // did — a bwrap process that starts and immediately fails with "Creating new
        // namespace failed: Operation not permitted" still set `bwrap_pid` before
        // dying. Gate on `bwrap_namespace_confirmed` instead — set only when
        // `bwrap::spawn_under_bwrap`'s `--info-fd` wiring got a real confirmation
        // that setup completed (see that function's doc comment) — and additionally
        // on `still_running`, so a since-exited child no longer attests to
        // enforcement it no longer provides. `Container`/`Remote` are unreachable in
        // this implementation today (no netns/remote executor exists yet), so their
        // mapping is moot for now and left as `Netns`/true per the doc table.
        let mechanism = match tier {
            Tier::Sandbox if bwrap_namespace_confirmed && still_running => {
                NetworkMechanism::Bubblewrap
            }
            Tier::Sandbox => NetworkMechanism::None, // never spawned, spawn failed, or since exited
            Tier::Container | Tier::Remote => NetworkMechanism::Netns, // unreachable today, forward-safe
            Tier::None | Tier::Worktree => NetworkMechanism::None,
        };

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
            net_enforced: net_enforced_for(mechanism),
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
