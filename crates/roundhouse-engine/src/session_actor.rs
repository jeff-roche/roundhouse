//! Cooperative cancellation (Phase 2, Task 3): a `SessionActor` tracks one
//! session's `SessionState` and, via an allowlist, refuses admission of new,
//! non-`finally:` tasks once that session has left `Created`/`Running`
//! (i.e. `Suspended`, `Cancelling`, or `Closed`).
//!
//! **Scope note — read before wiring this in anywhere:** this is a correct,
//! fully unit-tested, standalone unit, *not* wired into any real dispatch
//! chokepoint. As of this task, `roundhouse-engine` has no unified
//! task-execution entry point — the only real driver is
//! [`crate::run_chat_turn`] in `chat.rs`, and tool executors are invoked ad
//! hoc from `roundhouse-daemon`'s demo wiring with no policy/sandbox gate in
//! front of the real executors yet. Threading `admit_task` in front of those
//! real call sites (chat turns, tool calls) is deferred to a later
//! integration task ("Task 25" — "Integration — wire the sealed floor and
//! network policy into the real task-admission path"), which already exists
//! specifically to thread multiple Phase 2 policy/admission mechanisms into
//! real call sites; cancellation admission-refusal fits the same umbrella.
//! Don't assume more integration happened here than did.
//!
//! Phase 2, Task 4 adds [`SessionActor::run_finally_steps`] to this same
//! file (not a separate `cancel.rs` — this module is `SessionActor`'s home).
//! It reuses `admit_task` for real, but same as above, still doesn't reach
//! into a real dispatch chokepoint for *executing* a step — that's injected
//! by the caller, for the same "Task 25 doesn't exist yet" reason.
//!
//! Phase 2, Task 25 is the integration task named throughout this file's
//! comments above: it wires `PolicyEngine::decide_sealed` (via a live
//! [`roundhouse_policy::sealed::SealedContext`] built from this session's
//! own isolation attestation and MCP registry) into `admit_task` as a
//! second gate after the `SessionState` allowlist, adds
//! [`create_session_isolation`] as the real, inline fix for the
//! isolation-shortfall `Degradation`-recording gap, and adds
//! [`create_session_with_egress`] to register a session's egress allowlist
//! with a real `roundhouse_net::proxy::LoopbackProxy` at the same
//! session-creation call site.

use roundhouse_core::{
    CancelReason, NoteLevel, Origin, SessionId, SessionSpec, SessionState, TaskInput, TaskKind,
    TaskRunner, Timestamp,
};
use roundhouse_net::policy::EgressPolicy;
use roundhouse_net::proxy::{LoopbackProxy, ProxyHandle, ProxyNotServingError};
use roundhouse_policy::engine::{Outcome, PolicyEngine, RuleId};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::TaskParams;
use roundhouse_sandbox::{Handle, Isolate, IsolationError};
use roundhouse_store::{EventWriter, StoreError};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// `Timestamp` has no `now()` — read the wall clock ourselves and convert.
/// Matches the identical helper in `chat.rs`/`roundhouse-store/tests/recovery.rs`.
fn now_ts() -> Timestamp {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_nanos() as i64;
    Timestamp::from_unix_nanos(nanos)
}

/// A request to admit a new task for execution, checked against the owning
/// session's current cancellation state by [`SessionActor::admit_task`].
#[derive(Debug, Clone)]
pub struct TaskCreateRequest {
    pub kind: TaskKind,
    pub origin: Origin,
    /// `true` for a workflow/session `finally:` cleanup step. Cooperative
    /// cancellation (§8) must still let these run even while the owning
    /// session is `Cancelling` — that's the entire point of admission
    /// refusal being scoped to *new*, non-cleanup work.
    pub is_finally_step: bool,
    /// Task 25 — the typed, parsed params `PolicyEngine::decide_sealed`
    /// judges this task against. Nothing carried policy-relevant params
    /// before this task; every real caller must now supply the real,
    /// already-parsed `TaskParams` for the task it is asking to admit.
    pub params: TaskParams,
}

#[derive(Debug, thiserror::Error)]
pub enum AdmitError {
    #[error("session is Cancelling; only a trusted finally: step is admitted")]
    SessionCancelling,
    #[error("session is Suspended; only a trusted finally: step is admitted")]
    SessionSuspended,
    #[error("session is Closed; only a trusted finally: step is admitted")]
    SessionClosed,
    /// Task 25: the sealed floor or a configured policy rule denied this
    /// task. `roundhouse_policy::engine::RuleId` — deliberately NOT
    /// `roundhouse_core`'s `RuleId(u64)`, a different type of the same name
    /// (see `roundhouse_policy::engine::RuleId`'s own doc comment).
    #[error("denied by sealed floor or configured policy: {0:?}")]
    Denied(Option<RuleId>),
    /// Task 25: `PolicyEngine::decide_sealed` returned `Outcome::Ask` — this
    /// task requires human approval before it may proceed. No approval
    /// workflow is wired to this call site yet (that's Task 15's
    /// `approval` module, consumed by a later integration); for now this
    /// variant simply refuses admission the same as `Denied`.
    #[error("requires human approval before this task can proceed")]
    RequiresApproval,
}

/// Tracks one session's `SessionState` and gates new-task admission on it.
///
/// Deliberately does not hold a `TaskRunner` field: `TaskRunner` is not
/// `Clone` and is meant to be a single process-wide singleton obtained once
/// via `TaskRunner::bootstrap()`. Wiring a shared `TaskRunner` into every
/// `SessionActor` instance is real production-wiring work left to Task 25;
/// for now `cancel` takes `runner: &TaskRunner` as a parameter, matching the
/// existing convention elsewhere in this codebase (e.g.
/// `recover_interrupted_tasks(store, writer, runner)`).
pub struct SessionActor {
    session_id: SessionId,
    writer: EventWriter,
    state_tx: tokio::sync::watch::Sender<SessionState>,
    /// Task 25 — the shared, process-wide `TaskRunner` this actor mints new
    /// events through for policy/admission-adjacent bookkeeping. `cancel()`'s
    /// existing `runner: &TaskRunner` *parameter* is untouched by this field;
    /// they're separate, deliberately (see `cancel`'s call sites, which keep
    /// passing their own `&TaskRunner` exactly as before).
    runner: &'static TaskRunner,
    policy: Arc<PolicyEngine>,
    /// Mirrors the daemon's `--unsealed` flag (§6.2's one documented sealed-
    /// floor escape), threaded in at construction — never toggled per-task.
    unsealed: bool,
    state_dir: PathBuf,
    daemon_binary: PathBuf,
    /// Populated by the MCP host (Phase 3) as servers complete their
    /// handshake; read here, never written from this module in this task's
    /// scope — Phase 3 is a hard prerequisite for this ever containing
    /// anything real. `ServerId` (`roundhouse_policy`) has no `Hash`
    /// derive, which is why `SealedContext` itself already stores raw
    /// `String` server names rather than `ServerId`.
    mcp_resolved: Arc<RwLock<HashSet<String>>>,
    isolate: Arc<dyn Isolate>,
    handle: Handle,
    session_spec: SessionSpec,
}

impl SessionActor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        writer: EventWriter,
        initial_state: SessionState,
        runner: &'static TaskRunner,
        policy: Arc<PolicyEngine>,
        unsealed: bool,
        state_dir: PathBuf,
        daemon_binary: PathBuf,
        isolate: Arc<dyn Isolate>,
        handle: Handle,
        session_spec: SessionSpec,
    ) -> Self {
        let (state_tx, _rx) = tokio::sync::watch::channel(initial_state);
        SessionActor {
            session_id,
            writer,
            state_tx,
            runner,
            policy,
            unsealed,
            state_dir,
            daemon_binary,
            mcp_resolved: Arc::new(RwLock::new(HashSet::new())),
            isolate,
            handle,
            session_spec,
        }
    }

    /// Builds the live `SealedContext` this session's tasks are judged
    /// against — the exact wiring finding 3's `sealed_tier_shortfall` check
    /// needed and never had before this task: reads the CURRENT isolation
    /// attestation (re-read every call, since §6.5 rule 4 says the achieved
    /// tier can change mid-session) and the MCP registry's currently-
    /// resolved servers, not a snapshot taken once at session start.
    fn sealed_context(&self) -> SealedContext {
        let attestation = self.isolate.attest(&self.handle);
        SealedContext {
            state_dir: self.state_dir.clone(),
            daemon_binary: self.daemon_binary.clone(),
            resolved_mcp_servers: self
                .mcp_resolved
                .read()
                .expect("mcp_resolved lock poisoned")
                .clone(),
            requested_tier: self.session_spec.requested_tier,
            attested_tier: attestation.tier,
        }
    }

    /// The session's current state, as of the last `cancel()` call (or
    /// whatever `initial_state` was constructed with, if none yet).
    pub fn state(&self) -> SessionState {
        self.state_tx.borrow().clone()
    }

    /// A clone-able observer of session-state transitions. Exposed now so a
    /// later task (Task 4's shell cancellation, or Task 25's integration)
    /// can subscribe to cancellation without this task needing to know who
    /// its future consumers are.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<SessionState> {
        self.state_tx.subscribe()
    }

    /// The shared, process-wide `TaskRunner` this actor was constructed
    /// with — exposed so a later caller (e.g. a real task-execution
    /// dispatch chokepoint) can mint further session-scoped events through
    /// the same authority `admit_task`'s own bookkeeping uses, without
    /// needing its own separate `&'static TaskRunner` threaded in.
    pub fn runner(&self) -> &'static TaskRunner {
        self.runner
    }

    /// Flip the in-memory admission gate to `Cancelling`, then mint and
    /// append a `SessionStateChanged { state: Cancelling, .. }` event
    /// through `runner` (the sole authority that may mint session-lifecycle
    /// events — see `roundhouse_core::TaskRunner`'s doc comment).
    ///
    /// **Fail-closed, not fail-open:** the gate (`state_tx`) is flipped
    /// *before* the durable append is even attempted, not after. If the
    /// append below fails (writer task shut down, pool exhaustion, a
    /// non-busy sqlite error surviving the retry loop), `admit_task` is
    /// already refusing new non-finally work by the time this function
    /// returns `Err` — the error still propagates to the caller (so failed
    /// persistence is loud, never silently swallowed), but a persistence
    /// failure can never leave the gate open. The same ordering also closes
    /// a narrower window that existed under the old (fail-open)
    /// append-then-signal ordering: the append is a cross-task channel
    /// round-trip plus a SQLite transaction (with possible busy-retry
    /// backoff) that can take anywhere from microseconds to seconds, during
    /// which a signal-after-append design would have let `admit_task` keep
    /// admitting new work even on the eventual success path. Note this is
    /// SQLite in WAL mode with `synchronous=NORMAL` (see `roundhouse_store::
    /// open`'s doc comment) — not fsync'd on every write — so "appended"
    /// here means "written to the write-ahead log," not "survives an
    /// OS-level power loss"; it is not a claim of strict durability.
    pub async fn cancel(
        &self,
        runner: &TaskRunner,
        reason: CancelReason,
    ) -> Result<(), StoreError> {
        self.state_tx.send_replace(SessionState::Cancelling);

        let event = runner.record_session_state_changed(
            self.session_id,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            SessionState::Cancelling,
            // `CancelReason` has no `Display` impl and no established
            // stringification convention exists elsewhere in this codebase
            // for this free-text field, so its `Debug` rendering (e.g.
            // "User") is used deliberately here — NOT a placeholder. This is
            // distinct from `TaskCancelled.reason`, which stores the typed
            // `CancelReason` itself rather than a string. Because this value
            // is written into the append-only event log, renaming a
            // `CancelReason` variant will silently change the text of
            // already-persisted historical events' `reason` field.
            Some(format!("{reason:?}")),
            1,
        );
        self.writer.append(event).await?;
        Ok(())
    }

    /// Admit or refuse a new task, gated on the session's current state.
    ///
    /// Deliberately an **allowlist**, not a denylist: only `Created` and
    /// `Running` admit an ordinary (non-finally-step) task. Every other
    /// state — `Suspended`, `Cancelling`, `Closed`, and any variant added to
    /// `SessionState` in the future — refuses one by default, so a new
    /// variant this match doesn't yet know about fails closed rather than
    /// silently admitting work into (for example) a terminated session.
    ///
    /// A `finally:` cleanup step is only honored as a trusted bypass of that
    /// refusal when `req.origin == Origin::System` — `is_finally_step` is a
    /// caller-asserted boolean with nothing else tying it to provenance, so
    /// honoring it regardless of origin would make cancellation merely
    /// advisory the moment any model-influenced caller sets it. A
    /// `finally_step` claim from any other origin is evaluated as an
    /// ordinary task for gating purposes — the bypass simply doesn't apply,
    /// it is not a hard error.
    ///
    /// Task 25: once the `SessionState` gate above admits the task (an
    /// ordinary admit or a trusted finally-step bypass — this gate's own
    /// logic is unchanged from Task 3/4), a *second*, later gate now
    /// actually calls `PolicyEngine::decide_sealed` — §6.2: "Every task
    /// passes Policy::decide before execution." This is the real call site
    /// every task goes through before `TaskRunner::execute`, not a unit
    /// test against `PolicyEngine::decide`/`decide_sealed` in isolation
    /// (Tasks 9/10 already cover that).
    pub fn admit_task(&self, req: &TaskCreateRequest) -> Result<(), AdmitError> {
        let trusted_finally_step = req.is_finally_step && req.origin == Origin::System;

        match self.state() {
            SessionState::Created | SessionState::Running => {}
            _ if trusted_finally_step => {}
            SessionState::Cancelling => return Err(AdmitError::SessionCancelling),
            SessionState::Suspended => return Err(AdmitError::SessionSuspended),
            SessionState::Closed => return Err(AdmitError::SessionClosed),
        }

        let ctx = self.sealed_context();
        let decision = self.policy.decide_sealed(&req.params, self.unsealed, &ctx);
        match decision.outcome {
            Outcome::Deny => Err(AdmitError::Denied(decision.rule)),
            Outcome::Ask => Err(AdmitError::RequiresApproval),
            Outcome::Allow => Ok(()),
        }
    }

    /// Runs each `finally:` step in order, even while this session is
    /// `Cancelling` (or `Suspended`/`Closed`) — `admit_task` (above)
    /// special-cases `is_finally_step: true` + `Origin::System` precisely so
    /// this path is legal, and every step here is admitted through that
    /// real check, not a bypass around it.
    ///
    /// `execute` is injected rather than hardcoded against a real dispatch
    /// chokepoint: as of this task, `roundhouse-engine` still has no unified
    /// task-execution entry point (see this module's doc comment — the same
    /// gap Task 3 already documented and worked around). Inventing a fake
    /// one here (e.g. a `TaskRunner::execute`/`executor_for` pair that
    /// doesn't exist anywhere in this codebase) would paper over that gap
    /// instead of leaving it honestly for the later integration task that
    /// owns wiring a real executor in ("Task 25" in the Phase 2 plan).
    ///
    /// Stops at the first step whose admission or execution fails — later
    /// steps are never attempted once an earlier one has failed, so a
    /// partially-run `finally:` sequence is always reported as an error
    /// rather than silently treated as complete.
    pub async fn run_finally_steps<F, Fut>(
        &self,
        steps: Vec<FinallySpec>,
        execute: F,
    ) -> Result<(), FinallyStepError>
    where
        F: Fn(FinallySpec) -> Fut,
        Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    {
        for step in steps {
            let req = TaskCreateRequest {
                kind: step.kind.clone(),
                origin: Origin::System,
                is_finally_step: true,
                params: step.params.clone(),
            };
            self.admit_task(&req)?;
            execute(step).await.map_err(FinallyStepError::Execute)?;
        }
        Ok(())
    }
}

/// One `finally:`/cleanup step to be run by [`SessionActor::run_finally_steps`].
#[derive(Debug, Clone)]
pub struct FinallySpec {
    pub kind: TaskKind,
    pub input: TaskInput,
    /// Task 25: `admit_task` now always consults `PolicyEngine::decide_sealed`,
    /// which needs a real `TaskParams` for every `TaskCreateRequest` it
    /// builds — `FinallySpec` didn't carry one before this task. Added here
    /// (rather than synthesizing a permissive default inside
    /// `run_finally_steps`) so a `finally:` step's own policy-relevant
    /// params are exactly what gets judged — a synthesized placeholder
    /// would either be spuriously permissive (bypassing the sealed floor
    /// for a step that should be caught by it) or spuriously restrictive,
    /// neither of which is honest about what the step actually does.
    pub params: TaskParams,
}

/// Failure modes for [`SessionActor::run_finally_steps`].
#[derive(Debug, thiserror::Error)]
pub enum FinallyStepError {
    #[error("finally step refused by admission gate: {0}")]
    Admit(#[from] AdmitError),
    #[error("finally step execution failed: {0}")]
    Execute(Box<dyn std::error::Error + Send + Sync>),
}

/// Task 25 — the real, inline fix for audit finding 11's deferred
/// downgrade-recording. Uses only the frozen `Isolate::probe`/`ProbeResult
/// { achieved, degradations }` contract — no downcast from the generic
/// `dyn Isolate` the engine actually holds, so this works identically for
/// every `Isolate` implementation, not just `BwrapLandlockIsolate`.
///
/// A free function, not a method: `SessionActor` doesn't exist yet at
/// session-creation time — this function's whole point is to build the
/// `Handle` that later goes INTO a `SessionActor`.
///
/// Follows the exact real pattern this same file's `cancel()` uses: mint an
/// `Event` via `TaskRunner::record_note`, append it via `EventWriter`,
/// deliberately best-effort (`let _ =`) on the append so a failed Degradation
/// note can never abort session creation — matching the brief's own
/// "regardless of whether prepare() below ends up erring" framing.
pub async fn create_session_isolation(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    isolate: &dyn Isolate,
    spec: &SessionSpec,
) -> Result<Handle, IsolationError> {
    let probe = isolate.probe().await;
    if probe.achieved < spec.requested_tier {
        // §6.5 rule 3: a downgrade requires SessionSpec.on_degrade, set by
        // the human at creation, and must be RECORDED — regardless of
        // whether prepare() below ends up erring (on_degrade=Refuse) or
        // succeeding at the lower tier (on_degrade=AllowDownTo). Recorded
        // here, unconditionally, before prepare() runs.
        let event = runner.record_note(
            session_id,
            0, // ignored — EventWriter::append assigns the real per-session seq
            now_ts(),
            None,
            NoteLevel::Degradation,
            format!(
                "isolation shortfall: requested {:?}, only {:?} achievable on this host ({})",
                spec.requested_tier,
                probe.achieved,
                probe.degradations.join("; "),
            ),
            1,
        );
        let _ = writer.append(event).await;
    }
    isolate.prepare(spec).await
}

/// Task 25 — the single real call site both `SealedContext` construction
/// (via a later `SessionActor::new`) and the network-policy proxy hang off
/// of: a session's isolation handle and its egress allowlist are decided
/// together, once, here, at session creation.
///
/// Deliberately does NOT call `proxy.serve()` itself: `LoopbackProxy` binds
/// exactly one listener for its whole lifetime and panics if `serve()` is
/// called a second time (see `LoopbackProxy::serve`'s doc comment) — in the
/// real daemon `serve()` runs once at daemon boot, well before any session
/// (and therefore any call to this function) exists. The caller is
/// responsible for having already `serve()`d `proxy` exactly once.
pub async fn create_session_with_egress(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    isolate: &dyn Isolate,
    spec: &SessionSpec,
    proxy: &Arc<LoopbackProxy>,
    egress_policy: EgressPolicy,
) -> Result<(Handle, ProxyHandle), CreateSessionError> {
    let handle = create_session_isolation(writer, runner, session_id, isolate, spec).await?;
    let proxy_handle = proxy.register_session(session_id, egress_policy)?;
    Ok((handle, proxy_handle))
}

/// Task 25's own design call (flagged as such by the addendum): a small
/// error enum wrapping both failure modes `create_session_with_egress` can
/// hit, so it has one coherent `Result` error type instead of forcing every
/// caller to match on an ad hoc combination.
#[derive(Debug, thiserror::Error)]
pub enum CreateSessionError {
    #[error(transparent)]
    Isolation(#[from] IsolationError),
    #[error(transparent)]
    ProxyNotServing(#[from] ProxyNotServingError),
}
