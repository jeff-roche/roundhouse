//! Cooperative cancellation (Phase 2, Task 3): a `SessionActor` tracks one
//! session's `SessionState` and, via an allowlist, refuses admission of new,
//! non-`finally:` tasks once that session has left `Created`/`Running`
//! (i.e. `Suspended`, `Cancelling`, or `Closed`).
//!
//! **Scope note — read before wiring this in anywhere:** `admit_task` (this
//! module) is real and fully wired to `PolicyEngine::decide_sealed` (Phase 2,
//! Task 25), but is **still not called from any real dispatch chokepoint**
//! as of this task. `roundhouse-engine` still has no unified task-execution
//! entry point — the only real driver is [`crate::run_chat_turn`] in
//! `chat.rs`, and tool executors are invoked ad hoc from
//! `roundhouse-daemon`'s demo wiring with no admission gate in front of the
//! real executors yet. Threading `admit_task` in front of those real call
//! sites (chat turns, tool calls) remains open, deferred to a further,
//! not-yet-numbered integration task. Don't assume more integration happened
//! here than did: Task 25 wired real policy/isolation/egress mechanisms
//! *into* `admit_task`/session creation; it did not wire `admit_task` *into*
//! a real dispatch chokepoint.
//!
//! Phase 2, Task 4 adds [`SessionActor::run_finally_steps`] to this same
//! file (not a separate `cancel.rs` — this module is `SessionActor`'s home).
//! It reuses `admit_task` for real, but same as above, still doesn't reach
//! into a real dispatch chokepoint for *executing* a step — that's injected
//! by the caller, for the same "no unified task-execution entry point yet"
//! reason above.
//!
//! Phase 2, Task 25 wires `PolicyEngine::decide_sealed` (via a live
//! [`roundhouse_policy::sealed::SealedContext`] built from this session's
//! own isolation attestation and MCP registry) into `admit_task` as a
//! second gate after the `SessionState` allowlist, adds
//! [`create_session_isolation`] as the real, inline fix for the
//! isolation-shortfall `Degradation`-recording gap, and adds
//! [`create_session_with_egress`] to register a session's egress allowlist
//! with a real `roundhouse_net::proxy::LoopbackProxy` at the same
//! session-creation call site.

use roundhouse_core::{
    CancelReason, NoteLevel, OnDegrade, Origin, SessionId, SessionSpec, SessionState, TaskInput,
    TaskKind, TaskRunner, Tier, Timestamp,
};
use roundhouse_mcp::config::{McpServerConfig, McpTransportKind};
use roundhouse_net::policy::{EgressPolicy, HostPattern};
use roundhouse_net::proxy::{LoopbackProxy, ProxyHandle, ProxyNotServingError};
use roundhouse_policy::engine::{Outcome, PolicyEngine, RuleId};
use roundhouse_policy::sealed::SealedContext;
use roundhouse_policy::TaskParams;
use roundhouse_provider::RequestCtx;
use roundhouse_sandbox::{Handle, Isolate, IsolationError};
use roundhouse_store::redact::Redactor;
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
    ///
    /// **SECURITY INVARIANT (Task 25 fix-round-1, security review):** for
    /// `TaskParams::Fs`, `canonical` MUST be the result of a genuine,
    /// symlink-followed filesystem resolution (e.g. `std::fs::
    /// canonicalize`) of the real path this task will touch — never merely
    /// the path string as received from wherever this request originated.
    /// The sealed floor's own path matchers (`sealed_write_under`,
    /// `sealed_state_dir_write`, `sealed_daemon_binary_write`) trust
    /// `canonical` completely and have no independent way to detect an
    /// unresolved value; a well-formed-looking `Ok(path)` that is
    /// technically absolute but still points at, or through, an
    /// unfollowed live symlink is a real, reproducible fail-open bypass of
    /// every sealed rule that matches on `canonical` (confirmed: writing
    /// through a symlink pointing at `~/.ssh/authorized_keys`, submitted
    /// with `canonical: Ok(<the symlink's own path>)` rather than its
    /// resolved target, is admitted). `SessionActor::admit_task` performs
    /// exactly one cheap, no-I/O partial guard (rejecting a non-absolute
    /// `Ok(path)` outright) — it cannot and does not perform real
    /// canonicalization itself (this is policy-adjacent code that
    /// deliberately does no I/O). Real, symlink-resolving canonicalization
    /// before this field is ever populated is a hard prerequisite for
    /// whoever wires `TaskCreateRequest` construction into a real tool
    /// executor next; that wiring does not exist anywhere in this codebase
    /// yet (see this module's own doc comment on `admit_task` still not
    /// being called from a real dispatch chokepoint).
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
    /// Task 25 fix-round-2 (security review): if the sealed-floor-disabled
    /// audit note (see `admit_task`'s doc comment) fails to durably
    /// append, admission fails CLOSED rather than silently proceeding with
    /// the sealed floor disabled and no audit trail — mirroring `cancel()`'s
    /// own fail-loud posture elsewhere in this file (propagated via `?`,
    /// never `let _ =`). Fix-round-1's version of this note used `let _ =`
    /// on the append and proceeded regardless — a real, reproduced
    /// "tries to be loud, then is silent anyway on the one path where
    /// loudness actually mattered" gap; this variant is what a caller now
    /// sees instead of that silent fallthrough.
    #[error(
        "failed to durably record the sealed-floor-disabled audit note; refusing admission \
         rather than proceeding without an audit trail: {0}"
    )]
    UnsealedAuditFailed(#[from] StoreError),
}

/// Tracks one session's `SessionState` and gates new-task admission on it.
///
/// Does not hold its own copy of `TaskRunner` semantics beyond the `runner`
/// field below: `TaskRunner` is not `Clone` and is meant to be a single
/// process-wide singleton obtained once via `TaskRunner::bootstrap()` — see
/// the `runner` field's own doc comment for how this actor holds one.
pub struct SessionActor {
    session_id: SessionId,
    writer: EventWriter,
    state_tx: tokio::sync::watch::Sender<SessionState>,
    /// The shared, process-wide `TaskRunner` this actor mints new events
    /// through for policy/admission-adjacent bookkeeping (Task 25).
    /// `TaskRunner` is not `Clone` and is meant to be a single process-wide
    /// singleton obtained once via `TaskRunner::bootstrap()` — this field
    /// holds a `'static` reference to that one singleton, not an owned
    /// copy. `cancel()`'s existing `runner: &TaskRunner` *parameter* is
    /// untouched by this field; they're separate, deliberately (see
    /// `cancel`'s call sites, which keep passing their own `&TaskRunner`
    /// exactly as before).
    runner: &'static TaskRunner,
    /// Task 25 fix-round-1 (security review): this is now the ONLY place
    /// `admit_task` reads whether the sealed floor is disabled —
    /// `self.policy.unsealed()`, never a separate actor-local copy. An
    /// earlier version of this struct held its own `unsealed: bool` field,
    /// independently settable from the `PolicyEngine` it wrapped; that let
    /// a `PolicyEngine::with_unsealed(false)` have its sealed floor
    /// disabled anyway because `admit_task` consulted the actor's own,
    /// unrelated flag. There must be exactly one source of truth for this.
    policy: Arc<PolicyEngine>,
    /// Absolute, non-empty by construction (`SessionActor::new` asserts
    /// this) — an empty or relative `state_dir` silently disables
    /// `sealed_state_dir_write` (see that rule's own empty-path guard,
    /// intended only for `roundhouse_policy::sealed::default_context`'s
    /// unit-test placeholder, never for a real session).
    state_dir: PathBuf,
    /// Same absolute/non-empty invariant as `state_dir`, for the same
    /// reason (`sealed_daemon_binary_write`'s empty-path guard).
    daemon_binary: PathBuf,
    /// The process's `HOME` value, snapshotted ONCE here at construction
    /// time (not read live at task-admission time) and threaded verbatim
    /// into every `SealedContext` this session builds. `None` means `HOME`
    /// was genuinely unset when this `SessionActor` was constructed — a
    /// real, unremarkable state under systemd or a minimal container.
    /// `roundhouse_policy::sealed::sealed_write_under` treats `SealedContext
    /// { home: None, .. }` as a fail-CLOSED match (deny) for dotfile writes,
    /// never as "rule doesn't apply" — see that function's doc comment. A
    /// prior version of the sealed dotfile rules read
    /// `std::env::var_os("HOME")` live and fail-OPEN when unset, which
    /// silently disarmed the entire dotfile-protection sealed floor; taking
    /// one snapshot here, at the same place `state_dir`/`daemon_binary` are
    /// already validated, closes that gap.
    home: Option<PathBuf>,
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
    /// The tier this session is actually ENTITLED to run at, derived from
    /// what the human's `on_degrade` setting authorized — `requested_tier`
    /// itself for `OnDegrade::Refuse` (nothing lower was ever accepted), or
    /// the accepted floor for `OnDegrade::AllowDownTo(floor)`.
    /// `sealed_context()` compares the CURRENT live attestation against
    /// THIS, not `session_spec.requested_tier` directly: a session created
    /// with `OnDegrade::AllowDownTo` that genuinely (and human-acceptedly)
    /// settles for a lower tier must not have `sealed_tier_shortfall` fire
    /// on every single task for the rest of its life just because the
    /// ORIGINAL ask never changes. A later, real mid-session degradation
    /// (attested tier dropping below `effective_tier`) still correctly
    /// fires the rule — only the one-time, accepted-at-creation gap is
    /// excused.
    ///
    /// **Task 25 fix-round-2 (security review):** deliberately NOT derived
    /// from `isolate.attest(&handle).tier` (fix-round-1's original
    /// approach) — `BwrapLandlockIsolate::attest` returns `Tier::None` for
    /// any handle not currently in its in-memory handle map (a dead handle,
    /// a handle from a different `Isolate` instance, or a session
    /// rehydrated after a daemon restart, since the handle map is purely
    /// in-memory), which made `effective_tier` silently collapse to `None`
    /// and PERMANENTLY disable `sealed:tier-shortfall` for that session's
    /// whole life — a genuine fail-open regression, reproduced by security
    /// review, in the opposite direction from finding 6's original bug.
    /// Deriving from `on_degrade` instead never depends on a live
    /// attestation succeeding: `Isolate::prepare` already enforces
    /// `achieved >= floor` before a `Handle` is ever returned (§6.5 rule
    /// 2), so on the happy path this agrees with what `attest()` would
    /// report anyway — it just doesn't fail open when attestation can't
    /// find the handle.
    effective_tier: Tier,
    /// Phase 7, Task 4: the merged model-facing tool catalog for this
    /// session — the built-in executor `ToolDef`s (Task 1's
    /// `tool_catalog::builtin_tool_defs`) plus whatever this session's
    /// configured MCP servers discovered, already merged and collision-checked
    /// by `tool_catalog::merged_tool_defs`. Computed BEFORE this
    /// `SessionActor` is constructed — see
    /// [`crate::mcp_spawner::start_session_mcp`], the async, fallible
    /// free function that calls `McpHost::start` and produces this value —
    /// and simply stored here so Task 5's agent loop has one place to read
    /// the tool list an `infer` task's `ChatRequest.tools` should draw
    /// from, without needing it threaded through by hand at every call
    /// site. An empty `Vec` (a session with zero configured MCP servers,
    /// still carrying the five builtins) is the common case, not an error.
    tool_defs: Vec<roundhouse_provider::ToolDef>,
}

impl SessionActor {
    /// # Panics
    /// Panics if `state_dir` or `daemon_binary` is not an absolute,
    /// non-empty path. This is a fail-closed construction-time invariant,
    /// not a soft validation: `roundhouse_policy::sealed::
    /// sealed_state_dir_write`/`sealed_daemon_binary_write` both silently
    /// no-op when their respective `SealedContext` field is empty (a guard
    /// meant only for `sealed::default_context`'s unit-test placeholder) —
    /// constructing a real `SessionActor` with an empty or relative path
    /// here would silently disable two of the sealed floor's compiled-in
    /// rules for this session's entire lifetime, with nothing downstream
    /// able to detect it. Panicking here, at construction, is deliberately
    /// louder than that.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        writer: EventWriter,
        initial_state: SessionState,
        runner: &'static TaskRunner,
        policy: Arc<PolicyEngine>,
        state_dir: PathBuf,
        daemon_binary: PathBuf,
        isolate: Arc<dyn Isolate>,
        handle: Handle,
        session_spec: SessionSpec,
        tool_defs: Vec<roundhouse_provider::ToolDef>,
    ) -> Self {
        assert!(
            state_dir.is_absolute(),
            "SessionActor::new: state_dir must be a non-empty, absolute path (got {state_dir:?}) \
             — an empty/relative path silently disables the real sealed:state-dir-write rule"
        );
        assert!(
            daemon_binary.is_absolute(),
            "SessionActor::new: daemon_binary must be a non-empty, absolute path (got \
             {daemon_binary:?}) — an empty/relative path silently disables the real \
             sealed:daemon-binary-write rule"
        );
        let (state_tx, _rx) = tokio::sync::watch::channel(initial_state);
        let effective_tier = match session_spec.on_degrade {
            OnDegrade::Refuse => session_spec.requested_tier,
            OnDegrade::AllowDownTo(floor) => floor,
        };
        // Snapshot HOME once, here, alongside state_dir/daemon_binary's own
        // construction-time validation — never read live at decision time
        // (see the `home` field's doc comment for why that matters).
        let home = roundhouse_policy::sealed::home_dir();
        SessionActor {
            session_id,
            writer,
            state_tx,
            runner,
            policy,
            state_dir,
            daemon_binary,
            home,
            mcp_resolved: Arc::new(RwLock::new(HashSet::new())),
            isolate,
            handle,
            session_spec,
            effective_tier,
            tool_defs,
        }
    }

    /// The merged model-facing tool catalog this session was constructed
    /// with — see the `tool_defs` field's own doc comment for how it's
    /// computed and by whom.
    pub fn tool_defs(&self) -> &[roundhouse_provider::ToolDef] {
        &self.tool_defs
    }

    /// Builds the live `SealedContext` this session's tasks are judged
    /// against — the exact wiring finding 3's `sealed_tier_shortfall` check
    /// needed and never had before Task 25: reads the CURRENT isolation
    /// attestation (re-read every call, since §6.5 rule 4 says the achieved
    /// tier can change mid-session) and the MCP registry's currently-
    /// resolved servers, not a snapshot taken once at session start.
    ///
    /// `requested_tier` here is `self.effective_tier` (the tier accepted at
    /// construction), not `self.session_spec.requested_tier` — see
    /// `effective_tier`'s own doc comment for why comparing against the
    /// stale original ask would make a legitimately-downgraded session deny
    /// every task for the rest of its life.
    fn sealed_context(&self) -> SealedContext {
        let attestation = self.isolate.attest(&self.handle);
        SealedContext {
            state_dir: self.state_dir.clone(),
            daemon_binary: self.daemon_binary.clone(),
            // Task 25 fix-round-1 (security review): a poisoned lock reads
            // as an empty resolved-server set (fail-closed — an empty set
            // makes every `TaskParams::Mcp` sealed-deny, never
            // spuriously-allow) rather than panicking. `mcp_resolved` is
            // write-only from Phase 3 code that doesn't exist yet in this
            // task's scope, but treating a future writer's panic as a
            // reason to also crash every *reader* of this session would be
            // a real, avoidable DoS surface once Phase 3 lands.
            resolved_mcp_servers: self
                .mcp_resolved
                .read()
                .map(|guard| guard.clone())
                .unwrap_or_default(),
            requested_tier: self.effective_tier,
            attested_tier: attestation.tier,
            home: self.home.clone(),
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

    /// The original `SessionSpec` this session was created with — kept for
    /// observability/debugging (e.g. surfacing the ORIGINAL ask alongside
    /// `effective_tier`, the tier actually accepted). `sealed_context()`
    /// deliberately does NOT read `requested_tier` off of this — see
    /// `effective_tier`'s own doc comment for why.
    pub fn session_spec(&self) -> &SessionSpec {
        &self.session_spec
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
    ///
    /// Now `async`, as of Task 25 fix-round-1: whenever `self.policy.
    /// unsealed()` is true (§6.2's one documented sealed-floor escape,
    /// `round daemon --unsealed`), a `Note` is durably recorded for THIS
    /// task — `sealed.rs`'s and `engine.rs`'s own pre-existing doc comments
    /// already committed to "`--unsealed` ... must be recorded per-task ...
    /// never silent"; this is that recording, finally real. As of
    /// fix-round-2, the note is recorded AFTER the policy decision is known
    /// (describing the real `Allow`/`Ask`/`Deny` outcome, not
    /// unconditionally "admitted" — an earlier version recorded before the
    /// decision and always said "admitted," which was actively misleading
    /// whenever the decision then turned out to be `Ask`/`Deny`), and a
    /// failed append fails admission CLOSED via `AdmitError::
    /// UnsealedAuditFailed` rather than silently proceeding — an earlier
    /// version used `let _ =` on this specific append and proceeded
    /// regardless, which was its own "tries to be loud, then is silent
    /// anyway" gap. This is a different posture from
    /// `create_session_isolation`'s Degradation note (still best-effort,
    /// by design — see that function's own doc comment for why session
    /// *creation* deliberately doesn't fail closed on that append).
    ///
    /// # Security invariant on `req.params`
    /// For `TaskParams::Fs`, `req.params`'s `canonical` field MUST be a
    /// genuinely resolved (symlink-followed, e.g. via `std::fs::
    /// canonicalize`) absolute path, not merely whatever path string the
    /// caller happened to receive — see [`TaskCreateRequest::params`]'s own
    /// doc comment for the full rationale and this function's one cheap,
    /// no-I/O partial guard (rejecting a non-absolute `Ok(path)` outright).
    pub async fn admit_task(&self, req: &TaskCreateRequest) -> Result<(), AdmitError> {
        let trusted_finally_step = req.is_finally_step && req.origin == Origin::System;

        match self.state() {
            SessionState::Created | SessionState::Running => {}
            _ if trusted_finally_step => {}
            SessionState::Cancelling => return Err(AdmitError::SessionCancelling),
            SessionState::Suspended => return Err(AdmitError::SessionSuspended),
            SessionState::Closed => return Err(AdmitError::SessionClosed),
        }

        // Cheap, no-I/O partial guard against the class of bug (not the
        // full attack) flagged by security review: a `canonical: Ok(path)`
        // that isn't even absolute is definitely not a real, resolved
        // canonical path (`std::fs::canonicalize` always returns an
        // absolute path), so it can never legitimately pass the sealed
        // floor's path-prefix matchers. This does NOT defend against a
        // caller supplying an absolute-but-unresolved path (e.g. the
        // symlink's own path rather than its resolved target) — that
        // requires real filesystem I/O this policy-adjacent, otherwise
        // I/O-free function deliberately does not perform; real
        // canonicalization is the caller's hard responsibility (see
        // `TaskCreateRequest::params`'s doc comment).
        if let TaskParams::Fs {
            canonical: Ok(p), ..
        } = &req.params
        {
            if !p.is_absolute() {
                return Err(AdmitError::Denied(None));
            }
        }

        let unsealed = self.policy.unsealed();
        let ctx = self.sealed_context();
        let decision = self.policy.decide_sealed(&req.params, &ctx);

        // Task 25 fix-round-2 (security review): recorded AFTER the
        // decision is known, and describing the REAL outcome — fix-round-1
        // recorded this note before `decide_sealed` ran and unconditionally
        // said "task admitted," which was actively misleading whenever the
        // decision then turned out to be Ask/Deny (an audit trail claiming
        // a denied task was admitted is worse than no note at all). The
        // append is also no longer best-effort: `?` propagates a failed
        // append as `AdmitError::UnsealedAuditFailed`, failing admission
        // CLOSED rather than silently proceeding with the sealed floor
        // disabled and no durable record of it — satisfying "must be
        // recorded ... never silent" for real, not just "tries to record,
        // then is silent anyway if that fails."
        if unsealed {
            let outcome_str = match decision.outcome {
                Outcome::Allow => "Allow",
                Outcome::Ask => "Ask",
                Outcome::Deny => "Deny",
            };
            let event = self.runner.record_note(
                self.session_id,
                0, // ignored — EventWriter::append assigns the real per-session seq
                now_ts(),
                None,
                NoteLevel::Warn,
                format!(
                    "task evaluated with the sealed floor DISABLED (--unsealed): kind={:?} \
                     origin={:?} outcome={outcome_str}",
                    req.kind, req.origin,
                ),
                1,
            );
            self.writer
                .append(event)
                .await
                .map_err(AdmitError::UnsealedAuditFailed)?;
        }

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
    /// chokepoint: `roundhouse-engine` still has no unified task-execution
    /// entry point (see this module's doc comment — the same gap Task 3
    /// already documented and worked around, and which Task 25 did not
    /// close either — Task 25 wired real policy/isolation/egress mechanisms
    /// into `admit_task` and session creation, not `admit_task` into a real
    /// dispatch chokepoint). Inventing a fake one here (e.g. a
    /// `TaskRunner::execute`/`executor_for` pair that doesn't exist anywhere
    /// in this codebase) would paper over that gap instead of leaving it
    /// honestly for the further, not-yet-numbered integration task that
    /// owns wiring a real executor in.
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
            self.admit_task(&req).await?;
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
/// downgrade-recording.
///
/// A free function, not a method: `SessionActor` doesn't exist yet at
/// session-creation time — this function's whole point is to build the
/// `Handle` that later goes INTO a `SessionActor`.
///
/// **Task 25 fix-round-1 (security review):** the shortfall decision is
/// driven by `isolate.attest(&handle).tier` — the REAL tier the returned
/// handle actually settled at — never by an independent `isolate.probe()`
/// call. An earlier version of this function compared `isolate.probe().
/// await.achieved` against `spec.requested_tier` before calling `prepare()`;
/// that is unsound for two reasons proven by security review: (1)
/// `Isolate::probe()`'s real implementation (`BwrapLandlockIsolate::probe`)
/// re-probes the actual live host from scratch via `probe_cached`, wholly
/// ignoring any probe result a test double was constructed with — so even
/// `test_with_probe`'s injected report was silently bypassed by that
/// `probe()` call, while `prepare()`/`attest()` correctly used it; and (2)
/// even for a real host, nothing guarantees `probe()`'s live re-read agrees
/// with what `prepare()` — called moments later — actually decided for
/// this specific handle. Both directions were reproduced: a session that
/// genuinely achieved full `Sandbox` tier got a spurious permanent
/// Degradation note (false positive, driven by a stale/mismatched `probe()`
/// read), and a custom `Isolate` whose `probe()` over-reports produced ZERO
/// degradation notes for a real downgrade (false negative). `prepare()` is
/// now called FIRST; the note is recorded from its real, handle-attested
/// outcome afterward on the success path. **Fix-round-2:** the
/// `OnDegrade::Refuse` error path (`prepare()` returning
/// `IsolationError::DegradedBelowRequested`, meaning no `Handle` was ever
/// created at all) ALSO records a Degradation note — sourced from
/// `isolate.probe()` for best-effort diagnostic detail, since there is no
/// handle to attest against there and none of finding 2's mismatch hazard
/// applies to a case where no decision is being made from the probe read (a
/// shortfall in that path is already, independently established by the
/// `DegradedBelowRequested` variant itself). Fix-round-1 had left this
/// specific path recording nothing, a real regression versus the original
/// (pre-fix-round-1) code, which recorded unconditionally before `prepare()`
/// ran.
///
/// Follows the exact real pattern this same file's `cancel()` uses for the
/// append itself: mint an `Event` via `TaskRunner::record_note`, append it
/// via `EventWriter`, deliberately best-effort (`let _ =`) on the append so
/// a failed Degradation-note append can never fail session creation itself.
pub async fn create_session_isolation(
    writer: &EventWriter,
    runner: &TaskRunner,
    session_id: SessionId,
    isolate: &dyn Isolate,
    spec: &SessionSpec,
) -> Result<Handle, IsolationError> {
    match isolate.prepare(spec).await {
        Ok(handle) => {
            let achieved = isolate.attest(&handle).tier;
            if achieved < spec.requested_tier {
                // §6.5 rule 3: a downgrade requires SessionSpec.on_degrade,
                // set by the human at creation, and must be RECORDED.
                // Driven by the real, handle-attested `achieved` tier
                // above, not an independent probe.
                let event = runner.record_note(
                    session_id,
                    0, // ignored — EventWriter::append assigns the real per-session seq
                    now_ts(),
                    None,
                    NoteLevel::Degradation,
                    format!(
                        "isolation shortfall: requested {:?}, this session's handle actually \
                         achieved {:?}",
                        spec.requested_tier, achieved,
                    ),
                    1,
                );
                let _ = writer.append(event).await;
            }
            Ok(handle)
        }
        // Task 25 fix-round-2 (optional, folded in): `OnDegrade::Refuse`
        // means `prepare()` errors instead of returning a `Handle` — with
        // fix-round-1's prepare-then-note reordering (the fix for finding
        // 2), that left this specific path recording nothing at all, a
        // real audit-trail gap versus the original (pre-fix-round-1)
        // behavior, which recorded unconditionally before `prepare()` ran.
        // Safe to record here from `isolate.probe()`: finding 2's
        // attest()-vs-probe() mismatch hazard was about a DECISION (whether
        // a shortfall exists / what tier to claim was achieved) disagreeing
        // with the real, handle-attested outcome — here there is no handle
        // to disagree with at all (`prepare()` already errored), so
        // `probe()`'s read is used purely as best-effort diagnostic color
        // for a shortfall the `DegradedBelowRequested` error variant has
        // already, independently established occurred.
        Err(e @ IsolationError::DegradedBelowRequested) => {
            let probe = isolate.probe().await;
            let event = runner.record_note(
                session_id,
                0,
                now_ts(),
                None,
                NoteLevel::Degradation,
                format!(
                    "isolation shortfall: requested {:?}, only {:?} achievable on this host \
                     ({}) — session refused to start (OnDegrade::Refuse)",
                    spec.requested_tier,
                    probe.achieved,
                    probe.degradations.join("; "),
                ),
                1,
            );
            let _ = writer.append(event).await;
            Err(e)
        }
        Err(e) => Err(e),
    }
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
///
/// If isolation succeeds but registering the session with `proxy` fails
/// (`ProxyNotServingError`), the isolation handle that was just created is
/// torn down (best-effort) before returning the error, rather than leaked
/// in the isolate's internal handle map.
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
    match proxy.register_session(session_id, egress_policy) {
        Ok(proxy_handle) => Ok((handle, proxy_handle)),
        Err(e) => {
            let _ = isolate.teardown(handle).await;
            Err(CreateSessionError::from(e))
        }
    }
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

/// Phase 7, Task 6 — closes the gap flagged by this task's own brief:
/// `roundhouse-store/src/writer.rs` builds every `EventWriter`'s `Redactor`
/// as `Redactor::build(&[])` at construction time (`spawn_writer`) — an
/// empty secret list, so redaction runs on every write but redacts
/// nothing — and `EventWriter::set_redactor` had zero non-test callers
/// anywhere in the workspace before this function existed.
///
/// A minimum-length guard is applied before the secrets ever reach
/// `Redactor::build`: `Redactor::build`'s own doc comment already filters
/// empty-string patterns (an empty pattern matches at every position and
/// pathologically mangles output), but a *short*, non-empty value is its
/// own hazard the automaton doesn't guard against — the demo daemon's own
/// placeholder `RequestCtx.api_key` is the literal string `"demo"`
/// (`roundhouse-daemon/src/main.rs`), and registering a 4-byte value as a
/// "secret" would redact every literal occurrence of the word "demo"
/// anywhere in this session's event log (including, e.g., "demo session
/// complete" / "demo file" Note text), destroying real, non-secret log
/// content. No real provider API key is anywhere near this short, so a
/// conservative minimum length excludes exactly the placeholder case
/// without weakening protection for any real credential.
const MIN_REDACTABLE_SECRET_LEN: usize = 12;

/// Installs a `Redactor` built from `secrets` onto `writer`, hot-swapping
/// whatever `Redactor` it was constructed with (`spawn_writer`'s
/// `Redactor::build(&[])` empty default, on every real call site today).
///
/// **Caller's responsibility — ordering is the entire point:** this must be
/// called before any event that could reference one of `secrets` is ever
/// appended through `writer`. `EventWriter::set_redactor` takes effect only
/// for writes from that point forward (`ArcSwap::store`, see its own doc
/// comment) — a write that already landed before this call is `EventWriter`
/// appended it in already-redacted-or-not form permanently: the `events`
/// table physically rejects `UPDATE`/`DELETE` (S-LOG-2), so there is no way
/// to retroactively redact a row once committed. See this function's real
/// call site in `roundhouse-daemon/src/demo.rs` (`run_demo_session`, called
/// immediately after `spawn_writer` and strictly before the first
/// `run_chat_turn`/`append`) for a concrete proof that nothing appends
/// in between.
pub fn wire_redaction_for_session(writer: &EventWriter, secrets: &[String]) {
    let filtered: Vec<String> = secrets
        .iter()
        .filter(|s| s.len() >= MIN_REDACTABLE_SECRET_LEN)
        .cloned()
        .collect();
    writer.set_redactor(Redactor::build(&filtered));
}

/// Collects every live secret value this session's creation already knows
/// about, for [`wire_redaction_for_session`]'s `secrets` argument.
///
/// Two sources today:
/// - `ctx.api_key` — Phase 1's original, simplified credential path,
///   always populated (every `RequestCtx` construction site sets it, even
///   the demo's harmless placeholder — filtered out downstream by
///   `wire_redaction_for_session`'s minimum-length guard, not here, so this
///   function stays an honest, unfiltered inventory of what it found).
/// - Every MCP `Stdio` server's `env` values (`McpTransportKind::Stdio.env:
///   Vec<(String, String)>`) — passed literally to the spawned child's
///   environment via `Command::envs` (`roundhouse-mcp/src/transport/
///   stdio.rs`), with no secret-ref resolution step in between. Whether a
///   given value is a raw secret or a reference string like
///   `"keyring:github"`, it is exactly what reaches the child process
///   verbatim, so it belongs in the redaction set regardless — nothing
///   downstream can distinguish the two shapes, and the brief itself names
///   MCP env values as in scope ("any resolved MCP server env-var
///   secrets").
///
/// **Documented seam, not a silent gap:** `ctx.credentials: Option<Arc<dyn
/// CredentialProvider>>` (Phase 6) is deliberately NOT a source here.
/// `CredentialProvider`'s only method, `apply(&self, req: &mut HttpRequest,
/// ctx: &CredentialCtx)`, mutates an outbound `HttpRequest` in place and
/// returns `Result<(), CredentialError>` — it has no accessor that exposes
/// the underlying secret material to a caller, by design (`roundhouse-
/// secrets`' six concrete implementations hold it, never this crate). There
/// is nothing to extract here today. Whoever gives `CredentialProvider` (or
/// a sibling trait) a value-exposing method next should feed its result
/// into this `Vec` alongside `ctx.api_key`.
///
/// **Never logs, `Debug`-prints, or echoes any value it collects** —
/// `RequestCtx` deliberately derives neither `Debug` nor `Serialize`
/// (§9.9), and this function does not add either.
pub fn live_secret_values(ctx: &RequestCtx, mcp_configs: &[McpServerConfig]) -> Vec<String> {
    let mut secrets = vec![ctx.api_key.clone()];
    for config in mcp_configs {
        let McpTransportKind::Stdio { env, .. } = &config.transport;
        secrets.extend(env.iter().map(|(_, value)| value.clone()));
    }
    secrets
}

/// Converts a plain, config-sourced allowlist (`roundhouse_config::network::
/// NetworkConfig.allowed_hosts`) into a real `roundhouse_net::policy::
/// EgressPolicy` — the conversion `roundhouse-config` cannot perform itself
/// (it must stay free of every `roundhouse-*` dependency; see that crate's
/// `network` module doc comment), so it lives here, above config, at the
/// one crate every real session-creation call site already depends on.
///
/// An empty `allowed_hosts` produces an `EgressPolicy` that denies every
/// host (`EgressPolicy::matches` is `self.allowed_hosts.iter().any(..)`,
/// vacuously `false` over an empty `Vec` — confirmed by this module's own
/// test, not just by reading the body) — fail-closed, matching
/// `load_network_config`'s own documented default.
///
/// Each entry becomes an exact-hostname match, **except** a `"*."`-prefixed
/// entry, which becomes a wildcard-suffix match over the text after the
/// prefix — with one deliberate guard: an entry of exactly `"*"` or `"*."`
/// (empty suffix) is skipped rather than converted. `HostPattern::
/// wildcard_suffix("")`'s own `match_kind` treats an empty suffix as
/// matching *every* host unconditionally (`suffix.is_empty()` in its match
/// arm) — silently turning one config line into "allow all egress,"
/// almost certainly not what a config author who wrote `"*"` intended
/// (probably a typo for a real suffix, or a mistaken belief that it means
/// "no restriction" — the actual no-restriction spelling is simply not
/// configuring `[network]` at all, which this task's default already
/// happens to deny, not allow). Fail-closed here means skipping the
/// malformed entry (denying whatever it would have matched) rather than
/// silently promoting it to allow-everything.
pub fn egress_policy_from_allowed_hosts(allowed_hosts: &[String]) -> EgressPolicy {
    let mut patterns = Vec::with_capacity(allowed_hosts.len());
    for host in allowed_hosts {
        if host == "*" {
            continue;
        }
        match host.strip_prefix("*.") {
            Some("") => continue,
            Some(suffix) => patterns.push(HostPattern::wildcard_suffix(suffix)),
            None => patterns.push(HostPattern::exact(host)),
        }
    }
    EgressPolicy {
        allowed_hosts: patterns,
    }
}

#[cfg(test)]
mod redaction_and_egress_tests {
    use super::*;

    #[test]
    fn empty_allowlist_denies_every_host() {
        let policy = egress_policy_from_allowed_hosts(&[]);
        assert!(!policy.matches("example.com"));
        assert!(!policy.matches("api.anthropic.com"));
    }

    #[test]
    fn an_exact_host_entry_matches_only_that_host() {
        let policy = egress_policy_from_allowed_hosts(&["api.anthropic.com".to_string()]);
        assert!(policy.matches("api.anthropic.com"));
        assert!(!policy.matches("evil.example.com"));
        assert!(!policy.matches("anthropic.com"));
    }

    #[test]
    fn a_wildcard_suffix_entry_matches_the_suffix_and_subdomains() {
        let policy = egress_policy_from_allowed_hosts(&["*.example.com".to_string()]);
        assert!(policy.matches("example.com"));
        assert!(policy.matches("api.example.com"));
        assert!(!policy.matches("evilexample.com"));
    }

    /// The foot-gun `HostPattern::wildcard_suffix("")` would otherwise
    /// create: a bare `"*"` or `"*."` entry must not silently become
    /// "allow every host."
    #[test]
    fn a_bare_wildcard_entry_is_skipped_not_promoted_to_allow_all() {
        let policy = egress_policy_from_allowed_hosts(&["*".to_string()]);
        assert!(!policy.matches("example.com"));
        assert!(!policy.matches("literally-anything.invalid"));

        let policy = egress_policy_from_allowed_hosts(&["*.".to_string()]);
        assert!(!policy.matches("example.com"));
    }

    fn stdio_config(id: &str, env: Vec<(&str, &str)>) -> McpServerConfig {
        McpServerConfig {
            id: roundhouse_policy::ServerId(id.to_string()),
            transport: McpTransportKind::Stdio {
                command: "some-mcp-server".to_string(),
                args: vec![],
                env: env
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
                pinned_binary_hash: None,
            },
        }
    }

    fn fake_ctx(api_key: &str) -> RequestCtx {
        RequestCtx {
            trace_id: None,
            transport: Arc::new(roundhouse_provider::ReqwestTransport::new()),
            api_key: api_key.to_string(),
            credentials: None,
        }
    }

    #[test]
    fn live_secret_values_collects_the_api_key_and_every_mcp_env_value() {
        let ctx = fake_ctx("sk-live-abc123");
        let configs = vec![
            stdio_config("github", vec![("GITHUB_TOKEN", "gh-secret-value")]),
            stdio_config("other", vec![("A", "one"), ("B", "two")]),
        ];
        let secrets = live_secret_values(&ctx, &configs);
        assert!(secrets.contains(&"sk-live-abc123".to_string()));
        assert!(secrets.contains(&"gh-secret-value".to_string()));
        assert!(secrets.contains(&"one".to_string()));
        assert!(secrets.contains(&"two".to_string()));
    }

    #[test]
    fn live_secret_values_with_no_mcp_servers_is_just_the_api_key() {
        let ctx = fake_ctx("sk-live-abc123");
        let secrets = live_secret_values(&ctx, &[]);
        assert_eq!(secrets, vec!["sk-live-abc123".to_string()]);
    }

    /// `wire_redaction_for_session`'s minimum-length guard: a short value
    /// (like the demo daemon's literal `"demo"` `api_key` placeholder) must
    /// not become a redaction pattern, or it would mangle unrelated,
    /// non-secret log text that happens to contain the same short string.
    #[tokio::test]
    async fn a_short_secret_is_not_installed_as_a_redaction_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let store = roundhouse_store::open(&db_path).await.unwrap();
        let writer = roundhouse_store::spawn_writer(store).await;

        wire_redaction_for_session(&writer, &["demo".to_string()]);

        let runner = roundhouse_core::TaskRunner::bootstrap();
        let session_id = SessionId::new();
        let event = runner.record_note(
            session_id,
            0,
            now_ts(),
            None,
            NoteLevel::Info,
            "demo session complete".to_string(),
            1,
        );
        writer.append(event).await.unwrap();

        let read_store = roundhouse_store::open(&db_path).await.unwrap();
        let events = roundhouse_store::session_events(&read_store, session_id)
            .await
            .unwrap();
        let roundhouse_core::EventPayload::Note { text, .. } = &events[0].payload else {
            panic!("expected a Note payload");
        };
        assert_eq!(
            text, "demo session complete",
            "a short non-secret-shaped value must not have redacted unrelated text"
        );
    }
}
