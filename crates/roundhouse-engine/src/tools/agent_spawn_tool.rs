//! The `agent` tool: the model-reachable, tracked sub-agent spawn path
//! (Phase 8, L5).
//!
//! Before this module, [`crate::agent_spawn::agent_spawn`] was a pure
//! decision function with zero production callers and no model-facing tool
//! name resolved to it — so §7.7's depth/fan-out limits, §7.5's team
//! auto-join and the daemon's `SpawnTree` could never fire on a real spawn.
//! This module is the wiring, not a reimplementation: every depth, fan-out,
//! budget and team-membership judgement still belongs to `agent_spawn`, which
//! is called here with real inputs.
//!
//! # The ordering contract, and why it is copied rather than invented
//!
//! `roundhouse-flow`'s `Executor::dispatch_call` already solved the identical
//! problem for workflow `call:` children — §8.12 makes those *"a chain of
//! nested Sessions exactly as sub-agent spawning is"* — and [`dispatch_agent`]
//! mirrors its sequence step for step:
//!
//! 1. mint the child's `SessionId`;
//! 2. **reserve** one direct-child slot for it in the shared `SpawnTree`
//!    (atomic against a concurrent sibling spawn — the pre-reservation count
//!    it observes is what the fan-out predicate then judges);
//! 3. **admit** — `agent_spawn`'s depth/fan-out/budget/team fences;
//! 4. **create** the real child session and durably record its
//!    `SessionCreated`;
//! 5. **commit** the reservation into a real runtime edge.
//!
//! Every failure edge between 2 and 5 releases the reservation, so a refused
//! spawn leaves the parent's fan-out budget exactly where it found it. That
//! is the whole reason the tree distinguishes a reservation from a committed
//! child at all: without the release, eight refused spawns would permanently
//! exhaust a parent that never got a single child.
//!
//! # What this module deliberately does NOT do
//!
//! - **It does not run the child.** Spawning and tracking is the deliverable;
//!   driving the child session to completion and reporting its result back to
//!   the parent turn is a separate concern. The `prompt` argument is recorded
//!   in the spawn task's input and carried no further today.
//! - **It does not merge the child's taint back on return**
//!   ([`crate::agent_spawn::merge_taint_on_child_return`] is still uncalled),
//!   because nothing here waits for a return.
//! - **It does not build new parent/child messaging.** `LocalBus`,
//!   `MessageWaitExecutor` and `TeamRegistry::join` already work; this tool
//!   only has to produce a real session those existing paths can address.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use roundhouse_bus::limits::MAX_FAN_OUT;
use roundhouse_bus::spawn_tree::SpawnTree;
use roundhouse_bus::teams::TeamRegistry;
use roundhouse_core::{
    IsolationAttestation, Origin, SessionId, SessionSpec, TaskError, TaskId, TaskInput, TaskKind,
    TaskOutput, TaskRunner, TeamId, Tier, Usage,
};
use roundhouse_policy::{ProviderId, TaskParams};
use roundhouse_provider::{tool_def_from_schema, ToolDef, ToolResultPart};
use roundhouse_store::EventWriter;

use crate::agent_spawn::{agent_spawn, AgentSpawnInput, Budget, SpawnPolicyScope, TaintSet};
use crate::session_actor::{SessionActor, TaskCreateRequest};

/// Typed parameter shape for the `agent` builtin. Mirrors the fields of
/// [`AgentSpawnInput`] a model is allowed to choose — never `parent`,
/// `parent_depth`, `parent_direct_children` or `parent_taint`, all of which
/// are facts about the *calling* session that the dispatcher reads from the
/// real session and the real spawn tree. A model that could name its own
/// depth or direct-child count could name `0` and defeat §7.7 outright.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct AgentParams {
    /// What the sub-agent should work on.
    prompt: String,
    /// The provider the child is authorized to use. Checked against the
    /// parent's own policy scope before the child is created — §9.9's
    /// "credentials are never automatic".
    provider: String,
    /// Tokens transferred from this session's remaining budget into the
    /// child's. A transfer, not a grant (§7.7): the parent is debited.
    budget_tokens: u64,
    /// The model the child should run. Optional; it feeds the `agent` policy
    /// predicate and the recorded task input. The child does not select a
    /// provider/model of its own yet — see this module's doc comment on what
    /// running the child is not.
    model: Option<String>,
    /// The child's role on the parent's team. Defaults to `worker`; asking
    /// for `lead` requires the parent to already hold it (§7.5).
    role: Option<String>,
}

/// The `agent` tool's `ToolDef`, built from [`AgentParams`] through
/// `tool_def_from_schema` like every other repo-authored tool (S-TOOL-9).
pub fn agent_tool_def() -> ToolDef {
    tool_def_from_schema::<AgentParams>(
        "agent",
        "Spawn a sub-agent: a real child session of this one, subject to this session's \
         depth, fan-out, budget and team limits. Returns the child's session id and handle.",
    )
}

/// The tier a spawned child asks for, matching the `requested_tier` that
/// [`agent_spawn`] puts on the child's own `SessionSpec` — the most
/// restrictive real tier, never the parent's (possibly higher) one. This is
/// also the `tier_request` the parent's `agent` policy predicate judges, so
/// the two cannot disagree about what was actually asked for.
const CHILD_TIER: Tier = Tier::Sandbox;

/// A [`SpawnPolicyScope`] backed by a real, already-completed admission.
///
/// The brief's requirement is that the parent's *real* policy scope decides
/// whether a provider may be spawned against. That decision is already made,
/// by the same `SessionActor::admit_task` gate every other dispatched tool
/// call goes through, against a `TaskParams::Agent` naming this exact
/// provider — so this scope's whole job is to carry that one answer into
/// `agent_spawn` rather than to ask a second, independent question that could
/// drift from it. It authorizes exactly the provider that was admitted and
/// nothing else.
struct AdmittedProviderScope {
    admitted: String,
}

impl SpawnPolicyScope for AdmittedProviderScope {
    /// **Reads as a tautology on purpose, and is not one.** `agent_spawn` is
    /// asking "may this session spawn against this provider?"; the answer was
    /// already decided — by `SessionActor::admit_task` on a real
    /// `TaskParams::Agent`, one caller up — and this carries that decision
    /// rather than re-deriving it. The comparison is what keeps it honest: if
    /// `agent_spawn` were ever handed a provider OTHER than the admitted one,
    /// this says no rather than waving it through. See the struct's own doc
    /// comment for why a second, independent policy question would be worse
    /// than no second question.
    fn authorizes_provider(&self, provider: &str) -> bool {
        provider == self.admitted
    }
}

/// Everything [`dispatch_agent`] needs to create a real child session, which
/// `roundhouse-engine` cannot do for itself: `create_headless_session`,
/// `SessionRegistry` and `HeadlessSession` all live in `roundhouse-daemon`,
/// and nothing may depend on that crate.
#[derive(Debug)]
pub struct ChildSessionRequest {
    pub parent: SessionId,
    pub child: SessionId,
    /// The child's own depth (`parent_depth + 1`), as
    /// [`agent_spawn`] computed and §7.7 admitted it. The implementor records
    /// it so a *nested* spawn from this child can report its own real depth
    /// back through [`SubAgentHost::depth`].
    pub depth: u8,
    /// The budget [`agent_spawn`] actually moved out of the parent and into
    /// this child (§7.7: *"budget inheritance is a transfer, not a grant"*).
    ///
    /// Threaded for exactly the same reason `depth` is, and the omission
    /// would be exactly as wrong: an implementor that seeded the child's host
    /// with anything else — an unmetered default, say — would make the
    /// transfer arithmetic constrain only siblings of one parent, while the
    /// child handed ITS own sub-agents a pool its parent never gave it.
    /// Conservation has to hold at every level of the tree, not just the
    /// first, and this is the value that makes it hold.
    pub child_budget: Budget,
    /// [`crate::agent_spawn::AgentSpawnOutput::session_spec`] verbatim,
    /// including its `parent: Some(parent)`. Implementors must persist this
    /// spec, never a template of their own.
    pub spec: SessionSpec,
    /// The parent's workspace root; a child works in the same workspace.
    pub workspace_root: PathBuf,
    /// The parent's `(device, inode)` workspace identity, when it has one.
    pub workspace_identity: Option<(i64, i64)>,
}

/// A child session could not be created or durably recorded.
///
/// `detail` is for the daemon's own log only — it can carry host paths and
/// `io::Error` text. [`dispatch_agent`] never returns it to the model; the
/// model sees a fixed sentence plus `category`.
#[derive(Debug, thiserror::Error)]
#[error("{detail}")]
pub struct ChildSessionError {
    /// A static diagnostic category, safe to render into a `tracing` field
    /// and into the `TaskError.category` of the recorded failure.
    pub category: &'static str,
    pub detail: String,
}

/// The daemon-owned half of the `agent` tool.
///
/// **One host serves exactly one session — the session it is registered on.**
/// Its accessors describe THAT session (its remaining budget, its depth, its
/// team), which is why none of them takes a `SessionId`: a host that answered
/// for an arbitrary session would need a daemon-wide index of facts the
/// daemon does not keep, and a caller passing the wrong id would silently
/// spend another session's budget. `register_sub_agent_host` is the one place
/// that binding is made, and it is made against the actor that owns the host.
///
/// Registered on a session's [`SessionActor`] at construction time
/// (`SessionActor::register_sub_agent_host`), mirroring how
/// `SessionActor::register_mcp` supplies the other capability the engine
/// cannot mint for itself. A session with no host registered refuses `agent`
/// calls honestly, exactly as a session with no MCP servers refuses MCP
/// calls.
#[async_trait::async_trait]
pub trait SubAgentHost: Send + Sync {
    /// The one daemon-wide spawn tree (`DaemonResources::spawn_tree`) — never
    /// a per-session tree, or a parent and its child would count children in
    /// different places.
    fn spawn_tree(&self) -> &Arc<SpawnTree>;

    /// The one daemon-wide team registry, for §7.5's auto-join.
    fn teams(&self) -> &TeamRegistry;

    /// This session's remaining token budget. Returned as a shared, locked
    /// cell rather than by value because [`agent_spawn`] mutates it in place
    /// and rolls it back on its own late failure edges — a read-then-write
    /// pair across the crate boundary would lose both properties.
    fn budget(&self) -> Arc<Mutex<Budget>>;

    /// How deep this session itself sits in the spawn tree; `0` for a root
    /// session. The child's depth is this `+ 1`, which is what §7.7's
    /// `MAX_DEPTH` is checked against.
    fn depth(&self) -> u8;

    /// The team this session belongs to, if any. `None` skips every team
    /// fence in [`agent_spawn`] — correct for a session that is not on a
    /// team, not a way to bypass one.
    fn team(&self) -> Option<TeamId>;

    /// Creates the real child session, durably appends its `SessionCreated`
    /// event carrying `req.spec` (and therefore `spec.parent`), and takes
    /// ownership of the live session so it can be retired later.
    ///
    /// **Must clean up after itself on failure**: an implementor that has
    /// already built a real session when persistence fails tears that session
    /// down before returning `Err`. The caller's only compensation is
    /// releasing the spawn-tree reservation and refunding the budget — it has
    /// no handle on anything the implementor built.
    async fn create_child_session(&self, req: ChildSessionRequest)
        -> Result<(), ChildSessionError>;
}

/// The model-supplied half of an `agent` call, already validated.
///
/// `prompt` is deliberately validated but not carried: it is already recorded
/// verbatim in the spawn task's `TaskInput::Json`, and nothing consumes it
/// yet because this tool does not run the child (see this module's doc
/// comment). Validating it anyway keeps the published schema honest — an
/// `agent` call with no prompt is a malformed call, not a prompt-less spawn.
struct AgentArgs {
    provider: String,
    budget_tokens: u64,
    model: String,
    role: Option<String>,
}

impl AgentArgs {
    /// Parses `input` against [`AgentParams`]' published schema. Every error
    /// names only the field at fault — the model's own argument names, never
    /// a value derived from its input.
    fn parse(input: &serde_json::Value) -> Result<Self, &'static str> {
        input
            .get("prompt")
            .and_then(serde_json::Value::as_str)
            .ok_or("prompt")?;
        let provider = input
            .get("provider")
            .and_then(serde_json::Value::as_str)
            .ok_or("provider")?
            .to_string();
        let budget_tokens = input
            .get("budget_tokens")
            .and_then(serde_json::Value::as_u64)
            .ok_or("budget_tokens")?;
        // Optional fields: absent is fine, present-but-wrong-type is not —
        // silently ignoring a `role: 7` would spawn a `worker` child for a
        // call that asked for something else.
        let model = match input.get("model") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(value) => value.as_str().ok_or("model")?.to_string(),
        };
        let role = match input.get("role") {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(value.as_str().ok_or("role")?.to_string()),
        };
        Ok(AgentArgs {
            provider,
            budget_tokens,
            model,
            role,
        })
    }
}

/// Dispatches one model-issued `agent` tool call: the full reserve → admit →
/// create → commit sequence this module's doc comment describes.
///
/// Records the parent's own `TaskKind::Agent` task lifecycle exactly as
/// `agent_loop`'s built-in arm records every other dispatched call (S-LOG-1):
/// `TaskCreated` before admission (so a refused spawn is still a queryable
/// attempt), then `TaskStarted`, then a terminal `TaskCompleted`/`TaskFailed`.
///
/// `parent_task` is the `chat` task of the turn that issued the call, so the
/// spawn task hangs off it in the session's task tree.
///
/// One failure edge is deliberately not compensated: if the child session was
/// created and committed but appending the parent's `TaskCompleted` then
/// fails, this returns `Err` to the model while the child session, its
/// committed spawn-tree edge and its `SubAgentSessions` entry all remain. That
/// is consistent with how `agent_loop`'s other arms treat a post-side-effect
/// append failure — its built-in arm `?`-propagates the same
/// `record_task_completed` append after `execute_builtin` has already written
/// files or run a command, and does not undo them either. The side effect is
/// real and durably recorded (the child's own `SessionCreated` committed in
/// its own transaction); only the parent's terminal task event is missing.
pub async fn dispatch_agent(
    actor: &SessionActor,
    writer: &EventWriter,
    runner: &TaskRunner,
    host: Option<&Arc<dyn SubAgentHost>>,
    input: &serde_json::Value,
    parent_task: TaskId,
) -> Result<Vec<ToolResultPart>, String> {
    let parent = actor.session_id();

    let Some(host) = host else {
        // The same shape `agent_loop`'s MCP arm uses when a session has no
        // MCP host: an honest, recorded refusal rather than a pretence that
        // the capability exists.
        return Err(refuse(
            writer,
            runner,
            actor,
            input,
            parent_task,
            "sub_agent_host_unavailable",
            "sub-agent spawning is not available for this session".to_string(),
        )
        .await);
    };

    let args = match AgentArgs::parse(input) {
        Ok(args) => args,
        Err(field) => {
            return Err(refuse(
                writer,
                runner,
                actor,
                input,
                parent_task,
                "bad_tool_arguments",
                format!("the `agent` tool call is missing or has an invalid `{field}` argument"),
            )
            .await);
        }
    };

    // S-LOG-1: mint and durably record the spawn this dispatch is ATTEMPTING
    // before admission decides its fate.
    let task_id = TaskId::new();
    let created = runner.record_task_created(
        parent,
        0, // ignored — EventWriter::append assigns the real per-session seq
        crate::agent_loop::now_ts(),
        task_id,
        TaskKind::Agent,
        Some(parent_task),
        Origin::Model,
        TaskInput::Json(input.clone()),
        1,
    );
    writer
        .append(created)
        .await
        .map_err(|e| format!("failed to record the dispatched agent spawn: {e}"))?;

    // The parent's real policy scope (§6.1/§9.9), through the same gate every
    // other dispatched tool call passes: `TaskParams::Agent` reaches
    // `Predicate::Agent` here and nowhere else.
    let req = TaskCreateRequest {
        kind: TaskKind::Agent,
        origin: Origin::Model,
        is_finally_step: false,
        params: TaskParams::Agent {
            provider: ProviderId(args.provider.clone()),
            model: args.model.clone(),
            tier_request: CHILD_TIER,
        },
    };
    if let Err(admit_err) = actor.admit_task(&req).await {
        return Err(
            crate::agent_loop::record_denial(writer, runner, parent, task_id, admit_err).await,
        );
    }

    let started = runner.record_task_started(
        parent,
        0,
        crate::agent_loop::now_ts(),
        task_id,
        // The spawn itself runs in-process; the CHILD gets its own real
        // isolation from `create_child_session`. Claiming the parent's tier
        // for this task would attest something this task never ran under —
        // the same placeholder `agent_loop`'s MCP arm uses for the same
        // reason.
        IsolationAttestation {
            tier: Tier::None,
            digest: String::new(),
            net_enforced: false,
        },
        None,
        1,
    );
    writer
        .append(started)
        .await
        .map_err(|e| format!("failed to record the dispatched agent spawn starting: {e}"))?;

    match spawn_child(actor, host, &args).await {
        Ok(spawned) => {
            let text = format!(
                "spawned sub-agent {handle} as session {child}",
                handle = spawned.handle,
                child = spawned.child
            );
            let completed = runner.record_task_completed(
                parent,
                0,
                crate::agent_loop::now_ts(),
                task_id,
                TaskOutput::Text(text.clone()),
                Usage::default(),
                1,
            );
            writer.append(completed).await.map_err(|e| {
                format!("failed to record the dispatched agent spawn completing: {e}")
            })?;
            Ok(vec![ToolResultPart { text }])
        }
        Err(refusal) => {
            tracing::warn!(
                session_id = %parent,
                category = refusal.category,
                detail = %refusal.detail,
                "a sub-agent spawn was refused"
            );
            let failed = runner.record_task_failed(
                parent,
                0,
                crate::agent_loop::now_ts(),
                task_id,
                TaskError {
                    message: refusal.model_message.clone(),
                    category: refusal.category.into(),
                },
                false,
                1,
            );
            writer
                .append(failed)
                .await
                .map_err(|e| format!("failed to record the dispatched agent spawn failing: {e}"))?;
            Err(refusal.model_message)
        }
    }
}

/// A spawn that did not happen, split into what the operator's log gets
/// (`detail`, which may carry host paths) and what the model gets
/// (`model_message`, built only from this module's own literals plus values
/// the model itself supplied).
struct SpawnRefusal {
    category: &'static str,
    detail: String,
    model_message: String,
}

struct SpawnedChild {
    child: SessionId,
    handle: String,
}

/// Steps 1-6 of this module's ordering contract, with the reservation
/// released on every edge that can fail after it is taken.
async fn spawn_child(
    actor: &SessionActor,
    host: &Arc<dyn SubAgentHost>,
    args: &AgentArgs,
) -> Result<SpawnedChild, SpawnRefusal> {
    let parent = actor.session_id();
    let tree = host.spawn_tree();

    // 1. The child's id, minted here so the reservation, the team join, the
    //    durable `SessionCreated` and the committed edge all name one session.
    let child = SessionId::new();

    // 2. The atomic slot hold. `direct_children` is read first: that
    //    pre-reservation count is what the fan-out predicate judges, exactly
    //    as `WorkflowSessionTree::reserve_child` reads it for a `call:` child.
    let direct_children = tree.direct_children(parent);
    if tree.reserve_child(parent, child, MAX_FAN_OUT).is_none() {
        return Err(SpawnRefusal {
            category: "fan_out_limit_exceeded",
            detail: format!(
                "session {parent} already holds {MAX_FAN_OUT} direct-child slots (committed \
                 plus reserved)"
            ),
            model_message: "this session has no sub-agent slots left".to_string(),
        });
    }

    // 3. The real §7.7/§7.5/§9.9 fences, in `agent_spawn` — not reimplemented
    //    here. Anything from here on releases the reservation first.
    let budget_cell = host.budget();
    let spawn_input = AgentSpawnInput {
        workspace: actor.session_spec().workspace,
        parent,
        child_id: child,
        parent_depth: host.depth(),
        parent_direct_children: direct_children,
        team: host.team(),
        role: args.role.clone(),
        provider: args.provider.clone(),
        budget_tokens: args.budget_tokens,
        // §6.8 seeds the child's taint from the parent's CURRENT taint, and
        // this workspace still has no live per-session taint tracker (see
        // `agent_loop::dispatch_mcp`, which picks the same conservative value
        // for the same reason). `Tainted` is the fail-closed of the two: a
        // child can only ever be at least as restricted as its parent, never
        // laundered clean by a tracker that does not exist yet. Revisit
        // together with that call site once one does.
        parent_taint: TaintSet { tainted: true },
    };

    let outcome = {
        let mut budget = match budget_cell.lock() {
            Ok(budget) => budget,
            Err(_) => {
                tree.release_child_reservation(parent, child);
                return Err(SpawnRefusal {
                    category: "budget_unavailable",
                    detail: format!("session {parent}'s budget lock is poisoned"),
                    model_message: "this session's budget could not be read".to_string(),
                });
            }
        };
        agent_spawn(
            host.teams(),
            &AdmittedProviderScope {
                admitted: args.provider.clone(),
            },
            &mut budget,
            spawn_input,
        )
    };
    let out = match outcome {
        Ok(out) => out,
        Err(err) => {
            tree.release_child_reservation(parent, child);
            return Err(SpawnRefusal {
                category: spawn_error_category(&err),
                detail: err.to_string(),
                model_message: spawn_error_message(&err),
            });
        }
    };

    // 4/5. The real child session plus its durable `SessionCreated`. The
    //      implementor owns cleanup of anything it built; this side owns the
    //      reservation, the debited budget and the team roster.
    let create = host
        .create_child_session(ChildSessionRequest {
            parent,
            child,
            depth: out.child_spec.depth,
            child_budget: out.child_budget,
            spec: out.session_spec,
            workspace_root: actor.workspace_root().to_path_buf(),
            workspace_identity: actor.workspace_identity(),
        })
        .await;
    if let Err(err) = create {
        tree.release_child_reservation(parent, child);
        // `agent_spawn` already debited the parent and joined the child to
        // the team. The child does not exist, so both must be undone or a
        // failed spawn would permanently cost the parent tokens and leave a
        // phantom on the roster.
        match budget_cell.lock() {
            Ok(mut budget) => {
                budget.remaining_tokens = budget
                    .remaining_tokens
                    .saturating_add(out.child_budget.remaining_tokens);
            }
            // The lock was readable moments ago, so this means the spawn
            // itself poisoned it. Never silent: the parent has been debited
            // for a child that does not exist, and nothing else will ever
            // notice or fix that.
            Err(_) => tracing::warn!(
                session_id = %parent,
                "could not refund a failed sub-agent spawn's budget transfer: this session's \
                 budget lock is poisoned, so the parent stays debited for a child that was \
                 never created"
            ),
        }
        if let Some(team) = host.team() {
            let _ = host.teams().mark_member_ended(team, child);
        }
        return Err(SpawnRefusal {
            category: err.category,
            detail: err.detail,
            model_message: "the sub-agent session could not be created".to_string(),
        });
    }

    // 6. The reservation becomes a real runtime edge.
    tree.commit_child_reservation(parent, child);

    Ok(SpawnedChild {
        child,
        handle: out.handle,
    })
}

/// A static `TaskError.category` per refusal reason — never the error's own
/// `Display`, which interpolates ids and counts.
fn spawn_error_category(err: &crate::agent_spawn::SpawnError) -> &'static str {
    use crate::agent_spawn::SpawnError;
    use roundhouse_bus::types::BusError;
    match err {
        SpawnError::ProviderNotAuthorized { .. } => "provider_not_authorized",
        SpawnError::InsufficientBudget { .. } => "insufficient_budget",
        SpawnError::Bus(BusError::DepthLimitExceeded { .. }) => "depth_limit_exceeded",
        SpawnError::Bus(BusError::FanOutLimitExceeded { .. }) => "fan_out_limit_exceeded",
        SpawnError::Bus(BusError::TeamSizeLimitExceeded { .. }) => "team_size_limit_exceeded",
        SpawnError::Bus(BusError::NotAuthorized { .. }) => "team_not_authorized",
        SpawnError::Bus(_) => "spawn_refused",
    }
}

/// What the model reads back. Says which limit it hit — useful and
/// disclosing nothing the model did not already supply or already know about
/// its own session — without embedding ids, counts or host state.
fn spawn_error_message(err: &crate::agent_spawn::SpawnError) -> String {
    use crate::agent_spawn::SpawnError;
    use roundhouse_bus::types::BusError;
    match err {
        SpawnError::ProviderNotAuthorized { .. } => {
            "the requested provider is not authorized for a sub-agent of this session".to_string()
        }
        SpawnError::InsufficientBudget { .. } => {
            "this session does not have enough remaining budget for the requested transfer"
                .to_string()
        }
        SpawnError::Bus(BusError::DepthLimitExceeded { .. }) => {
            "sub-agents may not be nested any deeper than this".to_string()
        }
        SpawnError::Bus(BusError::FanOutLimitExceeded { .. }) => {
            "this session has no sub-agent slots left".to_string()
        }
        SpawnError::Bus(BusError::TeamSizeLimitExceeded { .. }) => {
            "this session's team is full".to_string()
        }
        SpawnError::Bus(BusError::NotAuthorized { .. }) => {
            "this session may not spawn a sub-agent into that team, or with that role".to_string()
        }
        SpawnError::Bus(_) => "the sub-agent spawn was refused".to_string(),
    }
}

/// Records an `agent` refusal raised before any `TaskCreated` was minted, as
/// its own `TaskCreated`/`TaskFailed` pair — the same "a refused call is
/// still a real, queryable attempt" guarantee `agent_loop`'s built-in and MCP
/// arms already give.
async fn refuse(
    writer: &EventWriter,
    runner: &TaskRunner,
    actor: &SessionActor,
    input: &serde_json::Value,
    parent_task: TaskId,
    category: &'static str,
    message: String,
) -> String {
    crate::agent_loop::record_unadmitted_refusal(
        writer,
        runner,
        actor.session_id(),
        TaskKind::Agent,
        parent_task,
        input,
        category,
        message,
    )
    .await
    .unwrap_or_else(|e| e)
}
