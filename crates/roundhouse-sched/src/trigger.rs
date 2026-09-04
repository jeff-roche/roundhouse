//! Core trigger/binding/event types for Subsystem A (Scheduling).
//!
//! `TriggerSpec` describes *what* starts a job (a cron schedule, a webhook,
//! a file-system watch, another session's message, ...); `Binding` pairs a
//! `TriggerSpec` with the `JobId` it starts plus its overlap policy and
//! scheduling cursor; `TriggerEvent` is the durable record of one firing,
//! persisted by Task 4 for dedupe. See
//! `docs/architecture/05-scheduling-and-workflows.md`.
use chrono::{DateTime, Utc};
use chrono_tz::Tz;
use roundhouse_core::{Address, BindingId, JobId, SessionId};
use serde::{Deserialize, Deserializer, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CatchUp {
    Latest,
    All,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DstGap {
    FireAtGapEnd,
    Skip,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DstAmbiguous {
    First,
    Second,
    Both,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Glob(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RefPattern(pub String);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsEventMask {
    pub create: bool,
    pub modify: bool,
    pub remove: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GitEventMask {
    pub push: bool,
    pub tag: bool,
    pub branch_created: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WebhookAuth {
    None,
    SharedSecret { header: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum OutcomeFilter {
    Any,
    /// Matches `report.outcome`; kept as a string rather than
    /// `roundhouse-flow`'s outcome enum to stay decoupled — `roundhouse-flow`
    /// depends on `roundhouse-sched`, not the other way around.
    Outcome(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TriggerSpec {
    Manual,
    Cron {
        expr: String,
        tz: Tz,
        catch_up: CatchUp,
        jitter: Duration,
        dst_gap: DstGap,
        dst_ambiguous: DstAmbiguous,
    },
    Interval {
        every: Duration,
        align: bool,
        anchor: Option<DateTime<Utc>>,
    },
    Fs {
        roots: Vec<PathBuf>,
        include: Vec<Glob>,
        exclude: Vec<Glob>,
        events: FsEventMask,
        debounce: Duration,
        coalesce: bool,
    },
    Git {
        repo: PathBuf,
        on: GitEventMask,
        refs: Vec<RefPattern>,
    },
    Webhook {
        path: String,
        auth: WebhookAuth,
        input_schema: Option<serde_json::Value>,
    },
    RunComplete {
        source_binding: BindingId,
        when: OutcomeFilter,
    },
    /// A4 (§7.3 deliberately cut topic pub/sub — "no subject space, no
    /// wildcard subscriptions"): binds on an `Address` (§7.2), never a topic
    /// string. Binding this variant creates a durable
    /// `Address::Handle { workspace, name }` that the scheduler itself owns
    /// (Task 4's `bind_message_trigger`); a `message_send` to that handle,
    /// resolved daemon-side exactly like any other address, is what fires
    /// the trigger. `filter` narrows on the message's typed payload *after*
    /// that resolution — it is never a topic/subject match. Kept as the
    /// expression-language's source text (`Option<String>`, evaluated by
    /// `roundhouse-flow`'s `${{ }}` engine at fire time) rather than a typed
    /// `Expr` AST, because `roundhouse-flow` depends on `roundhouse-sched`
    /// and not the other way around — this crate cannot name
    /// `roundhouse-flow`'s expression type without an illegal upward
    /// dependency.
    Message {
        address: Address,
        filter: Option<String>,
    },
}

/// Sanity ceiling on `OverlapPolicy::Concurrent`'s `max`. Without this, a
/// binding configured (accidentally, maliciously, or by a corrupted
/// persisted record — this policy round-trips through `serde` with no
/// validation of its own) with `max: u32::MAX` would disable the
/// concurrency bound entirely while still looking like a bounded policy to
/// anyone reading the config. Enforced at deserialize time (see
/// `OverlapPolicy`'s manual `Deserialize` impl below) rather than only at
/// the point `roundhouse-sched::admission` reads the policy, so a
/// persisted `Binding` never carries an unbounded value in the first
/// place — admission-round-1 fix that only clamped at the read site left
/// exactly that gap (fix round 2, finding L1). Chosen the same way this
/// module's other sanity ceilings are (see `scheduler.rs`'s
/// `MAX_INTERVAL`): comfortably above any concurrency a real deployment
/// would legitimately configure, while still bounding the worst case.
/// Re-exported from `roundhouse_sched::admission` so existing callers of
/// that module see no path change.
pub const MAX_OVERLAP_CONCURRENCY: u32 = 1_000;

/// Sanity ceiling on `OverlapPolicy::Queue`'s `depth`, for the same reason
/// and by the same reasoning as [`MAX_OVERLAP_CONCURRENCY`].
pub const MAX_OVERLAP_QUEUE_DEPTH: u32 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OverlapPolicy {
    Skip,
    Queue { depth: u32 },
    Concurrent { max: u32 },
    CancelPrevious,
}

/// Serde wire shape for [`OverlapPolicy`] — identical variants/fields, so
/// it reads exactly what `OverlapPolicy`'s derived `Serialize` writes.
/// `OverlapPolicy`'s own `Deserialize` impl (below) deserializes into this
/// first and then validates/clamps `Queue`'s `depth` and `Concurrent`'s
/// `max`, which a plain `#[derive(Deserialize)]` on `OverlapPolicy` itself
/// cannot do.
#[derive(Deserialize)]
enum OverlapPolicyWire {
    Skip,
    Queue { depth: u32 },
    Concurrent { max: u32 },
    CancelPrevious,
}

impl<'de> Deserialize<'de> for OverlapPolicy {
    /// Fix round 2, finding L1: a bare `#[derive(Deserialize)]` let a
    /// persisted `Binding` carry `Concurrent { max: u32::MAX }` or
    /// `Queue { depth: u32::MAX }` — a policy that *looks* bounded but
    /// isn't — with the only enforcement living in
    /// `roundhouse_sched::admission::decide_admission`'s use-site `.min()`
    /// clamp. This impl clamps at load time instead, so the ceiling is a
    /// property of the value from the moment it's decoded, and logs once
    /// (at `WARN`) naming both the configured and the effective value so a
    /// misconfiguration is visible rather than silently rewritten.
    /// `decide_admission`'s own clamp stays in place as a silent backstop
    /// for policies constructed directly in Rust code (this enum's fields
    /// are public, so nothing stops `OverlapPolicy::Concurrent { max:
    /// u32::MAX }` as a struct literal, which never goes through
    /// `Deserialize` at all) — the warning here covers the realistic
    /// "loaded from persisted/external config" vector this finding is
    /// about.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match OverlapPolicyWire::deserialize(deserializer)? {
            OverlapPolicyWire::Skip => OverlapPolicy::Skip,
            OverlapPolicyWire::CancelPrevious => OverlapPolicy::CancelPrevious,
            OverlapPolicyWire::Queue { depth } => {
                let effective = depth.min(MAX_OVERLAP_QUEUE_DEPTH);
                if effective != depth {
                    tracing::warn!(
                        configured = depth,
                        effective,
                        "OverlapPolicy::Queue depth clamped to the sanity ceiling at load time"
                    );
                }
                OverlapPolicy::Queue { depth: effective }
            }
            OverlapPolicyWire::Concurrent { max } => {
                let effective = max.min(MAX_OVERLAP_CONCURRENCY);
                if effective != max {
                    tracing::warn!(
                        configured = max,
                        effective,
                        "OverlapPolicy::Concurrent max clamped to the sanity ceiling at load time"
                    );
                }
                OverlapPolicy::Concurrent { max: effective }
            }
        })
    }
}

impl OverlapPolicy {
    pub fn default_for(spec: &TriggerSpec) -> Self {
        match spec {
            TriggerSpec::Cron { .. } | TriggerSpec::Interval { .. } => OverlapPolicy::Skip,
            TriggerSpec::Webhook { .. } | TriggerSpec::Message { .. } => {
                OverlapPolicy::Queue { depth: 8 }
            }
            TriggerSpec::Fs { .. } => OverlapPolicy::CancelPrevious,
            TriggerSpec::Manual | TriggerSpec::Git { .. } | TriggerSpec::RunComplete { .. } => {
                OverlapPolicy::Skip
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Binding {
    pub id: BindingId,
    pub job_id: JobId,
    pub spec: TriggerSpec,
    pub overlap: OverlapPolicy,
    pub last_fired_for: Option<DateTime<Utc>>,
    pub next_fire_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

impl Binding {
    pub fn new(job_id: JobId, spec: TriggerSpec) -> Self {
        let overlap = OverlapPolicy::default_for(&spec);
        Binding {
            id: BindingId::new(),
            job_id,
            spec,
            overlap,
            last_fired_for: None,
            next_fire_at: None,
            enabled: true,
        }
    }

    pub fn new_cron(job_id: JobId, expr: String, tz: Tz) -> Self {
        Self::new(
            job_id,
            TriggerSpec::Cron {
                expr,
                tz,
                catch_up: CatchUp::Latest,
                jitter: Duration::from_secs(0),
                dst_gap: DstGap::FireAtGapEnd,
                dst_ambiguous: DstAmbiguous::First,
            },
        )
    }

    /// The `SessionId` this binding registers a bus mailbox under when its
    /// spec is `Message` (Task 4). Deliberately a re-typing of the binding's
    /// own `BindingId`, not a second minted identity — a `Message` binding
    /// *is* the addressable recipient (§8.2: "the binding is the addressable
    /// recipient, the same way any other named session/handle is
    /// addressable"), so there is exactly one stable id per binding across
    /// daemon restarts, with no separate id to persist or reconcile.
    pub fn trigger_session_id(&self) -> SessionId {
        SessionId::from_uuid(self.id.as_uuid())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TriggerEvent {
    pub binding_id: BindingId,
    pub idempotency_key: String,
    pub scheduled_for: DateTime<Utc>,
    pub fired_at: DateTime<Utc>,
    pub is_catch_up: bool,
    pub session_id: Option<SessionId>,
}
