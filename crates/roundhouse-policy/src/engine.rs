use crate::{FsOp, MemoryOp, Method, PolicyInput, ProviderId, ServerId, TaskParams};
use roundhouse_core::{MemoryScope, PolicyDecision, SessionId, TeamId, Tier};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    Builtin,
    UserGlobal,
    Project,
    Workspace,
    Grant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    Ask,
    Deny,
}

impl From<Outcome> for PolicyDecision {
    fn from(o: Outcome) -> Self {
        match o {
            Outcome::Allow => PolicyDecision::Allow,
            Outcome::Ask => PolicyDecision::Ask,
            Outcome::Deny => PolicyDecision::Deny,
        }
    }
}

/// This plan's own human-readable rule identifier ("sealed:ssh-write",
/// "grant:<session>:<task>", …) — deliberately distinct from, and not
/// interchangeable with, Phase 0's frozen `roundhouse_core::RuleId(pub u64)`
/// that `EventPayload::TaskDecided` / `SuspendReason::AwaitingApproval`
/// actually persist. **Gap flagged, not silently papered over:** turning a
/// `policy::RuleId` string into a stable `core::RuleId(u64)` for those event
/// payloads needs a rule-compiler interning table (assigned once when a
/// `CompiledRule` is compiled from config, stable across reloads for the same
/// rule text) that this plan does not specify — the same "materialized schema
/// is Phase 0/1's responsibility" caveat this plan's own self-review already
/// makes for the `tasks` cache table applies here too. `approval::
/// core_rule_id_from_policy_rule_id` (Task 15) closes *part* of this gap with
/// a one-way blake3-hash truncation used only when minting a persisted
/// `SuspendReason::AwaitingApproval` event — it is explicitly a lossy
/// stopgap, not the real bidirectional interning table this comment
/// describes; that table is still unbuilt. Everywhere below that
/// constructs a real `EventPayload` (Tasks 1, 2, 15, 21), the `Option<RuleId>`
/// written is the frozen `core::RuleId(u64)`; everywhere else (`Decision`,
/// `CompiledRule`, audit/debug output) it is this string type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleId(pub String);

#[derive(Debug, Clone)]
pub struct Decision {
    pub outcome: Outcome,
    pub rule: Option<RuleId>,
}

/// Covers all seven `TaskParams` variants — the audit's "only Fs*/Shell
/// predicates ever get defined" bug meant no rule could ever Allow a
/// git/http/mcp/agent task regardless of config; every variant gets a
/// matcher here.
#[derive(Debug, Clone)]
pub enum Predicate {
    FsPrefix {
        op: FsOp,
        prefix: PathBuf,
    },
    FsExact {
        op: FsOp,
        path: PathBuf,
    },
    /// Matched against a single already-resolved `(program, argv)` pipeline
    /// node (Task 13's `decide_pipeline` builds exactly one `TaskParams::Shell`
    /// per node) — never against a whole AST, so there is nothing here for a
    /// predicate to misresolve back to a different node (audit finding 1).
    Shell {
        program: String,
        matcher: ArgMatcher,
        allow_interpreter: bool,
    },
    Http {
        method: Option<Method>,
        url_prefix: String,
        /// When `true`, `url` must equal `url_prefix` exactly rather than
        /// merely start with it. Added for Task 15's `synthesize_grant`
        /// (security fix round 1, finding 1): a plain `starts_with` match
        /// let an approved URL like `https://api.example.com/v1/status` also
        /// silently cover `.../v1/status?exfil=...` or
        /// `.../v1/statusSECRET` — a human approving one exact call must not
        /// grant a family of calls. Every non-grant caller (config-authored
        /// rules via `Predicate::http_prefix`) sets this `false`, preserving
        /// prefix semantics for everyone except grants.
        exact: bool,
    },
    Mcp {
        server: ServerId,
        tool: Option<String>,
        /// Task 22 (W4): binds the approved call's arguments. `None` means
        /// unscoped — matches any `args`, the pre-fix behaviour, retained as
        /// an explicit opt-in for genuinely argument-independent approvals
        /// (e.g. a read-only discovery tool where the arguments never carry
        /// anything sensitive). Before this field existed, approving one MCP
        /// call with specific arguments silently granted every future call
        /// to that tool regardless of arguments — the real least-privilege
        /// bug every sibling grant type (`Http`/`Git`/`Shell`) was already
        /// fixed for. Same idiom as `Predicate::Memory`'s `session` field:
        /// `matches`'s specificity `bound` is bumped when this is `Some`, so
        /// a more specific (args-bound) grant outranks a less specific one.
        args: Option<ArgsPattern>,
    },
    Git {
        subcommand: String,
        argv_prefix: Vec<String>,
        /// When `true`, `argv` must equal `argv_prefix` exactly rather than
        /// merely start with it. Added for Task 15's `synthesize_grant`
        /// (security fix round 1, finding 2): a plain `starts_with` match
        /// let an approved `git push origin main` also silently cover
        /// `git push origin main --force` (or any other appended args) —
        /// a human approving one exact invocation must not grant a family
        /// of invocations. Every non-grant caller (config-authored rules via
        /// `Predicate::git`) sets this `false`, preserving prefix semantics
        /// for everyone except grants.
        exact: bool,
    },
    Agent {
        provider: Option<ProviderId>,
        model: Option<String>,
        /// **Task 21 (W4): this is now an isolation FLOOR, not a ceiling,
        /// despite the name.** `Tier` (`roundhouse-core/src/tier.rs`) derives
        /// `Ord` over ascending isolation (`None < Worktree < Sandbox <
        /// Container < Remote`). `matches` used to require
        /// `tier_request <= max_tier`, so a grant approved at, say,
        /// `max_tier: Remote` also covered `tier_request: None` — approving
        /// the *most*-isolated request silently permitted the *least*-isolated
        /// one. The comparison is now `tier_request >= max_tier`: a request is
        /// covered only if it asks for at least as much isolation as was
        /// approved. The field is **deliberately not renamed** to something
        /// like `min_tier` (orchestrator Ruling W4-5): another lane is
        /// concurrently writing new `Predicate::Agent` construction sites
        /// against this field's name on `main`, and a rename would hand that
        /// merge a compile break for zero behavioural gain. A post-merge
        /// rename is expected but out of scope here.
        ///
        /// **B3 (review round 2) — this same floor comparison applies to
        /// `Deny` rules too, and it inverts the meaning an operator is most
        /// likely to expect from one.** `Predicate::matches` doesn't know or
        /// care what `Outcome` its rule carries — a matching `Deny` wins
        /// outright, same as a matching `Allow`. An operator writing "deny
        /// agent spawns that ask for weak isolation" would naturally author
        /// `Deny` with `max_tier: Sandbox`, expecting it to deny
        /// `None`/`Worktree`/`Sandbox`. What it actually denies is
        /// `tier_request >= Sandbox`, i.e. `Sandbox`/`Container`/`Remote` —
        /// and lets `None`/`Worktree` (the actually-weak requests) through.
        /// To deny weak isolation, the operator must instead author the
        /// floor at `None` (which denies everything, being the universal
        /// floor) — there is no config shape today that expresses "deny
        /// anything below X" directly.
        ///
        /// This is a documented limit, not something to fix by making the
        /// comparison direction depend on `outcome` (orchestrator Ruling
        /// W4-17 rejected that: one field meaning two opposite things
        /// depending on its own rule's outcome is a worse footgun than the
        /// one it would close). There is also no live exposure today: the
        /// only `Predicate::Agent` construction sites in the workspace are
        /// `synthesize_grant` (always `Allow`-shaped) and this crate's own
        /// tests, and there is no config→`Predicate` compiler for `Agent` at
        /// all yet. The real fix, when a rule compiler for `Agent` exists,
        /// is a shape change — two separate optional bounds (a floor for
        /// `Allow`, a ceiling for `Deny`, or similar) — not a same-field
        /// direction flip.
        max_tier: Tier,
    },
    /// Task 20 (W4): binds a config-authored or synthesized grant to an
    /// exact `(scope, op)` pair, matching every sibling variant's
    /// least-privilege contract.
    ///
    /// Fix round 1 (Ruling W4-11): `session` binds the requesting session —
    /// `None` means "any session" (what a config-authored rule, which has no
    /// session to name, must use), `Some(s)` requires the request's `session`
    /// to equal `s` exactly. This is not optional polish: `PolicyEngine` is
    /// held behind an `Arc` shared across every session actor, so a rule with
    /// no session binding matches every session's identical request. Before
    /// this field existed, a durable `Always`-scoped grant synthesized from
    /// session A's `MemoryScope::User` request also matched session B's
    /// (including an untrusted sub-agent's) — `synthesize_grant` binds
    /// `Some(session)` from the params being generalized, the same
    /// least-privilege contract `Http`/`Git`/`Shell` already follow for their
    /// own fields.
    ///
    /// Correcting an earlier, incorrect claim in this comment: this field is
    /// *not* redundant with `GrantScope::Session` or `GrantProvenance`.
    /// `GrantScope::Session` is documented elsewhere in this crate as "not
    /// enforced yet" and `into_rule_for_installation` refuses to install a
    /// rule for it at all; `GrantProvenance` is folded into the rule's id
    /// string for audit purposes only and is never read by `matches`. This
    /// `session` field is the only thing that actually restricts which
    /// session a `Predicate::Memory` rule matches.
    ///
    /// A `Team`-scoped rule of this kind is still inert for the read/write
    /// asymmetry the security model actually relies on: `PolicyEngine::decide`
    /// short-circuits `MemoryScope::Team` before rule matching is ever
    /// reached (see `decide`'s `TaskParams::Memory` arm), so this predicate
    /// can never be used to route around `TeamMembership` regardless of how
    /// `session` is bound. It only ever participates in ordinary rule
    /// matching for `User`/`Project` scope, where this binding is live.
    Memory {
        scope: MemoryScope,
        op: MemoryOp,
        session: Option<SessionId>,
    },
}

/// How a `Predicate::Shell`'s argv is matched against `TaskParams::Shell`'s
/// resolved argv. `Glob` stores raw patterns (compiled lazily at match time,
/// not eagerly) — see the `Predicate::matches` `Shell` arm for why an
/// invalid pattern must not panic.
#[derive(Debug, Clone)]
pub enum ArgMatcher {
    Exact(Vec<String>),
    ArgvPrefix(Vec<String>),
    /// Positional glob matching: pattern index `i` is checked ONLY against
    /// `argv[i]` — pattern 0 against `argv[0]`, pattern 1 against `argv[1]`,
    /// and so on. This is NOT "any pattern matches any arg": a pattern with
    /// no corresponding argv slot (argv shorter than the pattern list) fails
    /// to match that position, and an argv slot with no corresponding
    /// pattern is simply unconstrained (not checked at all — only the first
    /// `patterns.len()` argv positions are constrained). E.g.
    /// `Glob(vec!["*.rs".into()])` matches `["a.rs"]` and `["a.rs", "extra"]`
    /// but not `["subdir", "a.rs"]`.
    Glob(Vec<String>),
}

/// How a `Predicate::Mcp`'s `args` binds against `TaskParams::Mcp`'s
/// `args: serde_json::Value` (Task 22, W4). `Prefix` is an **object-subset
/// match** — every key/value in the pattern must be present and equal in the
/// candidate; extra keys in the candidate are allowed. This is deliberately
/// not JSON-schema matching (no wildcards, no type constraints, no nested
/// subset matching) — sufficient for "these specific keys must match"
/// without building a schema engine.
#[derive(Debug, Clone)]
pub enum ArgsPattern {
    /// The candidate `args` must equal this value exactly.
    Exact(serde_json::Value),
    /// The candidate `args` must be a JSON object containing every key in
    /// this map with an equal value. A non-object candidate never matches —
    /// fail closed, not a vacuous match.
    ///
    /// **B4 (review round 2), operator footgun:** this only checks that the
    /// listed keys are present with the listed values — it does not check
    /// that the candidate has *no other* keys. `Prefix({"path": "/tmp/x"})`
    /// is also satisfied by `{"path": "/tmp/x", "recursive": true}`. An
    /// operator authoring a `Prefix` rule for a tool where an unlisted key
    /// can widen the operation (a `recursive`/`force`/`overwrite`-style flag,
    /// for instance) must list every key that matters, or use `Exact`
    /// instead — `Prefix` alone does not bound the operation to what was
    /// actually intended. Not reachable from grant synthesis today (grant
    /// synthesis always emits `Exact` — see `synthesize_grant`'s `Mcp` arm),
    /// so this is purely a hazard for a human- or config-authored `Prefix`
    /// rule, not a live bypass.
    Prefix(serde_json::Map<String, serde_json::Value>),
}

impl ArgsPattern {
    fn matches(&self, candidate: &serde_json::Value) -> bool {
        match self {
            ArgsPattern::Exact(expected) => candidate == expected,
            ArgsPattern::Prefix(required) => match candidate {
                serde_json::Value::Object(obj) => {
                    required.iter().all(|(k, v)| obj.get(k) == Some(v))
                }
                // Fail closed: a Prefix pattern is meaningless against a
                // non-object candidate, so it must never match one.
                _ => false,
            },
        }
    }
}

impl Predicate {
    /// A bare program-name match: any argv is accepted (empty required prefix).
    pub fn program(p: &str) -> Self {
        Predicate::Shell {
            program: p.to_string(),
            matcher: ArgMatcher::ArgvPrefix(vec![]),
            allow_interpreter: false,
        }
    }
    /// A program match requiring `argv` to start with `prefix` (in order,
    /// from position 0).
    pub fn argv_prefix(program: &str, prefix: &[&str]) -> Self {
        Predicate::Shell {
            program: program.to_string(),
            matcher: ArgMatcher::ArgvPrefix(prefix.iter().map(|s| s.to_string()).collect()),
            allow_interpreter: false,
        }
    }
    pub fn fs_write_prefix(p: &str) -> Self {
        Predicate::FsPrefix {
            op: FsOp::Write,
            prefix: PathBuf::from(p),
        }
    }
    pub fn fs_write_exact(p: &str) -> Self {
        Predicate::FsExact {
            op: FsOp::Write,
            path: PathBuf::from(p),
        }
    }
    pub fn fs_edit_prefix(p: &str) -> Self {
        Predicate::FsPrefix {
            op: FsOp::Edit,
            prefix: PathBuf::from(p),
        }
    }
    pub fn fs_edit_exact(p: &str) -> Self {
        Predicate::FsExact {
            op: FsOp::Edit,
            path: PathBuf::from(p),
        }
    }
    pub fn http_prefix(method: Option<Method>, url_prefix: &str) -> Self {
        Predicate::Http {
            method,
            url_prefix: url_prefix.to_string(),
            exact: false,
        }
    }
    /// Unscoped by arguments (`args: None`) — the convenience constructor
    /// config-authored rules use, which have no specific approved call to
    /// bind to. A synthesized grant (`approval::synthesize_grant`) builds
    /// `Predicate::Mcp` directly instead, defaulting to `ArgsPattern::Exact`.
    pub fn mcp(server: ServerId, tool: Option<String>) -> Self {
        Predicate::Mcp {
            server,
            tool,
            args: None,
        }
    }
    pub fn git(subcommand: &str, argv_prefix: &[&str]) -> Self {
        Predicate::Git {
            subcommand: subcommand.to_string(),
            argv_prefix: argv_prefix.iter().map(|s| s.to_string()).collect(),
            exact: false,
        }
    }
    pub fn agent(provider: Option<ProviderId>, model: Option<String>, max_tier: Tier) -> Self {
        Predicate::Agent {
            provider,
            model,
            max_tier,
        }
    }

    /// `outcome` is the *rule's own* outcome this predicate is attached to —
    /// needed only by the `Shell` arm's interpreter gate (see its comment):
    /// an interpreter program must force a bare `Allow` rule to fall through
    /// to no-match, but must NOT do the same to an explicit `Deny` rule,
    /// which is at least as restrictive as the default `Ask` a suppressed
    /// match would otherwise fall back to.
    fn matches(&self, params: &TaskParams, outcome: Outcome) -> Option<(usize, usize)> {
        // returns (literal_prefix_len, bound_predicate_count) on match
        match (self, params) {
            (
                Predicate::FsExact {
                    op: pop,
                    path: ppath,
                },
                TaskParams::Fs {
                    op,
                    canonical: Ok(c),
                    ..
                },
            ) if matches_op(pop, op) && c == ppath => Some((ppath.to_string_lossy().len(), 2)),
            (
                Predicate::FsPrefix { op: pop, prefix },
                TaskParams::Fs {
                    op,
                    canonical: Ok(c),
                    ..
                },
            ) if matches_op(pop, op) && c.starts_with(prefix) => {
                Some((prefix.to_string_lossy().len(), 1))
            }
            (
                Predicate::Http {
                    method,
                    url_prefix,
                    exact,
                },
                TaskParams::Http { method: m, url, .. },
            ) => {
                let method_ok = method.as_ref().map(|x| method_eq(x, m)).unwrap_or(true);
                let url_ok = if *exact {
                    url == url_prefix
                } else {
                    url.starts_with(url_prefix.as_str())
                };
                (method_ok && url_ok)
                    .then(|| (url_prefix.len(), if method.is_some() { 2 } else { 1 }))
            }
            (
                Predicate::Mcp { server, tool, args },
                TaskParams::Mcp {
                    server: s,
                    tool: t,
                    args: a,
                },
            ) => {
                let tool_ok = tool.as_ref().map(|x| x == t).unwrap_or(true);
                let args_ok = args.as_ref().map(|p| p.matches(a)).unwrap_or(true);
                let bound = [tool.is_some(), args.is_some()]
                    .iter()
                    .filter(|b| **b)
                    .count()
                    + 1;
                (server == s && tool_ok && args_ok).then_some((server.0.len(), bound))
            }
            (
                Predicate::Git {
                    subcommand,
                    argv_prefix,
                    exact,
                },
                TaskParams::Git {
                    subcommand: sc,
                    argv,
                    ..
                },
            ) => {
                let argv_ok = if *exact {
                    argv == argv_prefix
                } else {
                    argv.starts_with(argv_prefix)
                };
                (subcommand == sc && argv_ok).then(|| (subcommand.len(), 1 + argv_prefix.len()))
            }
            (
                Predicate::Shell {
                    program,
                    matcher,
                    allow_interpreter,
                },
                TaskParams::Shell(cmd),
            ) => {
                if cmd.program != *program {
                    return None;
                }
                // Interpreter programs force a bare Allow rule to fall
                // through to no-match (-> Ask upstream) regardless of argv,
                // unless the rule opted out (§6.3 step 6) — we do not
                // analyse an interpreter's payload. This must NOT also
                // suppress a Deny-scoped rule: an operator-authored
                // `Deny python` has to still produce Deny, not get weakened
                // to the Ask default by falling through here (Important 4).
                if crate::shell::interpreter::is_interpreter(program)
                    && !allow_interpreter
                    && outcome == Outcome::Allow
                {
                    return None;
                }
                let matched = match matcher {
                    ArgMatcher::Exact(v) => &cmd.argv == v,
                    ArgMatcher::ArgvPrefix(prefix) => cmd.argv.starts_with(prefix),
                    ArgMatcher::Glob(patterns) => patterns.iter().enumerate().all(|(i, pat)| {
                        // A pattern that fails to compile can never wrongly grant
                        // Allow — treat it as "does not match" rather than
                        // panicking the whole evaluation (ruling 5).
                        globset::Glob::new(pat)
                            .ok()
                            .map(|g| g.compile_matcher())
                            .zip(cmd.argv.get(i))
                            .is_some_and(|(m, a)| m.is_match(a))
                    }),
                };
                let bound = 1 + match matcher {
                    ArgMatcher::Exact(v) => v.len(),
                    ArgMatcher::ArgvPrefix(prefix) => prefix.len(),
                    ArgMatcher::Glob(patterns) => patterns.len(),
                };
                matched.then_some((program.len(), bound))
            }
            (
                Predicate::Agent {
                    provider,
                    model,
                    max_tier,
                },
                TaskParams::Agent {
                    provider: p,
                    model: m,
                    tier_request,
                },
            ) => {
                let provider_ok = provider.as_ref().map(|x| x == p).unwrap_or(true);
                let model_ok = model.as_ref().map(|x| x == m).unwrap_or(true);
                let bound = [provider.is_some(), model.is_some()]
                    .iter()
                    .filter(|b| **b)
                    .count()
                    + 1;
                (provider_ok && model_ok && *tier_request >= *max_tier).then_some((0, bound))
            }
            (
                Predicate::Memory {
                    scope: pscope,
                    op: pop,
                    session: psession,
                },
                TaskParams::Memory { scope, op, session },
            ) => {
                let session_ok = psession.as_ref().map(|s| s == session).unwrap_or(true);
                (pscope == scope && pop == op && session_ok)
                    .then_some((0, if psession.is_some() { 3 } else { 2 }))
            }
            _ => None,
        }
    }
}

fn matches_op(a: &FsOp, b: &FsOp) -> bool {
    a == b
}

fn method_eq(a: &Method, b: &Method) -> bool {
    a == b
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub scope: Scope,
    pub outcome: Outcome,
    pub predicate: Predicate,
    pub file_order: usize,
    pub id: RuleId,
}

impl CompiledRule {
    /// Public (not `pub(crate)`) because `roundhouse-engine`'s tests
    /// construct `CompiledRule`s directly through this constructor — another
    /// lane's crate, so this stays `pub`. `#[doc(hidden)]` only hides it from
    /// generated docs so it doesn't read as a sanctioned way to build a rule
    /// for production use; it does not restrict who can call it. (B1, review
    /// round 2: this constructor plus `Predicate: Clone` is why
    /// `Grant::predicate()` cannot promise that an out-of-crate caller
    /// cannot reconstruct an installable rule — see that method's doc
    /// comment in `approval.rs`.)
    #[doc(hidden)]
    pub fn test_new(scope: Scope, outcome: Outcome, predicate: Predicate) -> Self {
        Self {
            scope,
            outcome,
            predicate,
            file_order: 0,
            id: RuleId("test".into()),
        }
    }

    /// Test-only sugar for a `Predicate::Shell` rule with an explicit
    /// `allow_interpreter` flag (bare program name, any argv).
    pub fn test_new_with_interpreter_flag(
        scope: Scope,
        outcome: Outcome,
        program: &str,
        allow_interpreter: bool,
    ) -> Self {
        Self::test_new(
            scope,
            outcome,
            Predicate::Shell {
                program: program.to_string(),
                matcher: ArgMatcher::ArgvPrefix(vec![]),
                allow_interpreter,
            },
        )
    }
}

/// Task 20 (W4): dependency-inverted membership check for `MemoryScope::Team`
/// — `roundhouse-policy` does not depend on `roundhouse-bus`, so this trait
/// is the seam a thin adapter in `roundhouse-bus` (wrapping its already-real
/// `can_read_team_memory`/`can_write_team_memory`, G5) implements, wired in
/// from `roundhouse-daemon` (another lane's crate, later).
pub trait TeamMembership: Send + Sync {
    fn can_read(&self, team: TeamId, session: SessionId) -> bool;
    fn can_write(&self, team: TeamId, session: SessionId) -> bool;
}

pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    unsealed: bool,
    sealed_ctx_provider: Arc<dyn Fn() -> crate::sealed::SealedContext + Send + Sync>,
    team_membership: Option<Arc<dyn TeamMembership>>,
}

impl PolicyEngine {
    pub fn from_rules(rules: Vec<CompiledRule>) -> Self {
        Self {
            rules,
            unsealed: false,
            sealed_ctx_provider: Arc::new(crate::sealed::default_context),
            team_membership: None,
        }
    }

    /// Constructed once at daemon boot from the resolved `--unsealed` CLI
    /// flag (§6.2's one documented sealed-floor escape) — never toggled
    /// per-task.
    pub fn with_unsealed(mut self, unsealed: bool) -> Self {
        self.unsealed = unsealed;
        self
    }

    /// Task 25 fix-round-1 (security review): the single source of truth for
    /// whether the sealed floor is disabled for this engine. Originally this
    /// existed so a caller could pass the flag into `decide_sealed` — before
    /// this accessor existed, `SessionActor` held its own independent
    /// `unsealed` bool, settable to a different value than the one this
    /// `PolicyEngine` was actually constructed with, so the sealed floor
    /// could get disabled even though whoever *called* `decide_sealed`
    /// consulted its own, unrelated flag instead of this one.
    ///
    /// Task 25 fix-round-2 (this unit) closed that hole at the type level:
    /// `decide_sealed`/`decide_pipeline`/`decide_shell_command` no longer
    /// accept `unsealed` as a parameter at all, reading `self.unsealed`
    /// internally instead — a caller can no longer supply a stale or wrong
    /// value even by mistake. This accessor now exists purely for callers
    /// that need to *observe* the flag for something other than feeding it
    /// into a decision, e.g. `SessionActor::admit_task`
    /// (`roundhouse-engine/src/session_actor.rs`), which reads it to decide
    /// whether the never-silent unsealed-audit note needs to be recorded at
    /// all.
    pub fn unsealed(&self) -> bool {
        self.unsealed
    }

    /// The daemon is the only place that knows the live state dir, daemon
    /// binary path, resolved MCP servers, and current attestation, so it
    /// supplies this provider at construction. Unit tests get the safe default
    /// from [`from_rules`](Self::from_rules).
    pub fn with_sealed_ctx_provider(
        mut self,
        provider: Arc<dyn Fn() -> crate::sealed::SealedContext + Send + Sync>,
    ) -> Self {
        self.sealed_ctx_provider = provider;
        self
    }

    pub fn sealed_ctx(&self) -> crate::sealed::SealedContext {
        (self.sealed_ctx_provider)()
    }

    /// The daemon (or, in tests, a fixture) supplies this at construction.
    /// Unit tests that never call this get `None` from
    /// [`from_rules`](Self::from_rules), which `decide`'s `TaskParams::Memory`
    /// arm treats as fail-closed: an unconfigured `TeamMembership` denies
    /// every `Team`-scoped op, including `Read`.
    pub fn with_team_membership(mut self, m: Arc<dyn TeamMembership>) -> Self {
        self.team_membership = Some(m);
        self
    }

    /// Sealed rules are matched first and are compiled in, not config. The only
    /// documented escape is `round daemon --unsealed`, which must be recorded on
    /// every task in the session once `TaskSecurity`/attestation lands
    /// (Tasks 17/25), never silent.
    pub fn decide_sealed(
        &self,
        params: &TaskParams,
        ctx: &crate::sealed::SealedContext,
    ) -> Decision {
        if !self.unsealed {
            for rule in crate::sealed::sealed_rules() {
                if (rule.matches)(params, ctx) {
                    return Decision {
                        outcome: Outcome::Deny,
                        rule: Some(RuleId(rule.id.to_string())),
                    };
                }
            }
        }
        self.decide(params)
    }

    /// A path that fails to canonicalise is Deny, never Ask — a human cannot
    /// evaluate a dangling symlink or a TOCTOU race (§6.2).
    pub fn decide(&self, params: &TaskParams) -> Decision {
        if let TaskParams::Fs {
            canonical: Err(_), ..
        } = params
        {
            return Decision {
                outcome: Outcome::Deny,
                rule: None,
            };
        }

        // Task 20 (W4), orchestrator Ruling W4-6: `Team`-scoped memory ops
        // are decided by `TeamMembership`, not by ordinary rule matching
        // (except for an operator `Deny`, handled first below) — a
        // config-authored or synthesized `Predicate::Memory` rule cannot be
        // used to route around the membership gate for Allow. `User`/
        // `Project` scope falls through unchanged to the rule loop and the
        // engine's existing default below.
        //
        // **Documented deviation from frozen `docs/architecture/
        // 12-memory-subsystem.md` §15.2** (fix round 1, Ruling W4-12b):
        // §15.2 says a team write is "a distinct, explicit grant, evaluated
        // by the same policy engine as everything else (§6.2)" — i.e. it
        // expects `Team` scope to go through ordinary rule matching like
        // every other scope, ending in `Ask` when nothing matches so a
        // human can approve it. This arm instead decides `Team` almost
        // entirely by `TeamMembership` and normally never consults rules at
        // all. Concretely, `roundhouse-bus`'s `can_write_team_memory` (G5)
        // is hardcoded to always return `false`, so once a real
        // `TeamMembership` adapter is wired in, every team write Denies
        // permanently: no `Ask` is ever raised, and no human can approve
        // one. This deviation runs in the safe direction (fail-closed,
        // never a silent Allow) and is deliberate, not an oversight — do
        // not "fix" it by simply letting rules decide `Team` scope again;
        // that is only safe now because `Predicate::Memory` binds the
        // requesting `session` (fix round 1, Ruling W4-11) — without that
        // binding, a single approved grant for one session's team op would
        // silently cover every other session's identical request, since
        // `PolicyEngine` is shared behind an `Arc` across session actors.
        // Reconciling this arm with §15.2 (e.g. giving team writes a real
        // `Ask` path) is an escalation for the orchestrator/operator, not a
        // unilateral change to make here.
        if let TaskParams::Memory {
            scope: MemoryScope::Team { team },
            op,
            session,
        } = params
        {
            // Fix round 1 (Ruling W4-12a): an operator-authored `Deny` must
            // still win over the membership check, exactly as the
            // interpreter-suppression logic below excludes `Outcome::Allow`
            // (not `Deny`) so "an operator-authored `Deny python` has to
            // still produce Deny." Checked first, before consulting
            // `TeamMembership` at all.
            if let Some(rule) = self.rules.iter().find(|r| {
                r.outcome == Outcome::Deny && r.predicate.matches(params, r.outcome).is_some()
            }) {
                return Decision {
                    outcome: Outcome::Deny,
                    rule: Some(RuleId(rule.id.0.clone())),
                };
            }

            let Some(membership) = self.team_membership.as_ref() else {
                // Unverifiable membership is not a reason to allow — fail
                // closed for every op, including Read.
                return Decision {
                    outcome: Outcome::Deny,
                    rule: Some(RuleId("team-memory:unconfigured".into())),
                };
            };
            let allowed = match op {
                MemoryOp::Read => membership.can_read(*team, *session),
                MemoryOp::Write | MemoryOp::Append | MemoryOp::Delete => {
                    membership.can_write(*team, *session)
                }
            };
            let rule_id = match op {
                MemoryOp::Read => "team-memory:read",
                MemoryOp::Write | MemoryOp::Append | MemoryOp::Delete => "team-memory:write",
            };
            return Decision {
                outcome: if allowed {
                    Outcome::Allow
                } else {
                    Outcome::Deny
                },
                rule: Some(RuleId(rule_id.into())),
            };
        }

        let mut matches: Vec<(&CompiledRule, usize, usize)> = self
            .rules
            .iter()
            .filter_map(|r| {
                r.predicate
                    .matches(params, r.outcome)
                    .map(|(lp, bp)| (r, lp, bp))
            })
            .collect();

        if matches.iter().any(|(r, _, _)| r.outcome == Outcome::Deny) {
            let rule = matches
                .iter()
                .find(|(r, _, _)| r.outcome == Outcome::Deny)
                .unwrap()
                .0;
            return Decision {
                outcome: Outcome::Deny,
                rule: Some(RuleId(rule.id.0.clone())),
            };
        }

        matches.sort_by(|(a, alp, abp), (b, blp, bbp)| {
            b.scope
                .cmp(&a.scope)
                .then(blp.cmp(alp))
                .then(bbp.cmp(abp))
                .then(a.file_order.cmp(&b.file_order))
        });

        match matches.first() {
            Some((rule, _, _)) => Decision {
                outcome: rule.outcome,
                rule: Some(RuleId(rule.id.0.clone())),
            },
            None => Decision {
                outcome: Outcome::Ask,
                rule: None,
            },
        }
    }

    /// Unattended runs default DenyAll (§6.4): an unmatched task is Deny, not
    /// the interactive default of Ask, because there is no human to answer the
    /// Ask. The sealed floor is still applied first.
    pub fn decide_unattended(&self, params: &TaskParams) -> Decision {
        let d = self.decide_sealed(params, &self.sealed_ctx());
        if d.rule.is_none() && d.outcome == Outcome::Ask {
            Decision {
                outcome: Outcome::Deny,
                rule: None,
            }
        } else {
            d
        }
    }
}

/// Bridges this plan's rich `Decision`/`Outcome` onto Phase 0's frozen
/// `Policy` trait and `PolicyDecision` enum, so `PolicyEngine` is a drop-in
/// `Box<dyn Policy>` everywhere `roundhouse-tools`/`roundhouse-engine` already
/// hold that trait object (Phase 0 Task 6).
///
/// Routes through `decide_sealed()` so the sealed floor is never bypassable
/// through the trait-object call path either.
impl crate::Policy for PolicyEngine {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision {
        self.decide_sealed(&input.params, &self.sealed_ctx())
            .outcome
            .into()
    }
}
