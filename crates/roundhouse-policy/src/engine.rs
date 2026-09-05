use crate::{FsOp, Method, PolicyInput, ProviderId, ServerId, TaskParams};
use roundhouse_core::{PolicyDecision, Tier};
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

/// Covers all six `TaskParams` variants (Phase 0, frozen) from the start — the
/// audit's "only Fs*/Shell predicates ever get defined" bug meant no rule could
/// ever Allow a git/http/mcp/agent task regardless of config; every variant
/// gets a matcher here.
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
        max_tier: Tier,
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
    pub fn mcp(server: ServerId, tool: Option<String>) -> Self {
        Predicate::Mcp { server, tool }
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
                Predicate::Mcp { server, tool },
                TaskParams::Mcp {
                    server: s, tool: t, ..
                },
            ) => {
                let tool_ok = tool.as_ref().map(|x| x == t).unwrap_or(true);
                (server == s && tool_ok)
                    .then(|| (server.0.len(), if tool.is_some() { 2 } else { 1 }))
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
                (provider_ok && model_ok && *tier_request <= *max_tier).then_some((0, bound))
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

pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    unsealed: bool,
    sealed_ctx_provider: Arc<dyn Fn() -> crate::sealed::SealedContext + Send + Sync>,
}

impl PolicyEngine {
    pub fn from_rules(rules: Vec<CompiledRule>) -> Self {
        Self {
            rules,
            unsealed: false,
            sealed_ctx_provider: Arc::new(crate::sealed::default_context),
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
    /// whether the sealed floor is disabled for this engine. Before this
    /// accessor existed, `SessionActor` held its own independent `unsealed`
    /// bool, settable to a different value than the one this `PolicyEngine`
    /// was actually constructed with — a caller could construct a
    /// `PolicyEngine::with_unsealed(false)` whose sealed floor still got
    /// disabled anyway because whatever *called* `decide_sealed` consulted
    /// its own, unrelated flag instead of this one. Every caller of
    /// `decide_sealed` outside this impl block must read `unsealed` from
    /// here, never maintain a parallel copy.
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
