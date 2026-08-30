use crate::{FsOp, Method, PolicyInput, ProviderId, ServerId, TaskParams};
use roundhouse_core::{PolicyDecision, Tier};
use std::path::PathBuf;

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
/// makes for the `tasks` cache table applies here too. Everywhere below that
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
    FsPrefix { op: FsOp, prefix: PathBuf },
    FsExact { op: FsOp, path: PathBuf },
    // Shell { .. } added by Task 14, matched against a single already-resolved node
    Http { method: Option<Method>, url_prefix: String },
    Mcp { server: ServerId, tool: Option<String> },
    Git { subcommand: String, argv_prefix: Vec<String> },
    Agent {
        provider: Option<ProviderId>,
        model: Option<String>,
        max_tier: Tier,
    },
}

impl Predicate {
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
        }
    }
    pub fn mcp(server: ServerId, tool: Option<String>) -> Self {
        Predicate::Mcp { server, tool }
    }
    pub fn git(subcommand: &str, argv_prefix: &[&str]) -> Self {
        Predicate::Git {
            subcommand: subcommand.to_string(),
            argv_prefix: argv_prefix.iter().map(|s| s.to_string()).collect(),
        }
    }
    pub fn agent(provider: Option<ProviderId>, model: Option<String>, max_tier: Tier) -> Self {
        Predicate::Agent {
            provider,
            model,
            max_tier,
        }
    }

    fn matches(&self, params: &TaskParams) -> Option<(usize, usize)> {
        // returns (literal_prefix_len, bound_predicate_count) on match
        match (self, params) {
            (Predicate::FsExact { op: pop, path: ppath }, TaskParams::Fs { op, canonical: Ok(c), .. })
                if matches_op(pop, op) && c == ppath =>
            {
                Some((ppath.to_string_lossy().len(), 2))
            }
            (Predicate::FsPrefix { op: pop, prefix }, TaskParams::Fs { op, canonical: Ok(c), .. })
                if matches_op(pop, op) && c.starts_with(prefix) =>
            {
                Some((prefix.to_string_lossy().len(), 1))
            }
            (Predicate::Http { method, url_prefix }, TaskParams::Http { method: m, url, .. }) => {
                let method_ok = method.as_ref().map(|x| method_eq(x, m)).unwrap_or(true);
                (method_ok && url.starts_with(url_prefix.as_str()))
                    .then(|| (url_prefix.len(), if method.is_some() { 2 } else { 1 }))
            }
            (Predicate::Mcp { server, tool }, TaskParams::Mcp { server: s, tool: t, .. }) => {
                let tool_ok = tool.as_ref().map(|x| x == t).unwrap_or(true);
                (server == s && tool_ok).then(|| (server.0.len(), if tool.is_some() { 2 } else { 1 }))
            }
            (Predicate::Git { subcommand, argv_prefix }, TaskParams::Git { subcommand: sc, argv, .. }) => {
                (subcommand == sc && argv.starts_with(argv_prefix))
                    .then(|| (subcommand.len(), 1 + argv_prefix.len()))
            }
            (
                Predicate::Agent { provider, model, max_tier },
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
                (provider_ok && model_ok && *tier_request <= *max_tier).then(|| (0, bound))
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
}

pub struct PolicyEngine {
    rules: Vec<CompiledRule>,
    unsealed: bool,
}

impl PolicyEngine {
    pub fn from_rules(rules: Vec<CompiledRule>) -> Self {
        Self {
            rules,
            unsealed: false,
        }
    }

    /// Constructed once at daemon boot from the resolved `--unsealed` CLI
    /// flag (§6.2's one documented sealed-floor escape) — never toggled
    /// per-task.
    pub fn with_unsealed(mut self, unsealed: bool) -> Self {
        self.unsealed = unsealed;
        self
    }

    /// A path that fails to canonicalise is Deny, never Ask — a human cannot
    /// evaluate a dangling symlink or a TOCTOU race (§6.2).
    pub fn decide(&self, params: &TaskParams) -> Decision {
        if let TaskParams::Fs { canonical: Err(_), .. } = params {
            return Decision {
                outcome: Outcome::Deny,
                rule: None,
            };
        }

        let mut matches: Vec<(&CompiledRule, usize, usize)> = self
            .rules
            .iter()
            .filter_map(|r| r.predicate.matches(params).map(|(lp, bp)| (r, lp, bp)))
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
    /// Ask.
    pub fn decide_unattended(&self, params: &TaskParams) -> Decision {
        let d = self.decide(params);
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
/// Routes through plain `decide()` for now; Task 10 edits this one line to
/// route through `decide_sealed()` once the sealed floor exists, so the sealed
/// floor is never bypassable through the trait-object call path either.
impl crate::Policy for PolicyEngine {
    fn decide(&self, input: &PolicyInput) -> PolicyDecision {
        self.decide(&input.params).outcome.into()
    }
}
