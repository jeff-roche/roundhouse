use crate::{FsOp, TaskParams};
use roundhouse_core::Tier;
use std::collections::HashSet;
use std::path::PathBuf;

/// A compiled-in rule on the sealed floor. Sealed rules are matched before any
/// config-derived rule and cannot be overridden by them. The one documented
/// escape is the daemon's `--unsealed` flag, which must be recorded per-task
/// once `TaskSecurity`/attestation wiring lands (Tasks 17/25).
pub struct SealedRule {
    pub id: &'static str,
    pub matches: fn(&TaskParams, &SealedContext) -> bool,
}

/// Built once per task by the caller (the task-admission path — see the
/// integration task at the end of this plan) from the session's live isolation
/// attestation and MCP registry. Never config-derived: every field here is
/// either a compiled-in path or a runtime fact the agent cannot influence by
/// editing a file.
#[derive(Debug, Clone)]
pub struct SealedContext {
    pub state_dir: PathBuf,
    pub daemon_binary: PathBuf,
    /// `ServerId` (Phase 0) has no `Hash` derive, so this holds the raw server
    /// name.
    pub resolved_mcp_servers: HashSet<String>,
    pub requested_tier: Tier,
    pub attested_tier: Tier,
}

/// A tiny home-dir helper matching `roundhouse-config/src/loader.rs` — no `dirs`
/// crate dependency is introduced.
#[doc(hidden)]
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Safe default for unit tests that do not exercise sealed rules. A
/// non-existent/empty `state_dir` and `daemon_binary` cannot `starts_with` match
/// any real path, `resolved_mcp_servers` is empty (fail-closed for MCP), and
/// both tiers are `None` so a tier shortfall can never fire.
pub fn default_context() -> SealedContext {
    SealedContext {
        state_dir: PathBuf::new(),
        daemon_binary: PathBuf::new(),
        resolved_mcp_servers: HashSet::new(),
        requested_tier: Tier::None,
        attested_tier: Tier::None,
    }
}

const SEALED_PROGRAMS: &[&str] = &[
    "sudo",
    "doas",
    "pkexec",
    "nsenter",
    "unshare",
    "chroot",
    "systemd-run",
];

pub fn sealed_rules() -> &'static [SealedRule] {
    &[
        SealedRule {
            id: "sealed:ssh-write",
            matches: |p, _| sealed_write_under(p, ".ssh"),
        },
        SealedRule {
            id: "sealed:gnupg-write",
            matches: |p, _| sealed_write_under(p, ".gnupg"),
        },
        SealedRule {
            id: "sealed:aws-write",
            matches: |p, _| sealed_write_under(p, ".aws"),
        },
        SealedRule {
            id: "sealed:roundhouse-config-write",
            matches: |p, _| sealed_write_under(p, ".config/roundhouse"),
        },
        SealedRule {
            id: "sealed:state-dir-write",
            matches: sealed_state_dir_write,
        },
        SealedRule {
            id: "sealed:daemon-binary-write",
            matches: sealed_daemon_binary_write,
        },
        SealedRule {
            id: "sealed:priv-escalation-program",
            matches: |p, _| sealed_program(p),
        },
        SealedRule {
            id: "sealed:mcp-unresolved-server",
            matches: sealed_mcp_unresolved,
        },
        SealedRule {
            id: "sealed:tier-shortfall",
            matches: sealed_tier_shortfall,
        },
    ]
}

fn sealed_write_under(params: &TaskParams, suffix: &str) -> bool {
    let TaskParams::Fs {
        op: FsOp::Write,
        canonical: Ok(c),
        ..
    } = params
    else {
        return false;
    };
    let Some(home) = home_dir() else { return false };
    c.starts_with(home.join(suffix))
}

/// §6.2's sealed floor lists the state dir alongside the dotfile paths — a prior
/// version of this rule set omitted it, which would have let an agent overwrite
/// the very store its own audit trail lives in.
fn sealed_state_dir_write(params: &TaskParams, ctx: &SealedContext) -> bool {
    let TaskParams::Fs {
        op: FsOp::Write,
        canonical: Ok(c),
        ..
    } = params
    else {
        return false;
    };
    c.starts_with(&ctx.state_dir)
}

/// §6.2's sealed floor also lists the daemon binary itself — self-modification
/// of the running daemon is exactly the kind of escalation the sealed floor
/// exists to block.
fn sealed_daemon_binary_write(params: &TaskParams, ctx: &SealedContext) -> bool {
    let TaskParams::Fs {
        op: FsOp::Write,
        canonical: Ok(c),
        ..
    } = params
    else {
        return false;
    };
    c == &ctx.daemon_binary
}

fn sealed_program(params: &TaskParams) -> bool {
    // TaskParams::Shell always carries exactly one already-resolved node (Task
    // 13/14's pipeline decomposition calls decide_sealed once per node), so no
    // iteration is needed or correct here.
    let TaskParams::Shell(cmd) = params else {
        return false;
    };
    SEALED_PROGRAMS.contains(&cmd.program.as_str())
}

/// §6.2's sealed floor: "MCP tools on unresolved servers." A server that never
/// completed its handshake has no verified tool surface — matching against a
/// config rule for it would be trusting the agent's own claim about what the
/// tool does.
fn sealed_mcp_unresolved(params: &TaskParams, ctx: &SealedContext) -> bool {
    let TaskParams::Mcp { server, .. } = params else {
        return false;
    };
    !ctx.resolved_mcp_servers.contains(&server.0)
}

/// §6.2: "any task where attested_tier < requested_tier" — deliberately
/// unconditional over every `TaskParams` variant. The previous stub limited this
/// to `TaskParams::Agent` and hardcoded `&& false`, i.e. it never fired at all;
/// a degraded sandbox must seal every task already running inside it, not merely
/// block spawning new agents.
fn sealed_tier_shortfall(_params: &TaskParams, ctx: &SealedContext) -> bool {
    ctx.attested_tier < ctx.requested_tier
}
