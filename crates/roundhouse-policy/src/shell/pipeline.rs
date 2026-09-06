//! Task 13: pipeline resolution and redirections-as-synthetic-writes.
//!
//! Turns a parsed, opaque-construct-free shell AST ([`ParsedShellAst`]) into
//! a flat sequence of already-resolved `(program, argv)` nodes plus their
//! filesystem-write redirections, then folds `PolicyEngine::decide_sealed`
//! over every node AND every redirection — one node at a time, each against
//! its own freshly built `TaskParams::Shell`.
//!
//! **The audit finding-1 fix lives entirely in [`decide_pipeline`]'s loop
//! body:** each node builds its own `TaskParams::Shell` from *its own*
//! `resolved_program`/`argv` — never a clone of the whole AST — so
//! `Predicate::Shell` has nothing left to misresolve back to node 0.

use std::path::PathBuf;

use brush_parser::ast;

use crate::engine::{Decision, Outcome, PolicyEngine, RuleId};
use crate::sealed::SealedContext;
use crate::shell::classify::{with_parse_stack, ParsedShellAst, SessionEnv};
use crate::shell::opaque::{classify_shell, ShellClassification};
use crate::{FsOp, ParsedCommand, PathErr, TaskParams};

/// A single filesystem target produced by a shell redirection (`<`, `>`,
/// `>>`, `&>`, `>&file`, ...) — evaluated as its own synthetic `Fs` task,
/// never folded into the program/argv match (§6.3 step 5). `op` reflects the
/// redirection's real direction: `FsOp::Read` for input-style redirects
/// (`<`), `FsOp::Write` for every output-style form (`>`, `>>`, `<>`,
/// `>|`, `&>`, `&>>`, and word-form `>&file`/`<&file` duplications that
/// resolve to a path rather than a bare fd number).
#[derive(Debug, Clone)]
pub struct Redirection {
    pub op: FsOp,
    pub path: PathBuf,
}

/// One already-resolved pipeline node: a concrete `(program, argv)` pair —
/// never an AST — plus the filesystem-write redirections attached to it.
#[derive(Debug, Clone)]
pub struct ResolvedNode {
    pub resolved_program: String,
    pub argv: Vec<String>,
    pub redirections: Vec<Redirection>,
}

/// Walks `ast` and returns one [`ResolvedNode`] per `SimpleCommand` reached,
/// in source order, including nodes nested inside compound commands
/// (`if`/`while`/`for`/`case`/brace groups/subshells/functions/coprocs).
///
/// Runs on the dedicated [`with_parse_stack`] stack (task-13/14 addendum
/// ruling 2): this walk recurses in lockstep with the same untrusted AST
/// shapes `classify.rs`'s and `opaque.rs`'s existing walkers do, so it carries
/// the identical stack-exhaustion risk those walkers were hardened against
/// across four fix rounds. A failure to get onto that stack fails closed to
/// an empty node list (which [`decide_pipeline`] turns into `Deny`) — this
/// should be unreachable in practice, since every real caller only ever
/// resolves an AST that `classify_shell` already parsed and walked
/// successfully on the same stack.
pub fn resolve_nodes(ast: &ast::Program) -> Vec<ResolvedNode> {
    with_parse_stack(|| {
        let mut nodes = Vec::new();
        walk_program(ast, &mut nodes);
        nodes
    })
    .unwrap_or_default()
}

/// Convenience view over [`resolve_nodes`]: just the `[program, ...argv]`
/// vectors, one per node, in the same order.
pub fn flatten_argv(ast: &ast::Program) -> Vec<Vec<String>> {
    resolve_nodes(ast)
        .into_iter()
        .map(|n| {
            let mut v = vec![n.resolved_program];
            v.extend(n.argv);
            v
        })
        .collect()
}

/// Returns true when `ast` contains syntax whose control flow cannot be
/// preserved by the direct-exec adapter. Compound commands, function
/// definitions, extended tests, timed/negated pipelines, and pipelines with
/// more than one command are all rejected by the model-facing shell tool
/// rather than flattened into independent executions.
pub fn contains_unsupported_control_flow(ast: &ast::Program) -> bool {
    ast.complete_commands.iter().any(|command| {
        command
            .0
            .iter()
            .any(|item| and_or_has_unsupported_control_flow(&item.0))
    })
}

fn and_or_has_unsupported_control_flow(list: &ast::AndOrList) -> bool {
    if !list.additional.is_empty() {
        return true;
    }
    pipeline_has_unsupported_control_flow(&list.first)
}

fn pipeline_has_unsupported_control_flow(pipeline: &ast::Pipeline) -> bool {
    pipeline.timed.is_some()
        || pipeline.bang
        || pipeline.seq.len() != 1
        || pipeline
            .seq
            .iter()
            .any(|command| !matches!(command, ast::Command::Simple(_)))
}

fn walk_program(program: &ast::Program, out: &mut Vec<ResolvedNode>) {
    for cc in &program.complete_commands {
        walk_compound_list(cc, out);
    }
}

fn walk_compound_list(list: &ast::CompoundList, out: &mut Vec<ResolvedNode>) {
    for item in &list.0 {
        walk_and_or_list(&item.0, out);
    }
}

fn walk_and_or_list(aol: &ast::AndOrList, out: &mut Vec<ResolvedNode>) {
    walk_pipeline(&aol.first, out);
    for and_or in &aol.additional {
        match and_or {
            ast::AndOr::And(p) | ast::AndOr::Or(p) => walk_pipeline(p, out),
        }
    }
}

fn walk_pipeline(pipeline: &ast::Pipeline, out: &mut Vec<ResolvedNode>) {
    for cmd in &pipeline.seq {
        walk_command(cmd, out);
    }
}

fn walk_command(cmd: &ast::Command, out: &mut Vec<ResolvedNode>) {
    match cmd {
        ast::Command::Simple(simple) => out.push(resolve_simple_command(simple)),
        ast::Command::Compound(compound, redirects) => {
            walk_compound_command(compound, out);
            if let Some(rl) = redirects {
                attach_command_level_redirects(rl, out);
            }
        }
        ast::Command::Function(func) => walk_function_body(&func.body, out),
        ast::Command::ExtendedTest(_ext, redirects) => {
            // `[[ ... ]]` never resolves to a `(program, argv)` pair — there
            // is no execve target here, only any attached redirections.
            if let Some(rl) = redirects {
                attach_command_level_redirects(rl, out);
            }
        }
    }
}

fn resolve_simple_command(cmd: &ast::SimpleCommand) -> ResolvedNode {
    let resolved_program = cmd
        .word_or_name
        .as_ref()
        .map(|w| w.value.clone())
        .unwrap_or_default();
    let mut argv = Vec::new();
    let mut redirections = Vec::new();
    if let Some(prefix) = &cmd.prefix {
        for item in &prefix.0 {
            collect_prefix_or_suffix_item(item, &mut argv, &mut redirections);
        }
    }
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            collect_prefix_or_suffix_item(item, &mut argv, &mut redirections);
        }
    }
    ResolvedNode {
        resolved_program,
        argv,
        redirections,
    }
}

fn collect_prefix_or_suffix_item(
    item: &ast::CommandPrefixOrSuffixItem,
    argv: &mut Vec<String>,
    redirections: &mut Vec<Redirection>,
) {
    match item {
        ast::CommandPrefixOrSuffixItem::Word(w) => argv.push(w.value.clone()),
        // Assignment-word prefixes (`FOO=bar cmd`) set environment for the
        // invocation, not an argv position — they don't belong in argv.
        ast::CommandPrefixOrSuffixItem::AssignmentWord(_, _) => {}
        ast::CommandPrefixOrSuffixItem::IoRedirect(r) => collect_redirect(r, redirections),
        // Opaque; `classify_shell` already hard-denies process substitution
        // upstream, so this is unreachable by construction in practice — do
        // nothing rather than misinterpret it as an argv word or a write
        // target.
        ast::CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => {}
    }
}

/// Redirections attached to a compound command / function / extended-test
/// itself (e.g. `{ cmd; } > file`) rather than to a specific `SimpleCommand`.
/// Filed against the last node collected from the construct's body, since
/// that's the node whose output the redirection actually affects; if the
/// construct produced no nodes at all, a placeholder node carries the
/// redirection alone so it still gets evaluated as a synthetic write.
fn attach_command_level_redirects(rl: &ast::RedirectList, out: &mut Vec<ResolvedNode>) {
    let mut redirections = Vec::new();
    for r in &rl.0 {
        collect_redirect(r, &mut redirections);
    }
    if redirections.is_empty() {
        return;
    }
    match out.last_mut() {
        Some(node) => node.redirections.extend(redirections),
        None => out.push(ResolvedNode {
            resolved_program: String::new(),
            argv: Vec::new(),
            redirections,
        }),
    }
}

/// Extracts every filesystem-path-shaped redirect target as a [`Redirection`]
/// with the correct read/write direction. Heredocs and process substitution
/// don't write to a filesystem path (and `classify_shell` already treats
/// process substitution/heredocs as opaque upstream, so those forms should
/// never actually reach here) — but this must not panic or misresolve if one
/// does; unrecognized shapes are simply skipped.
///
/// Three real `IoRedirect`/`IoFileRedirectTarget` shapes produce a
/// filesystem path (task-13/14 fix-round-1 Critical 2 / Important 5 — the
/// original version only handled the first of these, silently dropping the
/// other two, which let `&>`/`&>>`/`>&file` bypass every write-path policy
/// rule entirely):
///
/// - `File(_, kind, Filename(w))` — the ordinary `<`/`>`/`>>`/`<>`/`>|` forms.
///   `kind` distinguishes direction: `Read` -> `FsOp::Read`, everything else
///   (`Write`/`Append`/`ReadAndWrite`/`Clobber`) -> `FsOp::Write` (each of
///   those can write to the target, so failing closed to `Write` is correct
///   even for `ReadAndWrite`'s `<>` form).
/// - `File(_, kind, Duplicate(w))` — the word-form `<&word` / `>&word`
///   duplications. Per brush-parser's own doc comment, after expansion `w`
///   "could be a filename, a file descriptor, or a file descriptor and a
///   \"-\" to indicate requested closure" — only treat it as a filesystem
///   write/read when it's actually path-shaped (`duplicate_target_is_path`),
///   never for a bare fd number or `-`, which are not filesystem paths at
///   all.
/// - `OutputAndError(w, _append)` — the `&>`/`&>>` "both stdout and stderr"
///   form. Always a write.
fn collect_redirect(r: &ast::IoRedirect, redirections: &mut Vec<Redirection>) {
    match r {
        ast::IoRedirect::File(_, kind, ast::IoFileRedirectTarget::Filename(w)) => {
            redirections.push(Redirection {
                op: fs_op_for_kind(kind),
                path: PathBuf::from(&w.value),
            });
        }
        ast::IoRedirect::File(_, kind, ast::IoFileRedirectTarget::Duplicate(w)) => {
            if duplicate_target_is_path(&w.value) {
                redirections.push(Redirection {
                    op: fs_op_for_kind(kind),
                    path: PathBuf::from(&w.value),
                });
            }
        }
        ast::IoRedirect::OutputAndError(w, _append) => {
            redirections.push(Redirection {
                op: FsOp::Write,
                path: PathBuf::from(&w.value),
            });
        }
        ast::IoRedirect::HereDocument(..) | ast::IoRedirect::HereString(..) => {}
        ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::Fd(_))
        | ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::ProcessSubstitution(_, _)) => {}
    }
}

/// Maps a real `IoFileRedirectKind` to the `FsOp` it actually performs on its
/// target path. `Read` is the only input-style kind; every other kind can
/// write to (or truncate/create) the target.
fn fs_op_for_kind(kind: &ast::IoFileRedirectKind) -> FsOp {
    match kind {
        ast::IoFileRedirectKind::Read | ast::IoFileRedirectKind::DuplicateInput => FsOp::Read,
        ast::IoFileRedirectKind::Write
        | ast::IoFileRedirectKind::Append
        | ast::IoFileRedirectKind::ReadAndWrite
        | ast::IoFileRedirectKind::Clobber
        | ast::IoFileRedirectKind::DuplicateOutput => FsOp::Write,
    }
}

/// A `Duplicate` redirect target (`<&word` / `>&word`) is only a filesystem
/// path when, after expansion, it isn't a bare fd number or the `-`
/// (close-fd) sentinel — matching brush-parser's own doc comment on
/// `IoFileRedirectTarget::Duplicate`.
fn duplicate_target_is_path(word_value: &str) -> bool {
    !word_value.is_empty() && word_value != "-" && !word_value.bytes().all(|b| b.is_ascii_digit())
}

fn walk_compound_command(cmd: &ast::CompoundCommand, out: &mut Vec<ResolvedNode>) {
    match cmd {
        // Arithmetic expressions (`(( ... ))`) contain no executable
        // commands. `ArithmeticForClauseCommand` (`for ((init;cond;incr))`)
        // is different — it has its own `body: DoGroupCommand`, exactly
        // like `ForClause`/`WhileClause`, and MUST be walked the same way:
        // fix-round-1 Critical 1 found that leaving this a no-op let a
        // `rm -rf` inside a C-style for-loop body reach exec with zero
        // policy evaluation at all (an unwalked node never becomes a
        // `ResolvedNode`, so it's simply invisible to `decide_pipeline`).
        //
        // B5 (review round 2), not fixed (orchestrator Ruling W4-18): no
        // commands live here, but the raw arithmetic expression string
        // itself (including the `for ((...))` header's own
        // initializer/condition/updater) is never inspected by this or any
        // sibling walker, so a `$(...)` command substitution embedded in one
        // is invisible everywhere, not just here. See `opaque.rs`'s
        // `find_opaque_in_compound_command` for the full writeup — this
        // becomes real the moment a shell-backed executor lands; tracked,
        // not fixed, here.
        ast::CompoundCommand::Arithmetic(_) => {}
        ast::CompoundCommand::ArithmeticForClause(c) => walk_do_group(&c.body, out),
        ast::CompoundCommand::BraceGroup(g) => walk_compound_list(&g.list, out),
        ast::CompoundCommand::Subshell(s) => walk_compound_list(&s.list, out),
        ast::CompoundCommand::ForClause(c) => walk_do_group(&c.body, out),
        ast::CompoundCommand::CaseClause(c) => {
            for case in &c.cases {
                if let Some(body) = &case.cmd {
                    walk_compound_list(body, out);
                }
            }
        }
        ast::CompoundCommand::IfClause(c) => {
            walk_compound_list(&c.condition, out);
            walk_compound_list(&c.then, out);
            if let Some(elses) = &c.elses {
                for e in elses {
                    if let Some(cond) = &e.condition {
                        walk_compound_list(cond, out);
                    }
                    walk_compound_list(&e.body, out);
                }
            }
        }
        ast::CompoundCommand::WhileClause(c) | ast::CompoundCommand::UntilClause(c) => {
            walk_compound_list(&c.0, out);
            walk_do_group(&c.1, out);
        }
        ast::CompoundCommand::Coprocess(c) => walk_command(&c.body, out),
    }
}

fn walk_do_group(group: &ast::DoGroupCommand, out: &mut Vec<ResolvedNode>) {
    walk_compound_list(&group.list, out);
}

fn walk_function_body(body: &ast::FunctionBody, out: &mut Vec<ResolvedNode>) {
    walk_compound_command(&body.0, out);
    if let Some(rl) = &body.1 {
        attach_command_level_redirects(rl, out);
    }
}

/// §6.3 steps 4-5: pipelines/conjunctions are not automatically `Opaque`, but
/// the command runs only if EVERY node independently matches `Allow`, and
/// every redirection is evaluated as its own synthetic write task against the
/// same path rules. `Deny` anywhere ends the pipeline immediately (fail
/// closed) rather than continuing to evaluate later nodes.
pub fn decide_pipeline(
    policy: &PolicyEngine,
    ctx: &SealedContext,
    cmd: &ParsedShellAst,
) -> Decision {
    let nodes = resolve_nodes(&cmd.program_ast);
    let mut worst: Option<Decision> = None;

    for node in &nodes {
        let params = TaskParams::Shell(ParsedCommand {
            program: node.resolved_program.clone(),
            argv: node.argv.clone(),
        });
        let d = policy.decide_sealed(&params, ctx);
        let is_deny = d.outcome == Outcome::Deny;
        worst = combine(worst, d);
        if is_deny {
            // Fail closed immediately — a later Allow node can't rescue a
            // denied one.
            return worst.unwrap();
        }

        for redir in &node.redirections {
            let canonical = redir
                .path
                .canonicalize()
                .map_err(|e| PathErr(e.to_string()));
            let fs_params = TaskParams::Fs {
                op: redir.op,
                path: redir.path.clone(),
                canonical,
            };
            let d = policy.decide_sealed(&fs_params, ctx);
            let is_deny = d.outcome == Outcome::Deny;
            worst = combine(worst, d);
            if is_deny {
                return worst.unwrap();
            }
        }
    }

    worst.unwrap_or(Decision {
        outcome: Outcome::Deny,
        rule: None,
    })
}

fn combine(acc: Option<Decision>, next: Decision) -> Option<Decision> {
    match acc {
        None => Some(next),
        Some(prev) if prev.outcome == Outcome::Deny => Some(prev), // Deny is absorbing
        Some(_) if next.outcome == Outcome::Deny => Some(next),
        Some(prev) if prev.outcome == Outcome::Ask || next.outcome == Outcome::Ask => {
            Some(Decision {
                outcome: Outcome::Ask,
                rule: next.rule.or(prev.rule),
            })
        }
        Some(_) => Some(next), // both Allow
    }
}

/// The composed entry point (audit finding 11): runs §6.3 steps 1-8 in order.
/// Every real call site and every test must call this, never [`decide_pipeline`]
/// alone — `decide_pipeline` has no way to hard-deny an `Opaque` construct,
/// since that classification happens upstream in `classify_shell`.
pub fn decide_shell_command(
    policy: &PolicyEngine,
    ctx: &SealedContext,
    raw: &str,
    env: &SessionEnv,
) -> Decision {
    match classify_shell(raw, env) {
        ShellClassification::HardDeny(hint) => Decision {
            outcome: Outcome::Deny,
            rule: Some(RuleId(hint.rule.to_string())),
        },
        ShellClassification::Program(cmd) => decide_pipeline(policy, ctx, &cmd),
    }
}
