use brush_parser::ast;
use brush_parser::ast::SourceLocation;

use super::classify::{
    check_input_guard, parse_command, parse_word_pieces, piece_is_opaque,
    resolve_variable_expansions, with_parse_stack, Classification, GuardRejection, OpaqueReason,
    ParsedShellAst, SessionEnv, MAX_INPUT_BYTES,
};

/// An opaque construct found in the shell AST, with its source span when available.
///
/// Spans may be `(0, 0)` for constructs where the underlying `brush-parser` surface
/// does not expose a source location (e.g. here-documents in 0.4.x).
pub struct OpaqueNode {
    pub reason: OpaqueReason,
    pub span: (usize, usize),
}

pub struct RestructureHint {
    pub error: &'static str,
    pub rule: &'static str,
    pub hint: String,
}

pub enum ShellClassification {
    Program(ParsedShellAst),
    HardDeny(RestructureHint),
}

/// Walks the AST looking for any source-level node this design treats as irreducibly
/// opaque: CommandSubstitution, ProcessSubstitution, Eval, Source, HereDoc, Backgrounding.
/// Intended to be invoked *before* VariableExpansion resolution so quoted literals such
/// as `'$(id)'` are not misclassified after quote stripping.
///
/// The walk recurses in lockstep with the AST's nesting, so it runs on the dedicated
/// bounded parse stack (see `classify::with_parse_stack`). A failure to get onto that
/// stack fails closed: the caller sees at least one `ParseError` node.
pub fn find_opaque_nodes(program: &ast::Program) -> Vec<OpaqueNode> {
    with_parse_stack(|| {
        let mut found = Vec::new();
        find_opaque_in_program(program, &mut found);
        found
    })
    .unwrap_or_else(|_| {
        vec![OpaqueNode {
            reason: OpaqueReason::ParseError,
            span: (0, 0),
        }]
    })
}

fn parse_failure_hint() -> RestructureHint {
    RestructureHint {
        error: "unparseable_shell_command",
        rule: "sealed:shell-parse-failure",
        hint:
            "The command could not be parsed as shell syntax. Restructure as a plain argv command."
                .into(),
    }
}

/// Honest hints for the cheap pre-parser guard. These inputs were *not* necessarily
/// unparseable — they were refused before the parser ever saw them — so telling the model
/// "could not be parsed" would send it chasing a syntax error that isn't there. The
/// machine-readable `error`/`rule` codes stay identical to the parse-failure case.
fn guard_rejection_hint(rejection: GuardRejection) -> RestructureHint {
    let hint = match rejection {
        GuardRejection::TooLarge => format!(
            "The command is longer than the {MAX_INPUT_BYTES}-byte limit the shell \
             classifier will inspect. Split it into smaller commands."
        ),
        GuardRejection::TooComplex => "The command contains too many shell grouping \
             constructs (parentheses, braces, backticks, or compound-command keywords) \
             for the classifier to inspect. Restructure it as one or more plain argv \
             commands."
            .to_string(),
    };
    RestructureHint {
        error: "unparseable_shell_command",
        rule: "sealed:shell-parse-failure",
        hint,
    }
}

/// Classify an untrusted shell command string.
///
/// The entire body — parse, opaque-node walk, and expansion walk — runs on a dedicated
/// thread with an explicitly sized stack, so that no input within `MAX_INPUT_BYTES` can
/// drive `brush-parser`'s (or this module's) recursion into an uncatchable stack-overflow
/// abort. See `classify::PARSE_STACK_BYTES` for the calibration.
pub fn classify_shell(raw: &str, env: &SessionEnv) -> ShellClassification {
    if let Err(rejection) = check_input_guard(raw) {
        return ShellClassification::HardDeny(guard_rejection_hint(rejection));
    }
    match with_parse_stack(|| classify_shell_inner(raw, env)) {
        Ok(classification) => classification,
        Err(_) => ShellClassification::HardDeny(parse_failure_hint()),
    }
}

fn classify_shell_inner(raw: &str, env: &SessionEnv) -> ShellClassification {
    let mut cmd = match parse_command(raw) {
        Classification::Opaque(_) => {
            return ShellClassification::HardDeny(parse_failure_hint());
        }
        Classification::Program(cmd) => cmd,
    };

    // Detect source-level opaque constructs BEFORE expanding plain variables. Expanded
    // env values are DATA under the execve-no-shell model; the original source tokens
    // (quotes, substitutions, etc.) are what make a construct opaque. Scanning pre-
    // expansion prevents quote-stripping false positives such as `echo '$(id)'`.
    let opaque = find_opaque_nodes(&cmd.program_ast);
    if !opaque.is_empty() {
        return ShellClassification::HardDeny(RestructureHint {
            error: "opaque_shell_construct",
            rule: "sealed:shell-opaque",
            hint: "Run the inner command as its own shell task, capture the result, \
                   then reference the literal captured value in a follow-up command."
                .into(),
        });
    }

    resolve_variable_expansions(&mut cmd.program_ast, env);

    ShellClassification::Program(cmd)
}

fn find_opaque_in_program(program: &ast::Program, found: &mut Vec<OpaqueNode>) {
    for cc in &program.complete_commands {
        find_opaque_in_compound_list(cc, found);
    }
}

fn find_opaque_in_compound_list(list: &ast::CompoundList, found: &mut Vec<OpaqueNode>) {
    for item in &list.0 {
        find_opaque_in_compound_list_item(item, found);
    }
}

fn find_opaque_in_compound_list_item(item: &ast::CompoundListItem, found: &mut Vec<OpaqueNode>) {
    find_opaque_in_and_or_list(&item.0, found);
    if matches!(item.1, ast::SeparatorOperator::Async) {
        found.push(OpaqueNode {
            reason: OpaqueReason::Backgrounding,
            span: source_span_to_tuple(item.0.location()),
        });
    }
}

fn find_opaque_in_and_or_list(aol: &ast::AndOrList, found: &mut Vec<OpaqueNode>) {
    find_opaque_in_pipeline(&aol.first, found);
    for and_or in &aol.additional {
        match and_or {
            ast::AndOr::And(pipeline) | ast::AndOr::Or(pipeline) => {
                find_opaque_in_pipeline(pipeline, found);
            }
        }
    }
}

fn find_opaque_in_pipeline(pipeline: &ast::Pipeline, found: &mut Vec<OpaqueNode>) {
    for cmd in &pipeline.seq {
        find_opaque_in_command(cmd, found);
    }
}

fn find_opaque_in_command(cmd: &ast::Command, found: &mut Vec<OpaqueNode>) {
    match cmd {
        ast::Command::Simple(simple) => find_opaque_in_simple_command(simple, found),
        ast::Command::Compound(compound, redirects) => {
            find_opaque_in_compound_command(compound, found);
            if let Some(rl) = redirects {
                find_opaque_in_redirect_list(rl, found);
            }
        }
        ast::Command::Function(func) => {
            find_opaque_in_word(&func.fname, found);
            find_opaque_in_function_body(&func.body, found);
        }
        ast::Command::ExtendedTest(ext, redirects) => {
            find_opaque_in_extended_test_expr(&ext.expr, found);
            if let Some(rl) = redirects {
                find_opaque_in_redirect_list(rl, found);
            }
        }
    }
}

fn find_opaque_in_simple_command(cmd: &ast::SimpleCommand, found: &mut Vec<OpaqueNode>) {
    if let Some(prefix) = &cmd.prefix {
        for item in &prefix.0 {
            find_opaque_in_prefix_or_suffix_item(item, found);
        }
    }
    if let Some(word_or_name) = &cmd.word_or_name {
        find_opaque_in_word(word_or_name, found);
        check_eval_or_source(word_or_name, found);
    }
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            find_opaque_in_prefix_or_suffix_item(item, found);
        }
    }
}

fn check_eval_or_source(word: &ast::Word, found: &mut Vec<OpaqueNode>) {
    if word.value == "eval" {
        found.push(OpaqueNode {
            reason: OpaqueReason::Eval,
            span: source_span_to_tuple(word.location()),
        });
    } else if word.value == "." || word.value == "source" {
        found.push(OpaqueNode {
            reason: OpaqueReason::Source,
            span: source_span_to_tuple(word.location()),
        });
    }
}

fn find_opaque_in_prefix_or_suffix_item(
    item: &ast::CommandPrefixOrSuffixItem,
    found: &mut Vec<OpaqueNode>,
) {
    match item {
        ast::CommandPrefixOrSuffixItem::Word(w) => find_opaque_in_word(w, found),
        ast::CommandPrefixOrSuffixItem::AssignmentWord(_, w) => find_opaque_in_word(w, found),
        ast::CommandPrefixOrSuffixItem::IoRedirect(r) => find_opaque_in_io_redirect(r, found),
        ast::CommandPrefixOrSuffixItem::ProcessSubstitution(_kind, cmd) => {
            found.push(OpaqueNode {
                reason: OpaqueReason::ProcessSubstitution,
                span: source_span_to_tuple(cmd.location()),
            });
        }
    }
}

fn find_opaque_in_redirect_list(rl: &ast::RedirectList, found: &mut Vec<OpaqueNode>) {
    for r in &rl.0 {
        find_opaque_in_io_redirect(r, found);
    }
}

fn find_opaque_in_io_redirect(r: &ast::IoRedirect, found: &mut Vec<OpaqueNode>) {
    match r {
        ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::Filename(w))
        | ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::Duplicate(w))
        | ast::IoRedirect::HereString(_, w)
        | ast::IoRedirect::OutputAndError(w, _) => find_opaque_in_word(w, found),
        ast::IoRedirect::HereDocument(_, _) => {
            found.push(OpaqueNode {
                reason: OpaqueReason::HereDoc,
                span: (0, 0),
            });
        }
        ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::Fd(_)) => {}
        ast::IoRedirect::File(_, _, ast::IoFileRedirectTarget::ProcessSubstitution(_, cmd)) => {
            found.push(OpaqueNode {
                reason: OpaqueReason::ProcessSubstitution,
                span: source_span_to_tuple(cmd.location()),
            });
        }
    }
}

fn find_opaque_in_compound_command(cmd: &ast::CompoundCommand, found: &mut Vec<OpaqueNode>) {
    match cmd {
        // Arithmetic expressions (`(( ... ))`) contain no executable
        // commands. `ArithmeticForClause` (`for ((init;cond;incr))`) is
        // different — it has its own `body: DoGroupCommand`, exactly like
        // `ForClause`, and MUST be walked the same way (Task 26, W4): this
        // was grouped with `Arithmetic` and left a no-op, so an opaque
        // construct (e.g. a command substitution) hidden inside a C-style
        // for-loop body was invisible to this hard-deny walk — matching the
        // exact bug `pipeline.rs`'s own "fix-round-1 Critical 1" already
        // closed for its own (different) walk.
        ast::CompoundCommand::Arithmetic(_) => {}
        ast::CompoundCommand::ArithmeticForClause(c) => {
            find_opaque_in_compound_list(&c.body.list, found)
        }
        ast::CompoundCommand::BraceGroup(g) => find_opaque_in_compound_list(&g.list, found),
        ast::CompoundCommand::Subshell(s) => find_opaque_in_compound_list(&s.list, found),
        ast::CompoundCommand::ForClause(c) => {
            if let Some(values) = &c.values {
                for w in values {
                    find_opaque_in_word(w, found);
                }
            }
            find_opaque_in_compound_list(&c.body.list, found);
        }
        ast::CompoundCommand::CaseClause(c) => {
            find_opaque_in_word(&c.value, found);
            for case in &c.cases {
                for p in &case.patterns {
                    find_opaque_in_word(p, found);
                }
                if let Some(body) = &case.cmd {
                    find_opaque_in_compound_list(body, found);
                }
            }
        }
        ast::CompoundCommand::IfClause(c) => {
            find_opaque_in_compound_list(&c.condition, found);
            find_opaque_in_compound_list(&c.then, found);
            if let Some(elses) = &c.elses {
                for e in elses {
                    if let Some(cond) = &e.condition {
                        find_opaque_in_compound_list(cond, found);
                    }
                    find_opaque_in_compound_list(&e.body, found);
                }
            }
        }
        ast::CompoundCommand::WhileClause(c) | ast::CompoundCommand::UntilClause(c) => {
            find_opaque_in_compound_list(&c.0, found);
            find_opaque_in_compound_list(&c.1.list, found);
        }
        ast::CompoundCommand::Coprocess(c) => {
            if let Some(name) = &c.name {
                find_opaque_in_word(name, found);
            }
            find_opaque_in_command(&c.body, found);
        }
    }
}

fn find_opaque_in_function_body(body: &ast::FunctionBody, found: &mut Vec<OpaqueNode>) {
    find_opaque_in_compound_command(&body.0, found);
    if let Some(rl) = &body.1 {
        find_opaque_in_redirect_list(rl, found);
    }
}

fn find_opaque_in_extended_test_expr(expr: &ast::ExtendedTestExpr, found: &mut Vec<OpaqueNode>) {
    match expr {
        ast::ExtendedTestExpr::And(left, right) | ast::ExtendedTestExpr::Or(left, right) => {
            find_opaque_in_extended_test_expr(left, found);
            find_opaque_in_extended_test_expr(right, found);
        }
        ast::ExtendedTestExpr::Not(inner) | ast::ExtendedTestExpr::Parenthesized(inner) => {
            find_opaque_in_extended_test_expr(inner, found);
        }
        ast::ExtendedTestExpr::UnaryTest(_, w) => find_opaque_in_word(w, found),
        ast::ExtendedTestExpr::BinaryTest(_, left, right) => {
            find_opaque_in_word(left, found);
            find_opaque_in_word(right, found);
        }
    }
}
fn find_opaque_in_word(word: &ast::Word, found: &mut Vec<OpaqueNode>) {
    match parse_word_pieces(&word.value) {
        Ok(pieces) => {
            if let Some(piece) = pieces.iter().find(|p| piece_is_opaque(&p.piece)) {
                found.push(OpaqueNode {
                    reason: OpaqueReason::CommandSubstitution,
                    span: (piece.start_index, piece.end_index),
                });
            }
        }
        Err(_) => found.push(OpaqueNode {
            reason: OpaqueReason::ParseError,
            span: (0, 0),
        }),
    }
}

fn source_span_to_tuple(span: Option<brush_parser::SourceSpan>) -> (usize, usize) {
    span.map(|s| (s.start.index, s.end.index)).unwrap_or((0, 0))
}
