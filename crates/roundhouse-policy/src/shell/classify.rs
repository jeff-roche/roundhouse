use std::collections::HashMap;
use std::io::Cursor;

use brush_parser::ast::{
    AndOr, AndOrList, Command, CommandPrefixOrSuffixItem, CompleteCommand, CompoundCommand,
    CompoundList, CompoundListItem, DoGroupCommand, ExtendedTestExpr, FunctionBody,
    FunctionDefinition, IoFileRedirectTarget, IoRedirect, Pipeline, Program, RedirectList,
    SimpleCommand, Word,
};
use brush_parser::word::{Parameter, ParameterExpr, WordPiece, WordPieceWithSource};
use brush_parser::{Parser, ParserOptions};

/// Byte-size cap on the raw shell command string (and on individual word strings).
const MAX_INPUT_BYTES: usize = 64 * 1024;

/// Maximum nesting depth of shell openers (`(`, backtick, `${`) accepted by the
/// pre-parser guard. Chosen to block the exponential backtracking and stack-overflow
/// blowups observed in `brush-parser` 0.4.0 while leaving realistic agent commands alone.
const MAX_NESTING_DEPTH: usize = 16;

/// Cheap pre-parser guard: rejects inputs that are too large or too deeply nested.
/// Over-limit inputs are treated as parse failures and hard-denied.
fn input_guard(raw: &str) -> Result<(), OpaqueReason> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(OpaqueReason::ParseError);
    }
    if nesting_depth(raw) > MAX_NESTING_DEPTH {
        return Err(OpaqueReason::ParseError);
    }
    Ok(())
}

/// Scans `raw` for unclosed `(`/backtick/`${` depth. Single-quoted regions are skipped
/// because their contents are literal and cannot drive parser nesting.
fn nesting_depth(raw: &str) -> usize {
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    let mut in_single_quote = false;
    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_single_quote {
            if ch == '\'' {
                in_single_quote = false;
            }
            continue;
        }
        if ch == '\'' {
            in_single_quote = true;
            continue;
        }
        match ch {
            '(' | '`' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            ')' => {
                depth = depth.saturating_sub(1);
            }
            '$' if chars.peek() == Some(&'{') => {
                depth += 1;
                max_depth = max_depth.max(depth);
                chars.next(); // consume the '{' that belongs to `${`
            }
            _ => {}
        }
    }
    max_depth
}

/// The full parsed pipeline AST — internal to the shell module. Deliberately not named
/// `ParsedCommand`: Phase 0 already froze that name for the simple `{program, argv}`
/// pair `TaskParams::Shell` carries (one resolved node, not a whole pipeline).
#[derive(Clone, Debug)]
pub struct ParsedShellAst {
    pub program_ast: Program,
    pub raw: String,
}

impl ParsedShellAst {
    /// Returns the argv of the first pipeline node, after any variable expansion.
    pub fn first_node_argv(&self) -> Vec<String> {
        first_pipeline_command(&self.program_ast)
            .and_then(|cmd| match cmd {
                Command::Simple(simple) => Some(flatten_simple_command_argv(simple)),
                _ => None,
            })
            .unwrap_or_default()
    }

    /// True if any word still contains an unresolved command substitution (`$(...)` or
    /// backtick form). Used after `resolve_variable_expansions` to confirm that step 2
    /// left opaque constructs untouched for step 3 to hard-deny.
    pub fn contains_unresolved_command_substitution(&self) -> bool {
        any_word_piece(&self.program_ast, piece_is_opaque)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueReason {
    ParseError,
    CommandSubstitution,
    ProcessSubstitution,
    Eval,
    Source,
    HereDoc,
    Backgrounding,
}

pub enum Classification {
    Program(ParsedShellAst),
    Opaque(OpaqueReason),
}

/// Parse a shell command string. Parse failures are returned as
/// `Classification::Opaque(OpaqueReason::ParseError)` rather than panicking.
pub fn parse_command(raw: &str) -> Classification {
    if let Err(reason) = input_guard(raw) {
        return Classification::Opaque(reason);
    }
    let options = ParserOptions::default();
    let reader = Cursor::new(raw);
    let mut parser = Parser::new(reader, &options);
    match parser.parse_program() {
        Ok(program_ast) => Classification::Program(ParsedShellAst {
            program_ast,
            raw: raw.to_string(),
        }),
        Err(_) => Classification::Opaque(OpaqueReason::ParseError),
    }
}

/// A minimal in-memory environment used during shell classification to resolve plain
/// variable expansions before policy matching.
#[derive(Default, Clone, Debug)]
pub struct SessionEnv {
    vars: HashMap<String, String>,
}

impl SessionEnv {
    pub fn set(&mut self, k: &str, v: &str) {
        self.vars.insert(k.to_string(), v.to_string());
    }

    pub fn get(&self, k: &str) -> Option<&str> {
        self.vars.get(k).map(String::as_str)
    }
}

/// Resolve plain `$VAR`/`${VAR}` variable expansions to their literal values from
/// `env`. Missing variables expand to the empty string. Any word containing a command
/// substitution, process substitution, arithmetic expansion, or non-plain parameter
/// expression is left exactly as-is so that `find_opaque_nodes` can hard-deny it.
pub fn resolve_variable_expansions(ast: &mut Program, env: &SessionEnv) {
    expand_in_program(ast, env);
}

// ---------------------------------------------------------------------------
// Word-level parsing helpers (used by expansion and opaque detection)
// ---------------------------------------------------------------------------

pub(crate) fn parse_word_pieces(word: &str) -> Result<Vec<WordPieceWithSource>, OpaqueReason> {
    input_guard(word)?;
    brush_parser::word::parse(word, &ParserOptions::default()).map_err(|_| OpaqueReason::ParseError)
}

/// True if the parsed word piece (recursively) contains any source-level opaque
/// construct: command substitution (including backticks inside double quotes),
/// arithmetic expansion embedding a substitution, or any non-plain parameter expansion.
pub(crate) fn piece_is_opaque(piece: &WordPiece) -> bool {
    match piece {
        WordPiece::CommandSubstitution(_) | WordPiece::BackquotedCommandSubstitution(_) => true,
        WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
            inner.iter().any(|p| piece_is_opaque(&p.piece))
        }
        WordPiece::ArithmeticExpression(expr) => raw_string_has_command_substitution(&expr.value),
        WordPiece::ParameterExpansion(expr) => parameter_expr_is_opaque(expr),
        _ => false,
    }
}

fn parameter_expr_is_opaque(expr: &ParameterExpr) -> bool {
    !matches!(
        expr,
        ParameterExpr::Parameter {
            parameter: Parameter::Named(_),
            indirect: false,
        }
    )
}

fn raw_string_has_command_substitution(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'`' && (i == 0 || bytes[i - 1] != b'\\') {
            return true;
        }
        if b == b'$' && i + 1 < bytes.len() && bytes[i + 1] == b'(' {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Variable expansion internals
// ---------------------------------------------------------------------------

fn expand_in_program(program: &mut Program, env: &SessionEnv) {
    for cc in &mut program.complete_commands {
        expand_in_complete_command(cc, env);
    }
}

fn expand_in_complete_command(cc: &mut CompleteCommand, env: &SessionEnv) {
    expand_in_compound_list(cc, env);
}

fn expand_in_compound_list(list: &mut CompoundList, env: &SessionEnv) {
    for item in &mut list.0 {
        expand_in_compound_list_item(item, env);
    }
}

fn expand_in_compound_list_item(item: &mut CompoundListItem, env: &SessionEnv) {
    expand_in_and_or_list(&mut item.0, env);
    // SeparatorOperator has no words.
}

fn expand_in_and_or_list(aol: &mut AndOrList, env: &SessionEnv) {
    expand_in_pipeline(&mut aol.first, env);
    for and_or in &mut aol.additional {
        match and_or {
            AndOr::And(pipeline) | AndOr::Or(pipeline) => expand_in_pipeline(pipeline, env),
        }
    }
}

fn expand_in_pipeline(pipeline: &mut Pipeline, env: &SessionEnv) {
    for cmd in &mut pipeline.seq {
        expand_in_command(cmd, env);
    }
}

fn expand_in_command(cmd: &mut Command, env: &SessionEnv) {
    match cmd {
        Command::Simple(simple) => expand_in_simple_command(simple, env),
        Command::Compound(compound, redirects) => {
            expand_in_compound_command(compound, env);
            if let Some(rl) = redirects {
                expand_in_redirect_list(rl, env);
            }
        }
        Command::Function(func) => expand_in_function_definition(func, env),
        Command::ExtendedTest(ext, redirects) => {
            expand_in_extended_test_expr(&mut ext.expr, env);
            if let Some(rl) = redirects {
                expand_in_redirect_list(rl, env);
            }
        }
    }
}

fn expand_in_simple_command(cmd: &mut SimpleCommand, env: &SessionEnv) {
    if let Some(prefix) = &mut cmd.prefix {
        expand_in_command_prefix(prefix, env);
    }
    if let Some(word_or_name) = &mut cmd.word_or_name {
        expand_word(word_or_name, env);
    }
    if let Some(suffix) = &mut cmd.suffix {
        expand_in_command_suffix(suffix, env);
    }
}

fn expand_in_command_prefix(prefix: &mut brush_parser::ast::CommandPrefix, env: &SessionEnv) {
    for item in &mut prefix.0 {
        expand_in_prefix_or_suffix_item(item, env);
    }
}

fn expand_in_command_suffix(suffix: &mut brush_parser::ast::CommandSuffix, env: &SessionEnv) {
    for item in &mut suffix.0 {
        expand_in_prefix_or_suffix_item(item, env);
    }
}

fn expand_in_prefix_or_suffix_item(item: &mut CommandPrefixOrSuffixItem, env: &SessionEnv) {
    match item {
        CommandPrefixOrSuffixItem::Word(w) => expand_word(w, env),
        CommandPrefixOrSuffixItem::AssignmentWord(_, w) => expand_word(w, env),
        CommandPrefixOrSuffixItem::IoRedirect(r) => expand_in_io_redirect(r, env),
        CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => {
            // Opaque; leave untouched so step 3 can deny it.
        }
    }
}

fn expand_in_redirect_list(rl: &mut RedirectList, env: &SessionEnv) {
    for r in &mut rl.0 {
        expand_in_io_redirect(r, env);
    }
}

fn expand_in_io_redirect(r: &mut IoRedirect, env: &SessionEnv) {
    match r {
        IoRedirect::File(_, _, IoFileRedirectTarget::Filename(w))
        | IoRedirect::File(_, _, IoFileRedirectTarget::Duplicate(w))
        | IoRedirect::HereString(_, w)
        | IoRedirect::OutputAndError(w, _) => expand_word(w, env),
        IoRedirect::HereDocument(_, hd) => {
            expand_word(&mut hd.here_end, env);
            expand_word(&mut hd.doc, env);
        }
        IoRedirect::File(_, _, IoFileRedirectTarget::Fd(_))
        | IoRedirect::File(_, _, IoFileRedirectTarget::ProcessSubstitution(_, _)) => {
            // Process substitution is opaque; leave untouched.
        }
    }
}

fn expand_in_compound_command(cmd: &mut CompoundCommand, env: &SessionEnv) {
    match cmd {
        CompoundCommand::Arithmetic(_) | CompoundCommand::ArithmeticForClause(_) => {
            // Arithmetic expressions contain no Words to expand at this layer.
        }
        CompoundCommand::BraceGroup(g) => expand_in_compound_list(&mut g.list, env),
        CompoundCommand::Subshell(s) => expand_in_compound_list(&mut s.list, env),
        CompoundCommand::ForClause(c) => {
            // `variable_name` is a plain String (the loop variable identifier).
            if let Some(values) = &mut c.values {
                for w in values {
                    expand_word(w, env);
                }
            }
            expand_in_do_group(&mut c.body, env);
        }
        CompoundCommand::CaseClause(c) => {
            expand_word(&mut c.value, env);
            for case in &mut c.cases {
                for p in &mut case.patterns {
                    expand_word(p, env);
                }
                if let Some(body) = &mut case.cmd {
                    expand_in_compound_list(body, env);
                }
            }
        }
        CompoundCommand::IfClause(c) => {
            expand_in_compound_list(&mut c.condition, env);
            expand_in_compound_list(&mut c.then, env);
            if let Some(elses) = &mut c.elses {
                for e in elses {
                    if let Some(cond) = &mut e.condition {
                        expand_in_compound_list(cond, env);
                    }
                    expand_in_compound_list(&mut e.body, env);
                }
            }
        }
        CompoundCommand::WhileClause(c) | CompoundCommand::UntilClause(c) => {
            expand_in_compound_list(&mut c.0, env);
            expand_in_do_group(&mut c.1, env);
        }
        CompoundCommand::Coprocess(c) => {
            if let Some(name) = &mut c.name {
                expand_word(name, env);
            }
            expand_in_command(&mut c.body, env);
        }
    }
}

fn expand_in_do_group(group: &mut DoGroupCommand, env: &SessionEnv) {
    expand_in_compound_list(&mut group.list, env);
}

fn expand_in_function_definition(f: &mut FunctionDefinition, env: &SessionEnv) {
    expand_word(&mut f.fname, env);
    expand_in_function_body(&mut f.body, env);
}

fn expand_in_function_body(body: &mut FunctionBody, env: &SessionEnv) {
    expand_in_compound_command(&mut body.0, env);
    if let Some(rl) = &mut body.1 {
        expand_in_redirect_list(rl, env);
    }
}

fn expand_in_extended_test_expr(expr: &mut ExtendedTestExpr, env: &SessionEnv) {
    match expr {
        ExtendedTestExpr::And(left, right) | ExtendedTestExpr::Or(left, right) => {
            expand_in_extended_test_expr(left, env);
            expand_in_extended_test_expr(right, env);
        }
        ExtendedTestExpr::Not(inner) | ExtendedTestExpr::Parenthesized(inner) => {
            expand_in_extended_test_expr(inner, env);
        }
        ExtendedTestExpr::UnaryTest(_, w) => expand_word(w, env),
        ExtendedTestExpr::BinaryTest(_, left, right) => {
            expand_word(left, env);
            expand_word(right, env);
        }
    }
}

fn expand_word(word: &mut Word, env: &SessionEnv) {
    let pieces = match parse_word_pieces(&word.value) {
        Ok(pieces) => pieces,
        Err(_) => return,
    };

    if !pieces.iter().all(|p| is_expandable_piece(&p.piece)) {
        return;
    }

    let mut expanded = String::new();
    for piece in &pieces {
        expand_piece(&piece.piece, env, &mut expanded);
    }
    word.value = expanded;
}

fn is_expandable_piece(piece: &WordPiece) -> bool {
    match piece {
        WordPiece::Text(_)
        | WordPiece::SingleQuotedText(_)
        | WordPiece::AnsiCQuotedText(_)
        | WordPiece::EscapeSequence(_) => true,
        WordPiece::ParameterExpansion(ParameterExpr::Parameter {
            parameter: Parameter::Named(_),
            indirect: false,
        }) => true,
        WordPiece::DoubleQuotedSequence(inner) => {
            inner.iter().all(|p| is_quoted_expandable(&p.piece))
        }
        _ => false,
    }
}

fn is_quoted_expandable(piece: &WordPiece) -> bool {
    matches!(
        piece,
        WordPiece::Text(_)
            | WordPiece::EscapeSequence(_)
            | WordPiece::ParameterExpansion(ParameterExpr::Parameter {
                parameter: Parameter::Named(_),
                indirect: false,
            })
    )
}

fn expand_piece(piece: &WordPiece, env: &SessionEnv, out: &mut String) {
    match piece {
        WordPiece::Text(s) | WordPiece::SingleQuotedText(s) | WordPiece::AnsiCQuotedText(s) => {
            out.push_str(s)
        }
        WordPiece::EscapeSequence(s) => out.push_str(unescape(s).as_str()),
        WordPiece::ParameterExpansion(ParameterExpr::Parameter {
            parameter: Parameter::Named(name),
            indirect: false,
        }) => out.push_str(env.get(name).unwrap_or("")),
        WordPiece::DoubleQuotedSequence(inner) => {
            for p in inner {
                expand_piece(&p.piece, env, out);
            }
        }
        _ => {}
    }
}

fn unescape(s: &str) -> String {
    if s.len() < 2 || !s.starts_with('\\') {
        return s.to_string();
    }
    let ch = s.chars().nth(1).unwrap_or('\0');
    match ch {
        '\\' => "\\".to_string(),
        '$' => "$".to_string(),
        '`' => "`".to_string(),
        '"' => "\"".to_string(),
        '\'' => "'".to_string(),
        _ => s[1..].to_string(),
    }
}

// ---------------------------------------------------------------------------
// AST helpers used by ParsedShellAst
// ---------------------------------------------------------------------------

fn first_pipeline_command(program: &Program) -> Option<&Command> {
    program
        .complete_commands
        .first()
        .and_then(|cc| cc.0.first())
        .map(|item| &item.0)
        .and_then(|aol| aol.first.seq.first())
}

fn flatten_simple_command_argv(cmd: &SimpleCommand) -> Vec<String> {
    let mut argv = Vec::new();
    if let Some(word_or_name) = &cmd.word_or_name {
        argv.push(word_or_name.value.clone());
    }
    if let Some(suffix) = &cmd.suffix {
        for item in &suffix.0 {
            if let CommandPrefixOrSuffixItem::Word(w) = item {
                argv.push(w.value.clone());
            }
        }
    }
    argv
}

fn any_word_piece(program: &Program, predicate: impl Fn(&WordPiece) -> bool) -> bool {
    for cc in &program.complete_commands {
        if any_word_piece_in_compound_list(cc, &predicate) {
            return true;
        }
    }
    false
}

fn any_word_piece_in_compound_list(
    list: &CompoundList,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    for item in &list.0 {
        if any_word_piece_in_and_or_list(&item.0, predicate) {
            return true;
        }
    }
    false
}

fn any_word_piece_in_and_or_list(aol: &AndOrList, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    if any_word_piece_in_pipeline(&aol.first, predicate) {
        return true;
    }
    for and_or in &aol.additional {
        match and_or {
            AndOr::And(p) | AndOr::Or(p) => {
                if any_word_piece_in_pipeline(p, predicate) {
                    return true;
                }
            }
        }
    }
    false
}

fn any_word_piece_in_pipeline(
    pipeline: &Pipeline,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    for cmd in &pipeline.seq {
        if any_word_piece_in_command(cmd, predicate) {
            return true;
        }
    }
    false
}

fn any_word_piece_in_command(cmd: &Command, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    match cmd {
        Command::Simple(simple) => {
            if let Some(word_or_name) = &simple.word_or_name {
                if word_matches(word_or_name, predicate) {
                    return true;
                }
            }
            if let Some(prefix) = &simple.prefix {
                for item in &prefix.0 {
                    if prefix_or_suffix_item_matches(item, predicate) {
                        return true;
                    }
                }
            }
            if let Some(suffix) = &simple.suffix {
                for item in &suffix.0 {
                    if prefix_or_suffix_item_matches(item, predicate) {
                        return true;
                    }
                }
            }
            false
        }
        Command::Compound(compound, redirects) => {
            if any_word_piece_in_compound_command(compound, predicate) {
                return true;
            }
            if let Some(rl) = redirects {
                if redirect_list_matches(rl, predicate) {
                    return true;
                }
            }
            false
        }
        Command::Function(func) => {
            if word_matches(&func.fname, predicate) {
                return true;
            }
            any_word_piece_in_function_body(&func.body, predicate)
        }
        Command::ExtendedTest(ext, redirects) => {
            if extended_test_expr_matches(&ext.expr, predicate) {
                return true;
            }
            if let Some(rl) = redirects {
                if redirect_list_matches(rl, predicate) {
                    return true;
                }
            }
            false
        }
    }
}

fn prefix_or_suffix_item_matches(
    item: &CommandPrefixOrSuffixItem,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    match item {
        CommandPrefixOrSuffixItem::Word(w) | CommandPrefixOrSuffixItem::AssignmentWord(_, w) => {
            word_matches(w, predicate)
        }
        CommandPrefixOrSuffixItem::IoRedirect(r) => io_redirect_matches(r, predicate),
        CommandPrefixOrSuffixItem::ProcessSubstitution(_, _) => false,
    }
}

fn redirect_list_matches(rl: &RedirectList, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    for r in &rl.0 {
        if io_redirect_matches(r, predicate) {
            return true;
        }
    }
    false
}

fn io_redirect_matches(r: &IoRedirect, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    match r {
        IoRedirect::File(_, _, IoFileRedirectTarget::Filename(w))
        | IoRedirect::File(_, _, IoFileRedirectTarget::Duplicate(w))
        | IoRedirect::HereString(_, w)
        | IoRedirect::OutputAndError(w, _) => word_matches(w, predicate),
        IoRedirect::HereDocument(_, hd) => {
            word_matches(&hd.here_end, predicate) || word_matches(&hd.doc, predicate)
        }
        IoRedirect::File(_, _, IoFileRedirectTarget::Fd(_))
        | IoRedirect::File(_, _, IoFileRedirectTarget::ProcessSubstitution(_, _)) => false,
    }
}

fn any_word_piece_in_compound_command(
    cmd: &CompoundCommand,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    match cmd {
        CompoundCommand::Arithmetic(_) | CompoundCommand::ArithmeticForClause(_) => false,
        CompoundCommand::BraceGroup(g) => any_word_piece_in_compound_list(&g.list, predicate),
        CompoundCommand::Subshell(s) => any_word_piece_in_compound_list(&s.list, predicate),
        CompoundCommand::ForClause(c) => {
            if let Some(values) = &c.values {
                for w in values {
                    if word_matches(w, predicate) {
                        return true;
                    }
                }
            }
            any_word_piece_in_compound_list(&c.body.list, predicate)
        }
        CompoundCommand::CaseClause(c) => {
            if word_matches(&c.value, predicate) {
                return true;
            }
            for case in &c.cases {
                for p in &case.patterns {
                    if word_matches(p, predicate) {
                        return true;
                    }
                }
                if let Some(body) = &case.cmd {
                    if any_word_piece_in_compound_list(body, predicate) {
                        return true;
                    }
                }
            }
            false
        }
        CompoundCommand::IfClause(c) => {
            if any_word_piece_in_compound_list(&c.condition, predicate) {
                return true;
            }
            if any_word_piece_in_compound_list(&c.then, predicate) {
                return true;
            }
            if let Some(elses) = &c.elses {
                for e in elses {
                    if let Some(cond) = &e.condition {
                        if any_word_piece_in_compound_list(cond, predicate) {
                            return true;
                        }
                    }
                    if any_word_piece_in_compound_list(&e.body, predicate) {
                        return true;
                    }
                }
            }
            false
        }
        CompoundCommand::WhileClause(c) | CompoundCommand::UntilClause(c) => {
            any_word_piece_in_compound_list(&c.0, predicate)
                || any_word_piece_in_compound_list(&c.1.list, predicate)
        }
        CompoundCommand::Coprocess(c) => {
            if let Some(name) = &c.name {
                if word_matches(name, predicate) {
                    return true;
                }
            }
            any_word_piece_in_command(&c.body, predicate)
        }
    }
}

fn any_word_piece_in_function_body(
    body: &FunctionBody,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    if any_word_piece_in_compound_command(&body.0, predicate) {
        return true;
    }
    if let Some(rl) = &body.1 {
        if redirect_list_matches(rl, predicate) {
            return true;
        }
    }
    false
}

fn extended_test_expr_matches(
    expr: &ExtendedTestExpr,
    predicate: &impl Fn(&WordPiece) -> bool,
) -> bool {
    match expr {
        ExtendedTestExpr::And(left, right) | ExtendedTestExpr::Or(left, right) => {
            extended_test_expr_matches(left, predicate)
                || extended_test_expr_matches(right, predicate)
        }
        ExtendedTestExpr::Not(inner) | ExtendedTestExpr::Parenthesized(inner) => {
            extended_test_expr_matches(inner, predicate)
        }
        ExtendedTestExpr::UnaryTest(_, w) => word_matches(w, predicate),
        ExtendedTestExpr::BinaryTest(_, left, right) => {
            word_matches(left, predicate) || word_matches(right, predicate)
        }
    }
}

fn word_matches(word: &Word, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    match parse_word_pieces(&word.value) {
        Ok(pieces) => pieces.iter().any(|p| piece_matches(&p.piece, predicate)),
        Err(_) => true,
    }
}

fn piece_matches(piece: &WordPiece, predicate: &impl Fn(&WordPiece) -> bool) -> bool {
    if predicate(piece) {
        return true;
    }
    match piece {
        WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
            inner.iter().any(|p| piece_matches(&p.piece, predicate))
        }
        _ => false,
    }
}
