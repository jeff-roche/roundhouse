use std::cell::Cell;
use std::collections::HashMap;
use std::io::Cursor;

use brush_parser::ast::{
    AndOr, AndOrList, Command, CommandPrefixOrSuffixItem, CompleteCommand, CompoundCommand,
    CompoundList, CompoundListItem, DoGroupCommand, ExtendedTestExpr, FunctionBody,
    FunctionDefinition, IoFileRedirectTarget, IoRedirect, Pipeline, Program, RedirectList,
    SimpleCommand, Word,
};
use brush_parser::word::{
    Parameter, ParameterExpr, ParameterTestType, WordPiece, WordPieceWithSource,
};
use brush_parser::{Parser, ParserOptions};

/// Byte-size cap on the raw shell command string (and on individual word strings).
///
/// 4 KiB. This is the *load-bearing* half of the stack-exhaustion bound: together with
/// [`PARSE_STACK_BYTES`] it fixes a hard ceiling on how much stack any attacker-controlled
/// input can drive `brush-parser` (and this module's own recursive AST walkers) to
/// consume. See [`PARSE_STACK_BYTES`] for the calibration.
///
/// 4 KiB is far above any legitimate agent-emitted command line; over-cap inputs fail
/// closed (hard-deny with a "restructure this" hint), so the cost of the lower cap is
/// availability for pathological commands, never a missed dangerous classification.
pub(crate) const MAX_INPUT_BYTES: usize = 4 * 1024;

/// Stack reserved for the dedicated thread that every untrusted parse and every
/// recursive walk over an untrusted AST runs on.
///
/// **Why a thread at all.** `brush-parser` is a recursive-descent (PEG) parser with no
/// internal recursion limit, and this module's own AST walkers recurse in lockstep with
/// it. A stack overflow in Rust is an *uncatchable* `SIGABRT` — not a panic, not
/// recoverable with `catch_unwind` — so the only way to keep model-controlled shell
/// syntax from killing the daemon is to make overflow unreachable. Three prior rounds
/// tried to do that by enumerating the grammar's recursion points in a pre-parser guard;
/// each enumeration turned out to be incomplete (the most recent gap: the extended-test
/// `!` prefix operator, `peg.rs:215`, which recurses once per token and is not an opener
/// any character-counting guard sees). This constant bounds the *resource* instead of the
/// grammar, so it holds for recursion points nobody has found yet.
///
/// **Calibration** (all figures measured on this crate's `dev` profile, which has larger
/// frames than `release`, i.e. the conservative direction; see the fix-round-4 section of
/// `task-11-12-report.md` for the raw probe output):
///
/// | construct                       | stack/level | input bytes/level | stack per input byte |
/// |---------------------------------|-------------|-------------------|----------------------|
/// | `[[ ! ! … x ]]` (uncounted)     | 9,473 B     | 2                 | **4,737 B**          |
/// | `echo $( $( … id ) )`           | 12,710 B    | 3                 | 4,237 B              |
/// | `echo ${ ${ … X } }`            | 11,397 B    | 3                 | 3,799 B              |
/// | `{ { … a; }; }`                 | 17,331 B    | 5                 | 3,466 B              |
/// | `while a; do … done`            | 17,848 B    | 18                | 992 B                |
/// | `if a; then … fi`               | 17,772 B    | 15                | 1,185 B              |
/// | `(( ( ( … ) ) ))`               | 708 B       | 2                 | 354 B                |
///
/// 256 MiB / 4 KiB = 65,536 bytes of stack tolerated per byte of input. That is **13.8x**
/// the densest construct measured, and still **3.7x** the deliberately paranoid bound of
/// "some undiscovered construct recurses once per *single* input byte at the largest
/// per-level frame ever measured here (17,848 B)" — which would need 15,050 bytes of
/// input to overflow, well past the 4 KiB cap. Empirically, the worst known payload
/// (`[[ ! ! … x ]]`) only overflows 256 MiB at 56,679 input bytes.
///
/// **Why this is cheap.** A thread stack is `mmap`ed lazily: only pages actually touched
/// are faulted in. Measured spawn+join cost is ~50 µs and peak RSS is unchanged whether
/// the stack size is 1 MiB or 256 MiB (2.7–2.8 MiB VmHWM over 2,000 iterations either
/// way).
const PARSE_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Structural complexity budget for the pre-parser guard: total count of every
/// grammar-recursing opener (`(`, backtick, `${`, bare `{`, `[[`) plus the whole-word
/// keywords `case`, `if`, `then`, `while`, `until`, `for`, `select`, `coproc`,
/// `function`. The budget is deliberately grammar-wide and over-counts (e.g., `echo`
/// containing the substring `for` would contribute +1 — accepted fail-closed cost).
///
/// Cap 16 is chosen to block the smallest observed crash payload (25 nested `case`
/// clauses, ~500 bytes) and the 1000/1500/2000-deep compound-command probes while
/// leaving normal arithmetic such as `(( i = i + 1 ))` (2 openers) well within budget.
///
/// Because the metric is a total *occurrence count* rather than a nesting depth, a flat
/// but bracket-heavy one-liner (a long `awk`/`jq` program, say) can exceed it even though
/// it would have parsed fine. That is an accepted fail-closed cost, and the rejection is
/// reported with its own hint (see [`GuardRejection`]) rather than being mislabelled a
/// parse failure.
const MAX_STRUCTURAL_BUDGET: usize = 16;

/// Why the cheap pre-parser guard rejected an input. Kept separate from
/// [`OpaqueReason`] (whose variants are frozen by the module contract) purely so callers
/// can render an honest hint: a budget rejection is *not* a parse failure, and saying so
/// would mislead a model that emitted a perfectly valid but paren-heavy one-liner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardRejection {
    TooLarge,
    TooComplex,
}

/// Cheap pre-parser guard: rejects inputs that are too large or exceed the structural
/// complexity budget. Over-limit inputs are hard-denied.
///
/// This is a *first-pass filter*, not the stack-exhaustion backstop — that role belongs
/// to [`PARSE_STACK_BYTES`]. It is kept because it is essentially free and because it
/// still cheaply blocks the exponential-backtracking (CPU, not stack) blowups documented
/// in earlier rounds, e.g. 25 nested `case` clauses in 502 bytes.
pub(crate) fn check_input_guard(raw: &str) -> Result<(), GuardRejection> {
    if raw.len() > MAX_INPUT_BYTES {
        return Err(GuardRejection::TooLarge);
    }
    if structural_budget(raw) > MAX_STRUCTURAL_BUDGET {
        return Err(GuardRejection::TooComplex);
    }
    Ok(())
}

fn input_guard(raw: &str) -> Result<(), OpaqueReason> {
    check_input_guard(raw).map_err(|_| OpaqueReason::ParseError)
}

thread_local! {
    /// True while the current thread *is* a parse-stack thread, so nested calls through
    /// the module's public entry points reuse the existing big stack instead of spawning
    /// another one.
    static ON_PARSE_STACK: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` on a dedicated thread with [`PARSE_STACK_BYTES`] of stack and joins it.
///
/// Every code path in this module that parses untrusted shell text or recurses over an
/// untrusted AST goes through here. Re-entrant: if the caller is already on a parse-stack
/// thread, `f` runs inline.
///
/// Returns `Err(OpaqueReason::ParseError)` if the thread could not be spawned or if `f`
/// panicked — both fail closed into a hard-deny.
pub(crate) fn with_parse_stack<T, F>(f: F) -> Result<T, OpaqueReason>
where
    F: FnOnce() -> T + Send,
    T: Send,
{
    if ON_PARSE_STACK.with(Cell::get) {
        return Ok(f());
    }
    std::thread::scope(|scope| {
        let handle = std::thread::Builder::new()
            .name("rh-shell-classify".to_string())
            .stack_size(PARSE_STACK_BYTES)
            .spawn_scoped(scope, || {
                ON_PARSE_STACK.with(|flag| flag.set(true));
                f()
            })
            .map_err(|_| OpaqueReason::ParseError)?;
        handle.join().map_err(|_| OpaqueReason::ParseError)
    })
}

/// Quote-naive count of all grammar-recursing openers/keywords in `raw`. Counting
/// every occurrence unconditionally (rather than net depth or quote-aware depth) is
/// fail-closed: any per-construct whack-a-mole against a recursive-descent grammar
/// is exactly how the earlier rounds were bypassed.
fn structural_budget(raw: &str) -> usize {
    let mut budget = 0usize;
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'`' => {
                budget += 1;
                i += 1;
            }
            b'[' if i + 1 < bytes.len() && bytes[i + 1] == b'[' => {
                budget += 1;
                i += 2;
            }
            b'{' => {
                // Always a bare brace: the `$` arm below consumes `${` as a single
                // two-byte unit, so the `{` of a `${` opener is never visited here.
                budget += 1;
                i += 1;
            }
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                budget += 1;
                i += 2;
            }
            _ => {
                if let Some(len) = keyword_match(bytes, i) {
                    budget += 1;
                    i += len;
                } else {
                    i += 1;
                }
            }
        }
    }
    budget
}

const KEYWORDS: &[&str] = &[
    "case", "if", "then", "while", "until", "for", "select", "coproc", "function",
];

fn keyword_match(bytes: &[u8], start: usize) -> Option<usize> {
    for kw in KEYWORDS {
        let kw_bytes = kw.as_bytes();
        let end = start + kw_bytes.len();
        if end > bytes.len() {
            continue;
        }
        if &bytes[start..end] != kw_bytes {
            continue;
        }
        let prev_ok = start == 0 || !is_identifier_byte(bytes[start - 1]);
        let next_ok = end == bytes.len() || !is_identifier_byte(bytes[end]);
        if prev_ok && next_ok {
            return Some(kw_bytes.len());
        }
    }
    None
}

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
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
        // Recursive walk over untrusted AST → bounded stack; fail closed on any error.
        with_parse_stack(|| any_word_piece(&self.program_ast, piece_is_opaque)).unwrap_or(true)
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
///
/// The parse itself runs on a dedicated [`PARSE_STACK_BYTES`] stack, so no input within
/// [`MAX_INPUT_BYTES`] can drive `brush-parser`'s recursion into a stack overflow.
pub fn parse_command(raw: &str) -> Classification {
    if let Err(reason) = input_guard(raw) {
        return Classification::Opaque(reason);
    }
    match with_parse_stack(|| parse_command_inner(raw)) {
        Ok(classification) => classification,
        Err(reason) => Classification::Opaque(reason),
    }
}

fn parse_command_inner(raw: &str) -> Classification {
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
///
/// The walk recurses in lockstep with the AST's nesting, so it runs on the same
/// dedicated [`PARSE_STACK_BYTES`] stack the parse used.
pub fn resolve_variable_expansions(ast: &mut Program, env: &SessionEnv) {
    let _ = with_parse_stack(|| expand_in_program(ast, env));
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
    !parameter_expr_is_allowlisted(expr)
}

/// The shared opaque-check/expand-resolution predicate (task-22.5). This crate's own
/// `parameter_expr_is_opaque` (used by `piece_is_opaque`, the hard-deny path) and
/// `is_expandable_piece`/`expand_piece` (the argv-resolution path) MUST stay in exact
/// lockstep: a form accepted here without a matching resolution arm in
/// `expand_parameter_expr` would let unexpanded `${...}` text reach argv verbatim (a
/// correctness *and* policy-fidelity regression — see the module-level task-22.5 brief).
///
/// **Design: allowlist, not deny-scan.** Denies by default; a form is accepted only when
/// BOTH of the following hold:
/// - `indirect: false` — an indirect reference (`${!x}`) computes its target name at
///   runtime, so it can never be statically resolved here and must stay denied.
/// - every payload string the variant carries (default/alternative value, pattern, ...)
///   is `None` or passes [`is_safe_literal_payload`] — no `$`, no backtick, no `~`. See
///   that function's doc comment for why all three are banned (task-22.5 fix round 1
///   closed a real command-injection regression here: an earlier version of this gate
///   banned only `$`, and `brush-parser` stores these payloads as RAW STRINGS — never
///   nested `WordPiece`s — so a bare backtick inside `${X:-\`cmd\`}` was invisible to
///   both `find_opaque_nodes` and the `$`-only check, and DID execute).
///
/// Every accepted variant is additionally restricted to `Parameter::Named(_)` — never
/// `Positional`/`Special` (no positional/special context exists at classify time) or
/// `NamedWithIndex`/`NamedWithAllIndices` (no array model in `SessionEnv`, and array
/// forms expand to MULTIPLE argv words, which this module's one-word-in/one-word-out
/// `expand_word` cannot represent). Leaving those denied is intentional, not a gap: the
/// bake-off gate's target is a false-Opaque rate comfortably under 15%, not 0%.
///
/// The four prefix/suffix pattern-stripping variants additionally require
/// [`prefix_suffix_pattern_is_safe`] — a pattern must be in the verified-safe glob
/// subset AND compile successfully via `globset`, or the whole expression is denied
/// (fail closed on either a pattern outside the verified subset or a compile failure —
/// task-22.5 fix round 1: previously a compile failure silently fell back to "no
/// stripping" at *resolve* time, which is a resolved-value divergence from real bash,
/// i.e. security-relevant in this module, not a mere correctness nit).
fn parameter_expr_is_allowlisted(expr: &ParameterExpr) -> bool {
    match expr {
        ParameterExpr::Parameter {
            parameter,
            indirect: false,
        } => is_plain_named(parameter),
        ParameterExpr::ParameterLength {
            parameter,
            indirect: false,
        } => is_plain_named(parameter),
        ParameterExpr::UseDefaultValues {
            parameter,
            indirect: false,
            test_type: _,
            default_value,
        } => is_plain_named(parameter) && is_safe_literal_payload(default_value),
        ParameterExpr::AssignDefaultValues {
            parameter,
            indirect: false,
            test_type: _,
            default_value,
        } => is_plain_named(parameter) && is_safe_literal_payload(default_value),
        ParameterExpr::UseAlternativeValue {
            parameter,
            indirect: false,
            test_type: _,
            alternative_value,
        } => is_plain_named(parameter) && is_safe_literal_payload(alternative_value),
        ParameterExpr::RemoveSmallestPrefixPattern {
            parameter,
            indirect: false,
            pattern,
        }
        | ParameterExpr::RemoveLargestPrefixPattern {
            parameter,
            indirect: false,
            pattern,
        }
        | ParameterExpr::RemoveSmallestSuffixPattern {
            parameter,
            indirect: false,
            pattern,
        }
        | ParameterExpr::RemoveLargestSuffixPattern {
            parameter,
            indirect: false,
            pattern,
        } => {
            is_plain_named(parameter)
                && is_safe_literal_payload(pattern)
                && prefix_suffix_pattern_is_safe(pattern)
        }
        // Deliberately NOT accepted, even though `indirect: false` alone wouldn't be
        // unsafe for some of these:
        // - `IndicateErrorIfNullOrUnset` (`${var:?msg}`): `error_message` carries no
        //   execution semantics, so it's plausibly safe under the same gating — but
        //   this classifier has no error-propagation model to correctly represent
        //   "fail the task if var is unset/null" during resolution, and the bake-off
        //   corpus doesn't need it to clear the gate. Left denied rather than guessed at.
        // - `Transform` (covers `${x@P}`, `${x@Q}`, etc.): never accepted regardless of
        //   payload — this is bypass #1 from the original brief; `${x@P}`'s danger
        //   lives entirely in the variable's own value, not in any string this
        //   expression carries.
        // - Every other transform/case-conversion/substring/replace variant not listed
        //   above (`UppercaseFirstChar`, `UppercasePattern`, `LowercaseFirstChar`,
        //   `LowercasePattern`, `ReplaceSubstring`, `Substring`): not reasoned about:
        //   `Substring`'s `offset`/`length` are arithmetic-expression payloads (bypass
        //   #3's exact shape), so it's excluded outright.
        // - `Parameter::Positional`/`Special`/`NamedWithIndex`/`NamedWithAllIndices` for
        //   any of the variants above: excluded by `is_plain_named`, per the doc comment.
        _ => false,
    }
}

fn is_plain_named(parameter: &Parameter) -> bool {
    matches!(parameter, Parameter::Named(_))
}

/// True if `payload` is absent, or present and safe to treat as an inert literal for
/// policy-matching purposes: contains no `$` (any expansion form, not just `$(`), no
/// backtick (command substitution — deliberately checked as a blunt unconditional
/// substring ban, NOT the escape-aware `raw_string_has_command_substitution` used
/// elsewhere in this module for arithmetic expressions; escape-awareness only ever
/// *weakens* a check by carving out exceptions, and this module's standing rule is
/// "when in doubt, deny" — see task-22.5 fix round 1's Critical finding), and no `~`
/// (tilde expansion: real bash expands a leading `~` to a real home-directory path in
/// this position, but this classifier has no such model and would otherwise resolve the
/// literal text `~/...`, which a path-shaped policy rule could be fooled by — task-22.5
/// fix round 1 Important finding #1).
fn is_safe_literal_payload(payload: &Option<String>) -> bool {
    payload.as_deref().is_none_or(is_safe_literal_str)
}

fn is_safe_literal_str(s: &str) -> bool {
    !s.contains('$') && !s.contains('`') && !s.contains('~')
}

/// True if `pattern` (a `${var#pattern}`-family payload) is `None`, or present and BOTH
/// in the verified-safe glob subset ([`is_verified_safe_glob_pattern`]) AND compiles
/// successfully via `globset::Glob`. Both conditions are checked at *classify* time
/// (not just resolve time) so a pattern this module can't confidently resolve correctly
/// denies the whole expression rather than silently falling back to a different
/// resolved value than real bash would produce (task-22.5 fix round 1, Important #2).
fn prefix_suffix_pattern_is_safe(pattern: &Option<String>) -> bool {
    match pattern.as_deref() {
        None => true,
        Some(p) => is_verified_safe_glob_pattern(p) && compile_glob(p).is_some(),
    }
}

/// True only for patterns in the glob subset this module has actually checked matches
/// bash's own prefix/suffix pattern-matching semantics: literal characters, `*`, `?`,
/// and simple (non-nested, single-`]`-terminated) bracket character classes, optionally
/// negated with a leading `!` or `^`. Rejects everything else, in particular:
/// - `**` (task-22.5 fix round 1, Important #3): `globset` gives `**` special
///   "match across path components" semantics that were adversarially confirmed to
///   diverge from bash's own glob matcher in BOTH directions on `${f#**/}`/`${f##**/}`
///   — under-stripping in one direction, over-stripping in the other. Not "fixable" by
///   a tweak; the safe move is to not accept `**` into the verified subset at all.
/// - `{`/`}` (brace alternation) and `\` (escape sequences, since `globset`'s default
///   `backslash_escape` is platform-dependent and this module hasn't verified its
///   semantics against bash here): neither has been checked against bash, so neither is
///   accepted — narrow the accepted pattern language to what's actually verified
///   correct, and deny the rest, rather than trying to faithfully support the full bash
///   glob dialect.
fn is_verified_safe_glob_pattern(pattern: &str) -> bool {
    if pattern.contains("**") {
        return false;
    }
    let bytes = pattern.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'*' | b'?' => i += 1,
            b'[' => {
                let mut j = i + 1;
                if j < bytes.len() && (bytes[j] == b'!' || bytes[j] == b'^') {
                    j += 1;
                }
                // A `]` immediately after `[` (or `[!`/`[^`) is a literal `]`, per the
                // usual glob/POSIX bracket-expression convention.
                if j < bytes.len() && bytes[j] == b']' {
                    j += 1;
                }
                let body_start = j;
                let mut closed = false;
                while j < bytes.len() {
                    match bytes[j] {
                        b'[' => return false, // nested bracket: outside the verified subset
                        b']' => {
                            closed = true;
                            break;
                        }
                        _ => j += 1,
                    }
                }
                if !closed || j == body_start {
                    return false;
                }
                i = j + 1;
            }
            b'{' | b'}' | b'\\' => return false,
            _ => i += 1,
        }
    }
    true
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
        // Arithmetic expressions contain no Words to expand at this layer.
        // `ArithmeticForClause` is different — it has its own
        // `body: DoGroupCommand` full of real words to expand, exactly like
        // `ForClause` below — grouping it with `Arithmetic` here (Task 26,
        // W4) left a plain `$VAR` inside a C-style for-loop body unexpanded.
        CompoundCommand::Arithmetic(_) => {}
        CompoundCommand::ArithmeticForClause(c) => expand_in_do_group(&mut c.body, env),
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

/// MUST accept exactly the `ParameterExpr` forms `parameter_expr_is_allowlisted` accepts
/// (task-22.5 lockstep requirement) — this is what makes a non-opaque `${...}` form
/// actually reach argv resolved, instead of being denied at `piece_is_opaque` but then
/// falling through `expand_word`'s "any non-expandable piece bails the whole word"
/// short-circuit and reaching argv as unexpanded literal `${...}` text.
fn is_expandable_piece(piece: &WordPiece) -> bool {
    match piece {
        WordPiece::Text(_)
        | WordPiece::SingleQuotedText(_)
        | WordPiece::AnsiCQuotedText(_)
        | WordPiece::EscapeSequence(_) => true,
        WordPiece::ParameterExpansion(expr) => parameter_expr_is_allowlisted(expr),
        WordPiece::DoubleQuotedSequence(inner) => {
            inner.iter().all(|p| is_quoted_expandable(&p.piece))
        }
        _ => false,
    }
}

fn is_quoted_expandable(piece: &WordPiece) -> bool {
    match piece {
        WordPiece::Text(_) | WordPiece::EscapeSequence(_) => true,
        WordPiece::ParameterExpansion(expr) => parameter_expr_is_allowlisted(expr),
        _ => false,
    }
}

fn expand_piece(piece: &WordPiece, env: &SessionEnv, out: &mut String) {
    match piece {
        WordPiece::Text(s) | WordPiece::SingleQuotedText(s) | WordPiece::AnsiCQuotedText(s) => {
            out.push_str(s)
        }
        WordPiece::EscapeSequence(s) => out.push_str(unescape(s).as_str()),
        WordPiece::ParameterExpansion(expr) => expand_parameter_expr(expr, env, out),
        WordPiece::DoubleQuotedSequence(inner) => {
            for p in inner {
                expand_piece(&p.piece, env, out);
            }
        }
        _ => {}
    }
}

/// Resolves every `ParameterExpr` variant `parameter_expr_is_allowlisted` accepts. Only
/// ever invoked on pieces that already passed `is_expandable_piece` (i.e. the allowlist),
/// so every reachable arm here mirrors an accepted variant; the wildcard arm is a
/// defensive no-op (never a panic) in case that invariant is ever violated by future
/// changes, rather than a silently-guessed resolution.
///
/// Known pre-existing divergence from real bash (not something this function can
/// correct): `brush-parser` collapses runs of whitespace inside a `${...}` payload, so
/// e.g. `${X:-a  b}` resolves here to `"a b"` where bash keeps `"a  b"`. This predates
/// task-22.5 but is newly *reachable* now that these forms are accepted (fix round 1,
/// Minor finding — not fixed, since the collapsing happens upstream in `brush-parser`'s
/// own tokenizer, outside this module's control).
fn expand_parameter_expr(expr: &ParameterExpr, env: &SessionEnv, out: &mut String) {
    match expr {
        ParameterExpr::Parameter {
            parameter: Parameter::Named(name),
            indirect: false,
        } => out.push_str(env.get(name).unwrap_or("")),
        ParameterExpr::ParameterLength {
            parameter: Parameter::Named(name),
            indirect: false,
        } => {
            let len = env.get(name).unwrap_or("").chars().count();
            out.push_str(&len.to_string());
        }
        ParameterExpr::UseDefaultValues {
            parameter: Parameter::Named(name),
            indirect: false,
            test_type,
            default_value,
        } => match resolve_if_set(env, name, test_type) {
            Some(v) => out.push_str(v),
            None => out.push_str(default_value.as_deref().unwrap_or("")),
        },
        ParameterExpr::AssignDefaultValues {
            parameter: Parameter::Named(name),
            indirect: false,
            test_type,
            default_value,
        } => {
            // Real bash also assigns the default back into the variable; this
            // classifier resolves a read-only `SessionEnv` snapshot purely to decide
            // what text reaches argv, so the assignment side-effect is intentionally
            // not modeled (see task-22.5-brief.md Step 3).
            match resolve_if_set(env, name, test_type) {
                Some(v) => out.push_str(v),
                None => out.push_str(default_value.as_deref().unwrap_or("")),
            }
        }
        ParameterExpr::UseAlternativeValue {
            parameter: Parameter::Named(name),
            indirect: false,
            test_type,
            alternative_value,
        } => {
            if resolve_if_set(env, name, test_type).is_some() {
                out.push_str(alternative_value.as_deref().unwrap_or(""));
            }
        }
        ParameterExpr::RemoveSmallestPrefixPattern {
            parameter: Parameter::Named(name),
            indirect: false,
            pattern,
        } => out.push_str(&strip_prefix_pattern(
            env.get(name).unwrap_or(""),
            pattern.as_deref().unwrap_or(""),
            true,
        )),
        ParameterExpr::RemoveLargestPrefixPattern {
            parameter: Parameter::Named(name),
            indirect: false,
            pattern,
        } => out.push_str(&strip_prefix_pattern(
            env.get(name).unwrap_or(""),
            pattern.as_deref().unwrap_or(""),
            false,
        )),
        ParameterExpr::RemoveSmallestSuffixPattern {
            parameter: Parameter::Named(name),
            indirect: false,
            pattern,
        } => out.push_str(&strip_suffix_pattern(
            env.get(name).unwrap_or(""),
            pattern.as_deref().unwrap_or(""),
            true,
        )),
        ParameterExpr::RemoveLargestSuffixPattern {
            parameter: Parameter::Named(name),
            indirect: false,
            pattern,
        } => out.push_str(&strip_suffix_pattern(
            env.get(name).unwrap_or(""),
            pattern.as_deref().unwrap_or(""),
            false,
        )),
        _ => {}
    }
}

/// Resolves `name` against `test_type`'s "is this considered set" rule and returns
/// `Some(value)` when it counts as set, `None` otherwise:
/// - `ParameterTestType::UnsetOrNull` (the `:`-prefixed test forms, e.g. `${var:-d}`):
///   a present-but-empty variable counts the same as unset.
/// - `ParameterTestType::Unset` (the bare forms, e.g. `${var-d}`): only a genuinely
///   absent variable counts as unset; present-and-empty resolves to the empty value.
fn resolve_if_set<'a>(
    env: &'a SessionEnv,
    name: &str,
    test_type: &ParameterTestType,
) -> Option<&'a str> {
    match env.get(name) {
        Some(v) if matches!(test_type, ParameterTestType::UnsetOrNull) && v.is_empty() => None,
        Some(v) => Some(v),
        None => None,
    }
}

/// Safety cap on the value length this module will attempt glob-anchored prefix/suffix
/// stripping against. The matching loop below is O(n) glob-match attempts each
/// proportional to the candidate substring's length, i.e. worst-case O(n^2) in the
/// resolved value's length; `SessionEnv` values come from this codebase's own tool
/// executors, not raw untrusted shell text today, but this cap keeps the classifier's
/// own CPU bound honest regardless of what ends up populating `SessionEnv` in the
/// future. Values over the cap are returned unmodified (fail-safe: no stripping, not a
/// panic or a hang — see the arithmetic-cost note above [`strip_prefix_pattern`]/
/// [`strip_suffix_pattern`] for why unlike a glob-compile failure this one stays a
/// correctness-only fallback, not a security-relevant one).
///
/// **Calibration** (task-22.5 fix round 1, Important #4): a single 289-byte command with
/// `structural_budget`'s maximum 15 permitted `${...}` expansions, each stripping
/// against a large `SessionEnv` value, was adversarially measured to cost 34.09s of
/// classifier CPU under the previous 64 KiB cap while still classifying as an allowed
/// `Program` — a real, large hole in this module's otherwise strict resource-bound
/// discipline (`MAX_INPUT_BYTES`, `PARSE_STACK_BYTES`, `MAX_STRUCTURAL_BUDGET`). Measured
/// directly against this crate's own `dev` profile (this module's established
/// conservative-direction calibration baseline, per [`PARSE_STACK_BYTES`]'s own note):
/// a single worst-case (always-scans-to-the-end, never-matches pattern) call costs
/// ~0.3–0.7ms at 256–512 bytes; 15 such calls back-to-back (`structural_budget`'s cap)
/// cost ~4.6ms at 256 bytes. 256 bytes keeps the worst case for an entire command,
/// across every expansion the structural budget allows, in the low single-digit
/// milliseconds even on the slower `dev` profile.
const MAX_GLOB_STRIP_INPUT_BYTES: usize = 256;

/// Implements `${var#pattern}` (`smallest = true`) / `${var##pattern}`
/// (`smallest = false`): removes the shortest (or longest) prefix of `value` that
/// glob-matches `pattern` in full, per bash's prefix-removal semantics. Returns `value`
/// unmodified if no prefix matches. `pattern` failing to compile as a glob is only
/// reachable here as a defensive no-op (never a panic), exactly like
/// `expand_parameter_expr`'s own wildcard arm: [`prefix_suffix_pattern_is_safe`] already
/// requires a successful compile at *classify* time, so this function is only ever
/// invoked (via `is_expandable_piece`/`expand_piece`'s shared allowlist gate) with a
/// pattern already proven to compile. Task-22.5 fix round 1, Important #2 moved the
/// real fail-closed decision to *classify* time specifically because a resolve-time
/// silent fallback to unmodified text on compile failure was itself a real
/// bash-divergence bug — this classifier's belief about the resolved value is exactly
/// what policy matching operates on.
fn strip_prefix_pattern(value: &str, pattern: &str, smallest: bool) -> String {
    if value.len() > MAX_GLOB_STRIP_INPUT_BYTES {
        return value.to_string();
    }
    let Some(matcher) = compile_glob(pattern) else {
        return value.to_string();
    };
    let boundaries = char_boundaries(value);
    let found = if smallest {
        boundaries.iter().find(|&&b| matcher.is_match(&value[..b]))
    } else {
        boundaries
            .iter()
            .rev()
            .find(|&&b| matcher.is_match(&value[..b]))
    };
    match found {
        Some(&b) => value[b..].to_string(),
        None => value.to_string(),
    }
}

/// Implements `${var%pattern}` (`smallest = true`) / `${var%%pattern}`
/// (`smallest = false`): removes the shortest (or longest) suffix of `value` that
/// glob-matches `pattern` in full. See [`strip_prefix_pattern`] for the shared
/// fallback/caps rationale.
fn strip_suffix_pattern(value: &str, pattern: &str, smallest: bool) -> String {
    if value.len() > MAX_GLOB_STRIP_INPUT_BYTES {
        return value.to_string();
    }
    let Some(matcher) = compile_glob(pattern) else {
        return value.to_string();
    };
    let boundaries = char_boundaries(value);
    // Suffix length is `value.len() - b`. Smallest suffix ⇒ largest `b` first
    // (descending); largest suffix ⇒ smallest `b` first (ascending).
    let found = if smallest {
        boundaries
            .iter()
            .rev()
            .find(|&&b| matcher.is_match(&value[b..]))
    } else {
        boundaries.iter().find(|&&b| matcher.is_match(&value[b..]))
    };
    match found {
        Some(&b) => value[..b].to_string(),
        None => value.to_string(),
    }
}

fn compile_glob(pattern: &str) -> Option<globset::GlobMatcher> {
    globset::Glob::new(pattern)
        .ok()
        .map(|g| g.compile_matcher())
}

/// Every valid UTF-8 byte-index boundary in `value`, ascending, including both `0` and
/// `value.len()` — the full candidate-split-point list for prefix/suffix pattern
/// matching.
fn char_boundaries(value: &str) -> Vec<usize> {
    value
        .char_indices()
        .map(|(i, _)| i)
        .chain(std::iter::once(value.len()))
        .collect()
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
        // `Arithmetic` has no words at this layer, but `ArithmeticForClause`
        // has its own `body: DoGroupCommand` full of real words — grouping
        // it with `Arithmetic` here (Task 26, W4) made this walker miss any
        // word piece (including an unresolved command substitution) hidden
        // inside a C-style for-loop body, exactly the bug this function's
        // sibling walks (`pipeline.rs`'s, already fixed) exist to avoid.
        CompoundCommand::Arithmetic(_) => false,
        CompoundCommand::ArithmeticForClause(c) => {
            any_word_piece_in_compound_list(&c.body.list, predicate)
        }
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
