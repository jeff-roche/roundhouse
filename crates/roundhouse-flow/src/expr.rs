//! The tiny, frozen `${{ ... }}` expression language (§8.9): property
//! access, indexing, ternary, comparisons, and exactly the ~10 named
//! functions §8.9 lists (`len`, `slice`, `default`, `contains`, `flatten`,
//! `json`, `env`). **"Frozen" is the security property.** The value of a
//! small closed language is that it cannot be grown into a general
//! evaluator — no arbitrary indexing beyond `[..]` on the value already in
//! hand, no user-defined functions, no loops, no arithmetic operators. Do
//! not add any of those here, ever, no matter how small the ask looks.
//!
//! This module deliberately does not claim to be "safe by construction" or
//! "bounded" anywhere beyond what is stated explicitly with what it does
//! and does not cover — `crates/roundhouse-flow/src/parse/` has had five
//! such claims made here and later falsified by execution (see
//! `parse/mod.rs`'s and `parse/steps.rs`'s own module doc comments), one of
//! which cost a regression test. Every bound below says what it stops and
//! what it does not.
//!
//! # Where a resolved secret can and cannot appear
//!
//! This module has no knowledge of what a `secrets.*` value actually is —
//! `ExprContext` stores whatever `serde_json::Value` a caller hands it
//! under whatever root name it chooses (`"secrets"`, `"inputs"`, `"steps"`,
//! a `map.as` binding, …). By the time a resolved secret reaches this
//! module it is already a plain `Value::String` — there is no way for this
//! crate to carry `roundhouse_secrets::Secret` through `eval`/`interpolate`
//! at all, because `Secret::expose_within_control_lane` (the only way to
//! read a `Secret`'s material) is `pub(crate)` to `roundhouse-secrets`
//! itself, reachable only via its two bridge modules
//! (`provider_bridge`/`mcp_bridge`) — not from any downstream crate, and
//! `roundhouse-flow`'s frozen dependency list (core, engine, store; see
//! Phase 5 ruling P7) does not include `roundhouse-secrets` regardless.
//! **Whoever wires `${{ secrets.* }}` up for real (a later task) is
//! therefore the one who must decide how a resolved secret gets from
//! `roundhouse-secrets`'s closure-scoped exposure into a free-standing
//! `serde_json::Value` this module can index — that conversion, wherever it
//! happens, is the actual point where the `Secret` wrapper's protection
//! ends.** This module cannot make that conversion safer; it can only avoid
//! making the exposure worse once a plain value is already in `ExprContext`.
//!
//! Given that constraint, here is what this module itself does and does
//! not do with whatever value it is handed:
//!
//! - **Can appear:** as the `Ok(Value)` returned by [`eval`], as text
//!   substituted into the `Ok(String)` returned by [`interpolate`], and as
//!   a leaf of the `Ok(Value)` returned by [`interpolate_json`] — that is
//!   the whole point of evaluating `${{ secrets.GH_TOKEN }}`, to produce
//!   the token for a caller to use (e.g. as an `env:` value). What the
//!   *caller* then does with that returned value (log it, print it, put it
//!   in a `Debug` derive somewhere) is outside this module's control.
//! - **Cannot appear** in any [`ExprError`] variant, **including as a
//!   derived byte offset.** Every error variant below carries only
//!   source-expression text (the unparsed remainder, a function name, a
//!   byte position) or a [`JsonErrorCategory`] — a fixed, four-way enum
//!   with no message text or position from `serde_json` at all. This is
//!   stronger than an earlier version of this claim: `json()`'s argument is
//!   any expression (`json(secrets.T)` is valid syntax), and a prior
//!   `ExprError::Json(#[from] serde_json::Error)` rendered that error's own
//!   `Display` text, which does not echo input *bytes* but does echo a
//!   line/column — a property of the secret's own shape. Measured directly:
//!   `json(secrets.T)` with `T = "unterminated` produced "column 13" (the
//!   secret's exact length); `T = "12345abcdef"` produced "column 6" (the
//!   length of its leading numeric run). [`JsonErrorCategory`]'s own doc
//!   comment has the full measurement. Verified by inspection of every
//!   construction site in this file: no `ExprError` variant is ever built
//!   from a `Value` pulled out of `ctx.vars` or a function's arguments, and
//!   the one variant that used to carry a third party's error type now
//!   carries only a closed, four-way category.
//! - **Cannot appear** in [`ExprContext`]'s `Debug` impl. `ExprContext`
//!   deliberately does **not** derive `Debug` — it implements it by hand to
//!   print only the sorted list of root names that have been `set`, never
//!   their values, since this module cannot tell a resolved secret apart
//!   from an ordinary `inputs.*` value once both are just
//!   `HashMap<String, Value>` entries.
//! - **No logging.** This module never calls `tracing`/`log`/`eprintln!`
//!   anywhere, so there is no log-line leak surface *inside* `expr.rs`
//!   itself to audit.
//!
//! ## `env()` is a second, independent secret-exposure surface
//!
//! `env()` (§8.9's own required function) reads the **calling process's
//! real environment** via [`std::env::var`] — the daemon's environment, not
//! a workflow-scoped view of it, and not restricted to whatever a workflow
//! declared under its own `secrets:` list. If the daemon process's
//! environment holds a provider API key or any other daemon-wide secret,
//! `env('ANTHROPIC_API_KEY')` reads it directly, through a path that has
//! nothing to do with `${{ secrets.* }}` or its (separately owned, not
//! built by this task) resolution pipeline. This is a real residual, not a
//! hypothetical: it is exactly what §8.9 asks this function to do, and
//! this task has no brief to scope it down (to what — an allowlist of
//! names? decided by whom?) without inventing a restriction nobody asked
//! for. Stated here so the next reader does not have to discover it by
//! reading `call_function`'s `"env"` arm.
//!
//! ## `json()` can synthesize control characters the source text never had
//!
//! §8.9 also requires `json()`. `json('"a\nb"')` decodes the two literal
//! source characters `\` and `n` into an actual newline byte in the
//! resulting `Value::String` — the same escape-decoding any JSON parser
//! does. This means the frozen function set can, on its own, produce a
//! newline (or `\t`, `\0`, any other JSON escape) in a value that did
//! not literally contain that byte in the workflow YAML source, which is
//! the exact shape of thing the dispatch's risk item 2 asked this task not
//! to add. It cannot be omitted (it is one of the ~10 frozen functions),
//! so it is documented instead: **whatever downstream sink consumes an
//! `interpolate`/`interpolate_json` result that passed through a `json()`
//! call must not assume the result is free of control characters just
//! because the source YAML looked clean.** Task 3's own `worktree.base_ref`
//! validator already reasons about this in the other direction (it
//! deliberately does not re-validate post-substitution content, see its
//! own doc comment) — this module is the reason that gap is real, not just
//! theoretical.
//!
//! # Substitution is single-pass — no re-evaluation of substituted output
//!
//! [`interpolate`] scans forward through the template exactly once. Each
//! match's replacement text is appended to the output buffer and the scan
//! resumes strictly *after* the consumed `}}`, in the original template —
//! it never re-scans anything it has already written. Concretely: if
//! evaluating `${{ json('"${{ evil }}"') }}` produces the literal string
//! `${{ evil }}` (because `json()` decoded a JSON string literal
//! containing that text), that text is written to the output verbatim and
//! `interpolate` never looks at it again — `${{ evil }}` is never
//! evaluated as a nested expression. This is deliberate: re-evaluating
//! substituted output is a template-injection hole (risk item 3), and it
//! is tested directly (`interpolation_is_single_pass_and_does_not_re_evaluate_substituted_output`).
//!
//! # An unpaired `${{` is an error, not left literal
//!
//! Task 3's own accepted values can contain an **unpaired** `${{` (a
//! recorded residual on that side — see `parse/steps.rs`). This module
//! meets that residual and makes a deliberate choice about it: a `${{`
//! with no matching `}}` anywhere in the rest of the template is
//! [`ExprError::Unterminated`], not silently left as literal text. This
//! module's whole design otherwise fails loud on anything it cannot make
//! sense of (unknown function, trailing garbage, wrong-shaped index) — an
//! unterminated expression opener is the same kind of author mistake, and
//! surfacing it as an error at evaluation time is the first and only place
//! left in the pipeline where it is still attributable to the exact
//! `${{` that never closed, rather than reaching a shell command, a URL, or
//! an env value as inert-looking punctuation. Tested:
//! `an_unpaired_opening_delimiter_is_an_error`.
//!
//! # Case sensitivity — the coupling with Task 3's reserved-root check
//!
//! `parse::steps::validate_map_as` rejects `map.as` values that
//! case-sensitively equal one of `RESERVED_EXPRESSION_ROOTS` (`secrets`,
//! `steps`, `inputs`, `run`, `vars`, `env`) — it does **not** reject `Steps`
//! or `STEPS`. That check is only sound if this evaluator is also
//! case-sensitive when resolving a root name, because `ExprContext::set`
//! and every identifier lookup in this module go through an ordinary
//! `HashMap<String, Value>` keyed by the exact byte string parsed out of
//! the expression (`parse_ident` copies bytes verbatim, no case-folding
//! anywhere in this file) — `"Steps"` and `"steps"` are two distinct,
//! non-colliding keys. **Verdict: this evaluator is case-sensitive
//! everywhere it looks up a name, so Task 3's case-sensitive check and this
//! module's case-sensitive lookup agree** — a step author who names a loop
//! binding `as: Steps` gets a `Steps` root that can never be confused with
//! the real `steps` root, exactly because both sides compare bytes exactly
//! rather than folding case. If a future change to this module ever
//! introduces any case-insensitive identifier handling, that agreement
//! breaks and Task 3's check would need to be revisited — nothing here
//! does that today, and this paragraph exists so a future editor has to see
//! it before doing so accidentally.
//!
//! # Cost: what is bounded, what is not, and what was actually measured
//!
//! Evaluating a single `${{ ... }}` block is a one-pass recursive-descent
//! parse-and-evaluate with no separate AST retained. For an expression with
//! no bracket/paren/ternary nesting, every construct in this file (property
//! chains, string/number literals, the fixed six-token comparison scan,
//! each named function) does work proportional to the length of the text
//! it consumes and nothing more — there is no sub-loop whose iteration
//! count depends on a different piece of the same input, so this shape of
//! expression is linear in its own length **on the path this was actually
//! measured on** (see
//! `long_flat_expressions_over_the_borrowed_chain_path_do_not_show_quadratic_blowup`):
//! a property-chain expression rooted at a `ctx` variable, never leaving
//! that borrow, has its evaluation time roughly track its length as the
//! length is repeatedly doubled, rather than growing quadratically. The
//! *owned*-root path (below) was a second, separate defect on the same
//! function and is measured separately, not covered by that test.
//!
//! **This is the second time this exact shape has needed fixing, and the
//! first fix's own doc comment overclaimed the second time round** — worth
//! recording plainly rather than smoothing over. A property-chain
//! implementation written against plain owned `Value` at every step (the
//! brief's own illustrative code) clones the *entire remaining nested
//! substructure* on each `.field`/`[idx]` step — `O(depth)` work repeated
//! `O(depth)` times, `O(depth²)` overall for indexing `depth` levels into
//! context data. Measured directly on exactly that code shape, before
//! fixing it: an 8x increase in chain length (and matching context nesting
//! depth) took roughly 70x longer to evaluate, consistent with quadratic
//! scaling. The first fix — [`Parser::parse_primary_chain`]/[`index_field`]/
//! [`index_array`] threading a [`Cow`] through the chain — made the
//! *borrowed*-root case above genuinely linear, but its own doc comment
//! then claimed the leftover owned-root case was "bounded by
//! `MAX_EXPR_DEPTH`, so its worst case is `MAX_EXPR_DEPTH²` trivial clones —
//! negligible." Review-round measurement showed **both halves of that
//! claim false**: chain length is not depth-counted at all (`.field`/`[idx]`
//! steps loop rather than recursing through the one function
//! `MAX_EXPR_DEPTH` counts), and the clones were not trivial — they scaled
//! with context size, not a fixed small constant. Measured directly on the
//! code as it stood at that point (a 50-level `.next` chain forced onto the
//! owned path via `default(missing, root)`, context padded to ~16 KB per
//! level): depth 50 → 1.88 ms; depth 100 (2x) → 7.52 ms (4.0x); depth 200
//! (2x again) → 29.66 ms (3.9x) — quadratic, not negligible, and **not**
//! stopped by `MAX_EXPR_DEPTH` (this chain shape never recurses through
//! `parse_ternary`, so the depth guard never engages).
//!
//! **The actual fix** was in [`index_field`]/[`index_array`]'s `Cow::Owned`
//! arm: move the matched element out of the owned map/vec (`Map::remove`,
//! `Vec::swap_remove`) instead of cloning it. Re-measured with the same
//! three depths after this fix: depth 50 → 45 µs; depth 100 → 66 µs; depth
//! 200 → 163 µs — roughly linear in depth, not quadratic, and about 180x
//! faster than the pre-fix depth-200 figure above. Pushed further (depths
//! this module has no reason to expect in practice, to confirm the
//! quadratic term is actually gone rather than just smaller): depth 1,000
//! → 1.57 ms; depth 4,000 (4x) → 11.24 ms (7.1x) — the sub-4x-per-4x-input
//! residual above 1.0 tracks the cost of *constructing* the padded test
//! context itself (`O(depth)` JSON building, unrelated to this module),
//! not evaluation. **What this module now actually verifies, not
//! assumes:** a chain rooted at owned data costs no more than a chain
//! rooted at borrowed data, to within measurement noise, for chain lengths
//! from 50 to 4,000. What it does **not** claim: a bound in terms of
//! `MAX_EXPR_DEPTH` (this path does not go through that guard) or any
//! bound independent of measurement past the depths actually tried.
//!
//! What is **not** covered by any of the above: the cost of a single
//! `map.over` fan-out evaluating the same expression once per item is
//! `O(items × per-item cost)` by construction, and this module has no
//! per-run or per-item budget of its own — that is the executor's concern
//! (a later task), not this evaluator's.
//!
//! ## A second, independent clone-amplification defect: unused arguments
//!
//! Distinct from the chain-cloning defect above: [`Parser::parse_primary_chain`]
//! used to end with `Ok(v.into_owned())`, unconditionally, regardless of
//! whether the caller needed an owned value at all. [`parse_args_until`]
//! (a function call's or array literal's comma-separated arguments) called
//! that once per argument — so every mention of a context root inside a
//! function call, *even one the function never reads* (this parser does
//! not enforce arity — `default(payload, x, payload, payload, ...)` is
//! syntactically fine and evaluates every argument), paid one full clone of
//! whatever that root resolved to. Measured directly, before this fix, with
//! a 20 MiB context bound to `payload` and a single `default(payload,
//! payload, ..., payload)` expression, one argument used and the rest
//! discarded: 1 mention → 84 MiB peak RSS; 5 mentions (48-byte expression)
//! → 187 MiB; 15 mentions (128-byte expression) → 391 MiB — amplification
//! tracking mention count 1:1, independent of whether the mentioned value
//! was ever used by the function it was passed to.
//!
//! **The fix**: thread the `Cow` all the way through
//! [`Parser::parse_comparison`]/[`Parser::parse_ternary`]/[`parse_args_until`]/[`call_function`]
//! instead of forcing ownership at the end of [`Parser::parse_primary_chain`];
//! [`eval`]'s own top-level call is now the only unconditional
//! `.into_owned()` left. Re-measured after this fix, same expression and
//! context, 1/5/15/**50** mentions: 64,188 KB / 64,204 KB / 64,188 KB /
//! 64,200 KB peak RSS — flat, within normal measurement noise, regardless
//! of mention count, because `default` only ever materializes the one
//! argument it actually selects and every other mention stays a zero-copy
//! `Cow::Borrowed` that is simply dropped.
//!
//! **This does not eliminate every amplification shape, and it would be
//! the same "bounded, so negligible" mistake called out above to claim it
//! does.** An array literal genuinely must own N independent copies of
//! whatever N elements it names — `[payload, payload, ..., payload]` is a
//! *request* for N copies of `payload` to exist in the result, not N
//! discarded reads of it, so [`Parser::parse_array_literal`] calling
//! `Cow::into_owned()` on every element is necessary work, not a residual
//! of this fix. Measured directly, same 20 MiB `payload`, expression
//! `[payload, payload, ..., payload]`: 1 mention → 64 MiB; 5 mentions
//! (41-byte expression) → 146 MiB; 15 mentions (121 bytes) → 351 MiB; 50
//! mentions (401 bytes) → **1,068 MiB**. Peak scales linearly with mention
//! count at very close to the full context size per mention (~20 MiB per
//! mention against a 20 MiB context) — this residual is **not capped** by
//! this module (an expression-length or argument-count cap would not bound
//! the work either, since the multiplicand is the context size a `map.over`
//! or webhook payload can make arbitrarily large, the same shape as the
//! open Task 10 finding) and is left open rather than papered over.
//!
//! **A separate, more alarming finding, also measured directly and not
//! assumed:** constructing and then dropping a `serde_json::Value` that is
//! deeply nested (thousands of levels of `{"next": {"next": {...}}}`) can
//! by itself overflow the default test-thread stack and abort the whole
//! process — `serde_json::Value`'s `Drop` implementation recurses one
//! stack frame per nesting level, and this happens with **no expression
//! evaluation involved at all**: building the value and immediately
//! dropping it is enough. Measured directly (a throwaway test, not
//! committed): 2,000 levels dropped cleanly, 4,000 levels aborted the
//! process with `SIGABRT`/stack overflow. [`MAX_EXPR_DEPTH`] above bounds
//! recursion driven by *expression syntax* nesting (`[`, `(`, `? :` written
//! in the `${{ ... }}` text); it does nothing for recursion driven by
//! *context data* nesting, because this module never walks a whole context
//! value recursively — it only follows the fixed property/index chain an
//! expression names. But a deeply-nested `Value` sitting in `ExprContext`
//! is a bomb this module cannot defuse: even an expression that never
//! touches the deep part of the tree still shares an `ExprContext` with it,
//! and the value's own `Drop`, whenever it eventually runs, pays the same
//! stack cost regardless of what any expression did. Since risk item 3
//! names `map.over` external data (attacker-influenced) as exactly what
//! populates a context like this, whatever deserializes that data into a
//! `serde_json::Value` before calling [`ExprContext::set`] is where a real
//! bound would have to live — a maximum nesting-depth check at
//! deserialization time, before a `Value` this deep is ever constructed.
//! Nothing in `roundhouse-flow` does that today, for context data generally
//! (not just `map.over`), and this module cannot add it without ceasing to
//! be "a pure evaluator over a `serde_json::Value` context" — the value
//! already has to exist before this module ever sees it. Recorded here
//! rather than left for the next person to rediscover by crashing a
//! shared machine.
//!
//! Separately, nesting depth (`[`, `(`, or `? :` chained inside one
//! another) recurses through [`Parser::parse_ternary`] once per level with
//! no other bound, so absent a limit, a single `${{ ... }}` block full of
//! deeply nested brackets is architecturally equivalent to unbounded
//! recursion — a stack overflow, which aborts the whole process, not a
//! graceful error. [`MAX_EXPR_DEPTH`] bounds exactly that: `parse_ternary`
//! counts its own recursion depth and returns
//! [`ExprError::ExpressionTooDeep`] once it would exceed the limit, rather
//! than recursing further. This bound covers nesting-depth-driven
//! recursion in this parser only. It says nothing about, and is not a
//! restatement or extension of, the separate open finding in
//! `parse/mod.rs` about `serde_yaml`'s own alias/anchor parse cost — that
//! finding is about parsing YAML *text* into a `serde_yaml::Value` before
//! any expression evaluation happens; this bound is about evaluating an
//! expression *after* that YAML has already parsed successfully. Note also
//! that a deliberate stack-overflow reproduction was not attempted here —
//! it would abort the test process running it, an unacceptable side effect
//! for a shared test binary — so this bound is justified by the recursion
//! structure itself (every nesting path funnels through the one counted
//! function) and pinned by tests at and just past the boundary, not by
//! having first observed the crash it prevents.

use serde_json::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Bounds the recursion depth of nested `[`, `(`, or `? :` inside a single
/// `${{ ... }}` expression — see the module doc comment's "Cost" section
/// for exactly what this does and does not cover.
pub const MAX_EXPR_DEPTH: usize = 64;

#[derive(Debug, Error)]
pub enum ExprError {
    #[error("unexpected token at position {0}: '{1}'")]
    UnexpectedToken(usize, String),
    #[error("unknown function '{0}'")]
    UnknownFunction(String),
    #[error("unterminated expression")]
    Unterminated,
    #[error("expression nesting exceeds the depth limit of {0}")]
    ExpressionTooDeep(usize),
    #[error("json() argument is not valid JSON ({0})")]
    Json(JsonErrorCategory),
}

/// What kind of problem `json()`'s `serde_json::from_str` hit, **carrying
/// only [`serde_json::Error::classify`]'s category, never the error's own
/// `Display` text.** This is a fix, not the obvious choice: `json()`'s
/// argument is any expression (`json(secrets.TOKEN)` is valid syntax), so a
/// prior version of this module that stored the `serde_json::Error` itself
/// via `#[from]` and rendered it in `ExprError::Json`'s `#[error(...)]`
/// text leaked a byte offset derived from the context value's own length —
/// `serde_json` never echoes input *bytes*, but it does echo a line/column,
/// and that column is a property of the secret: measured directly,
/// `json(secrets.T)` with `T = "unterminated` (13 bytes before EOF)
/// produced an error whose text contained "column 13" — the secret's exact
/// length — and `T = "12345abcdef"` produced "column 6" — the length of
/// its leading numeric run. Reducing to a fixed, small category (no line,
/// no column, no message text from `serde_json`) removes that channel
/// entirely: every one of these variants renders the same fixed string
/// regardless of what was fed to `json()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonErrorCategory {
    /// The input was not syntactically valid JSON at all (e.g. `not json`).
    Syntax,
    /// The input ended before a complete JSON value was parsed (e.g. an
    /// unterminated string or object).
    Eof,
    /// The input parsed but did not fit the type being deserialized into.
    /// `json()` always deserializes into `serde_json::Value`, which accepts
    /// any valid JSON, so this arm is unreachable in practice — kept for
    /// exhaustiveness against `serde_json::error::Category`.
    Data,
    /// An I/O error occurred. Unreachable for `from_str` (which reads from
    /// an in-memory `&str`, not an I/O source) — kept for exhaustiveness.
    Io,
}

impl fmt::Display for JsonErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JsonErrorCategory::Syntax => "syntax error",
            JsonErrorCategory::Eof => "unexpected end of input",
            JsonErrorCategory::Data => "wrong shape for the target type",
            JsonErrorCategory::Io => "I/O error",
        })
    }
}

impl From<serde_json::Error> for JsonErrorCategory {
    fn from(e: serde_json::Error) -> Self {
        match e.classify() {
            serde_json::error::Category::Io => JsonErrorCategory::Io,
            serde_json::error::Category::Syntax => JsonErrorCategory::Syntax,
            serde_json::error::Category::Data => JsonErrorCategory::Data,
            serde_json::error::Category::Eof => JsonErrorCategory::Eof,
        }
    }
}

/// The evaluation context: a flat table of named roots (`inputs`, `steps`,
/// `secrets`, a `map.as` loop binding, …), each an arbitrary
/// `serde_json::Value`. Lookups are exact-byte-string, case-sensitive —
/// see the module doc comment's "Case sensitivity" section for why that
/// matters beyond style.
#[derive(Default, Clone)]
pub struct ExprContext {
    vars: HashMap<String, Value>,
}

impl ExprContext {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    /// Binds `name` as a root usable from an expression (`name.field`,
    /// `name[0]`, or bare `name`). Overwrites any existing binding of the
    /// same name.
    pub fn set(&mut self, name: &str, value: Value) {
        self.vars.insert(name.to_string(), value);
    }
}

impl fmt::Debug for ExprContext {
    /// Deliberately does not print bound values — see the module doc
    /// comment's "Where a resolved secret can and cannot appear" section.
    /// This context cannot tell a resolved secret apart from an ordinary
    /// `inputs.*` value once both are just `Value`s in the same map, so it
    /// never prints any of them; only the sorted set of root names bound so
    /// far.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut roots: Vec<&str> = self.vars.keys().map(String::as_str).collect();
        roots.sort_unstable();
        f.debug_struct("ExprContext")
            .field("roots", &roots)
            .finish()
    }
}

/// Evaluates one `${{ ... }}` inner expression (without the delimiters)
/// against `ctx`. See the module doc comment for the frozen grammar and
/// function set.
///
/// This is not a general-purpose `eval` — it is a small, closed
/// recursive-descent interpreter over exactly the grammar and ~10 named
/// functions this module's doc comment lists (no arbitrary code, no
/// user-defined functions, no I/O beyond `env()`'s documented process-env
/// read and `json()`'s documented string-argument parse). Named `eval` to
/// match §8.9's own vocabulary for this frozen language, not because it
/// evaluates arbitrary input.
pub fn eval(expr: &str, ctx: &ExprContext) -> Result<Value, ExprError> {
    let mut p = Parser {
        s: expr.as_bytes(),
        pos: 0,
        depth: 0,
        ctx,
    };
    p.skip_ws();
    let v = p.parse_ternary()?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(ExprError::UnexpectedToken(p.pos, expr[p.pos..].to_string()));
    }
    // The one unavoidable clone: `eval`'s own signature returns an owned
    // `Value`, and `ctx` must outlive this call, so the top-level result has
    // to be materialized here regardless of how much of the evaluation
    // above stayed borrowed. See the module doc comment's "Cost" section
    // for what staying borrowed through here actually saves.
    Ok(v.into_owned())
}

/// Replaces every `${{ ... }}` block in `template` with its evaluated,
/// string-coerced result, leaving surrounding text untouched. Single-pass:
/// substituted text is never re-scanned for further `${{` — see the module
/// doc comment's "Substitution is single-pass" section. An unpaired `${{`
/// (no matching `}}` anywhere in the rest of the template) is
/// [`ExprError::Unterminated`] — see the module doc comment's "An unpaired
/// `${{` is an error" section.
pub fn interpolate(template: &str, ctx: &ExprContext) -> Result<String, ExprError> {
    let mut out = String::new();
    let mut rest = template;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = find_closing_delimiter(after).ok_or(ExprError::Unterminated)?;
        let inner = &after[..end];
        let value = eval(inner.trim(), ctx)?;
        out.push_str(&value_to_string(&value));
        // Resume scanning strictly after the consumed `}}`, in the
        // *original* template — never re-scan `value`'s own text. This is
        // what makes substitution single-pass.
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Finds the byte offset of the first `}}` in `s` that is not inside a
/// `'...'`/`"..."` string literal, tracking quote state with the same
/// no-escapes rule [`Parser::parse_string_literal`] uses (an unescaped
/// quote always closes the current string). Fixed to this task's own
/// requirement: a naive `str::find("}}")` — the brief's illustrative
/// code — mis-splits a block whose own text legitimately contains `}}`
/// inside a string argument (e.g. `${{ json('"${{ x }}"') }}`, where the
/// literal `${{ x }}` is data inside a `json()` argument, not a nested
/// expression) — it would treat the first `}}` it finds textually as the
/// block's end even though that `}}` is quoted data, truncating the real
/// expression. Verified by reproducing exactly that truncation before
/// writing this function: the naive version produced an incomplete inner
/// expression (missing its closing quote and parenthesis) that then failed
/// to parse, rather than the intended value. This scan is still a single
/// forward pass over `s` with one byte of state (which quote, if any, is
/// currently open) — it does not parse or validate the expression itself,
/// only decides where the block ends.
fn find_closing_delimiter(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut open_quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match open_quote {
            Some(q) => {
                if b == q {
                    open_quote = None;
                }
                i += 1;
            }
            None => {
                if b == b'\'' || b == b'"' {
                    open_quote = Some(b);
                    i += 1;
                } else if b == b'}' && bytes.get(i + 1) == Some(&b'}') {
                    return Some(i);
                } else {
                    i += 1;
                }
            }
        }
    }
    None
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Walks an arbitrary JSON value and runs every string leaf through
/// [`interpolate`] — a step's whole `with:`/`env:` block is JSON, not a
/// single string, so a caller resolving every `${{ }}` in it needs this
/// rather than hand-picking one field. Non-string leaves (numbers, bools,
/// null) pass through unchanged; object keys are never interpolated, only
/// values. Recursion depth here tracks the JSON value's own nesting depth,
/// which for a `with`/`env` block already passed through `serde_yaml`'s own
/// nesting guard before reaching this function — this function adds no new
/// depth bound of its own.
pub fn interpolate_json(value: &Value, ctx: &ExprContext) -> Result<Value, ExprError> {
    match value {
        Value::String(s) => Ok(Value::String(interpolate(s, ctx)?)),
        Value::Array(items) => {
            let resolved: Result<Vec<Value>, ExprError> =
                items.iter().map(|v| interpolate_json(v, ctx)).collect();
            Ok(Value::Array(resolved?))
        }
        Value::Object(map) => {
            let mut resolved = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                resolved.insert(k.clone(), interpolate_json(v, ctx)?);
            }
            Ok(Value::Object(resolved))
        }
        other => Ok(other.clone()),
    }
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
    ctx: &'a ExprContext,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }
    fn starts_with(&self, tok: &str) -> bool {
        self.s[self.pos..].starts_with(tok.as_bytes())
    }

    /// Top of the recursive-descent grammar, and the single choke point
    /// every form of nesting (`[`, `(`, `? :`) recurses back through — see
    /// the module doc comment's "Cost" section. Counts and bounds its own
    /// recursion depth via [`MAX_EXPR_DEPTH`] before doing any work.
    fn parse_ternary(&mut self) -> Result<Cow<'a, Value>, ExprError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err(ExprError::ExpressionTooDeep(MAX_EXPR_DEPTH));
        }
        let result = self.parse_ternary_inner();
        self.depth -= 1;
        result
    }

    fn parse_ternary_inner(&mut self) -> Result<Cow<'a, Value>, ExprError> {
        let cond = self.parse_comparison()?;
        self.skip_ws();
        if self.peek() == Some(b'?') {
            self.pos += 1;
            self.skip_ws();
            let then_v = self.parse_ternary()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(ExprError::UnexpectedToken(self.pos, "expected ':'".into()));
            }
            self.pos += 1;
            self.skip_ws();
            let else_v = self.parse_ternary()?;
            return Ok(if truthy(cond.as_ref()) {
                then_v
            } else {
                else_v
            });
        }
        Ok(cond)
    }

    fn parse_comparison(&mut self) -> Result<Cow<'a, Value>, ExprError> {
        let lhs = self.parse_primary_chain()?;
        self.skip_ws();
        for (tok, op) in COMPARISON_OPS {
            if self.starts_with(tok) {
                self.pos += tok.len();
                self.skip_ws();
                let rhs = self.parse_primary_chain()?;
                return Ok(Cow::Owned(Value::Bool(op(lhs.as_ref(), rhs.as_ref()))));
            }
        }
        Ok(lhs)
    }

    /// Resolves a primary value followed by zero or more `.field`/`[idx]`
    /// steps. **Threads a borrowed [`Cow`] through the whole chain, and
    /// returns it still as a `Cow` rather than forcing it to an owned
    /// `Value` here** — see [`index_field`]/[`index_array`]'s own doc
    /// comments for why the *chaining* half of this is load-bearing (a
    /// version written against plain `Value`, the brief's own illustrative
    /// code, clones the entire remaining nested substructure on every
    /// `.field` step — `O(depth²)` overall; measured directly, before that
    /// fix, an 8x increase in property-chain length took roughly 70x
    /// longer).
    ///
    /// **Not forcing ownership here is a second, independent fix**, for a
    /// different defect than the chain-cloning one above: a version of this
    /// function that ended with `Ok(v.into_owned())` (this module's own
    /// prior shape) clones its *result* unconditionally, even when the
    /// caller — [`parse_args_until`] collecting a function's arguments, or
    /// [`Parser::parse_comparison`] comparing two chains — only ever reads
    /// through a reference and never needs an owned copy at all. Every
    /// mention of a context root inside a function call (`len(payload)`,
    /// or an unused extra argument like `default(payload, x, payload,
    /// payload, ...)`) paid one full clone of whatever that root resolved
    /// to, regardless of whether the function that received it ever used
    /// the clone. Measured directly on that exact code shape, before this
    /// fix, with a 20 MiB context bound to `payload` and a single
    /// `default(payload, payload, ..., payload)` expression: 1 mention →
    /// 84 MiB peak RSS; 5 mentions (48-byte expression) → 187 MiB; 15
    /// mentions (128-byte expression) → 391 MiB — amplification tracking
    /// mention count, independent of whether the mentioned value was ever
    /// used. See the module doc comment's "Cost" section for the
    /// post-fix numbers and the harness that produced both sets. Every
    /// step that resolves from data still reachable through `ctx`'s
    /// original borrow now returns a fresh `Cow::Borrowed` all the way up
    /// through comparisons and argument collection at zero copy cost;
    /// [`eval`]'s own top-level `.into_owned()` is the only place left that
    /// unconditionally clones, and it clones only the one final result
    /// `eval` actually returns.
    fn parse_primary_chain(&mut self) -> Result<Cow<'a, Value>, ExprError> {
        self.skip_ws();
        let mut v = self.parse_primary()?;
        loop {
            if self.peek() == Some(b'.') {
                self.pos += 1;
                let ident = self.parse_ident();
                v = index_field(v, &ident);
            } else if self.peek() == Some(b'[') {
                self.pos += 1;
                self.skip_ws();
                let idx_val = self.parse_ternary()?;
                self.skip_ws();
                if self.peek() != Some(b']') {
                    return Err(ExprError::UnexpectedToken(self.pos, "expected ']'".into()));
                }
                self.pos += 1;
                v = index_array(v, idx_val.as_ref());
            } else {
                break;
            }
        }
        Ok(v)
    }

    fn parse_primary(&mut self) -> Result<Cow<'a, Value>, ExprError> {
        self.skip_ws();
        match self.peek() {
            Some(b'\'') | Some(b'"') => self.parse_string_literal().map(Cow::Owned),
            Some(c) if c.is_ascii_digit() => self.parse_number().map(Cow::Owned),
            Some(b'[') => self.parse_array_literal().map(Cow::Owned),
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let ident = self.parse_ident();
                self.skip_ws();
                if self.peek() == Some(b'(') {
                    self.pos += 1;
                    let args = self.parse_args()?;
                    call_function(&ident, args).map(Cow::Owned)
                } else {
                    // The load-bearing borrow: a bare root/identifier
                    // resolves directly against `ctx`'s own storage with no
                    // clone at all — see `parse_primary_chain`'s doc
                    // comment for why threading this borrow through every
                    // subsequent `.field`/`[idx]` step, instead of cloning
                    // at each one, is what makes a long property chain
                    // over context data linear rather than quadratic.
                    Ok(match self.ctx.vars.get(&ident) {
                        Some(v) => Cow::Borrowed(v),
                        None => Cow::Owned(Value::Null),
                    })
                }
            }
            _ => Err(ExprError::UnexpectedToken(
                self.pos,
                "unexpected character".into(),
            )),
        }
    }

    fn parse_ident(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == b'_' {
                self.pos += 1;
            } else {
                break;
            }
        }
        String::from_utf8_lossy(&self.s[start..self.pos]).to_string()
    }

    /// Parses a `'...'`/`"..."` literal with no escape processing at all —
    /// the string body is a byte-for-byte copy of whatever sits between the
    /// quotes, so it can never introduce a character that was not already
    /// literally present in the source expression text. Returns
    /// [`ExprError::Unterminated`], not a panic, when the closing quote is
    /// never found — a naive version of this function that unconditionally
    /// advances past the (absent) closing quote panics on `expr[pos..]` in
    /// [`eval`]'s trailing-garbage check once `pos` runs past the end of
    /// the string; that was measured directly against exactly the code
    /// shape this module started from and fixed before shipping, not left
    /// to be found by a fuzzer.
    fn parse_string_literal(&mut self) -> Result<Value, ExprError> {
        let quote = self.peek().unwrap();
        self.pos += 1;
        let start = self.pos;
        while self.peek().is_some() && self.peek() != Some(quote) {
            self.pos += 1;
        }
        if self.peek() != Some(quote) {
            return Err(ExprError::Unterminated);
        }
        let s = String::from_utf8_lossy(&self.s[start..self.pos]).to_string();
        self.pos += 1; // closing quote
        Ok(Value::String(s))
    }

    /// Parses a non-negative number literal (no unary minus, no exponent —
    /// §8.9's frozen grammar has no arithmetic operators at all, only
    /// literals). **Prefers a whole-number (`u64`-backed) representation
    /// over a float one when the literal has no decimal point.** This is a
    /// fix, not a style choice: `serde_json::Number`'s `PartialEq` (which
    /// `Value`'s own derived `PartialEq` uses, and which backs this
    /// module's `==`/`!=` before the [`value_eq`] fix below) treats a
    /// `Float`-variant number as unequal to a `PosInt`-variant number even
    /// when they represent the identical value — so a version of this
    /// function that always builds a `Float` (the brief's own illustrative
    /// code, `s.parse::<f64>()` unconditionally) makes an array literal
    /// like `[1,2,3]` compare unequal to the *identical-looking*
    /// `serde_json::json!([1,2,3])`, and makes an ordinary integer literal
    /// like `2` render back out through `interpolate`/`interpolate_json` as
    /// the text `2.0` rather than `2`. Measured directly:
    /// `eval("[1,2,3][1]", ..)` returned `Number(2.0)`, not `Number(2)`,
    /// before this fix.
    fn parse_number(&mut self) -> Result<Value, ExprError> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == b'.' {
                self.pos += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.s[start..self.pos]).unwrap();
        if !s.contains('.') {
            if let Ok(i) = s.parse::<u64>() {
                return Ok(Value::from(i));
            }
        }
        let n: f64 = s
            .parse()
            .map_err(|_| ExprError::UnexpectedToken(start, s.to_string()))?;
        Ok(serde_json::json!(n))
    }

    /// Builds a new, owned array literal. Unlike a function's arguments (see
    /// [`parse_args`]), every element here genuinely must be cloned into the
    /// new `Value::Array` this constructs — the result **is** a brand-new
    /// value that has to own N independent copies of whatever N elements
    /// were written, so `Cow::into_owned()` on each item is necessary work,
    /// not a residual of the argument-clone amplification fixed in
    /// [`Parser::parse_primary_chain`]'s doc comment. It is still a real,
    /// measured cost when an element is itself a mention of a large context
    /// root repeated many times (`[payload, payload, ..., payload]`) — see
    /// the module doc comment's "Cost" section for the measured coefficient
    /// and why this residual is left open rather than capped.
    fn parse_array_literal(&mut self) -> Result<Value, ExprError> {
        self.pos += 1; // '['
        let items = self.parse_args_until(b']')?;
        Ok(Value::Array(
            items.into_iter().map(Cow::into_owned).collect(),
        ))
    }

    /// Collects a function call's comma-separated arguments **without**
    /// forcing any of them to an owned `Value` — see
    /// [`Parser::parse_primary_chain`]'s doc comment for why that matters.
    /// A pure-read function (`len`, `contains`, `slice`'s source array,
    /// `flatten`'s outer array) can read straight through the `Cow` and
    /// never pay for a clone at all; only a function that must produce new
    /// owned data from a chosen argument (`default` returning the one
    /// branch it picked) calls `Cow::into_owned()`, and only on that one
    /// argument.
    fn parse_args(&mut self) -> Result<Vec<Cow<'a, Value>>, ExprError> {
        self.parse_args_until(b')')
    }

    fn parse_args_until(&mut self, close: u8) -> Result<Vec<Cow<'a, Value>>, ExprError> {
        let mut args = Vec::new();
        self.skip_ws();
        if self.peek() == Some(close) {
            self.pos += 1;
            return Ok(args);
        }
        loop {
            self.skip_ws();
            args.push(self.parse_ternary()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(c) if c == close => {
                    self.pos += 1;
                    break;
                }
                _ => {
                    return Err(ExprError::UnexpectedToken(
                        self.pos,
                        "expected ',' or close".into(),
                    ));
                }
            }
        }
        Ok(args)
    }
}

type ComparisonOp = fn(&Value, &Value) -> bool;
const COMPARISON_OPS: &[(&str, ComparisonOp)] = &[
    (">=", |a, b| as_f64(a) >= as_f64(b)),
    ("<=", |a, b| as_f64(a) <= as_f64(b)),
    ("==", |a, b| value_eq(a, b)),
    ("!=", |a, b| !value_eq(a, b)),
    (">", |a, b| as_f64(a) > as_f64(b)),
    ("<", |a, b| as_f64(a) < as_f64(b)),
];

/// Equality for `==`/`!=`. For two numbers, compares by numeric value via
/// `as_f64()` rather than `Value`'s own derived (representation-sensitive)
/// `PartialEq` — otherwise a number literal parsed by this module (see
/// [`Parser::parse_number`]) could compare unequal to a numerically
/// identical value from ordinary context data whenever the two happen to
/// be backed by different `serde_json::Number` variants (a real,
/// measured gap even after `parse_number`'s own int/float preference fix,
/// since context data can arrive as either — e.g. a `map.over` item field
/// serialized as `3.0`). Everything else (strings, bools, arrays, objects,
/// null, and any Number-vs-other-type comparison) falls back to `Value`'s
/// ordinary structural equality, which is exactly what is wanted there.
fn value_eq(a: &Value, b: &Value) -> bool {
    if let (Value::Number(na), Value::Number(nb)) = (a, b) {
        return match (na.as_f64(), nb.as_f64()) {
            (Some(fa), Some(fb)) => fa == fb,
            _ => false,
        };
    }
    a == b
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::Null => false,
        Value::Number(n) => n.as_f64().unwrap_or(0.0) != 0.0,
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn as_f64(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

/// Resolves `v.field`, preserving a borrow from `v`'s own original lifetime
/// `'a` whenever `v` is itself borrowed — see `parse_primary_chain`'s doc
/// comment for why that matters. `Value::get` on a `&'a Value` hands back
/// `Option<&'a Value>` (the *same* lifetime, not one tied to this
/// function's local borrow of `v`), so matching on `v` explicitly rather
/// than going through `Cow`'s `Deref` is what lets this stay zero-copy for
/// the `Cow::Borrowed` case instead of accidentally re-shortening the
/// lifetime to this call.
///
/// **The `Cow::Owned` arm moves the field out of `o` by removing it from the
/// map, it does not clone it.** An earlier version of this function called
/// `o.get(field).cloned()` here, which — because `o` is itself already an
/// owned clone made once when the chain's root left the `ctx` borrow (see
/// [`Parser::parse_primary_chain`]'s doc comment) — clones the **entire
/// subtree still hanging off `field`** at every single step of a chain
/// evaluated after that point, i.e. `O(depth)` work repeated `O(depth)`
/// times once a chain is rooted at owned data. Measured directly on that
/// exact code (a 50-level `.next` chain over a context padded to ~16 KB
/// per level, evaluated through `default(missing, root)` to force the
/// owned root): depth 50 → 1.88 ms; depth 100 (2x) → 7.52 ms (4.0x); depth
/// 200 (2x again) → 29.66 ms (3.9x) — quadratic, not linear, in chain
/// length, matching security's independent measurement of the same shape.
/// `Map::remove` (a lookup plus a move of the one matched value out of the
/// map) does none of that: it touches only the current level's own
/// bookkeeping, not the size of what it returns, so the chain's total cost
/// across all steps drops to being bounded by the size of the data actually
/// touched, not by depth times remaining-subtree size. Re-measured after
/// this fix with the same three depths: see this module's doc comment
/// "Cost" section for the numbers and the harness that produced them.
fn index_field<'a>(v: Cow<'a, Value>, field: &str) -> Cow<'a, Value> {
    match v {
        Cow::Borrowed(r) => match r.get(field) {
            Some(inner) => Cow::Borrowed(inner),
            None => Cow::Owned(Value::Null),
        },
        Cow::Owned(Value::Object(mut map)) => match map.remove(field) {
            Some(inner) => Cow::Owned(inner),
            None => Cow::Owned(Value::Null),
        },
        Cow::Owned(_) => Cow::Owned(Value::Null),
    }
}

/// Converts a `Value` used as an index or a `slice()` bound into a
/// `usize`, accepting a non-negative whole number regardless of how
/// `serde_json` happened to store it. **This is a fix, not the obvious
/// choice, and it matters**: every number this module's own parser
/// produces (see [`Parser::parse_number`]) is built via `f64::parse` and
/// `serde_json::json!(n)`, which stores it as `serde_json::Number`'s
/// `Float` variant — and `Number::as_u64()` returns `None` for a
/// `Float`-variant number even when it exactly represents a whole number
/// like `0.0`. A version of `index_array` written against `idx.as_u64()`
/// (the brief's own illustrative code) therefore returns `Null` for
/// *every* `[N]` index and every numeric `slice()` bound this parser can
/// ever produce — verified directly: `eval("[1,2,3][1]", ..)` returned
/// `Null` before this fix, not `2`. `as_f64()` works uniformly across all
/// of `Number`'s internal representations, so this function goes through
/// that instead and does the whole-number check itself.
fn as_index(v: &Value) -> Option<usize> {
    let f = v.as_f64()?;
    if f.is_finite() && f >= 0.0 && f.fract() == 0.0 {
        Some(f as usize)
    } else {
        None
    }
}

/// Resolves `v[idx]`, borrow-preserving like [`index_field`] — see its doc
/// comment for why, including why the `Cow::Owned` arm below uses
/// `Vec::swap_remove` (an O(1) move of the matched element, with the last
/// element moved into its place, no clone of the element or of any sibling)
/// rather than `a.get(i).cloned()`, which paid the same per-step
/// whole-remaining-subtree clone cost `index_field` used to.
fn index_array<'a>(v: Cow<'a, Value>, idx: &Value) -> Cow<'a, Value> {
    let i = match as_index(idx) {
        Some(i) => i,
        None => return Cow::Owned(Value::Null),
    };
    match v {
        Cow::Borrowed(Value::Array(a)) => match a.get(i) {
            Some(inner) => Cow::Borrowed(inner),
            None => Cow::Owned(Value::Null),
        },
        Cow::Owned(Value::Array(mut a)) => {
            if i < a.len() {
                Cow::Owned(a.swap_remove(i))
            } else {
                Cow::Owned(Value::Null)
            }
        }
        _ => Cow::Owned(Value::Null),
    }
}

/// The complete, frozen function set — exactly what §8.9 names (`len`,
/// `slice`, `default`, `contains`, `flatten`, `json`, `env`). Do not add a
/// function here without going back to §8.9 first; this list is meant to
/// stay this short forever.
///
/// Takes its arguments as `Cow<Value>`, not owned `Value` — see
/// [`Parser::parse_primary_chain`]'s doc comment for the amplification bug
/// this avoids. Every arm below reads through `.as_ref()` and clones only
/// what it actually returns: `len`/`contains` never clone at all; `slice`
/// clones just the sliced range, not the source array; `flatten` clones
/// only the elements it copies into the new flattened array, never the
/// outer array itself; `default` clones only whichever one of its two
/// arguments it selects, leaving any others (including extra, unused ones —
/// this parser does not enforce arity) untouched.
fn call_function<'a>(name: &str, args: Vec<Cow<'a, Value>>) -> Result<Value, ExprError> {
    match name {
        "len" => Ok(serde_json::json!(match args.first().map(|v| v.as_ref()) {
            Some(Value::Array(a)) => a.len(),
            Some(Value::String(s)) => s.len(),
            Some(Value::Object(o)) => o.len(),
            _ => 0,
        })),
        "slice" => {
            let arr = args.first().and_then(|v| v.as_ref().as_array());
            let arr_len = arr.map(|a| a.len()).unwrap_or(0);
            let start = args.get(1).and_then(|v| as_index(v.as_ref())).unwrap_or(0);
            let end = args
                .get(2)
                .and_then(|v| as_index(v.as_ref()))
                .unwrap_or(arr_len)
                .min(arr_len);
            let sliced = arr.and_then(|a| a.get(start.min(end)..end)).unwrap_or(&[]);
            Ok(Value::Array(sliced.to_vec()))
        }
        "default" => {
            let mut it = args.into_iter();
            let primary = it.next();
            let primary_is_null = matches!(primary.as_deref(), None | Some(Value::Null));
            if primary_is_null {
                Ok(it.next().map(Cow::into_owned).unwrap_or(Value::Null))
            } else {
                Ok(primary.map(Cow::into_owned).unwrap_or(Value::Null))
            }
        }
        "contains" => {
            let hay = args.first().and_then(|v| v.as_ref().as_str()).unwrap_or("");
            let needle = args.get(1).and_then(|v| v.as_ref().as_str()).unwrap_or("");
            Ok(Value::Bool(hay.contains(needle)))
        }
        "flatten" => {
            let mut out = Vec::new();
            if let Some(Value::Array(outer)) = args.first().map(|v| v.as_ref()) {
                for inner in outer {
                    if let Value::Array(a) = inner {
                        out.extend(a.iter().cloned());
                    } else {
                        out.push(inner.clone());
                    }
                }
            }
            Ok(Value::Array(out))
        }
        "json" => {
            let s = args
                .first()
                .and_then(|v| v.as_ref().as_str())
                .unwrap_or("null");
            serde_json::from_str(s).map_err(|e| ExprError::Json(JsonErrorCategory::from(e)))
        }
        "env" => {
            // Reads the real process environment — see the module doc
            // comment's "`env()` is a second, independent secret-exposure
            // surface" section. Not scoped to a workflow's declared
            // `secrets:` list.
            let key = args.first().and_then(|v| v.as_ref().as_str()).unwrap_or("");
            Ok(match std::env::var(key) {
                Ok(v) => Value::String(v),
                Err(_) => Value::Null,
            })
        }
        other => Err(ExprError::UnknownFunction(other.to_string())),
    }
}
