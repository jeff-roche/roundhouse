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
//! - **Can appear:** in the `Ok` half of all three public entry points —
//!   [`eval`]/[`eval_delimited_expression`] return
//!   [`Evaluated`] (`value` plus a `secret_derived` flag), [`interpolate`]
//!   returns [`Interpolated<String>`](Interpolated) and [`interpolate_json`]
//!   returns [`Interpolated<Value>`](Interpolated), each carrying **two**
//!   renderings of one evaluation. A resolved secret appears in
//!   `Evaluated::value` and in `Interpolated`'s
//!   [`unredacted_for_dispatch`](Interpolated::unredacted_for_dispatch) half
//!   — that is the whole point of evaluating `${{ secrets.GH_TOKEN }}`, to
//!   produce the token for a caller to use (e.g. as an `env:` value). It
//!   does **not** appear in `Interpolated`'s
//!   [`redacted_for_logging`](Interpolated::redacted_for_logging) half, which
//!   is what exists for the caller to log. What the *caller* then does with
//!   the unredacted half (log it, print it, put it in a `Debug` derive
//!   somewhere) is outside this module's control — the accessor names are the
//!   only guard, and they are names, not enforcement.
//!   (These are the real return types as of fix round 4. An earlier version
//!   of this list said `eval`/`interpolate`/`interpolate_json` returned bare
//!   `Value`/`String`/`Value`, which stopped being true when ruling P33's
//!   dual rendering landed.)
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
//!   print only the sorted list of root names that have been bound, never
//!   their values.
//!
//!   **The reason for that used to be stated wrongly, and the correction
//!   matters (fix round 4, item A).** The old wording justified it on the
//!   claim that this module "cannot tell a resolved secret apart from an
//!   ordinary `inputs.*` value". Since ruling P33 that premise is false:
//!   `ExprContext` records per-root provenance and *can* tell a
//!   [`set_secret`](ExprContext::set_secret)-bound root apart from a
//!   [`set_public`](ExprContext::set_public)-bound one. The conclusion is
//!   unchanged — no values are printed — but for a different and weaker
//!   reason: a root marked non-secret is only *asserted* to be non-secret by
//!   whichever caller bound it (see the boundary section below), so
//!   "provenance says clean" is not evidence that printing the value is safe.
//!   Printing root names only needs no such assertion at all.
//! - **No logging.** This module never calls `tracing`/`log`/`eprintln!`
//!   anywhere, so there is no log-line leak surface *inside* `expr.rs`
//!   itself to audit.
//!
//! # Provenance's true boundary is [`ExprContext`]'s constructors, not the grammar (ruling P35)
//!
//! Taint is complete *inside* the evaluator — every operation the grammar can
//! perform is enumerated in the propagation table below, and each has a test.
//! What taint cannot do is see how a value got into the context in the first
//! place. **A secret bound through a root the caller marked non-secret is not
//! tainted and logs in cleartext.** Executed end to end through
//! `parse_workflow` -> `Executor::new` -> `run_to_completion`, with the
//! credential handed in as `inputs`/`vars` rather than through `secrets`:
//! `emit: { v: "${{ inputs.carried }}", w: "${{ vars.carried }}" }` logs
//! `{"v":"INPUTSCARRIEDSECRET","w":"VARSCARRIEDSECRET"}`.
//!
//! `crate::exec`'s whole-secret backstop covers only the **sub-case** where
//! such a value happens to equal a declared `secrets` entry *exactly* (an
//! exact-match needle finds it wherever it appears). A value merely *derived*
//! from a mis-bound secret — a field of it, a slice of it — is covered by
//! neither mechanism.
//!
//! One narrowing of this boundary is worth recording so a later reader does not
//! mistake it for a mitigation that was silently removed (fix round 5, item 3):
//! fix round 3's **whole-leaf** redaction *incidentally* covered a
//! P35-boundary value that happened to share a JSON leaf with a genuine
//! secret, and fix round 4's per-substitution rendering (ruling E, correctly)
//! does not. Executed:
//! `emit: { v: "${{ secrets.T }} and ${{ inputs.cred }}" }` now logs
//! `{"v":"*** and INPUTS-CARRIED-CREDENTIAL-0009"}` where round 3 logged
//! `{"v":"***"}`. **This is not a new hole:** the same mis-bound value already
//! logged in cleartext whenever it sat in a leaf of its own, in both rounds, so
//! the set of values that can leak is unchanged — only the incidental coverage
//! of one co-location is gone, and it was never a property anyone could rely
//! on.
//!
//! This is the honest boundary of the design, and it relocates the
//! correctness argument: it rests on **every binding site choosing the right
//! constructor**. That is why [`ExprContext::set_public`] is named as an
//! assertion rather than being the plain, default-looking `set` it used to be,
//! why binding a value of unknown provenance must use
//! [`ExprContext::set_secret`], and why a rebinding can never *lower* a root's
//! recorded provenance (see [`ExprContext::set_public`]).
//!
//! **Ruling P37's correction to that argument, and the strongest lever
//! available (fix round 5, item 2).** Naming the non-secret path
//! `set_public` is *convention*; it is one keystroke from `set_secret`, and an
//! author who does not know a value's provenance still reaches for it because
//! it is the only method that lets them proceed without knowing. Where a value
//! has a **producer** — an [`Evaluated`] or an [`Interpolated<Value>`](Interpolated)
//! this module returned — [`ExprContext::set_from`] reads the provenance off
//! that producer, so the binding site never asserts anything. Propagate, do not
//! re-assert. [`ProvenanceCarrier`] is sealed, which closes the set of carriers
//! to those two types — but sealing the trait alone does not make "the
//! producer says clean" unforgeable. [`Evaluated`]'s `value`/`secret_derived`
//! are now private (ruling P44, correcting P40's original, unachievable
//! "cannot lower taint" demand), which closes the naive clone-and-mutate
//! forgery from outside this crate — but not [`Evaluated::derive`] called on
//! the wrong source, and not [`ExprContext::set_public`]'s own accepted
//! assertion. See [`ProvenanceCarrier`] and [`Evaluated`]'s own doc comments
//! for the full, precise accounting of what is and is not closed.
//!
//! # Provenance-based redaction (ruling P33) — the complete propagation table
//!
//! A value is redacted in a **logged** rendering because of *where it came
//! from*, never because of what a JSON key it landed under happens to be
//! called and never because of how long it is. [`ExprContext::set_secret`]
//! (and [`ExprContext::set_with_secret_paths`], for a root that holds secret
//! material only at particular paths) marks a binding as secret; every
//! evaluation that reads through such a binding produces a value flagged
//! `secret_derived`, and [`interpolate`]/[`interpolate_json`] replace that
//! value's substitution, **in its entirety**, with [`REDACTION_PLACEHOLDER`]
//! in the redacted half of the [`Interpolated`] they return. The unredacted
//! half is untouched and is what must reach the dispatched task.
//!
//! This replaced a list of "sensitive-looking" JSON key names, which
//! under-redacted 29 real credential field names measured end to end. The
//! decisive property of provenance is not tidiness — it is that **its risk is
//! bounded and enumerable**: this grammar has a finite set of operations, and
//! taint's behaviour through each of them is listed here and tested
//! individually (`tests/exec_sequencing.rs`'s `TAINT_PROPAGATION_TABLE`).
//!
//! | operation | taint of the result |
//! |---|---|
//! | string literal `'x'` / `"x"` | clean (workflow source text) |
//! | number literal `12` | clean |
//! | bare identifier bound by [`ExprContext::set_public`] | clean — *asserted* so by the binding site, not proven here (see the boundary section above) |
//! | bare identifier bound by [`ExprContext::set_secret`] | **secret** |
//! | bare identifier bound by [`ExprContext::set_with_secret_paths`] | **secret** — the whole object, secret sub-paths included, escapes |
//! | bare identifier bound by [`ExprContext::set_from`] | whatever its producer recorded — *propagated* from the [`Evaluated`]/[`Interpolated`] it came from, never asserted by the binding site (ruling P37) |
//! | unbound identifier (resolves to `Null`) | clean |
//! | `.field` on a secret value | **secret** |
//! | `.field` walking a root with declared secret paths | **secret** once the walked path reaches or passes a declared path; clean once it provably diverges from every one; still undecided while it is a strict prefix of one |
//! | `[idx]` on a secret value, or on a walk not yet clear of a declared path | **secret** (no static knowledge of which entry is selected) |
//! | `[idx]` where the *index expression* is secret | **secret** (the subscript chooses which element escapes) |
//! | array literal `[a, b]` | **secret** iff any element is |
//! | any function call `f(a, b)` | **secret** iff any argument is, read or not |
//! | comparison `a == b` (and `!=`, `<`, `<=`, `>`, `>=`) | **secret** iff either side is — the resulting `Bool` is a one-bit oracle on the secret |
//! | ternary `c ? a : b` | **secret** iff `c` is, or iff the *selected* branch is; the untaken branch's value never appears in the result so its taint is not propagated |
//! | `env('NAME')` with no secret argument | **clean** — see the section below; `env()` is a separately escalated, unowned surface and its behaviour is deliberately unchanged here |
//!
//! Two consequences worth stating plainly. First, this is **deliberately
//! conservative**: a value merely *computed from* a secret (its length, a
//! comparison against it, a slice of it) logs as `***` even though it is not
//! the secret. That over-redaction is predictable and local to the
//! substitution, unlike the global find-and-replace it replaces. Second, it
//! **cannot see a credential an author pasted literally into workflow YAML** —
//! that text never came from a secret binding. `crate::exec` keeps one
//! bounded, exact-match backstop for precisely that case: the whole declared
//! `secrets` values, and nothing derived from them.
//!
//! ## `env()` is a second, independent secret-exposure surface — AWAITING AN OWNER
//!
//! `env()` (§8.9's own required function, `docs/architecture/05-scheduling-and-workflows.md:295-296`)
//! reads the **calling process's real environment** via [`std::env::var`] —
//! the daemon's environment, not a workflow-scoped view of it, and not
//! restricted to whatever a workflow declared under its own `secrets:`
//! list. Building it exactly this way, with no allowlist invented
//! unilaterally, is correct against the frozen contract — a security review
//! independently confirmed both that §8.9 really does freeze `env` in the
//! function list and that declining to scope it down without a brief to do
//! so was the right call. **What is not settled is what happens next.**
//! Concretely: `crates/roundhouse-daemon/src/main.rs:125` reads
//! `ANTHROPIC_API_KEY` from the daemon's process environment to configure
//! the real provider; `env()` reads that same environment, unscoped; so
//! `${{ env('ANTHROPIC_API_KEY') }}` in any workflow file yields the
//! provider key as cleartext into an `env:`/`with:`/header/`run:` value,
//! bypassing `roundhouse-secrets` and the redaction discipline at
//! `crates/roundhouse-secrets/src/resolve.rs:108`, and bypassing the
//! workflow's own declared `secrets:` list entirely. This residual is
//! **escalated, not closed**: it needs an owner and a decision (process-env
//! scrubbing before workflow evaluation, or a daemon-config allowlist of
//! which variable names `env()` may read) that this task is not the one to
//! make unilaterally. Stated here so the next reader does not mistake the
//! absence of a fix for the absence of a decision, and does not have to
//! rediscover the residual by reading `call_function`'s `"env"` arm cold.
//!
//! ## The trust newtypes assert at the call site, not the parse boundary — a Task 13 design input (ruling P23)
//!
//! [`TemplateSource`], [`JsonTemplateSource`], and [`ExpressionSource`] meet
//! ruling P20's stated bar — one visible, greppable `::from_workflow_file`
//! call at the point a template or expression's trust is established — and
//! no more. All three constructors are infallible and accept any `&str`/
//! `&Value`; none of the three types derive `Clone`/`Debug`, so nothing can
//! hold one, and every call site in this crate builds one inline as a
//! temporary, immediately consumed by `interpolate`/`interpolate_json`/
//! `eval`. Wrapping an untrusted `String` reproduces the P20 abuse
//! verbatim — the newtype makes the trust assertion auditable at each call
//! site, but does not make an *un*trusted value harder to wrap.
//!
//! The design that would buy real visibility is to establish trust where it
//! is actually established, not where the template is consumed: have
//! `parse::parse_workflow` hand back step fields already typed as
//! `TemplateSource`/`ExpressionSource`, so the assertion happens once per
//! workflow at the YAML boundary and the type *flows* into the evaluator —
//! a caller holding an untrusted `String` would then have nothing to wrap
//! and no obvious way to obtain one, instead of a one-line escape available
//! at every call site.
//!
//! **Deliberately not done here.** It requires a storable (owned + `Clone`)
//! type and it changes `parse`'s output types, which Tasks 13-21 build on —
//! retrofitting that through nine downstream tasks is the expensive
//! version; doing it speculatively now, before an executor exists to show
//! what actually needs to flow, is the wrong version. It is a required
//! design input to Task 13 (the first task that holds both a parsed
//! workflow and an evaluator, and therefore the first place this can be
//! decided against real usage, not speculatively) — recorded here so the
//! next owner finds this analysis rather than rediscovering it.
//!
//! ## A resolved value can carry control characters the workflow YAML never had
//!
//! §8.9 requires `json()`, and `json('"a\nb"')` decodes the two literal
//! source characters `\` and `n` into an actual newline byte in the
//! resulting `Value::String` — the same escape-decoding any JSON parser
//! does. **`json()` is not the dominant path here, and naming it as the
//! reason this gap is real would be wrong: plain context data already
//! carries the same risk with no `json()` call involved at all** —
//! whatever deserializes a `map.over` item or a webhook payload into the
//! `serde_json::Value` this module receives already turns an escaped
//! sequence in *that* source data into a real control byte before
//! [`ExprContext`]'s binding methods ever run, so freezing or removing
//! `json()` would narrow this vector by exactly zero: `json()` can merely
//! reach the same outcome from expression text the author typed directly,
//! which is a smaller and more visible surface than attacker-controlled
//! `map.over` data. The residual belongs on **whatever deserializes context data**
//! (this module included, when `json()` is the one doing the decoding),
//! and on **whatever sink consumes the resulting string**, not on `json()`
//! alone.
//!
//! Blast radius, measured at the sinks a resolved value can reach:
//! a synthesized **NUL byte reaching an argv element fails closed**
//! (`std::process::Command::arg` returns `InvalidInput: nul byte found`,
//! measured directly). A synthesized **newline reaching an argv element
//! placed after a `--` separator is inert** — the argument stays one
//! element rather than splitting, which is the shape Task 3's
//! `worktree.base_ref` argv+`--` requirement
//! (`crates/roundhouse-flow/src/parse/steps.rs:657-658`) depends on, *if*
//! the executor that actually spawns the process (Task 6) honors that
//! requirement — this module cannot verify that from here. **A synthesized
//! newline reaching an `env:` value is the real hazard**: measured
//! directly, `/usr/bin/env` rendered a value containing an embedded newline
//! as two separate lines, forging a second `KEY=VALUE` entry that was not
//! present in the original single value. Any consumer that parses
//! `KEY=VALUE` lines (a `.env` file, `--env-file`, a systemd
//! `EnvironmentFile`, a `GITHUB_ENV`-style append) would see the forged
//! entry as genuine. [`interpolate_json`] exists precisely to resolve a
//! step's `env:` block, so this is not a hypothetical shape for this
//! module's own output to reach. Task 3's own `worktree.base_ref`
//! validator already reasons about this in the other direction (it
//! deliberately does not re-validate post-substitution content, see its
//! own doc comment) — whatever wires `env:` resolution up for real is where
//! this residual needs to be closed, by validating the resolved value
//! before it reaches an env-file-style sink, not by restricting this
//! module's own functions.
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
//! # A ternary evaluates both branches before selecting one (documented, not fixed — fix round 2)
//!
//! [`Parser::parse_ternary_inner`] parses and evaluates `cond`, `then_v`,
//! *and* `else_v` unconditionally, and only picks which of `then_v`/`else_v`
//! to return afterward, based on [`truthy`]. This is pre-existing behaviour,
//! not a leak introduced by this fix round, and the argument-clone fix
//! above made the discarded branch's *evaluation cost* free in the common
//! case (an unused chain mention now stays a zero-copy `Cow::Borrowed` that
//! is simply dropped) — but it does not change *whether* the untaken branch
//! runs at all. Concretely: `${{ allowed ? secrets.TOKEN : '' }}` evaluates
//! `secrets.TOKEN` — including any `env()` call nested inside that branch —
//! regardless of whether `allowed` is true. Nothing in this module's frozen
//! grammar has short-circuit evaluation, and adding it would be exactly the
//! kind of grammar change the module doc's opening paragraph forbids without
//! going back to §8.9 first. This matters wherever `if:`-style conditional
//! semantics get built on top of this evaluator later: a condition guarding
//! whether a step *runs* is not the same as a condition guarding which
//! *value* an already-running ternary selects, and the latter does not
//! prevent the untaken side's lookups (or its `env()` calls) from happening.
//!
//! # Case sensitivity — the coupling with Task 3's reserved-root check
//!
//! `parse::steps::validate_map_as` rejects `map.as` values that
//! case-sensitively equal one of `RESERVED_EXPRESSION_ROOTS` (`secrets`,
//! `steps`, `inputs`, `run`, `vars`, `env`) — it does **not** reject `Steps`
//! or `STEPS`. That check is only sound if this evaluator is also
//! case-sensitive when resolving a root name, because `ExprContext`'s
//! binding methods and every identifier lookup in this module go through an
//! ordinary `HashMap<String, Value>` keyed by the exact byte string parsed
//! out of the expression (`parse_ident` copies bytes verbatim, no case-folding
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
//! **This does not eliminate every amplification shape, and — corrected in
//! fix round 2 (security finding S2-Imp-1) — an earlier version of this
//! paragraph overclaimed why the remaining one is there.** It used to say an
//! array literal "genuinely must own N independent copies ... not N
//! discarded reads", and called [`Parser::parse_array_literal`]'s per-element
//! `Cow::into_owned()` "necessary work, not a residual". **That is true only
//! when the array literal's value actually escapes into the result** —
//! becomes the expression's final value, is selected by `default(...)`, or
//! is read by `slice`/`flatten` (which copy the elements they return). It is
//! false whenever the literal is consumed by a function that only *reads*
//! it and returns something else entirely: `len([payload, ..., payload])`
//! discards every one of the N clones and returns a single integer, and
//! `contains`/a comparison/an index on an array literal are the same shape.
//! Measured directly (reproduced independently by security, then again for
//! this fix round, both agreeing with the original figures to within normal
//! process-baseline noise): `len([payload x N])` against a 20 MiB `payload`,
//! 50 mentions (406-byte expression) → 1,046,832 kB peak RSS; 100 mentions
//! (806 bytes) → 2,071,684 kB; and against a 100 MiB `payload`, 15 mentions
//! (126 bytes) → 1,641,396 kB. Coefficient ≈ `(expr_len / 8.1) × context_size`
//! — the multiplicand is the context, the exact shape the argument-clone fix
//! above just closed, and the exact shape this module's own claims elsewhere
//! say a length or argument-count cap cannot bound (an expression-length or
//! argument-count cap would not bound the work either, since the
//! multiplicand is the context size a `map.over` or webhook payload can make
//! arbitrarily large — the same shape as Task 10's anchor/alias parse-cost
//! finding, which was closed in Task X1 by metering the real work unit
//! rather than capping a proxy for it; see `parse/mod.rs`).
//!
//! **This is left open, not closed, and that is a deliberate choice, not an
//! oversight.** Closing it in general requires an array literal to flow
//! through this module's chain-evaluation pipeline (`parse_ternary` →
//! `parse_ternary_inner` → `parse_comparison` → `parse_primary_chain` →
//! `parse_args_until` → [`call_function`]) as something other than a single,
//! already-owned `Value` — i.e. threading a second, lazy representation
//! (an unresolved list of still-borrowed elements) through every one of
//! those functions, so that `len`/`contains`/a comparison/an index can read
//! through it without forcing ownership, while `default`/`slice`/`flatten`
//! and the top-level result still force it exactly where the value
//! genuinely escapes. That is precisely the same shape of pervasive
//! Cow-threading change that produced *both* of this file's own prior
//! quadratic-clone defects (the property-chain fix and the argument-clone
//! fix immediately above) — each time, the fix itself, not the original
//! bug, was where an overclaim or a second defect crept in and had to be
//! caught by a later review round. Repeating that shape of change a third
//! time, under this fix round's time budget, for a residual that is not
//! reachable by any caller today (this module still has zero callers
//! anywhere in the workspace) trades a real but inert residual for a real
//! risk of a fresh correctness bug in a security-load-bearing module. The
//! honest, narrower claim above, with its measured coefficient, is the
//! chosen fix for this round; a lazy-array representation through the full
//! pipeline is the correct fix for whoever picks this back up with room to
//! rebuild the byte-identical-output test coverage this kind of change
//! needs (see the argument-clone fix's own review history for what that
//! coverage looked like).
//!
//! **A separate finding, measured directly, corrected once already after
//! the first measurement turned out to be a debug-build artifact:**
//! constructing and then dropping a `serde_json::Value` that is deeply
//! nested (thousands of levels of `{"next": {"next": {...}}}`) can by
//! itself overflow a small enough stack and abort the whole process —
//! `serde_json::Value`'s `Drop` implementation recurses one stack frame
//! per nesting level, and this happens with **no expression evaluation
//! involved at all**: building the value and immediately dropping it is
//! enough. An earlier measurement of this, taken in a debug build, reported
//! depth 4,000 aborting; that number does not hold in the release profile
//! this crate actually ships. Re-measured in `--release`, each figure its
//! own separate run: depth 10,000 drops cleanly on the ~8 MiB default main
//! thread stack; depth 4,000 drops cleanly on an explicit 2 MiB thread
//! stack; depth 20,000 on that same 2 MiB thread stack aborts with
//! `SIGABRT` (exit 134) — stack size, not depth alone, is what determines
//! where this lands, and this module has no way to know how large the
//! stack of whatever thread eventually drops a given `Value` will be.
//!
//! **This diff cannot itself construct a `Value` anywhere near deep enough
//! to hit either failure point, measured, not assumed:** `json()`'s
//! `serde_json::from_str` enforces its own fixed recursion limit —
//! verified directly, parsing `{"a":{"a":...1...}}}` errors with "recursion
//! limit exceeded" at exactly depth 128, succeeding at 127 — and this
//! module's own array-literal syntax is independently capped by
//! [`MAX_EXPR_DEPTH`] (64), already pinned by
//! `excessive_bracket_nesting_is_a_typed_error_not_a_stack_overflow`. Both
//! are one to two orders of magnitude below either abort threshold above.
//! [`MAX_EXPR_DEPTH`] bounds recursion driven by *expression syntax*
//! nesting (`[`, `(`, `? :` written in the `${{ ... }}` text); it does
//! nothing for recursion driven by *context data* nesting, because this
//! module never walks a whole context value recursively — it only follows
//! the fixed property/index chain an expression names — but `json()`'s own
//! limit closes that gap for the one way this module can itself produce a
//! `Value` from text it does not already have. **What remains open is data
//! this module never constructed at all**: a deeply-nested `Value` handed
//! to [`ExprContext`] by a caller — risk item 3 names `map.over`
//! external data (attacker-influenced) as exactly what could populate a
//! context like this — still shares that `ExprContext`, and the value's
//! own `Drop`, whenever it eventually runs on whatever thread holds it,
//! pays the stack cost measured above regardless of what any expression
//! did. Whatever deserializes that external data before calling
//! binding it into an [`ExprContext`] is where a real bound would have to
//! live — a maximum nesting-depth check at deserialization time, before a
//! `Value` this deep is ever constructed. Nothing in `roundhouse-flow` does that today, for
//! context data generally (not just `map.over`), and this module cannot
//! add it without ceasing to be "a pure evaluator over a
//! `serde_json::Value` context" — the value already has to exist before
//! this module ever sees it. Recorded here rather than left for the next
//! person to rediscover by crashing a shared machine.
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
//! restatement or extension of, the separate `parse/mod.rs` finding about
//! `serde_yaml`'s own alias/anchor parse cost (closed in Task X1 by
//! `parse::MAX_EXPANDED_WEIGHT`) — that finding is about parsing YAML *text*
//! into a `serde_yaml::Value` before any expression evaluation happens;
//! this bound is about evaluating an expression *after* that YAML has
//! already parsed successfully. Note also
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

/// Fix round 2, item 7 (M-3): public, reachable from a second entry point
/// this round ([`eval_delimited_expression`], alongside [`eval`]), and
/// already grew a variant once ([`ExprError::NotADelimitedExpression`], fix
/// round 1). Any downstream exhaustive `match` would break on the next
/// variant added; `#[non_exhaustive]` makes that a compile error at the
/// `match` site instead of a silent behavior change. No security impact —
/// cheap insurance against a real, already-demonstrated growth pattern.
#[non_exhaustive]
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
    /// Fix round 1, item 4: the field's whole text was not a single
    /// delimited expression — either it wasn't wrapped in `${{ }}` at all
    /// (a bare expression, e.g. a `when:` field written as `"1 == 1"`
    /// instead of `"${{ 1 == 1 }}"`), or non-whitespace text followed the
    /// block's closing `}}`. Named separately from
    /// [`ExprError::UnexpectedToken`] specifically so the message states
    /// the real problem (missing/misplaced delimiters) rather than
    /// "unexpected character", which is what a naive attempt to feed the
    /// still-delimited text straight to the bare-expression parser used to
    /// produce (it died on the leading `$`, at position 0, before parsing
    /// anything).
    #[error(
        "expected the field's whole text to be wrapped in the documented expression \
         delimiters (docs/architecture/05-scheduling-and-workflows.md section 8.9), not a \
         bare expression; found: {0:?}"
    )]
    NotADelimitedExpression(String),
    /// Fix round 4, item F: a `[..]` subscript whose expression did not
    /// evaluate to a non-negative whole number — `steps['a']`, `x[1.5]`,
    /// `x[nosuchroot]`. This grammar's `[..]` subscripts an **array by
    /// position** only; there is no string keying (that is what `.field` is
    /// for), so string subscripting was never implemented. It used to
    /// evaluate silently to `Null`, which is the shape that lets a wrong
    /// result look like a right one: the security lens found this while
    /// retracting one of its own probes as vacuous — the probe appeared to
    /// show `***` only because `[idx]` unconditionally escalates an
    /// unresolved `ValueProvenance::AbovePath` to secret, so it proved
    /// nothing about taint, and the silent `Null` is what hid that.
    ///
    /// Carries the subscript's **source text** (bounded by
    /// `MAX_ECHOED_FIELD_LEN`) and its byte position within the expression,
    /// never the value it evaluated to — same rule every other variant here
    /// follows, so a `${{ steps[secrets.T] }}` reports `secrets.T`, not the
    /// secret.
    ///
    /// # Carry-forward for Tasks 14-21: `default()` no longer rescues a bad subscript
    ///
    /// This error is raised while *evaluating the chain*, so it aborts the
    /// whole expression rather than producing a `Null` for a wrapper to catch.
    /// Two behaviours changed with it, and a workflow that relied on either now
    /// fails its step instead:
    ///
    /// - `default(inputs.arr[inputs.obj.nope], 'fallback')` used to return
    ///   `Ok("fallback")` — the subscript resolved to `Null`, so `default`
    ///   substituted. It is now this error.
    /// - `inputs.arr[inputs.s]` with `s = "1"` used to return `Null`. It is now
    ///   this error: `"1"` is a *string*, and `[..]` takes a number.
    ///
    /// **The loss is deliberate** (fix round 4, item F; kept by fix round 5):
    /// fail-loud beats silently-wrong, which is the defect F fixed — a silent
    /// `Null` is what let a wrong result look like a right one.
    ///
    /// **Open question, not decided here:** whether a numeric *string* index
    /// (`"1"`) should coerce to `1`. It is a real design question and it gets
    /// its own decision, not a fix-round add-on. The place it will actually
    /// bite is Subsystem D's trigger payloads, where values arrive from JSON
    /// bodies and query strings and a numeric string is the normal shape;
    /// whoever writes the first `${{ trigger.* }}` subscript should settle it.
    /// Today: no coercion, and the error above.
    ///
    /// Both payloads are executed and pinned by
    /// `tests/expr.rs::default_cannot_rescue_a_failed_subscript_and_a_numeric_string_index_does_not_coerce`,
    /// so this carry-forward cannot quietly stop being true.
    #[error(
        "the subscript {index_expression:?} at position {position} did not evaluate to a \
         non-negative whole number; `[..]` indexes an array by position (use `.field` to read \
         an object's member)"
    )]
    NonNumericIndex {
        position: usize,
        index_expression: String,
    },
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

/// Which parts of a bound root hold secret material, for taint tracking —
/// see [`ExprContext::set_secret`] and the module doc comment's
/// "Provenance-based redaction" section.
#[derive(Clone, Debug, PartialEq, Eq)]
enum RootProvenance {
    /// Every value reachable through this root is secret-derived (`secrets`).
    Whole,
    /// Only these field paths *within* this root are secret-derived, each a
    /// non-empty sequence of field names (the executor's `steps` root, where
    /// `["<step id>", "output"]` is secret because that step computed its
    /// output from a secret, while `["<step id>", "status"]` is not). Never
    /// empty — an empty set is stored as no entry at all.
    Paths(Vec<Vec<String>>),
}

/// The evaluation context: a flat table of named roots (`inputs`, `steps`,
/// `secrets`, a `map.as` loop binding, …), each an arbitrary
/// `serde_json::Value`. Lookups are exact-byte-string, case-sensitive —
/// see the module doc comment's "Case sensitivity" section for why that
/// matters beyond style.
///
/// Alongside each binding the context records **whether that binding is
/// secret material** (ruling P33). That flag is the only input to redaction:
/// a value is redacted in a logged rendering because it was computed from a
/// root marked secret here, never because of what a JSON key it landed under
/// happens to be called. See the module doc comment's "Provenance-based
/// redaction" section for the full propagation table.
#[derive(Default, Clone)]
pub struct ExprContext {
    vars: HashMap<String, Value>,
    /// Roots (or parts of roots) whose values are secret material. A root
    /// absent from this map is entirely clean.
    secret_provenance: HashMap<String, RootProvenance>,
}

/// An opaque snapshot of one root's binding — both its [`Value`] and its
/// taint provenance, or the fact that it is currently unbound — captured by
/// [`ExprContext::snapshot_root`] and later restored, atomically, by
/// [`ExprContext::restore_root`]. See that method's own doc comment for the
/// full safety argument (Task 14 fix round 2, item 2/3).
///
/// Deliberately `pub(crate)` with private fields: a caller outside this
/// module (or outside `roundhouse-flow` entirely) can hold a value of this
/// type but cannot construct or inspect one — the only way to obtain one is
/// [`ExprContext::snapshot_root`], and the only thing it is good for is
/// handing straight back to [`ExprContext::restore_root`] on the same
/// instance.
pub(crate) struct RootSnapshot {
    value: Option<Value>,
    provenance: Option<RootProvenance>,
}

impl ExprContext {
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            secret_provenance: HashMap::new(),
        }
    }

    /// Binds `name` to a value the evaluator produced, **carrying that value's
    /// own provenance across with it** (ruling P37).
    ///
    /// This is the binding method to reach for whenever the value came from
    /// [`eval`], [`eval_delimited_expression`] or [`interpolate_json`]: the
    /// producer already computed whether reaching that value read secret
    /// material, so nobody has to re-assert it. Provenance is *propagated*, not
    /// *re-stated* — the third time in this phase that has been the right shape
    /// (the fix-round-3 step boundary and fix-round-4 monotonicity were the
    /// other two).
    ///
    /// ```text
    /// let item = eval(ExpressionSource::from_workflow_file(over), &ctx)?;
    /// ctx.set_from("item", &item);   // secret iff `over` read a secret
    /// ```
    ///
    /// # Why this is stronger than choosing between `set_public` and `set_secret`
    ///
    /// [`Self::set_public`] and [`Self::set_secret`] are one keystroke apart,
    /// and an author who does not know a value's provenance will reach for
    /// `set_public` because it is the only one that lets them proceed without
    /// knowing (ruling P37's own diagnosis of the fix-round-4 rename). Here
    /// there is nothing to know at the binding site: the flag is read off
    /// [`ProvenanceCarrier`] rather than passed in.
    ///
    /// # What the seal does and does not buy (ruling P44, correcting an earlier version of this section)
    ///
    /// [`ProvenanceCarrier`] is sealed, so no *foreign* type can implement it:
    /// the set of carriers is closed to [`Evaluated`] and
    /// [`Interpolated<Value>`](Interpolated). That is the whole of it. It does
    /// **not**, by itself, authenticate the provenance inside a carrier.
    /// Before Task 14, [`Evaluated`] had public fields and no
    /// `#[non_exhaustive]`, so a caller in *any* crate could build one with
    /// whatever `secret_derived` it liked and hand it here — the naive
    /// struct-literal forgery. **An earlier version of this section claimed
    /// `#[non_exhaustive]` alone closed that for an external caller. It did
    /// not**: with fields still `pub`, an out-of-tree crate could still
    /// `real.clone()` then assign `.secret_derived = false` directly — no
    /// struct-expression involved, so `#[non_exhaustive]` (which only blocks
    /// that syntax) never engaged. Measured: this compiles and leaks from
    /// outside the crate, reproducing the fix-round-5 leak byte-for-byte.
    ///
    /// **What actually closes the external route:** `value`/`secret_derived`
    /// are now **private**, so `eval`/[`eval_delimited_expression`]/
    /// [`Evaluated::derive`] are the only places that can name a
    /// `secret_derived` value at all — there is no field to clone-and-mutate
    /// from outside this crate. What this still does **not** close, and
    /// cannot by this design: `clean.derive(secret_value)` (nothing can check
    /// that the value passed to `derive` is actually reachable from the
    /// `Evaluated` it is called on) and [`Self::set_public`] (still an
    /// assertion, never verified). See [`Evaluated`]'s own doc comment for
    /// the full accounting — this module's own standard is to state exactly
    /// what a mechanism enforces rather than implying a seal where one of
    /// three routes remains open.
    ///
    /// # It binds a whole producer; per-item derivation goes through `Evaluated::derive`
    ///
    /// `set_from` itself still takes one carrier and binds one name from it —
    /// it has no sub-value operation of its own. What changed (Task 14) is
    /// that [`Evaluated::derive`] now exists as a *second* step a caller
    /// takes first: evaluate `over:` once to get one [`Evaluated`] over a
    /// whole collection, call `.derive(item.clone())` per element to get a
    /// correctly-tainted per-item [`Evaluated`], then call `set_from` with
    /// that. `crate::exec::map_step::dispatch_map_step` is exactly this
    /// shape, and it is what closes the per-item gap ruling P37 originally
    /// left open (hand-building an `Evaluated` around one element, which is
    /// re-assertion, not propagation).
    ///
    /// # What it binds
    ///
    /// The producer's **unredacted** value — see
    /// [`ProvenanceCarrier::provenance_value`] for why binding `***` would be
    /// wrong. This clones that value; the cost of the clone is unmeasured and
    /// is the value's own size only — `set_from` does not clone anything
    /// beyond the one value it is handed. (An earlier version of this
    /// sentence pointed at a "per-item context-clone cost" in
    /// `crate::exec::map_step`; that cost no longer exists there as of Task 14
    /// fix round 2 — see [`Self::snapshot_root`]/[`Self::restore_root`].)
    ///
    /// # Interaction with monotonicity, and the one thing it does not fix
    ///
    /// `set_from` on a clean producer goes through [`Self::set_public`], so it
    /// inherits monotonicity: it cannot lower a name already marked secret
    /// **on the `ExprContext` it is called on, for that instance's life**. It
    /// does **not** rescue a name from the per-root-name conservatism
    /// described on [`Self::set_public`] within one such life — a loop that
    /// binds one name per item still escalates that name for as long as this
    /// same `ExprContext` value persists, once any one item taints it. Ruling
    /// P45 records the sharpest form of this: since `map.over` is evaluated
    /// once, every item in one `map` step shares one taint bit regardless of
    /// binding strategy — this is not a monotonicity artifact to be fixed, it
    /// is collection-granularity taint, accepted. A caller that needs a name's
    /// monotonic history to *end* — as `crate::exec::map_step::Executor::dispatch_map_step`
    /// does, once per `map` step and once per nesting level — uses
    /// [`Self::snapshot_root`]/[`Self::restore_root`] to revert the name to an
    /// earlier, already-established state; that is not `set_from` rescuing
    /// anything, it is a different, narrower operation for a different
    /// purpose. See [`Self::set_public`]'s own doc comment for the full
    /// accounting and the measured figure, and [`Self::restore_root`]'s for
    /// why reverting a name's history this way is safe where lowering its
    /// provenance by assertion would not be.
    ///
    /// # Callers (Task 14, landed)
    ///
    /// `crate::exec::map_step::Executor::dispatch_map_step` is this method's
    /// first real caller: it evaluates `over:` once, calls
    /// [`Evaluated::derive`] once per item, and binds the result with this
    /// method directly onto `self.ctx` — the run's own, shared
    /// `ExprContext` — for the duration of that item's inner steps, then
    /// reverts the binding via [`Self::restore_root`] once the whole `map`
    /// step (or, when nested, the whole enclosing item) finishes. See that
    /// function's own doc comment for why binding onto the shared context and
    /// reverting by name, rather than forking a whole separate context, is
    /// both correct and (unlike an earlier design) affordable under nesting.
    /// `inputs`/`vars`/`run.id`/`secrets` still bind through
    /// [`Self::set_public`]/[`Self::set_secret`] directly (none of them has a
    /// producer to read), and `steps` still goes through
    /// [`Self::set_with_secret_paths`], strictly more precise than this
    /// (per-step paths rather than a whole root) and so deliberately not
    /// migrated.
    pub fn set_from<P: ProvenanceCarrier>(&mut self, name: &str, produced: &P) {
        let value = produced.provenance_value().clone();
        if produced.provenance_is_secret_derived() {
            self.set_secret(name, value);
        } else {
            self.set_public(name, value);
        }
    }

    /// Binds a value **you wrote literally yourself** as a root usable from an
    /// expression (`name.field`, `name[0]`, or bare `name`), **asserting that
    /// nothing reachable through it is secret material.**
    ///
    /// # This is the rare escape hatch, not the ordinary binding method (ruling P37)
    ///
    /// Reach for it only for genuinely literal data: `run.id`, a workflow
    /// constant, a fixed test fixture. **If the value came from the evaluator,
    /// bind it with [`Self::set_from`] instead**, which reads provenance off
    /// the producer rather than asking you to re-assert it. If it came from
    /// somewhere else and you do not know its provenance, bind it with
    /// [`Self::set_secret`] — over-redacting a log line is recoverable, and a
    /// credential in the append-only `events` table is not.
    ///
    /// # Why the name, and why the name is only half of it (rulings P35, P37)
    ///
    /// This used to be called `set`, which made the non-secret path both the
    /// plainly-named one and the one a reader reaches for by default, with the
    /// assertion living only in this doc comment. Ruling P35 made it
    /// self-announcing. Ruling P37 then recorded the honest assessment of that
    /// rename: it is **the weaker half of the fix.** `set_public` is one
    /// keystroke from `set_secret`, and an author who does not know a value's
    /// provenance will still reach for it, *because it is the only method that
    /// lets them proceed without knowing*. What actually closes the hazard is
    /// enforcement — the monotonicity below, and [`Self::set_from`] for values
    /// that have a producer to read.
    ///
    /// # A rebinding can never *lower* a root's provenance
    ///
    /// Calling this on a name previously bound through [`Self::set_secret`] or
    /// [`Self::set_with_secret_paths`] replaces the **value** but keeps the
    /// recorded provenance. Silently un-tainting a root used to be exactly
    /// what this method did. Measured against the pre-fix code, and
    /// reproduced by
    /// `tests/expr.rs::a_public_rebinding_cannot_untaint_a_root_that_was_bound_as_secret`:
    /// after `set_secret`, a following plain `set` on the same name returned
    /// `secret_derived=false` with the value unchanged, so [`Evaluated`]'s
    /// `Debug` — which exists specifically to print `***` — printed
    /// `SECRETVALUE12345` in cleartext, because it trusts the flag. Two
    /// callers of this API would hit it directly: `map.as` per-item binding
    /// (rebinding one loop name per item — Task 14, landed; see the note
    /// below on the design it actually chose) and Task 8 folding real tool
    /// outputs into `steps.<id>.output`. It is the same silent-taint-loss
    /// shape that had to be fixed at the step boundary in fix round 3, so it
    /// is made **unrepresentable** here rather than documented again.
    ///
    /// # Monotonicity is per root NAME and irreversible **for one `ExprContext` instance's life** — a REQUIREMENT on the caller, not a hint
    ///
    /// A name that has ever held secret material keeps redacting for as long
    /// as **the particular `ExprContext` value** it was bound on lives, even
    /// if a later binding of that same name, on that same instance, is
    /// genuinely clean — there is no method on this type that lowers a root's
    /// recorded provenance by *assertion*. **A caller that rebinds one name in
    /// a loop, and wants clean items to stay readable in the log, must end
    /// that name's monotonic history deliberately** — either by moving to a
    /// different `ExprContext` instance (a fresh one, or a different existing
    /// one), or by reverting the name to an earlier, already-established state
    /// via [`Self::snapshot_root`]/[`Self::restore_root`], which is the
    /// mechanism `crate::exec::map_step` actually uses (see below). This is a
    /// requirement, not a suggestion: **within one instance**, there is no way
    /// to lower a root's provenance by assertion, by design.
    ///
    /// The scale of the consequence (ruling P45): a 500-item `map` in which
    /// only item 1 carries a credential produces 500 fully-redacted log
    /// lines, *including every item's name* — one tainted item costs the
    /// observability of the other 499. **This figure is unconditional under
    /// collection-granularity taint, not contingent on any particular binding
    /// strategy or on which `ExprContext` mechanism a caller uses**:
    /// `map.over` is evaluated **once** ([`eval_delimited_expression`]),
    /// producing a single [`Evaluated`] whose `secret_derived` bit is then
    /// propagated to every element by [`Evaluated::derive`]. There is no
    /// per-element evaluation in this crate to give any one item a taint bit
    /// independent of the others', so this is not a bug in
    /// `crate::exec::map_step`'s binding strategy — it is the inherent cost of
    /// taint being tracked per *collection*, not per *element*. **This is
    /// accepted, over- not under-redaction**, and the `steps` root is
    /// unaffected regardless, because [`Self::set_with_secret_paths`] keeps it
    /// per-step precise rather than whole-root.
    ///
    /// **What `crate::exec::map_step` actually fixes — a different, real
    /// problem, not this one.** `dispatch_map_step` snapshots `as_name`'s
    /// prior binding (via [`Self::snapshot_root`]) before its first item, binds
    /// each item onto the run's own, shared `ExprContext` for that item's
    /// inner steps, and restores the snapshot (via [`Self::restore_root`])
    /// once the whole `map` step — or, when `map`s nest, once the enclosing
    /// item — finishes. Because a restore reverts **value and provenance
    /// together, atomically**, a name's taint from **one `map` step** (or one
    /// nesting level) can never survive to poison a **different** `map` step,
    /// or an *enclosing* one reusing the same `as:` name after a nested `map`
    /// returns. This is not the same claim as "no monotonicity artifact
    /// exists" — it is a **narrower**, correct one: monotonicity is real and
    /// unavoidable within the span between a snapshot and its restore
    /// (exactly the 500-item figure above), and `restore_root` is what ends
    /// that span deliberately rather than leaving it open for the rest of the
    /// run. It does **not**, and structurally cannot, give item 2 of one
    /// 500-item map a taint bit independent of item 1's — both come from the
    /// same one `Evaluated` the collection produced. Measured end to end (two
    /// **sibling** `map` steps, both `as: item`, the first's `over:`
    /// secret-derived, the second's genuinely clean):
    /// `tests/map_step.rs`'s
    /// `a_secret_derived_maps_as_name_does_not_poison_a_later_clean_maps_use_of_the_same_as_name`
    /// — the second map's items log in cleartext, not `***`. Measured again
    /// for **nested** maps sharing a name (the case this argument has to
    /// survive, not just the sibling case):
    /// `a_nested_maps_secret_derived_as_name_does_not_poison_the_outer_maps_use_of_the_same_as_name`
    /// — inside the nested map, `${{ item }}` logs `***`; after it returns,
    /// the outer item's own remaining inner steps read `${{ item }}` and get
    /// the outer's real, clean value in cleartext.
    ///
    /// What this conservatism cannot do is corrupt a dispatched value, which
    /// never consults provenance at all; it costs log readability only.
    ///
    /// # What monotonicity does NOT cover
    ///
    /// It only stops a *downgrade of a name already marked secret, by
    /// assertion, within one `ExprContext` instance's ordinary lifetime*. A
    /// **new** name bound here for the first time is clean because you said
    /// so, and nothing checks you. This is exactly why `map.as` (Task 14) does
    /// not call this method with a bare item value at all: if the collection
    /// being iterated was itself derived from a secret (`over:
    /// "${{ json(secrets.K).items }}"`), a per-item binding built with this
    /// method would be a fresh name with no prior provenance, stopping taint
    /// at the loop boundary exactly the way it stopped at the step boundary
    /// before [`Self::set_with_secret_paths`] existed. The rule
    /// `dispatch_map_step` follows instead: **propagate the provenance of
    /// whatever the value was computed from** — evaluate `over:` once via
    /// [`eval_delimited_expression`], call [`Evaluated::derive`] once per
    /// item to get a correctly-tainted per-item [`Evaluated`], then
    /// [`Self::set_from`] with that. [`Self::set_secret`] remains correct
    /// where there is no producer to read and the caller does not know.
    pub fn set_public(&mut self, name: &str, value: Value) {
        self.vars.insert(name.to_string(), value);
    }

    /// Binds `name` as a root and marks **everything reachable through it**
    /// as secret material. This is how `secrets` is bound: every value any
    /// expression computes by reading through this root is tainted, and any
    /// tainted value is replaced in its entirety by `***` in the *logged*
    /// rendering [`interpolate`]/[`interpolate_json`] produce — never in the
    /// real value, which still reaches the dispatched task.
    ///
    /// This is the correct choice for a value whose provenance the binding
    /// site does not know (ruling P35) — but if the value came from the
    /// evaluator its provenance *is* known, and [`Self::set_from`] reads it off
    /// the producer instead of making you decide (ruling P37).
    pub fn set_secret(&mut self, name: &str, value: Value) {
        self.vars.insert(name.to_string(), value);
        self.secret_provenance
            .insert(name.to_string(), RootProvenance::Whole);
    }

    /// Binds `name` as a root of which only the listed **field paths** are
    /// secret material. This is how the executor binds `steps`: a step whose
    /// output was computed from a secret contributes the path
    /// `["<its id>", "output"]`, so `${{ steps.<id>.output.body }}` is
    /// tainted while `${{ steps.<id>.status }}` — a fixed
    /// `"completed"`/`"failed"`/`"skipped"` discriminant that carries no
    /// secret material — stays clean and readable in the log.
    ///
    /// Reading a *prefix* of a secret path (a bare `${{ steps }}`, or
    /// `${{ steps.<id> }}`) yields an object that still contains the secret
    /// material below it, so it is tainted. Indexing with `[..]` anywhere
    /// along a prefix is tainted too, because this evaluator cannot tell
    /// which entry an arbitrary index expression selects. An empty
    /// `secret_paths`, or paths that are all empty, is exactly equivalent to
    /// [`Self::set_public`].
    ///
    /// Rebinding through this method **unions** the new paths with whatever
    /// this root already had, and never lowers a root already marked
    /// `RootProvenance::Whole` — see [`Self::set_public`]'s "A rebinding can
    /// never *lower* a root's provenance" section, which this method obeys for
    /// the same reason. `crate::exec::Executor::run_to_completion` rebinds
    /// `steps` once per step with a monotonically growing path list, so the
    /// union is exactly the list it passes; the rule matters for the callers
    /// that come after it.
    pub fn set_with_secret_paths<I>(&mut self, name: &str, value: Value, secret_paths: I)
    where
        I: IntoIterator<Item = Vec<String>>,
    {
        self.vars.insert(name.to_string(), value);
        let mut paths: Vec<Vec<String>> =
            secret_paths.into_iter().filter(|p| !p.is_empty()).collect();
        match self.secret_provenance.get(name) {
            // Already fully secret: a narrower statement cannot widen the
            // clean set.
            Some(RootProvenance::Whole) => {}
            Some(RootProvenance::Paths(existing)) => {
                for old in existing {
                    if !paths.contains(old) {
                        paths.push(old.clone());
                    }
                }
                self.secret_provenance
                    .insert(name.to_string(), RootProvenance::Paths(paths));
            }
            None => {
                if !paths.is_empty() {
                    self.secret_provenance
                        .insert(name.to_string(), RootProvenance::Paths(paths));
                }
            }
        }
    }

    /// Captures `name`'s current binding — its value **and** its taint
    /// provenance, or the fact that it is currently unbound — for later,
    /// exact restoration via [`Self::restore_root`]. See that method's own
    /// doc comment for what this pair exists to make affordable (Task 14 fix
    /// round 2, item 2) and why bypassing the ordinary monotonicity
    /// guarantee here is safe.
    pub(crate) fn snapshot_root(&self, name: &str) -> RootSnapshot {
        RootSnapshot {
            value: self.vars.get(name).cloned(),
            provenance: self.secret_provenance.get(name).cloned(),
        }
    }

    /// Restores `name`'s binding to exactly what `snapshot` captured —
    /// value and provenance together, in one call, so no reader of this
    /// `ExprContext` ever observes a value under a provenance that does not
    /// (yet) match it. If the snapshot recorded `name` as unbound, this
    /// removes it (from both `vars` and `secret_provenance`) rather than
    /// binding an empty value.
    ///
    /// # Why this may bypass monotonicity, when nothing else in this module may (Task 14 fix round 2)
    ///
    /// [`Self::set_public`]/[`Self::set_secret`]/[`Self::set_with_secret_paths`]
    /// can never *lower* a root's recorded provenance, deliberately — see
    /// [`Self::set_public`]'s own doc comment. This method is not one of
    /// those, and does not weaken that guarantee: it never lets a caller
    /// *assert* new, weaker provenance for a value it is choosing now. It
    /// reverts a root to a state **this exact `ExprContext` instance
    /// genuinely held a moment before** — the snapshot came from
    /// [`Self::snapshot_root`] on this same instance, so no new information
    /// is asserted and nothing is claimed clean that this instance had not
    /// already, independently, established clean earlier in its own life.
    ///
    /// **The atomicity is the whole of what makes this safe, and it is load-
    /// bearing, not incidental** (established by Task 14 fix round 2's
    /// security lens, correcting a weaker justification an earlier draft of
    /// `crate::exec::map_step` gave for the whole-context version of this
    /// same idea). `ExprContext` monotonicity ("a name that has ever held
    /// secret material keeps redacting") is an invariant of **one
    /// `ExprContext` value**, not of anything outside it — nothing prevents
    /// a *second*, later value (or the same value, deliberately reset by a
    /// call like this one) from legitimately holding a different history for
    /// the same name. `crate::exec::Executor::dispatch_map_step` deliberately
    /// discards and reconstitutes root bindings across `map` step and
    /// nesting-level boundaries for exactly this reason: value and
    /// provenance always change *together*, so a reader can never observe
    /// the mismatched combination (an old, secret-flavoured provenance still
    /// attached to a new, clean value, or vice versa) that would make this
    /// unsafe.
    ///
    /// **Verified, not merely argued** — the case this reasoning has to
    /// survive is a *nested* `map` reusing its parent's `as:` name: outer
    /// `as: item` clean, inner (nested) `map` also `as: item`, secret. Inside
    /// the nested `map`, `${{ item }}` correctly logs `***`; once the nested
    /// `map` returns (restoring `item` to the outer's snapshot), a sibling
    /// step in the *outer* item's own remaining inner steps reads
    /// `${{ item }}` again and gets the outer's real, clean value logged in
    /// cleartext (`tests/map_step.rs`'s
    /// `a_nested_maps_secret_derived_as_name_does_not_poison_the_outer_maps_use_of_the_same_as_name`).
    /// The reverse direction (outer secret, inner clean, same name) also
    /// holds and is deliberately **conservative rather than incorrect**: the
    /// nested map's own clean items are over-redacted for the duration of
    /// the nested call (they share the outer's still-`Whole` provenance
    /// entry, since [`Self::set_public`] cannot lower it), which is the same
    /// accepted, safe-direction cost this module already documents for
    /// same-name rebinding generally — never under-redaction, only a log
    /// readability cost, and never a corrupted dispatched value.
    ///
    /// `pub(crate)`, not `pub`: an external caller restoring an arbitrary,
    /// self-supplied `RootSnapshot` would be indistinguishable from
    /// re-assertion by the back door — precisely the shape rulings
    /// P35/P37/P40/P44 close everywhere else this module is reachable from
    /// outside the crate. In-crate, the one call site
    /// (`crate::exec::map_step::Executor::dispatch_map_step`) is reviewed
    /// alongside the invariant it depends on: a snapshot must always come
    /// from [`Self::snapshot_root`] on the very `ExprContext` it is later
    /// restored onto, never constructed by hand or carried across instances.
    pub(crate) fn restore_root(&mut self, name: &str, snapshot: RootSnapshot) {
        match snapshot.value {
            Some(value) => {
                self.vars.insert(name.to_string(), value);
            }
            None => {
                self.vars.remove(name);
            }
        }
        match snapshot.provenance {
            Some(provenance) => {
                self.secret_provenance.insert(name.to_string(), provenance);
            }
            None => {
                self.secret_provenance.remove(name);
            }
        }
    }

    /// Classifies the field path `walked` (relative to `root`) against the
    /// root's declared secret paths. Only consulted by [`Parser::narrow`],
    /// and only for a root recorded as [`RootProvenance::Paths`].
    ///
    /// - a declared path is a **prefix of** `walked` — the walk has reached
    ///   into (or exactly onto) secret material: secret;
    /// - `walked` is a **strict prefix of** a declared path — the walk is
    ///   still above the secret material, and a further `.field` decides:
    ///   undetermined;
    /// - neither: clean.
    fn classify_path(&self, root: &str, walked: &[String]) -> PathVerdict {
        let paths = match self.secret_provenance.get(root) {
            Some(RootProvenance::Whole) => return PathVerdict::Secret,
            Some(RootProvenance::Paths(paths)) => paths,
            None => return PathVerdict::Clean,
        };
        let mut undetermined = false;
        for declared in paths {
            if declared.len() <= walked.len() {
                if declared[..] == walked[..declared.len()] {
                    return PathVerdict::Secret;
                }
            } else if declared[..walked.len()] == walked[..] {
                undetermined = true;
            }
        }
        if undetermined {
            PathVerdict::Undetermined
        } else {
            PathVerdict::Clean
        }
    }
}

/// The three outcomes of [`ExprContext::classify_path`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathVerdict {
    Clean,
    Secret,
    /// Still above the declared secret material — a further `.field` may
    /// reach it, so nothing is decided yet.
    Undetermined,
}

impl fmt::Debug for ExprContext {
    /// Deliberately does not print bound values — see the module doc
    /// comment's "Where a resolved secret can and cannot appear" section.
    ///
    /// **Corrected reasoning (fix round 4, item A).** This comment used to say
    /// the context "cannot tell a resolved secret apart from an ordinary
    /// `inputs.*` value". Since ruling P33 it can: its `secret_provenance` map
    /// records which roots hold secret material. Printing values for the roots
    /// provenance calls clean would still be wrong, because "clean" is an
    /// assertion made by whoever bound the root, not a fact this type
    /// established (ruling P35) — the executed counter-example is in the module
    /// doc comment's boundary section. Printing only the sorted set of root
    /// names depends on no assertion at all, so that is what this prints.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut roots: Vec<&str> = self.vars.keys().map(String::as_str).collect();
        roots.sort_unstable();
        f.debug_struct("ExprContext")
            .field("roots", &roots)
            .finish()
    }
}

/// Asserts that the wrapped text is safe to evaluate as a bare `${{ }}`
/// expression — the sibling of [`TemplateSource`] for [`eval`] rather than
/// [`interpolate`]. See ruling P22 (fix round 3, item 1): P20's trust
/// assertion covers **all three** public entry points into this module, not
/// just `interpolate`/`interpolate_json`. `eval` is in fact the *shortest*
/// path to the abuse P20 exists to prevent, because it skips the `${{ }}`
/// delimiters entirely — `eval` on the bare text `env('ANTHROPIC_API_KEY')`
/// (no `${{ }}` needed at all) returns the daemon's provider key exactly as
/// `${{ env('ANTHROPIC_API_KEY') }}` does through `interpolate`. Measured on
/// HEAD with a planted key: `eval("env('ANTHROPIC_API_KEY')", &ctx)` ->
/// `"sk-ant-PRETEND-KEY"`.
///
/// A distinct type from [`TemplateSource`], not a reuse of it, because the
/// two wrap different grammars: `TemplateSource` wraps a whole template —
/// arbitrary surrounding text plus zero or more `${{ }}` blocks —
/// `ExpressionSource` wraps a single bare expression with no delimiters and
/// no surrounding text. Constructible only through
/// [`ExpressionSource::from_workflow_file`], for the same reason
/// `TemplateSource` is: one explicit, greppable call site at the point an
/// expression's trust is established, rather than an invisible type
/// coincidence between `&str` (expression text) and `&str` (an ordinary,
/// possibly-untrusted string value). The abuse path this closes: a Task 5/6
/// caller evaluating an `if:`/`over:` expression whose text is not
/// workflow-file-controlled (a webhook field, a `map.over` item, a
/// previously evaluated result) must not be able to hand that text straight
/// to `eval`.
pub struct ExpressionSource<'a>(&'a str);

impl<'a> ExpressionSource<'a> {
    /// Asserts that `expr` is the workflow file's own YAML source for a
    /// bare expression field (`if:`, `over:`, …) as authored — not an
    /// evaluated expression result, a `map.over` item, webhook payload, or
    /// any other value this evaluator's caller does not control. See
    /// [`ExpressionSource`]'s own doc comment for what is at stake if that
    /// assertion is wrong.
    pub fn from_workflow_file(expr: &'a str) -> Self {
        Self(expr)
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
///
/// Takes an [`ExpressionSource`], not a bare `&str` — see its doc comment
/// for why (ruling P22). `eval` carries the identical P20 trust assertion
/// that [`interpolate`]/[`interpolate_json`] carry: the three public entry
/// points into this module are symmetric, not two guarded and one bare.
pub fn eval(expr: ExpressionSource<'_>, ctx: &ExprContext) -> Result<Evaluated, ExprError> {
    let (value, secret_derived) = eval_inner(expr.0, ctx)?;
    Ok(Evaluated {
        value,
        secret_derived,
    })
}

/// The text a tainted substitution is replaced by in a *logged* rendering —
/// see [`Interpolated`]. The substitution is replaced **in its entirety**;
/// this is never used as the replacement half of a find-and-replace over
/// surrounding text (ruling P33).
pub const REDACTION_PLACEHOLDER: &str = "***";

/// What [`eval`]/[`eval_delimited_expression`] produce: the expression's
/// value, plus whether computing it read a root bound through
/// [`ExprContext::set_secret`]/[`ExprContext::set_with_secret_paths`].
///
/// Fields are private, reachable only through [`Self::value`]/
/// [`Self::into_value`]/[`Self::secret_derived`] — see the "What this design
/// closes, and what it does not" section below for exactly why (ruling P44).
/// Callers that want a redacted-for-logging stand-in produced for them
/// should use [`interpolate`]/[`interpolate_json`] and their [`Interpolated`]
/// result instead.
///
/// # `#[non_exhaustive]` plus private fields — what this design closes, and what it does not (ruling P44, correcting P40)
///
/// **P40 asked for a constructor that "cannot lower taint" and treated that
/// as an enforcement boundary. That property does not exist, and shipping
/// exactly what P40 asked for proved it by execution (ruling P44).** From an
/// out-of-tree crate, with the type as it shipped in Task 14 (`#[non_exhaustive]`,
/// but `value`/`secret_derived` still `pub`), both of these compiled and
/// leaked, reproducing the fix-round-5 leak byte-for-byte:
///
/// ```text
/// let mut f = real.clone(); f.secret_derived = false;   // clone, then mutate a pub field
/// clean.derive(real.value.clone())                       // derive from an UNRELATED clean Evaluated
/// ```
///
/// `#[non_exhaustive]` blocks *struct-expression* syntax from outside this
/// crate — that closes only the most naive forgery
/// (`Evaluated { value: .., secret_derived: false }`) and nothing else, because
/// with public fields a caller can still `clone()` a real value and then
/// **assign** to the field directly (no struct-expression involved at all).
///
/// **What actually closes that route:** the fields are now private. `eval`,
/// [`eval_delimited_expression`], and [`Self::derive`] are the only places in
/// this crate that can name a `secret_derived` value, so from outside this
/// crate there is no field to clone-and-mutate.
///
/// **What remains open, stated plainly rather than implied closed (this is
/// the corrected, weaker property P44 asks for):**
/// - **`clean.derive(secret_value)`** — [`Self::derive`] cannot express "this
///   `value` came from `self`"; nothing checks that the `Value` passed in is
///   actually reachable from the `Evaluated` `derive` is called on, because
///   nothing *could* check that — it is an arbitrary caller-supplied `Value`
///   by design (that is what lets `map` derive a per-item `Evaluated` from a
///   whole-collection one in the first place). The only property `derive`
///   can and does guarantee is **output taint = source taint** — never that
///   the output value is actually derived from the source value. Calling
///   `derive` on the *wrong* (differently-tainted) `Evaluated` still produces
///   a wrongly-tainted result; nothing in this type stops that.
/// - **[`ExprContext::set_public`]** — ruling P35's accepted escape hatch for
///   genuinely literal data remains exactly what it always was: an assertion
///   the binding site makes, not something this type can verify.
///
/// Private fields therefore close **one of three** external routes to a
/// mislabeled taint, not all three. [`Self::derive`] is a **convenience for
/// propagation, not an enforcement boundary** — it exists so a caller who
/// *does* have the right source `Evaluated` does not have to hand-build one
/// and get `secret_derived` wrong by a typo; it cannot stop a caller who
/// deliberately or mistakenly calls it on the wrong source. Do not read this
/// section as "the forgery hole is closed" — it narrows the surface, it does
/// not seal it. (This is the fourth time this phase a ruling's stated
/// enforcement claim needed correcting after review — see the P33 amendment,
/// P35, and P37's own history of the identical pattern with `set`/`set_public`
/// — and the third time it was *my own* ruling, per P44's own admission.)
#[non_exhaustive]
#[derive(Clone, PartialEq)]
pub struct Evaluated {
    value: Value,
    secret_derived: bool,
}

impl Evaluated {
    /// The expression's own value. Borrowed — see [`Self::into_value`] for
    /// the owned form, and [`ProvenanceCarrier::provenance_value`] for why a
    /// caller reading this must never write it to a log or persisted field
    /// without also checking [`Self::secret_derived`].
    pub fn value(&self) -> &Value {
        &self.value
    }

    /// The expression's own value, by value — see [`Self::value`].
    pub fn into_value(self) -> Value {
        self.value
    }

    /// Whether computing [`Self::value`] read a root bound through
    /// [`ExprContext::set_secret`]/[`ExprContext::set_with_secret_paths`]
    /// (directly, or by [`Self::derive`] propagation from such a value).
    pub fn secret_derived(&self) -> bool {
        self.secret_derived
    }

    /// Derives a new [`Evaluated`] for a value computed **from this one** —
    /// an element of `self.value()` when it is an array, a field of it, or
    /// any other value whose provenance genuinely traces back to this
    /// producer. `secret_derived` is carried forward from `self` and there
    /// is no way to call this and get a *lower* taint out than `self`
    /// already carries: the method has exactly one source of provenance to
    /// read (`self`), and reads it unconditionally.
    ///
    /// # Why this exists (ruling P40; R-1/R-2 of Task 14's brief)
    ///
    /// `map` evaluates `over:` once (via [`eval_delimited_expression`]),
    /// producing a single [`Evaluated`] over a whole collection; each
    /// element is then a bare [`Value`] with no `Evaluated` of its own.
    /// Before this method existed, the only way to bind one item into an
    /// [`ExprContext`] via [`ExprContext::set_from`] was to hand-build
    /// `Evaluated { value: item, secret_derived: ?? }` — precisely the
    /// re-assertion-by-the-back-door ruling P37 exists to remove, one token
    /// (`secret_derived: false`) from silently un-tainting a secret-derived
    /// item. Calling this method instead makes that mistake impossible to
    /// make *by omission*: there is no `secret_derived` parameter to get
    /// wrong, because the only value in scope is the one already on `self`.
    ///
    /// # What this does NOT and cannot guarantee (ruling P44)
    ///
    /// This method has no way to check that `value` is actually reachable
    /// from `self.value()` — it is *any* caller-supplied [`Value`], by
    /// design (that is exactly what lets `map` derive a per-item value out
    /// of a whole-collection one). The only property it can and does
    /// enforce is **output `secret_derived` = source `secret_derived`**. A
    /// caller that calls this on the wrong source (a clean `Evaluated` when
    /// the real value came from a secret one) still gets a wrongly-tainted
    /// result — this method is a propagation convenience, not proof the
    /// value passed in actually came from `self`. See [`Evaluated`]'s own
    /// doc comment for the full accounting of what is and is not closed.
    pub fn derive(&self, value: Value) -> Evaluated {
        Evaluated {
            value,
            secret_derived: self.secret_derived,
        }
    }
}

impl fmt::Debug for Evaluated {
    /// Prints `***` in place of a secret-derived value, for the same reason
    /// [`ExprContext`]'s own `Debug` impl prints only root names: this type
    /// is `pub` and a caller's `tracing::debug!`/`dbg!`/`expect` reaches it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("Evaluated");
        if self.secret_derived {
            s.field("value", &REDACTION_PLACEHOLDER);
        } else {
            s.field("value", &self.value);
        }
        s.field("secret_derived", &self.secret_derived).finish()
    }
}

/// Both renderings of one interpolation, produced by a **single** evaluation
/// pass (ruling P33).
///
/// - the **unredacted** rendering is the real result, and is what must reach
///   the dispatched task — a workflow that legitimately passes
///   `${{ secrets.GH_TOKEN }}` to a step's `env:` has to receive the token,
///   not `***`;
/// - the **redacted** rendering is the only thing that may be logged: every
///   substitution whose value was computed from a secret-marked root is
///   replaced, in its entirety, by [`REDACTION_PLACEHOLDER`]. Surrounding
///   literal template text is untouched — there is no find-and-replace over
///   the output anywhere in this module.
///
/// The two fields are private and reachable only through accessors named for
/// what they are *for*, so that a `sink.emit(..., x.unredacted_for_dispatch())`
/// reads as obviously wrong at the call site rather than as a plausible field
/// access. `Debug` prints only the redacted rendering.
#[derive(Clone)]
pub struct Interpolated<T> {
    unredacted: T,
    redacted: T,
    secret_derived: bool,
}

impl<T> Interpolated<T> {
    /// The real, unredacted result — for handing to the dispatched task,
    /// never for logging or persisting.
    pub fn unredacted_for_dispatch(&self) -> &T {
        &self.unredacted
    }

    /// The real, unredacted result, by value — see
    /// [`Self::unredacted_for_dispatch`].
    pub fn into_unredacted_for_dispatch(self) -> T {
        self.unredacted
    }

    /// The rendering safe to log or persist: every secret-derived
    /// substitution replaced whole by [`REDACTION_PLACEHOLDER`].
    pub fn redacted_for_logging(&self) -> &T {
        &self.redacted
    }

    /// The redacted rendering, by value — see [`Self::redacted_for_logging`].
    pub fn into_redacted_for_logging(self) -> T {
        self.redacted
    }

    /// Whether any substitution in this interpolation read a secret-marked
    /// root, i.e. whether the two renderings actually differ.
    pub fn is_secret_derived(&self) -> bool {
        self.secret_derived
    }
}

impl<T: fmt::Debug> fmt::Debug for Interpolated<T> {
    /// Prints the redacted rendering only — the unredacted one is exactly
    /// what this type exists to keep out of logs.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interpolated")
            .field("redacted", &self.redacted)
            .field("secret_derived", &self.secret_derived)
            .finish_non_exhaustive()
    }
}

/// A value **this module's evaluator produced**, which therefore already knows
/// whether producing it read secret-marked material.
///
/// This is what [`ExprContext::set_from`] reads provenance off (ruling P37).
/// It is implemented for [`Evaluated`] and for
/// [`Interpolated<Value>`](Interpolated) — the two of this module's three
/// return shapes that already hold a `Value` a caller could bind — and it is
/// **sealed**.
///
/// # What the seal enforces
///
/// Exactly one thing: no type outside this crate can implement it. An external
/// crate that tries gets `E0277: the trait bound 'Liar: expr::sealed::Sealed'
/// is not satisfied`. So the set of carriers is closed to the two types above,
/// and adding a producer means implementing this here, beside the evaluator
/// that computes the flag.
///
/// # What it does not enforce (ruling P44)
///
/// The seal closes the set of carrier *types*; by itself it would not
/// authenticate the provenance *inside* one. Before Task 14, [`Evaluated`]
/// had public fields and no `#[non_exhaustive]`, so a caller in any crate
/// could construct one with any `secret_derived` it chose and pass it to
/// [`ExprContext::set_from`] — re-assertion by the back door, through a type
/// the seal permitted. `#[non_exhaustive]` alone did **not** close that for
/// an external caller, contrary to what an earlier version of this section
/// claimed: with fields still `pub`, `real.clone()` then a direct field
/// assignment bypasses `#[non_exhaustive]` entirely (it only blocks
/// struct-*expression* syntax). What actually closes it is that
/// `value`/`secret_derived` are now **private** — `eval`/
/// `eval_delimited_expression`/[`Evaluated::derive`] are the only places that
/// can name a `secret_derived` value. This narrows, but does not seal:
/// `clean.derive(secret_value)` and [`ExprContext::set_public`] remain open
/// routes that no type-level mechanism here can close (see [`Evaluated`]'s
/// own doc comment for the full accounting).
///
/// [`Interpolated<String>`](Interpolated) is left out on purpose rather than by
/// oversight: [`Self::provenance_value`] returns a *borrow*, and a
/// `String` rendering has no `&Value` to lend. A caller holding one should
/// wrap it (`Value::String`) and choose the binding method deliberately, which
/// is a visible decision rather than a silent conversion.
pub trait ProvenanceCarrier: sealed::Sealed {
    /// The **real, unredacted** value to bind — never the redacted rendering.
    /// A bound root feeds real dispatch as well as the log (a dependent step
    /// reading `${{ steps.a.output.token }}` must get the token), and the
    /// redacted half is re-derived at render time from the provenance this
    /// same trait carries, so binding `***` would corrupt every downstream
    /// value while buying nothing.
    fn provenance_value(&self) -> &Value;

    /// Whether producing this value read a root bound as secret material.
    fn provenance_is_secret_derived(&self) -> bool;
}

mod sealed {
    /// Private supertrait of [`super::ProvenanceCarrier`]. Being in a private
    /// module is what seals it against other crates while still letting this
    /// one add a producer.
    pub trait Sealed {}
    impl Sealed for super::Evaluated {}
    impl Sealed for super::Interpolated<serde_json::Value> {}
}

impl ProvenanceCarrier for Evaluated {
    fn provenance_value(&self) -> &Value {
        &self.value
    }

    fn provenance_is_secret_derived(&self) -> bool {
        self.secret_derived
    }
}

impl ProvenanceCarrier for Interpolated<Value> {
    fn provenance_value(&self) -> &Value {
        &self.unredacted
    }

    fn provenance_is_secret_derived(&self) -> bool {
        self.secret_derived
    }
}

/// The recursive-descent implementation behind [`eval`]. Private and
/// untyped-by-`ExpressionSource` on purpose, mirroring
/// [`interpolate_json_inner`]: the trust assertion belongs once, at the
/// public entry point, not re-asserted at [`interpolate`]'s own internal
/// call for each `${{ }}` block it finds — that inner text is already known
/// trusted by construction, because it was sliced out of a template that
/// itself only reached [`interpolate`] through a [`TemplateSource`].
fn eval_inner(expr: &str, ctx: &ExprContext) -> Result<(Value, bool), ExprError> {
    let mut p = Parser {
        s: expr.as_bytes(),
        pos: 0,
        depth: 0,
        ctx,
    };
    p.skip_ws();
    let (v, secret_derived) = p.parse_ternary()?;
    p.skip_ws();
    if p.pos != p.s.len() {
        return Err(ExprError::UnexpectedToken(p.pos, expr[p.pos..].to_string()));
    }
    // The one unavoidable clone: `eval`'s own signature returns an owned
    // `Value`, and `ctx` must outlive this call, so the top-level result has
    // to be materialized here regardless of how much of the evaluation
    // above stayed borrowed. See the module doc comment's "Cost" section
    // for what staying borrowed through here actually saves.
    Ok((v.into_owned(), secret_derived))
}

/// Evaluates a whole workflow-file field that §8.9 documents as always
/// being a single `${{ ... }}` block — the form used for `when:`
/// (`when: "${{ len(steps.review.output.findings) > 0 }}"`,
/// `when: "${{ steps.gate.output.approve }}"`, both taken verbatim from
/// `docs/architecture/05-scheduling-and-workflows.md` §8.9's own reference
/// workflow) and, by the identical grammar, `map.over`. Returns the
/// expression's own typed [`Value`] — a `when:` field evaluates to
/// `Value::Bool`, not the *string* `"true"`/`"false"` that stringifying
/// through [`interpolate`] would produce — which matters because a caller
/// gating on the result (`matches!(v, Value::Bool(true))`) must not have to
/// re-parse a string back into a bool.
///
/// **Fix round 1, item 4.** An earlier caller passed a `when:` field's raw
/// text — still wrapped in its documented `${{ }}` delimiters — straight to
/// [`eval`], which takes an undelimited [`ExpressionSource`] and has no
/// delimiter-stripping of its own (that is `eval`'s whole contract: a bare
/// expression, no surrounding text). The result was that every `when:`
/// written in the documented form failed immediately with
/// `unexpected token at position 0: '${{ ... }}'` — the parser choked on
/// the leading `$`, which is not valid expression syntax, before it ever
/// reached the expression inside. Only an undocumented bare form
/// (`when: "1 == 1"`, no delimiters at all) happened to work. This function
/// is the fix: it requires and strips exactly one well-formed `${{ ... }}`
/// wrapper — reusing [`find_closing_delimiter`]'s quote-aware scan, the same
/// one [`interpolate`] uses, so a `}}` appearing inside a string argument
/// (e.g. `${{ contains(x, '}}') }}`) does not truncate the block early —
/// and evaluates the interior. A field that isn't wrapped at all, or that
/// has non-whitespace text following the block's closing `}}`, is
/// [`ExprError::NotADelimitedExpression`], which names the actual problem
/// (missing/misplaced delimiters) rather than the misleading
/// "unexpected token" a bare pass-through to [`eval`] would report.
///
/// Only the delimited form is supported — no bare-expression fallback —
/// because every `when:`/`map.over` example in the frozen §8.9 reference
/// workflow uses the delimited form and none uses a bare one; ruling P28
/// requires implementing exactly what the frozen spec shows, not inventing
/// a second accepted form it does not document.
///
/// Takes a [`TemplateSource`], not a bare `&str` — the trust assertion is
/// identical to [`interpolate`]'s (ruling P20): the caller must construct
/// this from the workflow file's own YAML source for the field, never from
/// a `map.over` item, webhook payload, or previously evaluated result.
pub fn eval_delimited_expression(
    field: TemplateSource<'_>,
    ctx: &ExprContext,
) -> Result<Evaluated, ExprError> {
    let text = field.0.trim();
    let after_open = text
        .strip_prefix("${{")
        .ok_or_else(|| ExprError::NotADelimitedExpression(truncate_echoed_field(text)))?;
    let end = find_closing_delimiter(after_open).ok_or(ExprError::Unterminated)?;
    let inner = &after_open[..end];
    let trailing = after_open[end + 2..].trim();
    if !trailing.is_empty() {
        return Err(ExprError::NotADelimitedExpression(truncate_echoed_field(
            text,
        )));
    }
    let (value, secret_derived) = eval_inner(inner.trim(), ctx)?;
    Ok(Evaluated {
        value,
        secret_derived,
    })
}

/// Bounds how much of the offending field's own text
/// [`ExprError::NotADelimitedExpression`] echoes (fix round 2, item 2).
/// Pre-fix, the whole field — bounded only by `parse::MAX_YAML_BYTES`, not
/// by anything this module controls — was echoed verbatim into a `when:`
/// evaluation failure, which `exec::steps_context_entry` writes into
/// `steps.<id>.error`: an append-only field a dependent step can read and
/// re-emit. Security measured this pre-fix: a 184,334-byte workflow (under
/// `MAX_YAML_BYTES`) produced a 200,202-byte `steps.a.error`, and with 60
/// dependent steps each reading and re-emitting it, 21,636,840 bytes reached
/// the sink — 117.4x amplification in 410ms, into a table that physically
/// rejects `UPDATE`/`DELETE`. A fixed prefix plus the original length names
/// the actual problem (the field is missing its documented `${{ }}`
/// delimiters) without reproducing the amplification.
const MAX_ECHOED_FIELD_LEN: usize = 64;

/// Truncates `text` to at most [`MAX_ECHOED_FIELD_LEN`] bytes (at a valid
/// UTF-8 boundary — `text` is workflow-author YAML, not guaranteed ASCII),
/// appending the original byte length so the truncation itself is visible
/// rather than silently shortening the message.
fn truncate_echoed_field(text: &str) -> String {
    if text.len() <= MAX_ECHOED_FIELD_LEN {
        return text.to_string();
    }
    let mut end = MAX_ECHOED_FIELD_LEN;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes total)", &text[..end], text.len())
}

/// Asserts that the wrapped text is safe to evaluate as `${{ }}` template
/// text — see ruling P20 (fix round 2, item 2): **untrusted data must never
/// become template text**, whether by being concatenated into a string
/// handed to [`interpolate`] or by being the `Value` handed to
/// [`interpolate_json`]. The consequence of getting this wrong is not the
/// silent cross-block merge (that was P19's original, weaker justification,
/// since corrected) — it is `${{ env('ANTHROPIC_API_KEY') }}` or
/// `${{ secrets.* }}` appearing in attacker-influenced content and
/// evaluating for real, emitting the daemon's provider key or the
/// workflow's own secrets in cleartext. Untrusted data must reach this
/// module only as a value bound into [`ExprContext`], never as template
/// text.
///
/// Constructible only through [`TemplateSource::from_workflow_file`], so
/// that assertion is one explicit, greppable call site at the point a
/// template's trust is established, rather than an invisible type
/// coincidence between `&str` (template text) and `&str` (an ordinary,
/// possibly-untrusted string value). `roundhouse-flow` has no other callers
/// of `interpolate` today (this crate's own `parse`/`job` modules do not
/// call it) — whoever wires a step's `run:`/`with:`/`env:`/`if:` field up
/// for real is the one who must construct this from that field's own YAML
/// source text, not from any evaluated result or runtime data value.
pub struct TemplateSource<'a>(&'a str);

impl<'a> TemplateSource<'a> {
    /// Asserts that `template` is the workflow file's own YAML source for a
    /// step field (`run:`, `with:`, `env:`, `if:`, …) as authored — not an
    /// evaluated expression result, a `map.over` item, webhook payload, or
    /// any other value this evaluator's caller does not control. See
    /// [`TemplateSource`]'s own doc comment for what is at stake if that
    /// assertion is wrong.
    pub fn from_workflow_file(template: &'a str) -> Self {
        Self(template)
    }
}

/// Replaces every `${{ ... }}` block in `template` with its evaluated,
/// string-coerced result, leaving surrounding text untouched. Single-pass:
/// substituted text is never re-scanned for further `${{` — see the module
/// doc comment's "Substitution is single-pass" section. An unpaired `${{`
/// (no matching `}}` anywhere in the rest of the template) is
/// [`ExprError::Unterminated`] — see the module doc comment's "An unpaired
/// `${{` is an error" section.
///
/// Takes a [`TemplateSource`], not a bare `&str` — see its doc comment for
/// why (ruling P20).
///
/// Returns **both** renderings from one pass (ruling P33): see
/// [`Interpolated`]. Only the text spliced in for a secret-derived
/// substitution differs between them — the template's own literal text is
/// byte-identical in both, because this function never searches the output
/// for anything to replace.
pub fn interpolate(
    template: TemplateSource<'_>,
    ctx: &ExprContext,
) -> Result<Interpolated<String>, ExprError> {
    interpolate_inner(template.0, ctx)
}

/// The implementation behind [`interpolate`], also called by
/// [`interpolate_json_inner`] for each string leaf — private and
/// untyped-by-`TemplateSource` for the same reason [`eval_inner`] is (the
/// trust assertion belongs once, at the public entry point).
fn interpolate_inner(template: &str, ctx: &ExprContext) -> Result<Interpolated<String>, ExprError> {
    let mut unredacted = String::new();
    let mut redacted = String::new();
    let mut secret_derived = false;
    let mut rest = template;
    while let Some(start) = rest.find("${{") {
        // Literal template text: identical in both renderings, always.
        unredacted.push_str(&rest[..start]);
        redacted.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = find_closing_delimiter(after).ok_or(ExprError::Unterminated)?;
        let inner = &after[..end];
        // One evaluation, two renderings — never evaluate twice, which would
        // both double the cost and risk the logged copy diverging from the
        // dispatched one.
        let (value, block_is_secret) = eval_inner(inner.trim(), ctx)?;
        let text = value_to_string(&value);
        unredacted.push_str(&text);
        if block_is_secret {
            secret_derived = true;
            redacted.push_str(REDACTION_PLACEHOLDER);
        } else {
            redacted.push_str(&text);
        }
        // Resume scanning strictly after the consumed `}}`, in the
        // *original* template — never re-scan `value`'s own text. This is
        // what makes substitution single-pass.
        rest = &after[end + 2..];
    }
    unredacted.push_str(rest);
    redacted.push_str(rest);
    Ok(Interpolated {
        unredacted,
        redacted,
        secret_derived,
    })
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
/// currently open), plus a small bounded lookahead at each *candidate*
/// closing quote (see [`looks_like_a_real_string_close`]) — it does not
/// parse or validate the expression itself, only decides where the block
/// ends.
///
/// # A correctness defect this scan used to have, and what fixing it does
/// and does not cover
///
/// An earlier version of this function closed a string at the *first*
/// occurrence of the matching quote character, unconditionally. Given this
/// grammar's no-escapes rule, that is not wrong on its own — a string that
/// never closes really does extend to the next matching quote character,
/// wherever it is — but it means an author who simply forgets a closing
/// quote inside one `${{ }}` block can have that open quote "borrow" a
/// closing character from ordinary prose *after* the block's own intended
/// end (an apostrophe in a contraction is enough), which can then swallow
/// a second, well-formed `${{ }}` block whole, since nothing about `${{`
/// or `}}` is special once scanning is inside quotes. Reproduced directly
/// against the pre-fix code:
/// `${{ 'oops }} plain text with it's own apostrophe ${{ inputs.repo }}`
/// resolved to `unexpected token at position 28: 's own apostrophe ${{
/// inputs.repo'` — the second, well-formed placeholder never evaluated,
/// and the error pointed at prose text nowhere near the missing quote.
///
/// **The fix**: before accepting a candidate closing quote, check whether
/// what immediately follows it (skipping whitespace) looks like a
/// plausible continuation of an expression — end of input, `.`/`[` (a
/// further chain step), `)`/`]`/`,` (closing a call/array or separating
/// arguments), `?`/`:` (ternary), the first byte of a comparison operator,
/// or `}` (the block's own `}}` terminator). If not, treat this quote
/// character as ordinary data and keep scanning for a *later* one. Against
/// the repro above, the apostrophe in "it's" is followed by `s own
/// apostrophe...`, which matches none of those, so it is rejected; no
/// later quote character exists in the rest of the input, so the scan now
/// correctly reports [`ExprError::Unterminated`] instead of an
/// unexpected-token error attributed to unrelated prose. Pinned by
/// `an_apostrophe_in_prose_between_two_blocks_does_not_merge_them`.
///
/// **What this does not do: resolve the underlying ambiguity in general.**
/// This grammar has no escape mechanism, so a quote character appearing in
/// ordinary prose can always be *made* to look like a plausible
/// continuation by whoever writes the template — the lookahead only
/// rejects continuations that are locally implausible, it cannot tell
/// intentional data from accidental prose when both happen to look
/// syntactically valid afterward. Confirmed by deliberately constructing
/// such a case (see `an_open_quote_can_still_silently_absorb_a_later_block_when_the_forgery_looks_syntactically_valid`
/// in `tests/expr.rs`): a first, broken block whose forgotten quote closes
/// on a *later* quote character chosen so what follows is exactly `' }}`
/// still parses cleanly as a single string literal, silently swallowing an
/// entire second `${{ ... }}` block's literal text (including a
/// third party's `${{ real }}` reference, never evaluated) into that
/// string's value, with no error at all. This residual is real, is not
/// closed by this fix, and is left open rather than claimed fixed — see
/// that test's own comment for the exact shape and why the grammar's lack
/// of escaping makes it structurally unclosable without either adding
/// escapes (a language change §8.9 does not ask for) or changing
/// `interpolate` to attempt more than one candidate split per block
/// (a bigger change than this fix round's scope).
///
/// **How general this hole is, measured, not assumed (fix round 2):** every
/// one of the twelve continuation bytes [`looks_like_a_real_string_close`]
/// accepts — `.` `[` `)` `]` `,` `?` `:` `==` `!=` `<` `>` and `}}` — hosts a
/// forged clean merge of this shape; only end-of-input cannot (no `}}`
/// follows it to forge). An earlier report on this fix accurately described
/// what was then known — that the other eleven continuations were
/// unexplored — while this doc comment's claim that the hole is general was
/// already correct; the two were not in conflict, just at different points
/// of what had actually been established at the time each was written.
/// Realism is a separate axis from generality, and does differ across the
/// twelve: four prose-shaped forgeries constructed directly against this
/// scan all failed closed, and the accidental risk in practice is dominated
/// by the `' }}` shape above — the other eleven continuations need
/// deliberate construction by whoever writes the template, not an accidental
/// typo, to actually trigger.
///
/// **A second, narrower disagreement, left unaligned rather than closed
/// (fix round 2):** this function's lookahead and [`Parser::parse_string_literal`]'s
/// own quote-closing rule can disagree with each other. This function
/// consults [`looks_like_a_real_string_close`] before accepting a candidate
/// closing quote; the parser itself still closes a string literal at the
/// *first* matching quote character, unconditionally, with no lookahead at
/// all. So when this splitter *rejects* a quote character that the parser
/// would happily accept as a close, the block this function reports as
/// unterminated (or as extending further than the author intended) can
/// still differ from where the parser itself would have closed the string,
/// had it been asked to parse that same text. Both sides fail closed — no
/// clean, successfully-parsed differential between the two was
/// constructible — and the only observed effect is that error text can now
/// carry strictly more of the original template than it used to, and the
/// cross-block merge above remains reachable via a malformed first block as
/// well as an unterminated one. Left as a documented disagreement rather
/// than aligned: doing so would mean either adding the same lookahead to
/// `parse_string_literal` (touching the one function every string literal in
/// every expression goes through, for a difference that has no observed
/// behavioural consequence today) or removing it from this function (giving
/// back the exact cross-block merge the lookahead was added to fix). Neither
/// is this fix round's call to make unilaterally (fix round 3, m-3: named
/// here rather than left ownerless). **Owner: whoever next touches
/// [`Parser::parse_string_literal`] or [`find_closing_delimiter`]** — align
/// the two functions' quote-closing rules, or explicitly re-affirm the
/// disagreement, as part of that change rather than as a separate pass.
fn find_closing_delimiter(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut open_quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match open_quote {
            Some(q) => {
                if b == q && looks_like_a_real_string_close(bytes, i + 1) {
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

/// Returns whether the byte immediately following a candidate
/// string-closing quote at `bytes[i..]` (after skipping ASCII whitespace)
/// is one this grammar could legitimately produce right after a string
/// literal — see [`find_closing_delimiter`]'s doc comment for why this
/// exists and what it does not fully solve. End of input counts as a valid
/// continuation (a string can legitimately be the last thing before the
/// block's own, already-consumed, `}}`).
///
/// **`}` requires its pair (fix round 2, code lens Minor).** The block's own
/// terminator is always `}}`, never a lone `}` — this grammar has no other
/// construct that starts with a single `}`. An earlier version of this
/// function accepted a bare `}` as a plausible continuation on its own,
/// which is looser than the grammar it is modeling (false-positive
/// direction only; no misbehaviour was ever found from it, since a lone `}`
/// not followed by a second one still fails to parse moments later). Now
/// requires the second byte, matching [`find_closing_delimiter`]'s own
/// `b'}' && bytes.get(i + 1) == Some(&b'}')` check exactly.
///
/// **This does change one observable thing (fix round 3, m-4): the
/// `ExprError` variant a `}`-continuation input produces.** Driven
/// end-to-end through [`interpolate`], a candidate closing quote followed
/// by a lone `}` (or `}x`, or `} `) used to be accepted as a plausible
/// continuation, so the scan would keep going, find no real `}}`, and the
/// overall result was [`ExprError::UnexpectedToken`] raised later by the
/// parser on the leftover text; it is now rejected here, so the scan
/// reports [`ExprError::Unterminated`] instead. All other 15 measured
/// continuation shapes are unaffected. Strictly information-reducing (no
/// secret text is in either variant either way), but it is a public-API
/// behaviour change for any caller matching on `ExprError`, pinned by
/// `tests/expr.rs::a_lone_closing_brace_is_unterminated_not_unexpected_token`.
fn looks_like_a_real_string_close(bytes: &[u8], mut i: usize) -> bool {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    match bytes.get(i) {
        None => true,
        Some(b'}') => bytes.get(i + 1) == Some(&b'}'),
        Some(b) => matches!(
            b,
            b'.' | b'[' | b')' | b']' | b',' | b'?' | b':' | b'=' | b'!' | b'<' | b'>'
        ),
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// The `Value`-shaped counterpart of [`TemplateSource`] — see its doc
/// comment for the constraint this asserts and why (ruling P20). This is
/// the more dangerous of the two shapes: [`interpolate_json`]'s own prior
/// doc comment described it as walking "an arbitrary JSON value" with no
/// trust caveat at all, which is exactly the invitation P20 was written
/// against — handing it an untrusted `Value` (a `map.over` item, a webhook
/// payload after `serde_json` deserialization, …) requires no string
/// concatenation whatsoever to reach the same outcome as pasting untrusted
/// text into a template: every string leaf of that value is evaluated as
/// `${{ }}` template text, so `{"note": "${{ env('ANTHROPIC_API_KEY') }}"}`
/// anywhere in the tree evaluates for real.
pub struct JsonTemplateSource<'a>(&'a Value);

impl<'a> JsonTemplateSource<'a> {
    /// Asserts that every string leaf of `value` is workflow-file-controlled
    /// template text — a `with:`/`env:` block as authored, after
    /// `serde_yaml` deserialization, not any value this evaluator's caller
    /// does not control. The assertion covers the **whole tree**, not just
    /// the top level: [`interpolate_json`] walks every string leaf, so a
    /// caller must not construct this from a value that merely has an
    /// untrusted subtree grafted into an otherwise-trusted document. See
    /// [`JsonTemplateSource`]'s own doc comment for what is at stake if that
    /// assertion is wrong.
    pub fn from_workflow_file(value: &'a Value) -> Self {
        Self(value)
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
///
/// Takes a [`JsonTemplateSource`], not a bare `&Value` — see its doc comment
/// for why (ruling P20).
///
/// Returns **both** renderings from one pass (ruling P33): see
/// [`Interpolated`]. Redaction is **per substitution**, identical to
/// [`interpolate`]'s own granularity: within a string leaf, only the text
/// spliced in for a secret-derived `${{ }}` block becomes
/// [`REDACTION_PLACEHOLDER`], and the leaf's surrounding literal template text
/// is byte-identical in both renderings. Object keys and non-string leaves are
/// likewise identical in both.
///
/// **This replaced whole-leaf redaction (fix round 4, item E).** Fix round 3
/// replaced an entire tainted leaf with `***`, which is strictly less
/// informative for no security gain, because the substitution itself is
/// whole-replaced either way. Measured: `with: { cmd: ["curl",
/// "https://api.example.com/v1?token=${{ secrets.T }}&x=1"] }` logged as
/// `{"cmd":["curl","***"]}` — losing the whole URL, including which host was
/// contacted, which is real operational and forensic loss — while the
/// `interpolate` path already logged the equivalent prose case correctly as
/// `"deploy using *** now"`. The two entry points now agree.
///
/// **The binding invariant is unchanged**: the substitution is replaced
/// *whole*. This is never a substring find-and-replace over the rendered
/// output — that mechanism is what ruling P33 abolished, and reintroducing it
/// here would reintroduce the corruption of unrelated text it was abolished
/// for.
pub fn interpolate_json(
    value: JsonTemplateSource<'_>,
    ctx: &ExprContext,
) -> Result<Interpolated<Value>, ExprError> {
    let (unredacted, redacted, secret_derived) = interpolate_json_inner(value.0, ctx)?;
    Ok(Interpolated {
        unredacted,
        redacted,
        secret_derived,
    })
}

/// The recursive implementation behind [`interpolate_json`]. Private and
/// untyped-by-`JsonTemplateSource` on purpose: the trust assertion belongs
/// once, at the public entry point, not re-asserted (or re-checked) at every
/// recursive step over a value this function itself already knows is
/// trusted by construction.
///
/// Returns `(unredacted, redacted, any_leaf_was_secret_derived)`.
#[allow(clippy::type_complexity)]
fn interpolate_json_inner(
    value: &Value,
    ctx: &ExprContext,
) -> Result<(Value, Value, bool), ExprError> {
    match value {
        Value::String(s) => {
            // Per-substitution, exactly as [`interpolate`] itself renders
            // (fix round 4, item E) — the leaf's surrounding literal text
            // survives and only the spliced-in text of a secret-derived
            // `${{ }}` block becomes `***`. `interpolate_inner` has already
            // produced precisely that string; nothing further is done to it.
            let interpolated = interpolate_inner(s, ctx)?;
            Ok((
                Value::String(interpolated.unredacted),
                Value::String(interpolated.redacted),
                interpolated.secret_derived,
            ))
        }
        Value::Array(items) => {
            let mut unredacted = Vec::with_capacity(items.len());
            let mut redacted = Vec::with_capacity(items.len());
            let mut secret_derived = false;
            for item in items {
                let (u, r, s) = interpolate_json_inner(item, ctx)?;
                unredacted.push(u);
                redacted.push(r);
                secret_derived |= s;
            }
            Ok((
                Value::Array(unredacted),
                Value::Array(redacted),
                secret_derived,
            ))
        }
        Value::Object(map) => {
            let mut unredacted = serde_json::Map::with_capacity(map.len());
            let mut redacted = serde_json::Map::with_capacity(map.len());
            let mut secret_derived = false;
            for (k, v) in map {
                let (u, r, s) = interpolate_json_inner(v, ctx)?;
                unredacted.insert(k.clone(), u);
                redacted.insert(k.clone(), r);
                secret_derived |= s;
            }
            Ok((
                Value::Object(unredacted),
                Value::Object(redacted),
                secret_derived,
            ))
        }
        other => Ok((other.clone(), other.clone(), false)),
    }
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
    depth: usize,
    ctx: &'a ExprContext,
}

/// Where the value currently in hand came from, during a `.field`/`[idx]`
/// chain. Collapses to a plain `bool` (`is_secret_derived`) the moment the
/// chain ends — the three-state form exists only so that a root holding
/// secret material at *some* paths (the executor's `steps`) can be narrowed
/// before the taint decision is made.
#[derive(Clone)]
enum ValueProvenance<'a> {
    /// Nothing read so far touched secret material.
    Clean,
    /// Computed from secret material.
    Secret,
    /// The chain is at `root` plus the field path walked so far, which is
    /// still a strict prefix of at least one declared secret path. If the
    /// chain ends here the object in hand still *contains* that secret
    /// material, so this collapses to secret; a following `.field` resolves
    /// it one way or the other.
    AbovePath { root: &'a str, walked: Vec<String> },
}

impl ValueProvenance<'_> {
    /// Collapses to the flag every other part of the evaluator threads. An
    /// unresolved [`ValueProvenance::AbovePath`] collapses to **secret**: the
    /// value escaping is an object that still contains the secret material
    /// below it.
    fn is_secret_derived(&self) -> bool {
        !matches!(self, ValueProvenance::Clean)
    }
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
    fn parse_ternary(&mut self) -> Result<(Cow<'a, Value>, bool), ExprError> {
        self.depth += 1;
        if self.depth > MAX_EXPR_DEPTH {
            self.depth -= 1;
            return Err(ExprError::ExpressionTooDeep(MAX_EXPR_DEPTH));
        }
        let result = self.parse_ternary_inner();
        self.depth -= 1;
        result
    }

    /// Taint rule for the ternary: the result is secret-derived if the
    /// *condition* was (it chose which value escapes, so the result leaks a
    /// bit about the secret) **or** if the branch actually selected was. The
    /// untaken branch's taint is deliberately not propagated: its value does
    /// not appear in the result at all, so it cannot leak through it. Note
    /// both branches are still *evaluated* — see the module doc comment's
    /// "A ternary evaluates both branches" section, which is a separate,
    /// documented property this rule does not change.
    fn parse_ternary_inner(&mut self) -> Result<(Cow<'a, Value>, bool), ExprError> {
        let (cond, cond_secret) = self.parse_comparison()?;
        self.skip_ws();
        if self.peek() == Some(b'?') {
            self.pos += 1;
            self.skip_ws();
            let (then_v, then_secret) = self.parse_ternary()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(ExprError::UnexpectedToken(self.pos, "expected ':'".into()));
            }
            self.pos += 1;
            self.skip_ws();
            let (else_v, else_secret) = self.parse_ternary()?;
            return Ok(if truthy(cond.as_ref()) {
                (then_v, cond_secret || then_secret)
            } else {
                (else_v, cond_secret || else_secret)
            });
        }
        Ok((cond, cond_secret))
    }

    /// Taint rule for a comparison: the resulting `Bool` is secret-derived if
    /// either side was. The boolean carries a bit of the secret's content
    /// (`${{ secrets.T == 'guess' }}` is an oracle), so it is redacted.
    fn parse_comparison(&mut self) -> Result<(Cow<'a, Value>, bool), ExprError> {
        let (lhs, lhs_secret) = self.parse_primary_chain()?;
        self.skip_ws();
        for (tok, op) in COMPARISON_OPS {
            if self.starts_with(tok) {
                self.pos += tok.len();
                self.skip_ws();
                let (rhs, rhs_secret) = self.parse_primary_chain()?;
                return Ok((
                    Cow::Owned(Value::Bool(op(lhs.as_ref(), rhs.as_ref()))),
                    lhs_secret || rhs_secret,
                ));
            }
        }
        Ok((lhs, lhs_secret))
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
    ///
    /// **Taint rules for the chain** (ruling P33). `.field` narrows: on a
    /// [`ValueProvenance::AbovePath`] it extends the walked path and
    /// re-classifies it against the root's declared secret paths; on an
    /// already-secret value it stays secret. `[idx]` cannot be narrowed —
    /// this evaluator does not know statically which entry an arbitrary index
    /// expression selects — so anywhere above a secret path it escalates to
    /// secret, and it additionally inherits the taint of the *index
    /// expression itself*, because a secret used as a subscript selects which
    /// element escapes and therefore leaks through the chosen value.
    fn parse_primary_chain(&mut self) -> Result<(Cow<'a, Value>, bool), ExprError> {
        self.skip_ws();
        let (mut v, mut prov) = self.parse_primary()?;
        loop {
            if self.peek() == Some(b'.') {
                self.pos += 1;
                let ident = self.parse_ident();
                v = index_field(v, &ident);
                prov = self.narrow(prov, ident);
            } else if self.peek() == Some(b'[') {
                self.pos += 1;
                self.skip_ws();
                let idx_start = self.pos;
                let (idx_val, idx_secret) = self.parse_ternary()?;
                let idx_end = self.pos;
                self.skip_ws();
                if self.peek() != Some(b']') {
                    return Err(ExprError::UnexpectedToken(self.pos, "expected ']'".into()));
                }
                self.pos += 1;
                // Fix round 4, item F: a subscript that is not a non-negative
                // whole number is a typed error, not a silent `Null`.
                let index = match as_index(idx_val.as_ref()) {
                    Some(i) => i,
                    None => {
                        let source = String::from_utf8_lossy(&self.s[idx_start..idx_end]);
                        return Err(ExprError::NonNumericIndex {
                            position: idx_start,
                            index_expression: truncate_echoed_field(source.trim()),
                        });
                    }
                };
                v = index_array(v, index);
                prov = if idx_secret || prov.is_secret_derived() {
                    ValueProvenance::Secret
                } else {
                    ValueProvenance::Clean
                };
            } else {
                break;
            }
        }
        let secret_derived = prov.is_secret_derived();
        Ok((v, secret_derived))
    }

    /// Applies one `.field` step to a chain's provenance — see
    /// [`Self::parse_primary_chain`]'s doc comment.
    fn narrow(&self, prov: ValueProvenance<'a>, field: String) -> ValueProvenance<'a> {
        match prov {
            ValueProvenance::Clean => ValueProvenance::Clean,
            ValueProvenance::Secret => ValueProvenance::Secret,
            ValueProvenance::AbovePath { root, mut walked } => {
                walked.push(field);
                match self.ctx.classify_path(root, &walked) {
                    PathVerdict::Secret => ValueProvenance::Secret,
                    PathVerdict::Clean => ValueProvenance::Clean,
                    PathVerdict::Undetermined => ValueProvenance::AbovePath { root, walked },
                }
            }
        }
    }

    /// **Taint rules for a primary** (ruling P33): a string or number literal
    /// is source text the workflow author typed, so it is clean; an array
    /// literal is secret-derived if any element is; a function call is
    /// secret-derived if **any** argument is, whether or not that particular
    /// function reads it (`default(secrets.T, 'x')` is redacted even when it
    /// returns `'x'`, and `len(secrets.T)` is redacted because the length is
    /// a property of the secret). A bare identifier takes its provenance from
    /// how [`ExprContext`] bound that root; an unbound identifier resolves to
    /// `Null` and is clean.
    fn parse_primary(&mut self) -> Result<(Cow<'a, Value>, ValueProvenance<'a>), ExprError> {
        self.skip_ws();
        match self.peek() {
            Some(b'\'') | Some(b'"') => Ok((
                Cow::Owned(self.parse_string_literal()?),
                ValueProvenance::Clean,
            )),
            Some(c) if c.is_ascii_digit() => {
                Ok((Cow::Owned(self.parse_number()?), ValueProvenance::Clean))
            }
            Some(b'[') => {
                let (arr, secret) = self.parse_array_literal()?;
                Ok((Cow::Owned(arr), provenance_from_flag(secret)))
            }
            Some(c) if c.is_ascii_alphabetic() || c == b'_' => {
                let ident = self.parse_ident();
                self.skip_ws();
                if self.peek() == Some(b'(') {
                    self.pos += 1;
                    let (args, any_arg_secret) = self.parse_args()?;
                    Ok((
                        Cow::Owned(call_function(&ident, args)?),
                        provenance_from_flag(any_arg_secret),
                    ))
                } else {
                    // The load-bearing borrow: a bare root/identifier
                    // resolves directly against `ctx`'s own storage with no
                    // clone at all — see `parse_primary_chain`'s doc
                    // comment for why threading this borrow through every
                    // subsequent `.field`/`[idx]` step, instead of cloning
                    // at each one, is what makes a long property chain
                    // over context data linear rather than quadratic.
                    //
                    // `get_key_value` rather than `get` on the provenance
                    // map: the returned key borrows from `ctx` for `'a`,
                    // which is what lets `AbovePath` name the root without
                    // allocating.
                    let value = match self.ctx.vars.get(&ident) {
                        Some(v) => Cow::Borrowed(v),
                        None => Cow::Owned(Value::Null),
                    };
                    let prov = match self.ctx.secret_provenance.get_key_value(ident.as_str()) {
                        Some((_, RootProvenance::Whole)) => ValueProvenance::Secret,
                        Some((name, RootProvenance::Paths(_))) => ValueProvenance::AbovePath {
                            root: name.as_str(),
                            walked: Vec::new(),
                        },
                        None => ValueProvenance::Clean,
                    };
                    Ok((value, prov))
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

    /// Builds a new, owned array literal by cloning every element into the
    /// new `Value::Array` this constructs, unconditionally — regardless of
    /// whether the caller that receives this array literal ever reads past
    /// its length or type. **This clone is necessary work only when the
    /// array literal's own value escapes into the result** (the literal
    /// itself is the expression's value, or it is selected by `default`, or
    /// read by `slice`/`flatten`); when the only consumer is `len`,
    /// `contains`, a comparison, or an index, the clone is a discarded
    /// residual with the same shape as the argument-clone amplification
    /// fixed in [`Parser::parse_primary_chain`]'s doc comment — see the
    /// module doc comment's "Cost" section (fix round 2, item 1) for the
    /// measured coefficient, why it is left open rather than capped, and why
    /// closing it in general was judged not worth the risk of a third
    /// pervasive-Cow-threading change to this same module in one fix round.
    fn parse_array_literal(&mut self) -> Result<(Value, bool), ExprError> {
        self.pos += 1; // '['
        let (items, any_secret) = self.parse_args_until(b']')?;
        Ok((
            Value::Array(items.into_iter().map(Cow::into_owned).collect()),
            any_secret,
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
    fn parse_args(&mut self) -> Result<(Vec<Cow<'a, Value>>, bool), ExprError> {
        self.parse_args_until(b')')
    }

    /// Also reports whether **any** collected argument was secret-derived —
    /// the taint a function call or array literal inherits from its inputs.
    fn parse_args_until(&mut self, close: u8) -> Result<(Vec<Cow<'a, Value>>, bool), ExprError> {
        let mut args = Vec::new();
        let mut any_secret = false;
        self.skip_ws();
        if self.peek() == Some(close) {
            self.pos += 1;
            return Ok((args, any_secret));
        }
        loop {
            self.skip_ws();
            let (arg, arg_secret) = self.parse_ternary()?;
            args.push(arg);
            any_secret |= arg_secret;
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
        Ok((args, any_secret))
    }
}

/// Lifts a collapsed taint flag back into a [`ValueProvenance`] — used where
/// a construct (array literal, function call) has already reduced its inputs
/// to a single flag and there is no root left to narrow.
fn provenance_from_flag(secret: bool) -> ValueProvenance<'static> {
    if secret {
        ValueProvenance::Secret
    } else {
        ValueProvenance::Clean
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
///
/// **`preserve_order` is now ACCEPTED workspace-wide (ruling P29, supersedes
/// P21/P24).** This comment used to assume `serde_json::Map` stayed its
/// default `BTreeMap`-backed form and treated any crate turning on
/// `preserve_order` as a regression to catch. A human ruling, relayed via
/// the coordinator, has since accepted the feature workspace-wide instead:
/// the pinned ACP SDK (`agent-client-protocol` 2.0.0) enables it
/// unconditionally, and vendoring the SDK to avoid it was considered and
/// rejected. `tests/expr.rs::preserve_order_feature_is_off`, which asserted
/// the feature was *off*, is obsolete under that ruling and has been
/// replaced (see `tests/expr.rs`'s replacement test) — it would fail at
/// merge on a decision someone deliberately made, which is exactly the
/// "red build caused by an approved choice" the replacement exists to
/// avoid.
///
/// What this does NOT change is whether this function's fix regresses.
/// Checked against the pinned `serde_json` 1.0.151 source
/// (`~/.cargo/registry/src/index.crates.io-*/serde_json-1.0.151/src/map.rs:156-165`),
/// not assumed: under `preserve_order`, `Map::remove` routes to
/// **`swap_remove`**, not `shift_remove` — O(1) (swap with the last
/// element), not O(sibling count) — so this fix does not regress under
/// `preserve_order` either; the claim above is in fact *stronger* than the
/// O(sibling count) case this comment used to describe as the only one.
/// What DOES change under `preserve_order` is object key **iteration**
/// order (sorted -> insertion-ordered) — irrelevant to `index_field`, which
/// does keyed lookup (`get`/`remove`) rather than iteration, and see
/// `tests/expr.rs`'s replacement test for the property that actually
/// depends on order-independence.
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
///
/// **Its `None` is interpreted differently by its two callers (fix round 4,
/// item F).** For a `[..]` subscript, [`Parser::parse_primary_chain`] turns it
/// into [`ExprError::NonNumericIndex`] — a subscript that is not a number is a
/// malformed expression, and returning `Null` for it made
/// `steps['a'].output.x` silently dead rather than wrong-looking. For
/// `slice()`'s optional bounds, [`call_function`] keeps treating `None` as
/// "bound not supplied" and falls back to `0`/the array length, which is what
/// makes `slice(a)` and `slice(a, 1)` legal calls at all; that behaviour is
/// deliberately unchanged here, since tightening it would reject those two
/// forms rather than catch a mistake.
fn as_index(v: &Value) -> Option<usize> {
    let f = v.as_f64()?;
    if f.is_finite() && f >= 0.0 && f.fract() == 0.0 {
        Some(f as usize)
    } else {
        None
    }
}

/// Resolves `v[i]`, borrow-preserving like [`index_field`] — see its doc
/// comment for why, including why the `Cow::Owned` arm below uses
/// `Vec::swap_remove` (an O(1) move of the matched element, with the last
/// element moved into its place, no clone of the element or of any sibling)
/// rather than `a.get(i).cloned()`, which paid the same per-step
/// whole-remaining-subtree clone cost `index_field` used to.
///
/// Takes an already-validated `usize`, not a `Value` (fix round 4, item F):
/// deciding that a subscript is not a number is [`Parser::parse_primary_chain`]'s
/// job now, because that is where the source text and byte position needed for
/// [`ExprError::NonNumericIndex`] are still in hand. An index that *is* a
/// number but is out of range stays a `Null` here — that is an ordinary
/// missing lookup, the same as a `.field` that is not present, not a malformed
/// expression.
fn index_array(v: Cow<'_, Value>, i: usize) -> Cow<'_, Value> {
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
///
/// **`default` catches a `Null`, not an error.** It cannot rescue a failed
/// subscript — `default(inputs.arr[inputs.obj.nope], 'x')` fails the whole
/// expression rather than returning `'x'`, because the chain errors before
/// this function is ever called. See [`ExprError::NonNumericIndex`] for the
/// two payloads that changed and why the loss is deliberate.
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
