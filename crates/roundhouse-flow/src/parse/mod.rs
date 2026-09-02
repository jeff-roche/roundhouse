//! YAML parsing of the top-level workflow definition (§8.9). Untrusted
//! input: this module's job is to turn workflow-author-supplied YAML text
//! into a typed [`WorkflowDef`] that fails closed on anything it doesn't
//! recognise, and to bound the resources a hostile or malformed document
//! can make the parser spend.
//!
//! Step bodies (`Task 3`, `StepDef`) are out of scope here; `WorkflowDef`
//! carries `steps`/`catch`/`finally` as raw `serde_yaml::Value` for that
//! task to type. (`pub mod steps;` will be added here in Task 3, alongside
//! `parse::steps`, without disturbing this module's public surface.)
//!
//! # Denial-of-service posture
//!
//! - **Anchors/aliases ("billion laughs"):** `serde_yaml` 0.9's event
//!   loader stores an alias as a single `Event::Alias(id)` marker rather
//!   than eagerly expanding it (`serde_yaml::loader`), so parsing raw YAML
//!   into its internal event list is already linear in input size.
//!   Materializing a Rust value that follows an alias is bounded by a jump
//!   counter internal to `serde_yaml`'s deserializer
//!   (`jumpcount > document.events.len() * 100` triggers
//!   `RepetitionLimitExceeded`) — total alias-expansion work is capped at
//!   roughly 100x the document's event count, not exponential in nesting
//!   depth. This protection is on by default in `serde_yaml` 0.9.34; this
//!   module relies on it rather than reimplementing it, and it surfaces
//!   through [`ParseError::Yaml`] like any other parse failure. See
//!   `rejects_a_billion_laughs_style_alias_bomb` in
//!   `tests/parse_top_level.rs`, which exercises this directly.
//! - **Pathological nesting depth, materializing a Rust value:** bounded by
//!   `serde_yaml`'s own `remaining_depth: 128` recursion guard
//!   (`RecursionLimitExceeded`), on by default. **This guard applies only
//!   to the deserialize-events-into-a-Rust-value stage — not to
//!   tokenizing/scanning the raw text into events in the first place**,
//!   which happens first and unconditionally. Fix round 1 on Task 10
//!   (finding H2) found that an earlier version of this doc comment
//!   conflated the two stages, incorrectly implying nesting depth was
//!   fully bounded before that scan was added below.
//! - **Pathological nesting depth, scanning the raw text:** measured
//!   directly (not merely inferred from the library's guards above) to be
//!   quadratic-or-worse in a document consisting of deeply nested flow
//!   collections (e.g. a long run of unclosed `[`) — a ~50 KB payload of
//!   nothing but `[` cost single-digit seconds *before* `serde_yaml` ever
//!   reaches the point of returning `RecursionLimitExceeded`. This is a
//!   property of tokenizing the text, not of any one YAML library's
//!   internals.
//!
//!   **Fix round 3 on Task 10 (finding H2) settled what actually bounds
//!   this, after two earlier scan designs were each found — by execution,
//!   not reasoning — to have their own bypass:**
//!   - Round 1 shipped a quote-tracking scan claiming to skip quoted
//!     content safely. A quote character in perfectly ordinary YAML
//!     (`name: don't`) desynchronized it permanently, silently disabling
//!     the depth bound for the rest of the document.
//!   - Round 2 replaced it with a scan that dropped quote-tracking (on the
//!     reasoning that over-counting brackets is always safe) but detected
//!     a `|`/`>` block-scalar opener via a bare `rfind(':')` over the
//!     whole line, with no awareness of flow-collection context. Both
//!     review lenses independently found the same consequence from that:
//!     a *comment* line containing a colon (`# x: |`) or a colon inside an
//!     *unclosed flow collection on the same line* (`items: ["note: |`)
//!     could be misread as a real block-scalar opener, which then hid
//!     every subsequent more-indented line — including a bracket bomb —
//!     from the depth counter entirely. Measured (release, via the real
//!     `parse_workflow`): the comment-line variant cost 531ms at 20 KB,
//!     5.85s at 80 KB, and over 12.6 minutes of pinned CPU at the (then)
//!     1 MiB byte cap.
//!
//!   **Round 3's conclusion: a text scan that must model enough of YAML to
//!   protect a YAML parser is the wrong shape for a soundness guarantee,
//!   and a fourth heuristic patch would only be the same bet a fourth
//!   time.** [`nesting_depth_bound_violation`] is kept — its rule for
//!   *what a block-scalar body is* is independently sound (verified: real
//!   `|`, `|2`, `|-`, `>` bodies are linear in `serde_yaml`, and a 30,000-
//!   bracket genuine `prompt: |` parses in 177µs), so it still buys real
//!   over-rejection relief and rejects the cases it does understand very
//!   cheaply — but it is now explicitly **best-effort defence in depth,
//!   not a security boundary**. It does not claim, and must never again
//!   claim, that it can only over-count or that it closes an entire bug
//!   class. (Round 3 did add a further-hardened opener check — see
//!   [`is_block_scalar_indicator_line`] — closing both bypasses found so
//!   far, and raised [`MAX_FLOW_NESTING_DEPTH`] from 64 to 256 alongside
//!   it, since 65 *unbalanced* brackets spread across comments or quoted
//!   scalars in an ordinary workflow — e.g. a shell-matcher regex like
//!   `"[a-z"` — is a real way to hit the old bound for a reason that isn't
//!   present. But no claim of soundness rides on that hardening; it is
//!   just today's best-effort, not tomorrow's guarantee.)
//!
//!   **The real bound is [`MAX_YAML_BYTES`], now 32 KiB** (down from 1
//!   MiB), sized directly off the measured cost curve above (~quadratic;
//!   27ms at 5 KB, 5.85s at 80 KB) so that the worst case *at the cap* —
//!   regardless of payload shape, and regardless of whether the best-
//!   effort scan above catches it — is bounded to roughly a second and a
//!   half of one-shot CPU, independent of `serde_yaml` or any future scan
//!   bypass. See `worst_case_bracket_nesting_at_the_byte_cap_is_bounded`
//!   in `tests/parse_top_level.rs`, which measures this directly against
//!   raw `serde_yaml::from_str` (bypassing the scan on purpose, to
//!   evidence the cap as the actual backstop rather than the scan).
//! - **Overall document size / "huge number of steps":** none of the
//!   protections above bound the size of an honestly large document, so
//!   this module adds its own caps on top: [`MAX_YAML_BYTES`] on the raw
//!   input before it is even handed to `serde_yaml`, and
//!   [`MAX_TOP_LEVEL_STEPS`] / [`MAX_CATCH_HANDLERS`] /
//!   [`MAX_FINALLY_HANDLERS`] on the parsed result's step lists.

pub mod types;

pub use types::WorkflowDef;
use types::{UnattendedDef, UnattendedEscalate};

use thiserror::Error;

/// 32 KiB. **This is the real DoS bound for pathological nesting (fix
/// round 3 on Task 10, finding H2)** — not [`nesting_depth_bound_violation`]
/// below, which is best-effort only. Sized directly off the measured cost
/// curve for a deeply-nested-flow-collection payload handed straight to
/// `serde_yaml` (quadratic-or-worse: ~27ms at 5 KB, 5.85s at 80 KB — see
/// the module doc comment), so that the worst case *at this cap*,
/// regardless of payload shape and regardless of whether the best-effort
/// scan below catches it, is bounded to roughly 1.5s of one-shot CPU. 16x
/// the frozen §8.9 fixture (~2 KiB), which is short, hand-authored YAML by
/// design. See `worst_case_bracket_nesting_at_the_byte_cap_is_bounded` in
/// `tests/parse_top_level.rs` for the measurement at exactly this size.
pub const MAX_YAML_BYTES: usize = 32_768;
/// No real workflow needs hundreds of top-level steps — a `map` step
/// already provides fan-out — so this bounds a maliciously (or
/// accidentally) huge step list without constraining legitimate use.
pub const MAX_TOP_LEVEL_STEPS: usize = 500;
pub const MAX_CATCH_HANDLERS: usize = 50;
pub const MAX_FINALLY_HANDLERS: usize = 50;
/// Maximum nesting depth of `[`/`{` flow collections
/// [`nesting_depth_bound_violation`]'s best-effort scan will tolerate
/// before rejecting a document early — comfortably under `serde_yaml`'s
/// own 128-deep recursion guard, so a legitimate document (§8.9's fixture
/// nests at most a handful of levels) is never affected. Raised from 64 to
/// 256 in fix round 3 on Task 10: since the scan counts every `[`/`{`
/// outside a block-scalar body unconditionally (including ones inside
/// comments or quoted scalars, which are not real nesting at all), 65
/// *unbalanced* bracket characters spread across such content — e.g. a
/// shell-matcher allowlist regex like `"[a-z"` — was a realistic way for
/// an ordinary workflow to hit this bound for a reason that isn't present
/// in the actual document. This scan is best-effort, not a security
/// boundary — see the module doc comment and [`MAX_YAML_BYTES`], which is
/// the real bound.
pub const MAX_FLOW_NESTING_DEPTH: usize = 256;
/// Maximum leading-whitespace width (raw character count, not "levels") any
/// one line may open with. Not a precise measure of block-style YAML
/// nesting depth — that would require reimplementing YAML's own
/// indentation rules — but a cheap, conservative, parser-independent bound
/// on how far a single line can indent, generous enough that no real
/// workflow (or the depth `serde_yaml` itself already tolerates) comes
/// close to it.
pub const MAX_LEADING_INDENT_CHARS: usize = 512;

/// Why [`parse_workflow`] rejected a document. Every variant names what was
/// wrong; [`ParseError::Yaml`] additionally carries a line/column when the
/// underlying `serde_yaml` error has one (see [`ParseError::location`]) —
/// `serde_yaml::Error`'s own `Display` already includes it, since this
/// module's `#[error(...)]` message wraps `{0}` verbatim.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error(
        "workflow YAML is {actual} bytes, exceeding the {max}-byte limit enforced on untrusted workflow input"
    )]
    TooLarge { actual: usize, max: usize },

    #[error("workflow declares {actual} top-level steps, exceeding the limit of {max}")]
    TooManySteps { actual: usize, max: usize },

    #[error("workflow declares {actual} catch handlers, exceeding the limit of {max}")]
    TooManyCatchHandlers { actual: usize, max: usize },

    #[error("workflow declares {actual} finally handlers, exceeding the limit of {max}")]
    TooManyFinallyHandlers { actual: usize, max: usize },

    #[error(
        "permissions.unattended.escalate is `park`, which requires both `deadline` and `on_timeout` (§8.5: \"Escalate is configurable per job: Park{{deadline, on_timeout}}\")"
    )]
    ParkEscalationRequiresDeadlineAndOnTimeout,

    #[error(
        "workflow YAML nests {depth} deep, exceeding the {max}-deep limit enforced before parsing (bounds a real quadratic-time cost in scanning deeply nested flow collections, independent of the YAML library in use)"
    )]
    TooDeeplyNested { depth: usize, max: usize },

    #[error(
        "a line in the workflow YAML opens with {width} characters of leading whitespace, exceeding the {max}-character limit enforced before parsing"
    )]
    ExcessiveIndentWidth { width: usize, max: usize },

    #[error("workflow YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

impl ParseError {
    /// 1-based line/column of the failure, when the underlying error
    /// carries one. `serde_yaml`'s YAML-syntax errors and most
    /// schema-shape errors (missing/unknown field, bad enum variant) do;
    /// this module's own whole-document bound checks (e.g.
    /// [`ParseError::TooLarge`]) don't, since they aren't tied to one
    /// location in the document.
    pub fn location(&self) -> Option<(usize, usize)> {
        match self {
            ParseError::Yaml(err) => err.location().map(|loc| (loc.line(), loc.column())),
            _ => None,
        }
    }
}

/// Parses raw workflow YAML text (§8.9) into a [`WorkflowDef`]. Consumes
/// `roundhouse_flow::job::Body::to_workflow_yaml`'s output — every `Body`
/// variant lowers to this same shape, so a `Body::Prompt` job is not a
/// special case here.
pub fn parse_workflow(yaml: &str) -> Result<WorkflowDef, ParseError> {
    if yaml.len() > MAX_YAML_BYTES {
        return Err(ParseError::TooLarge {
            actual: yaml.len(),
            max: MAX_YAML_BYTES,
        });
    }

    match nesting_depth_bound_violation(yaml) {
        Some(NestingViolation::FlowDepth(depth)) => {
            return Err(ParseError::TooDeeplyNested {
                depth,
                max: MAX_FLOW_NESTING_DEPTH,
            });
        }
        Some(NestingViolation::IndentWidth(width)) => {
            return Err(ParseError::ExcessiveIndentWidth {
                width,
                max: MAX_LEADING_INDENT_CHARS,
            });
        }
        None => {}
    }

    let def: WorkflowDef = serde_yaml::from_str(yaml)?;

    if def.steps.len() > MAX_TOP_LEVEL_STEPS {
        return Err(ParseError::TooManySteps {
            actual: def.steps.len(),
            max: MAX_TOP_LEVEL_STEPS,
        });
    }
    if def.catch.len() > MAX_CATCH_HANDLERS {
        return Err(ParseError::TooManyCatchHandlers {
            actual: def.catch.len(),
            max: MAX_CATCH_HANDLERS,
        });
    }
    if def.finally.len() > MAX_FINALLY_HANDLERS {
        return Err(ParseError::TooManyFinallyHandlers {
            actual: def.finally.len(),
            max: MAX_FINALLY_HANDLERS,
        });
    }

    validate_unattended(&def.permissions.unattended)?;

    Ok(def)
}

fn validate_unattended(unattended: &UnattendedDef) -> Result<(), ParseError> {
    if unattended.escalate == UnattendedEscalate::Park
        && (unattended.deadline.is_none() || unattended.on_timeout.is_none())
    {
        return Err(ParseError::ParkEscalationRequiresDeadlineAndOnTimeout);
    }
    Ok(())
}

/// Which of [`nesting_depth_bound_violation`]'s two bounds was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NestingViolation {
    FlowDepth(usize),
    IndentWidth(usize),
}

/// A cheap, `serde_yaml`-independent, line-oriented pass over the raw text
/// that rejects two shapes of pathological nesting *before* the text is
/// handed to `serde_yaml` at all: `[`/`{` flow-collection depth beyond
/// [`MAX_FLOW_NESTING_DEPTH`], and any line whose leading whitespace
/// exceeds [`MAX_LEADING_INDENT_CHARS`]. Returns the specific violation, or
/// `None` if the document stays within both bounds.
///
/// # This is best-effort defence in depth, not a security boundary
///
/// (Fix round 3 on Task 10, finding H2, after two earlier versions of this
/// doc comment claimed soundness properties that execution then falsified
/// — see the module doc comment for the full history.) The actual bound
/// on untrusted-input cost is [`MAX_YAML_BYTES`]. This function exists
/// only to reject the cases it happens to understand cheaply, before
/// paying `serde_yaml`'s cost on them; it is not claimed to catch
/// everything, and a future crafted input finding a new way past it would
/// not be a regression of any promise this function makes.
///
/// It still does not track quote state (an earlier version did, and a
/// quote character in an entirely ordinary position — `name: don't` — could
/// desynchronize it permanently). Every `[`/`{`/`]`/`}` outside a
/// block-scalar body counts toward `depth`, including ones that happen to
/// sit inside a quoted flow scalar — this can over-count (occasionally
/// rejecting a document with an unusually bracket-heavy quoted scalar,
/// mitigated by [`MAX_FLOW_NESTING_DEPTH`]'s 256 headroom), but a bracket
/// that never gets to the counter at all (this scan's actual failure mode
/// twice now) is the more serious direction.
///
/// The one content this scan skips outright is a block scalar's body
/// (`is_block_scalar_indicator_line` / the `in_block_scalar` handling
/// below): `serde_yaml` itself decides where such a body ends purely by
/// indentation (strictly more indented than the line that opened it, or
/// blank), so this scan uses the identical rule. That rule itself is
/// sound — the risk was never in "what is a block-scalar body," it was in
/// correctly recognising when one starts; see
/// `is_block_scalar_indicator_line`'s own doc comment for round 3's
/// hardening of that specific detector.
fn nesting_depth_bound_violation(yaml: &str) -> Option<NestingViolation> {
    let mut depth: usize = 0;
    let mut in_block_scalar = false;
    let mut block_scalar_parent_indent: usize = 0;

    for line in yaml.split('\n') {
        let indent = line.chars().take_while(|&c| c == ' ' || c == '\t').count();
        let trimmed = line.trim();

        if in_block_scalar {
            if trimmed.is_empty() {
                continue; // a blank line never ends a block scalar
            }
            if indent > block_scalar_parent_indent {
                continue; // still inside the block scalar's body — not scanned at all
            }
            in_block_scalar = false; // this line is at or below the parent's indentation: the block ended before it
        }

        if indent > MAX_LEADING_INDENT_CHARS {
            return Some(NestingViolation::IndentWidth(indent));
        }

        if is_block_scalar_indicator_line(trimmed, depth) {
            in_block_scalar = true;
            block_scalar_parent_indent = indent;
            // The indicator itself (`prompt: |`) carries no brackets of its
            // own interest, but scan it anyway below for uniformity — a
            // key name could theoretically carry a stray `[`/`{`.
        }

        for c in line.chars() {
            match c {
                '[' | '{' => {
                    depth += 1;
                    if depth > MAX_FLOW_NESTING_DEPTH {
                        return Some(NestingViolation::FlowDepth(depth));
                    }
                }
                ']' | '}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }

    None
}

/// True if `trimmed` (a line with leading whitespace already stripped) is
/// exactly a YAML block-scalar indicator (`|` or `>`), optionally followed
/// by a chomping indicator (`+`/`-`) and/or an explicit indentation digit
/// (`1`-`9`) in either order — the value-position content of a `key: |`,
/// `key: |-2`, or `- |` line, ignoring a trailing `# comment`.
///
/// `depth_before_line` is the bracket-nesting depth carried into this line
/// from everything scanned so far (i.e. before this line's own `[`/`{`/
/// `]`/`}` characters are counted).
///
/// # Fix round 3 on Task 10, finding H2 (defence in depth, not soundness)
///
/// An earlier version found the indicator with a bare
/// `without_comment.rfind(':')` over the *whole* line, with no concept of
/// where the line actually sits structurally. Both review lenses
/// independently found the same two ways that went wrong, and both are
/// really the same underlying mistake (a colon match with no awareness of
/// context):
/// - **A pure-comment line** (`# x: |`) has a colon in ordinary comment
///   prose, which used to be read as a real mapping-value indicator,
///   opening (bogus) block-scalar mode for the rest of the document.
/// - **A colon inside an unclosed flow collection opened earlier on the
///   *same* line** (`items: ["note: |`) used to be read the same way,
///   even though YAML has no block scalars in flow context at all.
///
/// This version closes both, still without needing to track quote state
/// (that's exactly what fix round 2 removed, for good reason — see the
/// module doc comment): a line starting with `#` is never a value
/// position, full stop; and the colon this function keys off of must be
/// the last one that sits at this line's own top level (`depth_before_line`
/// plus this line's own bracket changes up to that point equal to zero),
/// not merely the last colon found anywhere in the line's text.
fn is_block_scalar_indicator_line(trimmed: &str, depth_before_line: usize) -> bool {
    if depth_before_line > 0 {
        // Still inside a flow collection opened on an earlier line — YAML
        // has no block scalars in flow context, so nothing on this line
        // (which is itself flow-collection content) can open one.
        return false;
    }
    if trimmed.starts_with('#') {
        return false; // a pure-comment line is never a value position
    }

    // A block-scalar indicator can only legally be followed by whitespace,
    // its own modifier characters, or a comment before the newline — a
    // trailing `# comment` is stripped the same simple way regardless
    // (this heuristic is only used to *detect* the indicator, never to
    // decide what counts as a bracket, so a false negative here just means
    // a block scalar's body gets bracket-scanned like ordinary text, which
    // is the over-counting/over-rejection direction, not a bypass).
    let without_comment = strip_trailing_comment(trimmed);

    // Track bracket depth *within this line* to find the last colon that
    // sits at the line's own top level (depth zero) — a colon inside a
    // `{...}`/`[...]` opened earlier on this same line is a nested key,
    // not a mapping-value indicator.
    let mut local_depth: i64 = 0;
    let mut top_level_colon_idx: Option<usize> = None;
    for (i, c) in without_comment.char_indices() {
        match c {
            '[' | '{' => local_depth += 1,
            ']' | '}' => local_depth = (local_depth - 1).max(0),
            ':' if local_depth == 0 => top_level_colon_idx = Some(i),
            _ => {}
        }
    }

    let value_part = if let Some(idx) = top_level_colon_idx {
        without_comment[idx + 1..].trim()
    } else if let Some(rest) = without_comment.strip_prefix("- ") {
        rest.trim()
    } else {
        without_comment.trim()
    };

    is_block_scalar_indicator_token(value_part)
}

fn strip_trailing_comment(line: &str) -> &str {
    match line.find(" #") {
        Some(idx) => line[..idx].trim_end(),
        None => line,
    }
}

fn is_block_scalar_indicator_token(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some('|') | Some('>') => {}
        _ => return false,
    }
    let rest: &str = chars.as_str();
    if rest.len() > 2 {
        return false;
    }
    let mut seen_digit = false;
    let mut seen_chomp = false;
    for c in rest.chars() {
        match c {
            '+' | '-' if !seen_chomp => seen_chomp = true,
            '1'..='9' if !seen_digit => seen_digit = true,
            _ => return false,
        }
    }
    true
}
