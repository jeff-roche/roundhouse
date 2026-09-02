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
//!   reaches the point of returning `RecursionLimitExceeded`, and cost
//!   grew highly non-linearly with size from there (measured up to ~560s
//!   at 520 KB), all comfortably under [`MAX_YAML_BYTES`]. This is a
//!   property of tokenizing the text, not of any one YAML library's
//!   internals, so [`nesting_depth_bound_violation`] bounds it with a
//!   cheap, library-independent linear pre-scan over the raw text, run
//!   *before* the text is ever handed to `serde_yaml`. See
//!   `rejects_pathological_flow_nesting_cheaply` in
//!   `tests/parse_top_level.rs`, which times this bound firing.
//!
//!   **Fix round 2 on Task 10 (finding H2) replaced this scan's design
//!   entirely** — an earlier version tracked single-/double-quote state
//!   char-by-char to skip quoted content, on the theory that under
//!   -counting (treating something as quoted when it wasn't) was the only
//!   possible failure and was safe. That was wrong on both ends, and both
//!   were found by execution, not reasoning:
//!   - A quote character appearing mid-plain-scalar (`name: don't` —
//!     entirely ordinary YAML; the apostrophe is literal text, not a
//!     scalar delimiter, because YAML only treats a quote as an indicator
//!     at scalar-start position) flipped the scanner into "quoted" state
//!     *permanently*, since nothing ever closed it — every character for
//!     the rest of the document, brackets included, was then silently
//!     skipped. Measured: a 50 KB bracket bomb preceded by `name: don't`
//!     passed the scan entirely and cost 2.53s once handed to `serde_yaml`
//!     regardless (38.8s at 200 KB, 80.3s at 300 KB) — quadratic, so ~15
//!     minutes of pinned CPU at the `MAX_YAML_BYTES` cap. This was not "a
//!     bracket disguised inside a string" as the previous version of this
//!     doc comment characterized the residual risk — the scanner's own
//!     corrupted state is what skipped the brackets, which were not
//!     inside any string at all.
//!   - Symmetrically, that scan also *over*-rejected: a block-scalar body
//!     (`prompt: |`) is literal text with zero nesting cost to YAML, but
//!     its `[`/`{` characters counted against the same global counter as
//!     structural brackets, so an ordinary prompt with a few dozen literal
//!     `[` characters could be rejected as "too deeply nested" while
//!     `serde_yaml` accepts it without hesitation.
//!
//!   The replacement drops quote-tracking entirely (never treats any
//!   region as "quoted," so it cannot get stuck in the wrong state the way
//!   the quote tracker did) and is block-scalar-aware instead: it detects
//!   a `|`/`>` block-scalar indicator ending a line and skips exactly that
//!   block's body (identified purely by indentation, the same rule
//!   `serde_yaml` itself uses) from both bracket-counting and the
//!   indentation-width check, resuming normal scanning at the first line
//!   indented at or below the block's own line. Counting every `[`/`{`
//!   outside a block-scalar body — including ones that happen to sit
//!   inside a quoted flow scalar, e.g. `${{ ... }}` interpolations — can
//!   only ever *over*-count relative to `serde_yaml`'s real structural
//!   depth, never under-count, so the scan's failure mode is now strictly
//!   "occasionally rejects a document with an unusually bracket-heavy
//!   quoted flow scalar," never "silently admits a real bomb." See
//!   `rejects_a_bracket_bomb_hidden_behind_an_apostrophe` (the bypass) and
//!   `accepts_a_bracket_heavy_block_scalar_prompt` (the over-rejection
//!   case) in `tests/parse_top_level.rs`, both timed.
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

/// 1 MiB. §8.9 workflows are short, hand-authored YAML (the full §8.9
/// `pr-review` fixture is ~2 KiB); this is generous headroom for a large
/// real workflow while still bounding parser memory/CPU on adversarial
/// input.
pub const MAX_YAML_BYTES: usize = 1_048_576;
/// No real workflow needs hundreds of top-level steps — a `map` step
/// already provides fan-out — so this bounds a maliciously (or
/// accidentally) huge step list without constraining legitimate use.
pub const MAX_TOP_LEVEL_STEPS: usize = 500;
pub const MAX_CATCH_HANDLERS: usize = 50;
pub const MAX_FINALLY_HANDLERS: usize = 50;
/// Maximum nesting depth of `[`/`{` flow collections this module will scan
/// before rejecting a document outright — comfortably under `serde_yaml`'s
/// own 128-deep recursion guard, so a legitimate document (§8.9's fixture
/// nests at most a handful of levels) is never affected. See
/// [`nesting_depth_bound_violation`].
pub const MAX_FLOW_NESTING_DEPTH: usize = 64;
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
/// # Design (fix round 2 on Task 10, finding H2)
///
/// Does **not** track quote state at all — an earlier version did, and a
/// quote character in an entirely ordinary position (`name: don't`) could
/// desynchronize it permanently, silently disabling the depth bound for
/// the rest of the document (see the module doc comment above for the
/// measured exploit). Instead, every `[`/`{`/`]`/`}` outside a
/// block-scalar body counts toward `depth`, full stop — including ones
/// that happen to sit inside a quoted flow scalar. This can only ever
/// *over*-count relative to `serde_yaml`'s real structural nesting (never
/// under-count), so the scan's only failure mode is rejecting an unusually
/// bracket-heavy quoted flow scalar, never admitting a real bomb.
///
/// The one content this scan *does* skip — deliberately, and by a rule
/// with no quote-like ambiguity — is a block scalar's body
/// (`is_block_scalar_indicator` / the `in_block_scalar` handling below):
/// `serde_yaml` itself decides where such a body ends purely by
/// indentation (strictly more indented than the line that opened it, or
/// blank), so this scan uses the identical rule, with no dependency on
/// character-level state that a crafted value could desynchronize.
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

        if is_block_scalar_indicator_line(trimmed) {
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
fn is_block_scalar_indicator_line(trimmed: &str) -> bool {
    // A block-scalar indicator can only legally be followed by whitespace,
    // its own modifier characters, or a comment before the newline — a
    // trailing `# comment` is stripped the same simple way regardless
    // (this heuristic is only used to *detect* the indicator, never to
    // decide what counts as a bracket, so a false negative here just means
    // a block scalar's body gets bracket-scanned like ordinary text, which
    // is the safe/over-counting direction, not a bypass).
    let without_comment = strip_trailing_comment(trimmed);

    let value_part = if let Some(idx) = without_comment.rfind(':') {
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
