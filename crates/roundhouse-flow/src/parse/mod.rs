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
//!   cheap, library-independent linear pre-scan over the raw text —
//!   counting `[`/`{`/`]`/`}` nesting depth and per-line leading
//!   indentation width, skipping quoted-string and comment content — run
//!   *before* the text is ever handed to `serde_yaml`. See
//!   `rejects_pathological_flow_nesting_cheaply` in
//!   `tests/parse_top_level.rs`, which times this bound firing.
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

    if let Some(depth) = nesting_depth_bound_violation(yaml) {
        return Err(ParseError::TooDeeplyNested {
            depth,
            max: MAX_FLOW_NESTING_DEPTH,
        });
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

/// A cheap, `serde_yaml`-independent, single linear pass over the raw text
/// that rejects two shapes of pathological nesting *before* the text is
/// handed to `serde_yaml` at all: `[`/`{` flow-collection depth beyond
/// [`MAX_FLOW_NESTING_DEPTH`], and any line whose leading whitespace
/// exceeds [`MAX_LEADING_INDENT_CHARS`]. Returns the offending depth/width
/// on violation, `None` if the document stays within both bounds.
///
/// Skips the contents of single- and double-quoted scalars and `#`
/// comments so ordinary content (a URL containing `[`, a comment
/// mentioning "nested arrays") is never miscounted — worst case this under
/// -counts (e.g. treating a `#` inside a genuinely unterminated quote as a
/// comment starts), which only makes this scan *more* permissive, never
/// less, so it can never reject a document `serde_yaml` would have
/// accepted; it can only fail to catch a pathological one that disguises
/// its brackets inside strings, which is not the resource-exhaustion shape
/// this bound defends against (a bracket inside a quoted string does not
/// drive the scanner's own nesting cost).
fn nesting_depth_bound_violation(yaml: &str) -> Option<usize> {
    let mut depth: usize = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut at_line_start = true;
    let mut indent_width: usize = 0;

    let mut chars = yaml.chars().peekable();
    while let Some(c) = chars.next() {
        if at_line_start {
            if c == ' ' || c == '\t' {
                indent_width += 1;
                continue;
            }
            at_line_start = false;
            if indent_width > MAX_LEADING_INDENT_CHARS {
                return Some(indent_width);
            }
        }

        if in_single_quote {
            if c == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next(); // YAML escapes `'` inside a single-quoted scalar as `''`
                } else {
                    in_single_quote = false;
                }
            }
            continue;
        }
        if in_double_quote {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => in_double_quote = false,
                _ => {}
            }
            continue;
        }

        match c {
            '\n' => {
                at_line_start = true;
                indent_width = 0;
            }
            '#' => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        at_line_start = true;
                        indent_width = 0;
                        break;
                    }
                }
            }
            '\'' => in_single_quote = true,
            '"' => in_double_quote = true,
            '[' | '{' => {
                depth += 1;
                if depth > MAX_FLOW_NESTING_DEPTH {
                    return Some(depth);
                }
            }
            ']' | '}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    None
}
