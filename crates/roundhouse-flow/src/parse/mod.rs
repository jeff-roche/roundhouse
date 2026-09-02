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
//! - **Pathological nesting depth:** bounded by `serde_yaml`'s own
//!   `remaining_depth: 128` recursion guard (`RecursionLimitExceeded`),
//!   also on by default.
//! - **Overall document size / "huge number of steps":** the two
//!   protections above bound *amplification*, not the size of an honestly
//!   large document, so this module adds its own caps on top:
//!   [`MAX_YAML_BYTES`] on the raw input before it is even handed to
//!   `serde_yaml`, and [`MAX_TOP_LEVEL_STEPS`] / [`MAX_CATCH_HANDLERS`] /
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
