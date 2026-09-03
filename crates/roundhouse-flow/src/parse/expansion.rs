//! The bound on anchor/alias expansion that closes the denial-of-service
//! finding recorded in [`super`]'s module doc comment.
//!
//! # The mechanism: use the real deserializer as its own budget meter
//!
//! `serde_yaml` 0.9's deserializer is **demand-driven**: it loads the
//! document once into a flat event list (linear in the input, with an alias
//! stored as a single `Event::Alias` marker), and *expands* an alias only
//! when a `Deserialize` impl asks for the node the alias points at —
//! `de.rs`'s `deserialize_any` on `Event::Alias(pos)` calls `jump(pos)` and
//! continues from the anchor's event index. Nothing is materialized ahead
//! of the visitor.
//!
//! [`check_expansion`] exploits that. It walks the document through a
//! `DeserializeSeed`/`Visitor` pair that accepts *any* YAML shape and
//! produces nothing but a count, charges one unit per node handed to the
//! visitor, and returns `Err` the moment the count passes the ceiling.
//! Because the walk is what drives the expansion, aborting the walk aborts
//! the expansion.
//!
//! This does not *model* the expansion — it does not re-derive alias
//! semantics, compute a bound from anchor sizes, or scan the raw text, all
//! of which are the shape of check this module has had bypassed three times
//! (see [`super`]'s history section). Its unit is the real work unit rather
//! than a proxy for it, which is what `MAX_ALIAS_TOKENS` — a proxy that
//! decoupled from cost by a factor of 3,000 — was not.
//!
//! # The counter allocates nothing, so it bounds memory as well as CPU
//!
//! The visitor's `Value` is `()`. It builds no tree, keeps no buffer, and
//! its only state is a `usize` and a `bool` behind shared references. Its
//! heap use is therefore independent of how far the document would expand;
//! its stack use is bounded by `serde_yaml`'s own 128-deep recursion guard.
//!
//! Measured, release build, walking the attack family with **no** ceiling
//! (`levels` is the fan-out depth of `tests/parse_top_level.rs`'s
//! `anchor_alias_fanout(1000, 4, levels)`):
//!
//! | levels | document | nodes visited | walk cost | process peak RSS |
//! |---|---|---|---|---|
//! | 1 | 2,140 B | 5,026 | 0.75 ms | 3.6 MB |
//! | 3 | 2,204 B | 85,134 | 2.96 ms | 3.8 MB |
//! | 5 | 2,268 B | 1,366,842 | 38.9 ms | 3.8 MB |
//! | 6 | 2,300 B | 5,468,304 | 155.8 ms | 3.8 MB |
//!
//! Node count quadruples per level (the fan) — exponential in document
//! size — while resident memory does not move. Contrast the *real* parse of
//! the same family, run in a child process under a 2 GiB `ulimit -v` so it
//! could not take the host down:
//!
//! | levels | document | real parse | process peak RSS |
//! |---|---|---|---|
//! | 5 | 2,268 B | 95 ms | 141 MB |
//! | 6 | 2,300 B | 367 ms | 555 MB |
//! | 7 | 2,332 B | **aborts: allocation failure** | exceeds 2 GiB |
//!
//! That is the finding's real severity, and it is worse than [`super`]'s
//! original write-up (which recorded CPU only): **a 2,332-byte document
//! exhausts a 2 GiB address space.** Uncapped, the same family has twice
//! been observed by the kernel OOM killer at ~35 GiB resident on this host.
//!
//! # Why this bounds the subsequent real parse too — measured, not argued
//!
//! [`super::parse_workflow`] runs this walk and then, if it stayed inside
//! the ceiling, hands the same text to `serde_yaml::from_str::<WorkflowDef>`.
//! Soundness therefore rests on a relationship between two walks, and an
//! earlier draft of this file asserted the wrong one: that the real parse
//! "visits a subset of the nodes the first one did", supported by an
//! enumeration of type constructs. That enumeration was false — it omitted
//! [`super::types`]'s `PermissionRuleDefWire`, whose `#[serde(flatten)]`
//! buffers its fields through serde's `Content` and then deserializes the
//! matcher value *again* via `#[serde(try_from)]`. An enumeration of
//! constructs is falsified by any construct its author did not list, so
//! this file does not make one.
//!
//! What is claimed instead is a **measured ratio**. Release build, twelve
//! documents admitted by the ceiling, six of them shaped to sit within 2%
//! of it by different means (alias-expanded `permissions.rules[]` args
//! through the flatten path; alias-expanded sequences and mappings inside
//! `steps`; a maximally dense alias-free document at the byte cap; one
//! 250 KB scalar; the frozen §8.9 fixture):
//!
//! - worst observed `real parse / metered walk` ratio: **2.95**
//!   (a 14,062-byte document expanding to 257,516 nodes: walk 8.30 ms,
//!   real parse 24.46 ms)
//! - worst observed absolute real-parse cost for an admitted document:
//!   **24.46 ms**
//! - worst observed peak-RSS growth across the real parse of an admitted
//!   document: **36 MB**
//!
//! **This is an observation over the shapes probed, not a proof of a
//! constant.** The construct that broke the earlier argument (`flatten`)
//! re-visits an owned `Content` buffer rather than the YAML event list, so
//! it costs a constant multiple of already-expanded content; the same is
//! true of `steps.rs`'s `#[serde(untagged)] MapIsolationWire`, which is
//! reached from `steps::parse_step` on an already-materialized
//! `serde_yaml::Value`, never from `parse_workflow`'s `from_str`. A future
//! construct that re-visited the *event list* rather than a buffer would
//! not be covered by these numbers, and the honest statement is that this
//! ceiling was chosen knowing the observed worst case is ~3x, with the
//! absolute figures — tens of milliseconds, tens of megabytes — leaving
//! room for that ratio to be several times worse than measured before it
//! becomes interesting.
//!
//! # `serde_yaml` errors reject the document; they do not wave it through
//!
//! [`check_expansion`] reports [`Verdict::Malformed`] for a document
//! `serde_yaml` rejects during the walk, and [`super::parse_workflow`]
//! returns that error rather than continuing to the real parse. An earlier
//! draft continued instead, to avoid replacing an accurate located error
//! with a misleading one — but that is a total bypass for any document
//! that errors cheaply in the meter while parsing expensively for real, and
//! the safety of "it can't" was an argument, not a measurement. Rejecting
//! removes the need for the argument: no document reaches the real parse
//! without a completed, in-budget walk.
//!
//! The cost of that choice is bounded and was checked rather than assumed:
//!
//! - The walk accepts every YAML shape, so it never produces a *schema*
//!   error. Anything it reports is a YAML-level error (syntax,
//!   `RepetitionLimitExceeded`, `RecursionLimitExceeded`, more than one
//!   document) that `WorkflowDef`'s own parse would hit on the same events.
//! - Across a 21-document sweep of legitimate shapes — the frozen §8.9
//!   fixture, `---`/`...` markers, comments, tagged nodes (`!Custom`,
//!   `!!binary`, a bare tagged null), merge keys, `.nan`/`.inf`, 120-deep
//!   flow nesting, anchor reuse, a maximally dense 256 KiB document — the
//!   walk's verdict and the typed parse's verdict agreed on every one:
//!   **zero over-rejections**. See
//!   `the_metered_walk_does_not_over_reject_legitimate_yaml_shapes` in
//!   `tests/parse_top_level.rs`.
//! - Error quality does not regress. `serde_yaml`'s errors carry their own
//!   marks, so [`super::ParseError::location`] still reports line/column.
//!   For a truncated flow mapping the walk actually reports better: the
//!   syntax error itself (`did not find expected ',' or '}' at line 5`)
//!   where the typed parse reported a downstream schema error
//!   (`permissions.unattended.escalate: unknown variant`) caused by it.
//!
//! # What this does NOT bound
//!
//! **Only the expansion stage.** Loading the raw text into the event list
//! (tokenizing/scanning) happens before any visitor runs and is untouched
//! by the ceiling. That cost is addressed — partially, best-effort, and
//! explicitly not as a security boundary — by
//! [`super::nesting_depth_bound_violation`] and [`super::MAX_YAML_BYTES`];
//! see [`super`]'s module doc for the measured shape that gets past the
//! scan (a run of unclosed `[`, ~80 ms at 32 KiB and ~650 ms at 256 KiB).
//!
//! It also does not bound anything downstream of parsing: the number of
//! tasks a parsed workflow dispatches is [`crate::caps`]'s problem, not
//! this module's (see ruling P47's nested-`map` measurement).
//!
//! # What breaks this if `serde_yaml` changes
//!
//! The mechanism depends on two properties of `serde_yaml`
//! `0.9.34+deprecated`, an unmaintained crate this workspace depends on as
//! `"0.9"` rather than an exact pin:
//!
//! 1. **Expansion is demand-driven.** If a future 0.9.x expanded aliases
//!    while building the event list, the damage would be done before the
//!    first `charge()` and this check would meter a walk over an
//!    already-materialized bomb.
//! 2. **`deserialize_any` follows an alias exactly once per encounter**
//!    (`de.rs`'s `jump`). If it memoized expansions, the counter would
//!    over-count relative to the real parse's cost — the over-rejection
//!    direction, which is safe but would need the ceiling revisited.
//!
//! Property 1 is what a regression would silently break, so it is tested
//! by wall-clock rather than by inspection:
//! `the_metered_walk_rejects_a_fan_out_without_expanding_it` in
//! `tests/parse_top_level.rs` rejects a document whose full expansion is
//! measured at over 5.4 million nodes and asserts the rejection is fast. If
//! expansion ever stops being demand-driven, that test stops passing
//! quickly rather than starting to fail silently.

use std::cell::Cell;
use std::fmt;

use serde::de::{
    self, DeserializeSeed, Deserializer, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor,
};

/// What [`check_expansion`] found. Every variant is a decision
/// [`super::parse_workflow`] acts on directly; there is no "proceed anyway"
/// case.
pub(super) enum Verdict {
    /// The walk completed and stayed at or under the ceiling.
    WithinBudget,
    /// The walk was stopped by the ceiling. The document expands to more
    /// nodes than are allowed, and how many more was deliberately not
    /// measured — measuring it is the attack.
    OverBudget,
    /// `serde_yaml` rejected the document during the walk. Carries its
    /// error, which keeps `serde_yaml`'s own line/column mark.
    Malformed(serde_yaml::Error),
}

/// Walks `yaml` with the real `serde_yaml` deserializer, following every
/// anchor and alias exactly as the subsequent typed parse will, and reports
/// whether the document expands to more than `max` nodes.
///
/// A "node" is one value handed to the visitor: each scalar, each sequence,
/// each mapping, each mapping key. An alias contributes the whole subtree it
/// expands to, because the walk follows it.
///
/// **The walk stops at `max + 1`.** It never counts higher and never
/// completes the expansion of a document that exceeds the ceiling, so the
/// work this function performs is bounded by `max` regardless of the input
/// — in memory as well as in time, since the walk allocates nothing per
/// node. See this module's doc comment for the measurements.
pub(super) fn check_expansion(yaml: &str, max: usize) -> Verdict {
    let counted = Cell::new(0usize);
    let over_budget = Cell::new(false);
    let counter = NodeCounter {
        counted: &counted,
        over_budget: &over_budget,
        max,
    };

    match counter.deserialize(serde_yaml::Deserializer::from_str(yaml)) {
        Ok(()) => Verdict::WithinBudget,
        Err(err) => {
            if over_budget.get() {
                Verdict::OverBudget
            } else {
                Verdict::Malformed(err)
            }
        }
    }
}

/// A `DeserializeSeed`/`Visitor` pair that accepts every YAML shape and
/// produces nothing but a count. Carries its counter by shared reference so
/// the seed stays `Copy` and can be reused for every element of a sequence
/// and every key/value of a mapping.
#[derive(Clone, Copy)]
struct NodeCounter<'a> {
    counted: &'a Cell<usize>,
    over_budget: &'a Cell<bool>,
    max: usize,
}

impl NodeCounter<'_> {
    /// Charges one node. Returns `Err` — which unwinds the whole walk, and
    /// with it the expansion driving it — once the ceiling is passed.
    ///
    /// The `over_budget` flag exists because this error has to be
    /// distinguishable from `serde_yaml`'s own: both arrive at
    /// [`check_expansion`] as a `serde_yaml::Error`, and they mean opposite
    /// things about the document.
    fn charge<E: de::Error>(&self) -> Result<(), E> {
        let counted = self.counted.get() + 1;
        self.counted.set(counted);
        if counted > self.max {
            self.over_budget.set(true);
            return Err(E::custom("expanded node budget exceeded"));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for NodeCounter<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NodeCounter<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any YAML node")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.charge()
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.charge()
    }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
        self.charge()
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.charge()
    }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
        self.charge()
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.charge()
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        self.charge()
    }
    fn visit_bytes<E: de::Error>(self, _: &[u8]) -> Result<(), E> {
        self.charge()
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.charge()
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        self.charge()
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.charge()?;
        deserializer.deserialize_any(self)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.charge()?;
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.charge()?;
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.charge()?;
        while map.next_key_seed(self)?.is_some() {
            map.next_value_seed(self)?;
        }
        Ok(())
    }

    /// `serde_yaml` routes a tagged node (`!Tag value`) through
    /// `visit_enum` (`de.rs`'s `deserialize_any` rewinds one event and hands
    /// the visitor an `EnumAccess`), so a fan-out hidden behind tags is
    /// walked — and charged — like an untagged one.
    ///
    /// An earlier draft of this file *asserted* that, adding that the
    /// payload "is always a newtype variant in `serde_yaml`'s encoding,
    /// including for a tagged null", and a wrong assertion here would have
    /// been a complete bypass: the walk would error at the tag while
    /// `WorkflowDef.steps` — a `serde_yaml::Value`, which constructs
    /// `Value::Tagged` happily — expanded the fan-out in full.
    ///
    /// It is now checked by construction rather than by reading. Wrapping
    /// every anchored level of the fan-out in `!Thing` changes the walk's
    /// node count by 0.3% (21,932,398 tagged vs 21,874,150 untagged for
    /// `anchor_alias_fanout(1000, 4, 7)`) and both are rejected; a bare
    /// `!Empty` and a tagged null field both walk without error. See
    /// `a_tag_wrapped_anchor_alias_fan_out_is_rejected` and
    /// `the_metered_walk_does_not_over_reject_legitimate_yaml_shapes` in
    /// `tests/parse_top_level.rs`.
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<(), A::Error> {
        self.charge()?;
        let (_, variant) = data.variant_seed(self)?;
        variant.newtype_variant_seed(self)
    }
}
