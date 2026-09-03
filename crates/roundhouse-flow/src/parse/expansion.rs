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
//! produces nothing but a running total, charges each node as it is handed
//! to the visitor, and returns `Err` the moment the total passes the
//! ceiling. Because the walk is what drives the expansion, aborting the
//! walk aborts the expansion.
//!
//! This does not *model* the expansion — it does not re-derive alias
//! semantics, compute a bound from anchor sizes, or scan the raw text, all
//! of which are the shape of check this module has had bypassed three times
//! (see [`super`]'s history section). It expands the document with the real
//! parser and stops when it has spent its budget.
//!
//! # The unit is expanded **byte weight**, not node count
//!
//! Each node is charged [`NODE_WEIGHT_BYTES`] plus, for a scalar, that
//! scalar's own length. An aliased scalar is therefore charged its full
//! length **every time it expands**, because the walk follows the alias
//! exactly as the real parse will.
//!
//! **This unit is a correction, and the reason for it matters.** The first
//! version of this check counted nodes: `charge()` added one per node and
//! `visit_str` discarded the string's length. One node can carry an
//! arbitrarily large aliased payload, so aliasing a big anchored scalar `K`
//! times in a **flat** list cost `K` at the meter while materializing
//! `K x L` bytes in the real parse. It stayed under [`super::MAX_YAML_BYTES`]
//! (the scalar is written once; each reuse costs about three source bytes),
//! and it did not trip `serde_yaml`'s `jumpcount > events.len() * 100`
//! guard, because a flat list keeps jumps proportional to events — unlike
//! the fan-outs that version's tests probed. Measured by a security review
//! against that version: a **180,138-byte document was admitted** and drove
//! the real parse to **4,593 MB** resident; a 260,210-byte one reached
//! allocation failure past 2 GiB. Same OOM class as the finding this module
//! exists to close.
//!
//! Two proxies would not have fixed it. A separate scalar-size check beside
//! a node counter is two guards each looking sufficient alone, which is
//! precisely this module's failure history. There is one unit, and it is
//! the quantity that drives the cost.
//!
//! ## What [`NODE_WEIGHT_BYTES`] is for, and why it is 8
//!
//! It stops a node from ever being free, which is what keeps the *count* of
//! nodes bounded as well as their content: an aliased empty collection
//! charges nothing but `NODE_WEIGHT_BYTES`, so it cannot be expanded
//! without limit. A weight budget `C` therefore bounds two things at once —
//! total expanded scalar bytes at `C`, and node count at
//! `C / NODE_WEIGHT_BYTES`.
//!
//! 8 is near the minimum of the two: raising it inflates the scalar budget
//! (which is what the ceiling must cover for an alias-free document, so the
//! ceiling rises with it), while lowering it inflates the node budget. With
//! the ceiling scaled to keep the densest alias-free document admitted, the
//! worst-case product is flattest around 8-12 for this workspace's
//! `size_of::<serde_yaml::Value>() == 72`. It is a charge-model tuning
//! constant, not a measurement of anything.
//!
//! # What weight actually implies for memory — measured, not derived
//!
//! **A weight budget is a charge model. It is not a memory measurement, and
//! nothing here claims otherwise.** An earlier version of this file carried
//! a section heading reading "The counter allocates nothing, so it bounds
//! memory as well as CPU". That was a non-sequitur: the reasoning under it
//! was about the *meter's* own heap use, which is genuinely independent of
//! expansion and says nothing whatever about the memory of the parse the
//! meter authorizes. It is recorded here because a wrong bound is a bug,
//! and a wrong bound the doc asserts is correct — on the exact axis two
//! kernel OOM kills made salient while this was being built — is worse.
//!
//! What weight ≤ [`super::MAX_EXPANDED_WEIGHT`] implies **directly** is
//! only the two budgets above. What that costs in real memory and time was
//! measured, in isolated child processes under a 6 GiB `ulimit -v`, one
//! document per process so the peak is attributable:
//!
//! | admitted document | bytes | nodes | weight | real parse | peak RSS |
//! |---|---|---|---|---|---|
//! | 100-element list aliased 4,600x | 14,105 | 464,720 | 4,177,921 | 36.2 ms | **60.4 MB** |
//! | 1,000-element list aliased 460x | 3,485 | 461,480 | 4,152,901 | 31.6 ms | 51.5 MB |
//! | 2,000-element list aliased 230x | 4,795 | 462,250 | 4,160,061 | 30.8 ms | 51.5 MB |
//! | densest alias-free `{a,a,…}` at the byte cap | 262,144 | 262,070 | 2,227,640 | 18.4 ms | 42.8 MB |
//! | densest alias-free `[x,x,…]` at the byte cap | 262,144 | 131,044 | 1,179,432 | 20.9 ms | 34.5 MB |
//! | 100,000-byte scalar aliased 40x | 100,310 | 101 | 4,100,869 | 1.1 ms | 7.9 MB |
//! | `permissions.rules[]` args aliased (flatten path) | 15,298 | 182,720 | 1,829,715 | 14.6 ms | 14.0 MB |
//!
//! **Worst observed for an admitted document: 60.4 MB and 36.2 ms**, across
//! every shape probed including the two families that broke earlier
//! versions. Against the 4,593 MB the previous unit admitted, that is a 76x
//! reduction on the measured worst case.
//!
//! Two honest qualifications, in the P18 sense:
//!
//! 1. **This is an observation over shapes probed, not a proof of a
//!    constant.** The previous version's equivalent table said 36 MB and a
//!    security lens then found 4,593 MB, so this sentence is load-bearing.
//!    What is different now is that the falsifying family — amplifying
//!    scalar bytes — is the one the unit charges, so it is no longer
//!    invisible to the meter; but "the one I did not think of" remains the
//!    standing risk, and the numbers above are evidence, not a guarantee.
//! 2. **About 43 MB of that worst case is inherent, not a tuning choice.**
//!    The ceiling must admit the densest legitimate alias-free document at
//!    the byte cap, which is 262,070 nodes and measures 42.8 MB on its own.
//!    No ceiling that admits `MAX_YAML_BYTES` of legitimate YAML can get
//!    the worst case much below that. The observed worst is ~1.4x that
//!    floor. Driving it lower means lowering [`super::MAX_YAML_BYTES`], not
//!    changing this unit.
//!
//! ## The meter's own footprint
//!
//! Distinct from the above, and true: the visitor's `Value` is `()`, it
//! builds no tree and keeps no buffer, its only state is two `Cell`s behind
//! shared references, and `str::len()` copies nothing. So the *meter* costs
//! `O(1)` heap however far the document would expand — which is what lets
//! it meter a payload it must never materialize. Measured on the rejection
//! path: a 2,332-byte fan-out is rejected with process peak RSS at 3.7 MB,
//! and the 260,110-byte aliased-scalar payload at 9.3 MB (essentially the
//! source string itself). This says nothing about the authorized parse; see
//! the table above for that.
//!
//! # Why this bounds the subsequent real parse too — measured, not argued
//!
//! [`super::parse_workflow`] runs this walk and then, if it stayed inside
//! the ceiling, hands the same text to `serde_yaml::from_str::<WorkflowDef>`.
//! Soundness therefore rests on a relationship between two walks, and an
//! early draft asserted the wrong one: that the real parse "visits a subset"
//! of the metered nodes, supported by an enumeration of type constructs.
//! That enumeration was false — it omitted [`super::types`]'s
//! `PermissionRuleDefWire`, whose `#[serde(flatten)]` buffers its fields
//! through serde's `Content` and then deserializes the matcher value *again*
//! via `#[serde(try_from)]`. An enumeration of constructs is falsified by
//! any construct its author did not list, so this file does not make one.
//!
//! What is claimed instead is the measured table above: for every admitted
//! document probed, the real parse cost at most 36.2 ms and 60.4 MB. The
//! construct that broke the enumeration (`flatten`) re-visits an owned
//! `Content` buffer rather than the YAML event list, so it costs a constant
//! multiple of already-expanded content; the same is true of `steps.rs`'s
//! `#[serde(untagged)] MapIsolationWire`, which is reached from
//! `steps::parse_step` on an already-materialized `serde_yaml::Value`, never
//! from `parse_workflow`'s `from_str`. A future construct that re-visited
//! the *event list* rather than a buffer would not be covered by these
//! numbers.
//!
//! # `serde_yaml` errors reject the document; they do not wave it through
//!
//! [`check_expansion`] reports [`Verdict::Malformed`] for a document
//! `serde_yaml` rejects during the walk, and [`super::parse_workflow`]
//! returns that error rather than continuing to the real parse. An earlier
//! draft continued instead, to avoid replacing an accurate located error
//! with a misleading one — but that is a total bypass for any document that
//! errors cheaply in the meter while parsing expensively for real, and the
//! safety of "it can't" was an argument, not a measurement. Rejecting
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
//!    over-charge relative to the real parse's cost — the over-rejection
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

/// Weight charged for every expanded node before its content, so that no
/// node is free and node *count* is bounded by
/// `MAX_EXPANDED_WEIGHT / NODE_WEIGHT_BYTES` as well as node content being
/// bounded by the ceiling itself.
///
/// A charge-model tuning constant, not a measurement — see this module's
/// doc comment for why 8 and what it trades against.
pub const NODE_WEIGHT_BYTES: usize = 8;

/// What [`check_expansion`] found. Every variant is a decision
/// [`super::parse_workflow`] acts on directly; there is no "proceed anyway"
/// case.
pub(super) enum Verdict {
    /// The walk completed and stayed at or under the ceiling.
    WithinBudget,
    /// The walk was stopped by the ceiling. How far over the document would
    /// have gone is deliberately not measured — measuring it is the attack.
    OverBudget,
    /// `serde_yaml` rejected the document during the walk. Carries its
    /// error, which keeps `serde_yaml`'s own line/column mark.
    Malformed(serde_yaml::Error),
}

/// Walks `yaml` with the real `serde_yaml` deserializer, following every
/// anchor and alias exactly as the subsequent typed parse will, and reports
/// whether the document's expanded weight exceeds `max`.
///
/// Weight is [`NODE_WEIGHT_BYTES`] per node handed to the visitor — each
/// scalar, each sequence, each mapping, each mapping key — plus each
/// scalar's own byte length. An alias contributes the full weight of the
/// subtree it expands to, every time it expands, because the walk follows
/// it.
///
/// **The walk stops as soon as the running total passes `max`.** It never
/// completes the expansion of a document that exceeds the ceiling, so the
/// work this function performs is bounded by `max` regardless of the input,
/// and it allocates nothing per node while doing it (`str::len()` copies
/// nothing). See this module's doc comment for what that does and does not
/// imply about the memory of the parse it then authorizes.
pub(super) fn check_expansion(yaml: &str, max: usize) -> Verdict {
    let weighed = Cell::new(0usize);
    let over_budget = Cell::new(false);
    let meter = ExpansionMeter {
        weighed: &weighed,
        over_budget: &over_budget,
        max,
    };

    match meter.deserialize(serde_yaml::Deserializer::from_str(yaml)) {
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
/// produces nothing but a running weight. Carries its counter by shared
/// reference so the seed stays `Copy` and can be reused for every element of
/// a sequence and every key/value of a mapping.
#[derive(Clone, Copy)]
struct ExpansionMeter<'a> {
    weighed: &'a Cell<usize>,
    over_budget: &'a Cell<bool>,
    max: usize,
}

impl ExpansionMeter<'_> {
    /// Charges one node: [`NODE_WEIGHT_BYTES`] plus `payload_bytes` (a
    /// scalar's length, or zero for a container or a non-string scalar,
    /// whose source form is a handful of bytes the node weight already
    /// covers). Returns `Err` — which unwinds the whole walk, and with it
    /// the expansion driving it — once the ceiling is passed.
    ///
    /// `saturating_add` rather than `+`: `payload_bytes` is attacker-chosen
    /// and the running total is charged once per alias expansion, so the
    /// sum can genuinely overflow `usize` on a 32-bit target. Saturating
    /// keeps that in the rejecting direction; wrapping would not.
    ///
    /// The `over_budget` flag exists because this error has to be
    /// distinguishable from `serde_yaml`'s own: both arrive at
    /// [`check_expansion`] as a `serde_yaml::Error`, and they mean opposite
    /// things about the document.
    fn charge<E: de::Error>(&self, payload_bytes: usize) -> Result<(), E> {
        let weighed = self
            .weighed
            .get()
            .saturating_add(NODE_WEIGHT_BYTES)
            .saturating_add(payload_bytes);
        self.weighed.set(weighed);
        if weighed > self.max {
            self.over_budget.set(true);
            return Err(E::custom("expanded size budget exceeded"));
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for ExpansionMeter<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ExpansionMeter<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any YAML node")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        self.charge(0)
    }

    /// The length is the whole point of this unit: a scalar reached through
    /// an alias is charged its full length on every expansion, which is
    /// exactly what the real parse will materialize. Charging `1` here
    /// instead of `v.len()` is the round-1 hole — see this module's doc
    /// comment.
    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        self.charge(v.len())
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<(), E> {
        self.charge(v.len())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        self.charge(0)
    }
    fn visit_none<E: de::Error>(self) -> Result<(), E> {
        self.charge(0)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.charge(0)?;
        deserializer.deserialize_any(self)
    }

    fn visit_newtype_struct<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        self.charge(0)?;
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.charge(0)?;
        while seq.next_element_seed(self)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.charge(0)?;
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
    /// uncapped weight by 0.3% — 197,449,877 tagged against 196,838,273
    /// untagged for `anchor_alias_fanout(1000, 4, 7)` — so the tagged
    /// payload is walked and charged, not skipped at the tag. Both are
    /// rejected; a bare `!Empty` and a tagged null field both walk without
    /// error. (Those two totals are why the ceiling is not raised to make
    /// this family fit: the document is 2,332 bytes and weighs 188 MiB.)
    /// See
    /// `a_tag_wrapped_anchor_alias_fan_out_is_rejected` and
    /// `the_metered_walk_does_not_over_reject_legitimate_yaml_shapes` in
    /// `tests/parse_top_level.rs`.
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<(), A::Error> {
        self.charge(0)?;
        let (_, variant) = data.variant_seed(self)?;
        variant.newtype_variant_seed(self)
    }
}
