//! §10.1's first load-bearing v2 detail: "Merge semantics are three-state:
//! omitted = unchanged, null = clear, value = replace." A plain `Option<T>`
//! cannot represent this — JSON `null` and a missing key both deserialize to
//! `None`, erasing the distinction the protocol depends on.
//!
//! Ruling C-P7: the pinned `agent-client-protocol` SDK already ships this
//! exact type, ungated, with byte-identical semantics and the exact
//! three-way merge (`agent_client_protocol::schema::MaybeUndefined`,
//! `MaybeUndefined::update_to`). Reimplementing it here would mean
//! maintaining a second copy that can silently diverge from the wire
//! format, so this module re-exports the SDK's type rather than hand-rolling
//! one.

/// Re-export of the pinned SDK's own tri-state type — see the module doc
/// comment. `#[serde(default, skip_serializing_if = "MaybeUndefined::is_undefined")]`
/// on the field is what makes a *missing* key deserialize to `Undefined`
/// (never even invoking `MaybeUndefined`'s own `Deserialize` impl) and keeps
/// `Undefined` from serializing back out as a spurious `null`.
pub use agent_client_protocol::schema::MaybeUndefined;

/// A thin by-reference adapter over the SDK's
/// [`MaybeUndefined::update_to`], which consumes `self` by value. This
/// adapter survives — rather than callers invoking `update_to` directly —
/// because callers here want by-reference ergonomics (a `&MaybeUndefined<T>`
/// patch applied against a `&mut Option<T>` destination) and a named seam
/// for the tri-state merge, matching [`append_chunk`]'s shape below.
pub fn apply_patch<T: Clone>(current: &mut Option<T>, patch: &MaybeUndefined<T>) {
    patch.clone().update_to(current);
}

/// §10.1: "chunks append." Deliberately a separate, trivial function from
/// [`apply_patch`] — a streamed chunk (e.g. `agent_message_chunk`) is never
/// tri-state; conflating the two would be exactly the kind of bug this v2
/// upsert model is designed to make impossible. The SDK has no equivalent of
/// this function — chunk streaming isn't a schema-merge concern at all.
pub fn append_chunk(target: &mut String, chunk: &str) {
    target.push_str(chunk);
}
