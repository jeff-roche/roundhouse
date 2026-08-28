/// A zero-sized marker only constructible inside `roundhouse-core`. Giving
/// `Event` one field of this type (see `event.rs`) makes `Event { .. }`
/// struct-literal syntax uncompilable from any other crate — the standard
/// Rust idiom for "all fields are public and readable, but only this crate
/// can construct the whole value." `TaskRunner` is the only thing that
/// mints one.
///
/// Deliberately **no `Default` impl.** An earlier draft of this task gave
/// `Seal` a `#[derive(Default)]` so `Event` could keep `#[derive(Deserialize)]`
/// with `#[serde(skip)]` on `_seal` (a skipped field needs `Default` to be
/// filled in on deserialize) — but that silently defeats S-LOG-1:
/// `serde_json::from_str::<Event>(..)` would fabricate a fully-formed
/// `Event` from *any* crate via `Seal::default()`, never touching
/// `TaskRunner`. `Event` no longer derives `Deserialize` at all (see
/// `event.rs` below) specifically to close that hole, and `Seal` staying
/// non-`Default` is a second, compiler-enforced tripwire: if `Deserialize`
/// is ever re-derived on `Event` in the future, that alone fails to compile
/// (`the trait bound 'Seal: Default' is not satisfied`) instead of silently
/// reopening the bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Seal(());

impl Seal {
    pub(crate) fn mint() -> Self {
        Seal(())
    }
}
