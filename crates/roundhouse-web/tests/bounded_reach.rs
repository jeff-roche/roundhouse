//! The **intra-crate** half of `BoundedStore`'s guarantee, which is the half
//! rulings P96 §C and P98 are actually about.
//!
//! # Why this is a source scan and not a compile-fail case
//!
//! Not a preference — the two obvious harnesses are both structurally incapable
//! of it, and each was checked rather than assumed:
//!
//! - **`trybuild`** compiles each `tests/ui/*.rs` case as its own crate. It can
//!   only ever test the out-of-crate direction, which holds no matter which
//!   module inside `roundhouse-web` defines the field. That case still exists
//!   (`tests/compile_fail.rs`) because that direction is real; it is just a
//!   different one.
//! - **A `compile_fail` doctest** is the same thing. Measured on a throwaway
//!   crate rather than recalled: a doctest body naming `crate::S` fails with
//!   `E0433: cannot find S in crate`, and one naming a private field of the
//!   crate it documents fails with the same `E0616` `trybuild` gives. Rustdoc
//!   compiles doctests as separate crates that `extern crate` the library, so a
//!   doctest is an out-of-crate harness wearing an in-crate file path.
//!
//! There is no in-crate compile-fail mechanism in Rust, so the property has to
//! be pinned where it is actually decided: in the source.
//!
//! # What is being pinned, and why these two assertions are the whole of it
//!
//! Rust privacy is *"the defining module **and its descendants**"*. The pool
//! field is private to `crate::bounded`, so the set of code that can read it is
//! exactly `bounded` plus `bounded`'s descendants. **`bounded` having no
//! descendants is therefore the entire guarantee**, and "does this file declare
//! a module" is a source-text question with an exact answer.
//!
//! The second assertion is the other half of that sentence: the field is
//! **private**, with no visibility modifier at all. It does not follow from the
//! first — a future `pub(crate) inner` compiles, restores the reach to every
//! handler module, and leaves leafness untouched.
//!
//! Rejected, so it is not re-derived: scanning the crate's other modules for the
//! token `inner`, which is the standing form of the `grep` ruling P98 ran by
//! hand. It cannot work here. `lan_auth::BindConfig` has an `inner` field of its
//! own and `host_guard` binds an `inner` local, so the scan reports seven sites
//! that have nothing to do with the pool, and a test that must be taught to
//! ignore most of what it finds is one a future reader edits rather than obeys.
//! The two assertions below are exact and need no exceptions.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Everything outside a whole-line `//` comment.
///
/// Whole-line only, deliberately: stripping to the first `//` anywhere would
/// also eat the inside of a string literal containing a URL. A trailing comment
/// that happens to contain one of the words below therefore fails this test
/// rather than passing it, which is the direction to be wrong in.
fn code_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

fn tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
}

/// **`bounded` is a leaf module, and that is the whole of `BoundedStore`'s
/// bound.**
///
/// The day this file grows a `mod` — most plausibly a `mod tests` for a unit
/// test, which is the innocent-looking version — the new module is a descendant
/// and can read the pool straight out of `inner`, and `AppState::store_connection`
/// stops being the only way to take a connection. That is not hypothetical: it
/// is the state the crate was in one commit ago, with `lib.rs` as the defining
/// module and every handler module its descendant.
///
/// Unit tests for anything in `bounded.rs` go in a `tests/` target, which is a
/// separate crate and reaches only the public surface.
#[test]
fn the_module_defining_the_pool_field_has_no_descendants() {
    let path = src_dir().join("bounded.rs");
    let source = std::fs::read_to_string(&path).expect("src/bounded.rs is readable");

    let declares_a_module = code_lines(&source)
        .iter()
        .any(|line| tokens(line).any(|token| token == "mod"));

    assert!(
        !declares_a_module,
        "{} declares a module. A private field is visible to its defining module *and its \
         descendants*, so a submodule here can read `BoundedStore::inner` and take a pool \
         connection outside `ApiPoolPermits` — ruling P93 §B's writer starvation, and the exact \
         hole ruling P98 recorded. Put the code somewhere else, or the field stops meaning \
         anything.",
        path.display()
    );
}

/// The pool field carries **no visibility modifier**, which is the other half
/// of the guarantee and the half a leafness check says nothing about.
///
/// `pub(crate) inner` compiles, keeps `bounded` a leaf, and hands the pool back
/// to every handler module in the crate — the precise state ruling P98 found the
/// crate in. The declaration is matched whole rather than searched for a `pub`,
/// so a rename is a failure too: this test is the only thing that knows which
/// field it is talking about.
#[test]
fn the_pool_field_is_private_and_not_merely_crate_visible() {
    const DECLARATION: &str = "inner: roundhouse_store::StorePool,";

    let path = src_dir().join("bounded.rs");
    let source = std::fs::read_to_string(&path).expect("src/bounded.rs is readable");

    let declarations: Vec<&str> = code_lines(&source)
        .into_iter()
        .map(str::trim)
        .filter(|line| line.contains("roundhouse_store::StorePool,"))
        .collect();

    assert_eq!(
        declarations,
        vec![DECLARATION],
        "`BoundedStore`'s pool field must be declared exactly `{DECLARATION}` in {}. Anything \
         wider — `pub(crate)` most plausibly — puts a pool connection back within reach of every \
         handler module in this crate, outside the permit that bounds it (ruling P93 §B).",
        path.display()
    );
}
