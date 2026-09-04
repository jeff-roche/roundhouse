//! The **intra-crate** half of `BoundedStore`'s guarantee, which is the half
//! rulings P96 §C, P98 and P101 are actually about.
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
//! # What is being pinned: a field path and a method path
//!
//! Rust privacy is *"the defining module **and its descendants**"*. The pool
//! field is private to `crate::bounded`, so the set of code that can read it is
//! exactly `bounded` plus `bounded`'s descendants. **`bounded` having no
//! descendants is therefore the whole of the field path**, and "does this file
//! declare a module" is a source-text question with an exact answer.
//!
//! The second assertion is the other half of that sentence: the field is
//! **private**, with no visibility modifier at all. It does not follow from the
//! first — a future `pub(crate) inner` compiles, restores the reach to every
//! handler module, and leaves leafness untouched.
//!
//! The third assertion is a **different path to the same pool**, and closing
//! the field path did nothing about it (ruling P101). `StoreConnection` is a
//! newtype over `roundhouse_store::PooledConnection`, and a newtype inherits its
//! `Deref` target's entire inherent API — including
//! `deadpool::managed::Object::pool`, a back-reference handing out the `Pool`
//! itself. While `StoreConnection` deref'd *to* `PooledConnection`, this built
//! with exit 0 in `src/runs.rs`, using the connection a permit was legitimately
//! taken for:
//!
//! ```text
//! let conn = state.store_connection().await?;
//! let pool = roundhouse_store::PooledConnection::pool(&conn).unwrap();
//! let _unbounded = pool.get().await;              // no permit
//! ```
//!
//! It never names `inner`, so the two assertions above cannot see it, and no
//! compile-fail case can either: `StoreConnection` is `pub(crate)`, so an
//! out-of-crate harness cannot obtain one. The fix is to deref one level
//! *further* — `<PooledConnection as Deref>::Target`, which is what `.interact`
//! actually lives on — and the assertion below pins that the target stays the
//! projection. A future widening back to `PooledConnection` reopens the reach
//! silently, which is precisely what this test exists to make loud.
//!
//! Rejected, so it is not re-derived: scanning the crate's other modules for the
//! token `inner`, which is the standing form of the `grep` ruling P98 ran by
//! hand. It cannot work here. `lan_auth::BindConfig` has an `inner` field of its
//! own and `host_guard` binds an `inner` local, so the scan reports seven sites
//! that have nothing to do with the pool, and a test that must be taught to
//! ignore most of what it finds is one a future reader edits rather than obeys.
//! The three assertions below are exact and need no exceptions.
//!
//! # Why the scans are also run against planted violations
//!
//! `xtask/tests/no_raw_event_mutation.rs` carries
//! `scanner_detects_raw_update_events_when_present` for a reason that applies
//! here unchanged: a scan asserting *absence* passes just as green when it has
//! stopped being able to find anything. Widen [`code_lines`] to strip trailing
//! comments, or [`tokens`] to split on `<`, and these tests keep passing over a
//! file that has grown the hole they exist to catch.
//!
//! So each scan is also pointed at a fixture containing the violation it looks
//! for, and asserted to *fire*. The fixtures are in-test strings rather than
//! temp files — unlike the precedent's scanner, these take source text — and
//! they exercise the same functions the live tests call, which is the only
//! arrangement in which they prove anything about those tests.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn bounded_source() -> (PathBuf, String) {
    let path = src_dir().join("bounded.rs");
    let source = std::fs::read_to_string(&path).expect("src/bounded.rs is readable");
    (path, source)
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

/// Whether `source` declares a module — the scan behind
/// [`the_module_defining_the_pool_field_has_no_descendants`].
fn declares_a_module(source: &str) -> bool {
    code_lines(source)
        .iter()
        .any(|line| tokens(line).any(|token| token == "mod"))
}

/// Every code line in `source` that declares a field of the pool's type,
/// trimmed — the scan behind
/// [`the_pool_field_is_private_and_not_merely_crate_visible`].
fn pool_field_declarations(source: &str) -> Vec<&str> {
    code_lines(source)
        .into_iter()
        .map(str::trim)
        .filter(|line| line.contains("roundhouse_store::StorePool,"))
        .collect()
}

/// Every associated-type declaration naming `Target` in `source`, trimmed — the
/// scan behind [`the_connection_derefs_past_the_type_that_owns_the_pool_handle`].
///
/// Both tokens are required. `Target` alone also matches
/// `fn deref(&self) -> &Self::Target {`, which is the impl's *body* and says
/// nothing about the target; `type` alone would match any future alias.
fn deref_target_declarations(source: &str) -> Vec<&str> {
    code_lines(source)
        .into_iter()
        .map(str::trim)
        .filter(|line| {
            let mut saw_type = false;
            let mut saw_target = false;
            for token in tokens(line) {
                saw_type |= token == "type";
                saw_target |= token == "Target";
            }
            saw_type && saw_target
        })
        .collect()
}

/// **`bounded` is a leaf module, and that is the whole of the field path.**
///
/// The day this file grows a `mod` — most plausibly a `mod tests` for a unit
/// test, which is the innocent-looking version — the new module is a descendant
/// and can read the pool straight out of `inner`, and `AppState::store_connection`
/// stops being how a connection is taken. That is not hypothetical: it is the
/// state the crate was in one commit ago, with `lib.rs` as the defining module
/// and every handler module its descendant.
///
/// Unit tests for anything in `bounded.rs` go in a `tests/` target, which is a
/// separate crate and reaches only the public surface.
#[test]
fn the_module_defining_the_pool_field_has_no_descendants() {
    let (path, source) = bounded_source();

    assert!(
        !declares_a_module(&source),
        "{} declares a module. A private field is visible to its defining module *and its \
         descendants*, so a submodule here can read `BoundedStore::inner` and take a pool \
         connection outside `ApiPoolPermits` — ruling P93 §B's writer starvation, and the exact \
         hole ruling P98 recorded. Put the code somewhere else, or the field stops meaning \
         anything.",
        path.display()
    );
}

/// The pool field carries **no visibility modifier**, which is the other half
/// of the field path and the half a leafness check says nothing about.
///
/// `pub(crate) inner` compiles, keeps `bounded` a leaf, and hands the pool back
/// to every handler module in the crate — the precise state ruling P98 found the
/// crate in. The declaration is matched whole rather than searched for a `pub`,
/// so a rename is a failure too: this test is the only thing that knows which
/// field it is talking about.
#[test]
fn the_pool_field_is_private_and_not_merely_crate_visible() {
    const DECLARATION: &str = "inner: roundhouse_store::StorePool,";

    let (path, source) = bounded_source();

    assert_eq!(
        pool_field_declarations(&source),
        vec![DECLARATION],
        "`BoundedStore`'s pool field must be declared exactly `{DECLARATION}` in {}. Anything \
         wider — `pub(crate)` most plausibly — puts a pool connection back within reach of every \
         handler module in this crate, outside the permit that bounds it (ruling P93 §B).",
        path.display()
    );
}

/// **The method path: `StoreConnection` must deref *past* the type that owns
/// `deadpool`'s pool back-reference, not to it.** Ruling P101.
///
/// `PooledConnection` is `deadpool::managed::Object`, whose inherent
/// `pub fn pool(this: &Self) -> Option<Pool<M>>` hands out the pool itself. A
/// `StoreConnection` deref'ing to it re-exposes that function to every handler,
/// reopening ruling P93 §B through an expression that names neither `inner` nor
/// `deadpool` — invisible to both tests above and to `tests/compile_fail.rs`.
///
/// Deref'ing to `<PooledConnection as Deref>::Target` keeps `.interact`, which
/// is what handlers use and which lives one step further down on
/// `deadpool_sync::SyncWrapper`, and makes `PooledConnection::pool(&conn)` an
/// `E0308`. That target's own inherent API was enumerated rather than assumed —
/// `new`, `interact`, `is_mutex_poisoned`, `lock`, `try_lock` — and it holds no
/// back-reference to the pool and implements no further `Deref`, so the chain
/// terminates here.
///
/// The target is written as the projection rather than spelled out because
/// naming `SyncWrapper<rusqlite::Connection>` would need two dependencies this
/// crate deliberately does not have (ruling P86). Matching the whole
/// declaration is what makes a *widening* fail rather than only a deletion, and
/// collecting every `type ... Target` line in the file is what makes a second
/// `Deref` impl fail too — either is a change to this type's reach that should
/// be looked at.
#[test]
fn the_connection_derefs_past_the_type_that_owns_the_pool_handle() {
    const DECLARATION: &str =
        "type Target = <roundhouse_store::PooledConnection as std::ops::Deref>::Target;";

    let (path, source) = bounded_source();

    assert_eq!(
        deref_target_declarations(&source),
        vec![DECLARATION],
        "`StoreConnection`'s `Deref` target must be declared exactly `{DECLARATION}` in {}. \
         Deref'ing to `roundhouse_store::PooledConnection` itself re-exposes \
         `deadpool::managed::Object::pool`, so a handler holding one permitted connection can \
         mint unbounded ones from the pool it hands back (rulings P93 §B and P101).",
        path.display()
    );
}

/// The leafness scan fires on a file that declares a module.
///
/// Without this, widening [`tokens`] — splitting on `<` as well, say, so that
/// `mod` stops being produced as a bare token — leaves
/// [`the_module_defining_the_pool_field_has_no_descendants`] green over a
/// `bounded.rs` that has grown a descendant. The fixture is the innocent-looking
/// version the live test names, plus the two spellings that are easy to miss.
#[test]
fn the_leafness_scan_fires_on_a_planted_module() {
    for planted in [
        "#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n",
        "mod evil;\n",
        "pub(crate) mod helpers {}\n",
    ] {
        assert!(
            declares_a_module(planted),
            "the leafness scan did not fire on a planted module: {planted:?}"
        );
    }

    // And does not fire on text that merely contains the letters. `MODEL` and
    // `model` are substrings of neither concern; the word "module" inside a doc
    // line is stripped before tokenizing.
    for benign in [
        "const MODEL: &str = \"opus\";\n",
        "fn model() -> u8 { 0 }\n",
        "/// A module is a thing this comment mentions.\n",
    ] {
        assert!(
            !declares_a_module(benign),
            "the leafness scan fired on benign source: {benign:?}"
        );
    }
}

/// The field and `Deref` scans fire on planted widenings.
///
/// Same purpose as the test above, for the other two assertions: a
/// [`code_lines`] that stripped trailing comments, or a `contains` narrowed to a
/// longer literal, would leave both live tests green over a `pub(crate) inner`
/// or a `Deref` pointed back at `PooledConnection`. Each fixture is asserted to
/// produce a declaration list that is *not* the accepted one, which is exactly
/// what makes the live `assert_eq!` fail.
#[test]
fn the_declaration_scans_fire_on_planted_widenings() {
    const FIELD: &str = "inner: roundhouse_store::StorePool,";
    const TARGET: &str =
        "type Target = <roundhouse_store::PooledConnection as std::ops::Deref>::Target;";

    for planted in [
        "    pub(crate) inner: roundhouse_store::StorePool,\n",
        "    pub inner: roundhouse_store::StorePool,\n",
        "    inner: roundhouse_store::StorePool,\n    second: roundhouse_store::StorePool,\n",
        "    pool: roundhouse_store::StorePool,\n",
    ] {
        assert_ne!(
            pool_field_declarations(planted),
            vec![FIELD],
            "the pool-field scan accepted a planted widening: {planted:?}"
        );
    }

    for planted in [
        "    type Target = roundhouse_store::PooledConnection;\n",
        "    type Target = deadpool_sqlite::Object;\n",
        "    type Target = <roundhouse_store::PooledConnection as std::ops::Deref>::Target;\n    \
         type Target = roundhouse_store::PooledConnection;\n",
    ] {
        assert_ne!(
            deref_target_declarations(planted),
            vec![TARGET],
            "the deref-target scan accepted a planted widening: {planted:?}"
        );
    }

    // Both scans still accept the accepted forms, so the assertions above are
    // discrimination and not a scan that rejects everything.
    assert_eq!(
        pool_field_declarations(&format!("    {FIELD}\n")),
        vec![FIELD]
    );
    assert_eq!(
        deref_target_declarations(&format!("    {TARGET}\n")),
        vec![TARGET]
    );
}
