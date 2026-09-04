//! Ruling P104's enforcement leg: no migration may reach for
//! `ALTER TABLE … ADD CONSTRAINT`.
//!
//! The reason this needs a scan rather than a comment is that **the statement
//! works**. Measured on the bundled SQLite (3.53.2 in this tree,
//! `libsqlite3-sys` 0.38.2): `ALTER TABLE t ADD CONSTRAINT ck CHECK (…)` is
//! accepted, lands in `sqlite_master` as a genuine table-level constraint, and
//! is enforced — on a `STRICT` table. It is still not `ALTER TABLE` syntax;
//! the grammar covers only `RENAME TABLE`, `RENAME COLUMN`, `ADD COLUMN` and
//! `DROP COLUMN`. It survives because `ADD COLUMN` textually appends the
//! column-def to the stored `CREATE TABLE` text, and `CONSTRAINT … CHECK (…)`
//! re-parses in that position as a table constraint.
//!
//! So the ordinary controls do not catch it: it compiles, it passes its own
//! test, and it ships. What it produces is the worst-shaped failure available
//! — **a migration that works on today's parser and is rejected by a future
//! one, so existing installs keep working while fresh installs fail** — and
//! `rusqlite` is `features = ["bundled"]`, so a routine dependency bump is
//! what moves the parser. A reviewer who has not read P104 has no reason to
//! object to the statement; this scan is what makes the ruling durable.
//!
//! Per-column `CHECK`s written as part of an `ADD COLUMN` are real syntax and
//! are deliberately **not** matched here — migration 0008 uses them on eleven
//! columns. The pattern below requires the literal words `ALTER` and
//! `ADD CONSTRAINT`, which no `ADD COLUMN … CHECK (…)` contains.

use std::fs;
use xtask::scan::{scan_dir_for, scan_workspace_for};

/// The shared predicate, so the live scan and the self-test below cannot
/// diverge: a planted violation that the live scan would miss is not evidence
/// of anything.
///
/// Line-oriented, like every other scan in this directory. A statement split
/// across two source lines between `ALTER TABLE` and `ADD CONSTRAINT` would
/// evade it — stated rather than left to be discovered, and the reason the
/// migration module doc names the rule too. It is deliberately not anchored to
/// `migrations.rs`: the point is that no file anywhere reaches for the
/// statement, including a test that would "just check it works".
fn alter_table_add_constraint(line: &str) -> Option<String> {
    let upper = line.to_ascii_uppercase();
    let code = upper.trim_start();
    if code.starts_with("--") || code.starts_with("//") || code.starts_with("///") {
        return None;
    }
    if upper.contains("ALTER") && upper.contains("ADD CONSTRAINT") {
        Some("ALTER TABLE ... ADD CONSTRAINT (ruling P104)".to_string())
    } else {
        None
    }
}

#[test]
fn no_file_reaches_for_alter_table_add_constraint() {
    let violations = scan_workspace_for(alter_table_add_constraint);
    assert!(
        violations.is_empty(),
        "ALTER TABLE ... ADD CONSTRAINT is not SQLite syntax even though it works \
         (ruling P104); found: {violations:?}"
    );
}

/// The self-test: plants the statement in an isolated directory and asserts
/// the *same* predicate the live scan uses fires on it. Without this, a
/// predicate broken by a refactor would report a clean workspace forever and
/// the live assertion above would still pass.
///
/// Two benign negatives are planted alongside it — a per-column `CHECK` in an
/// `ADD COLUMN` (what migration 0008 actually writes) and a comment line
/// describing the banned statement (what this file's own module doc is made
/// of) — so the test pins that the scan distinguishes the three, not merely
/// that it fires on something.
#[test]
fn the_scan_fires_on_a_planted_add_constraint_and_not_on_a_legitimate_add_column() {
    let thread_id = format!("{:?}", std::thread::current().id())
        .replace("ThreadId(", "")
        .replace(")", "");
    // Under the workspace, not `/tmp`: ruling P91's fourth variant is a build
    // artefact leaking across worktrees through a `/tmp` path.
    let temp_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("xtask_add_constraint_scan_{thread_id}"));
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&temp_root).expect("create the scan's scratch directory");

    fs::write(
        temp_root.join("violation.rs"),
        "const M: &str = \"ALTER TABLE workflow_run ADD CONSTRAINT ck CHECK (a > 0);\";\n",
    )
    .unwrap();
    fs::write(
        temp_root.join("legitimate.rs"),
        "const M: &str = \"ALTER TABLE workflow_run ADD COLUMN parked_at INTEGER \
         CHECK (parked_at IS NULL OR parked_at >= 0);\";\n\
         -- ALTER TABLE t ADD CONSTRAINT ck CHECK (x); described, not written\n",
    )
    .unwrap();

    let hits = scan_dir_for(&temp_root, alter_table_add_constraint);
    let _ = fs::remove_dir_all(&temp_root);

    assert_eq!(
        hits.len(),
        1,
        "expected exactly the planted violation to fire, got {hits:?}"
    );
    assert!(
        hits[0].0.ends_with("violation.rs"),
        "the ADD COLUMN file and the comment line must not fire: {hits:?}"
    );
}
