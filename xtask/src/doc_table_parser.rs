//! Parses the Cargo-workspace crate-dependency table that
//! `docs/architecture/02-system-architecture.md` §5.2 defines, directly out
//! of the doc's markdown text.
//!
//! This exists so `xtask/tests/workspace_shape.rs`'s drift guard can compare
//! real `Cargo.toml` dependencies against what the doc *actually currently
//! says*, instead of a hand-maintained mirror of it (`EXPECTED_EDGES`, which
//! this parser exists to make retirable) that can silently drift from either
//! side.
//!
//! The `Depends on` column is prose, not a clean token list: it carries
//! parenthetical rationale (sometimes containing commas, nested parens, and
//! crate names of its own), a couple of rows fall back to an em-dash-led
//! "no dependency" note, and one row (`roundhouse-daemon`) continues past
//! its dependency list with trailing prose in a *negative* sense. This
//! module has to see through all of that without ever silently dropping a
//! token it doesn't understand — anything it can't fully account for is a
//! [`ParseError`], never a skip.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

/// The exact header row §5.2's table starts with. Finding this line is how
/// the parser locates the table without assuming it's the only table (or
/// the first one) in the document.
const HEADER_ROW: &str = "| Crate | Responsibility | Depends on |";

/// A single em dash. `roundhouse-core`'s cell is exactly this (no internal
/// dependency); other cells use it, once parenthetical rationale is
/// stripped, to introduce prose that isn't part of the dependency list.
const EM_DASH: char = '—';

/// Something about §5.2's table (or one of its rows) that this parser could
/// not fully account for. Every variant carries enough context to point
/// straight at the offending row/token — this parser never silently skips
/// something it can't read.
#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The `| Crate | Responsibility | Depends on |` header row (and/or its
    /// `|---|---|---|` delimiter) could not be found.
    TableNotFound,
    /// A table row did not split into exactly the three expected columns.
    MalformedRow { row: String },
    /// A `Depends on` cell's parentheses don't balance.
    UnbalancedParens { crate_name: String, cell: String },
    /// A dependency token, once normalized, doesn't correspond to any
    /// `crates/<name>` directory in the workspace.
    UnknownDependency { crate_name: String, token: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::TableNotFound => write!(
                f,
                "could not find the §5.2 '| Crate | Responsibility | Depends on |' table header"
            ),
            ParseError::MalformedRow { row } => {
                write!(f, "table row did not split into exactly 3 cells: {row:?}")
            }
            ParseError::UnbalancedParens { crate_name, cell } => write!(
                f,
                "{crate_name}: unbalanced parentheses in 'Depends on' cell: {cell:?}"
            ),
            ParseError::UnknownDependency { crate_name, token } => write!(
                f,
                "{crate_name}: doc claims a dependency on {token:?}, which does not normalize \
                 to an existing crates/<name> directory"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parses §5.2's crate-dependency table out of `doc_text`, returning each
/// crate's internal (`roundhouse-*`) dependency edges, sorted.
///
/// Never silently drops a row or a token: anything the table's prose
/// contains that this parser cannot fully enumerate is a [`ParseError`].
pub fn parse_dependency_table(doc_text: &str) -> Result<HashMap<String, Vec<String>>, ParseError> {
    let mut lines = doc_text.lines();

    // Find the header row.
    let found_header = lines.by_ref().any(|line| line.trim() == HEADER_ROW);
    if !found_header {
        return Err(ParseError::TableNotFound);
    }

    // The very next line must be the `|---|---|---|` delimiter row.
    let delimiter = lines.next().ok_or(ParseError::TableNotFound)?;
    if !delimiter.trim().starts_with("|---") {
        return Err(ParseError::TableNotFound);
    }

    let mut result = HashMap::new();
    for line in lines {
        let trimmed = line.trim();
        if !trimmed.starts_with('|') {
            // Blank line (or anything else): the table has ended.
            break;
        }
        let [crate_cell, _responsibility_cell, deps_cell] = split_row(trimmed)?;
        let crate_name = normalize_token(crate_cell);
        let deps = parse_deps_cell(&crate_name, deps_cell)?;
        result.insert(crate_name, deps);
    }

    Ok(result)
}

/// Splits one `| a | b | c |` row into exactly 3 trimmed cells. A row that
/// doesn't split into exactly that shape (extra/missing `|`, cell content
/// that isn't sandwiched by exactly two boundary pipes) is a
/// [`ParseError`], not something to salvage by best-effort splitting.
fn split_row(row: &str) -> Result<[&str; 3], ParseError> {
    let parts: Vec<&str> = row.split('|').collect();
    if parts.len() != 5 || !parts[0].trim().is_empty() || !parts[4].trim().is_empty() {
        return Err(ParseError::MalformedRow {
            row: row.to_string(),
        });
    }
    Ok([parts[1].trim(), parts[2].trim(), parts[3].trim()])
}

/// Removes every parenthetical group from `cell` via a balanced-paren scan
/// (not a regex, since these parentheticals nest and carry commas and their
/// own crate names). Returns an error if the parens in `cell` don't
/// balance.
fn strip_parens(crate_name: &str, cell: &str) -> Result<String, ParseError> {
    let mut out = String::with_capacity(cell.len());
    let mut depth: i32 = 0;
    for ch in cell.chars() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(ParseError::UnbalancedParens {
                        crate_name: crate_name.to_string(),
                        cell: cell.to_string(),
                    });
                }
            }
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ParseError::UnbalancedParens {
            crate_name: crate_name.to_string(),
            cell: cell.to_string(),
        });
    }
    Ok(out)
}

/// Normalizes one dependency (or crate-name) token: strips backticks and
/// `**bold**` asterisks, trims whitespace, and prefixes `roundhouse-` if
/// it's not already present (so `core`, `` `roundhouse-core` ``, and
/// `**core**` all normalize to `roundhouse-core`).
fn normalize_token(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| *c != '`' && *c != '*').collect();
    let cleaned = cleaned.trim();
    if cleaned.starts_with("roundhouse-") {
        cleaned.to_string()
    } else {
        format!("roundhouse-{cleaned}")
    }
}

/// Parses one `Depends on` cell into a sorted list of internal dependency
/// names.
fn parse_deps_cell(crate_name: &str, cell: &str) -> Result<Vec<String>, ParseError> {
    let stripped = strip_parens(crate_name, cell)?;
    let trimmed = stripped.trim();

    if trimmed == EM_DASH.to_string() {
        return Ok(Vec::new());
    }

    // Trailing em-dash prose (e.g. `roundhouse-daemon`'s row continues past
    // its dependency list with negative-sense prose about crates it does
    // NOT depend on). Cut at the first ` — ` and parse only what precedes
    // it. This runs *after* paren-stripping, since some rows' parenthetical
    // rationale contains its own ` — ` that must not trigger the cut.
    let dash_pattern = format!(" {EM_DASH} ");
    let before_dash = match trimmed.find(&dash_pattern) {
        Some(idx) => &trimmed[..idx],
        None => trimmed,
    };

    let mut deps = Vec::new();
    for token in before_dash.split(',') {
        if token.trim().is_empty() {
            return Err(ParseError::UnknownDependency {
                crate_name: crate_name.to_string(),
                token: token.to_string(),
            });
        }
        let normalized = normalize_token(token);
        if !crate_dir_exists(&normalized) {
            return Err(ParseError::UnknownDependency {
                crate_name: crate_name.to_string(),
                token: normalized,
            });
        }
        deps.push(normalized);
    }
    deps.sort();
    Ok(deps)
}

/// Whether `name` corresponds to a real `crates/<name>` directory in this
/// workspace. Uses `CARGO_MANIFEST_DIR` (this crate, `xtask`, lives at the
/// workspace root's `xtask/` directory) the same way
/// `xtask/tests/workspace_shape.rs`'s own helpers locate the workspace root.
fn crate_dir_exists(name: &str) -> bool {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent directory (the workspace root)");
    workspace_root.join("crates").join(name).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(deps_cell: &str) -> String {
        format!("{HEADER_ROW}\n|---|---|---|\n| `roundhouse-x` | does things | {deps_cell} |\n")
    }

    #[test]
    fn bare_em_dash_means_no_dependencies() {
        let parsed = parse_dependency_table(&table("—")).unwrap();
        assert_eq!(parsed["roundhouse-x"], Vec::<String>::new());
    }

    #[test]
    fn em_dash_with_trailing_parenthetical_still_means_no_dependencies() {
        let parsed =
            parse_dependency_table(&table("— (no internal `roundhouse-*` dependency)")).unwrap();
        assert_eq!(parsed["roundhouse-x"], Vec::<String>::new());
    }

    #[test]
    fn nested_and_comma_bearing_parentheticals_are_stripped() {
        let parsed = parse_dependency_table(&table(
            "core, store (Task 1, Phase 2: some rationale naming core, engine, and store \
             inside prose (plus a nested aside) that must not leak into the parsed set)",
        ))
        .unwrap();
        assert_eq!(
            parsed["roundhouse-x"],
            vec![
                "roundhouse-core".to_string(),
                "roundhouse-store".to_string()
            ]
        );
    }

    #[test]
    fn trailing_em_dash_prose_is_cut_after_paren_stripping() {
        // The em dash sits INSIDE the parenthetical here, so paren-stripping
        // must remove it before any "cut at first em dash" logic runs, or
        // this would wrongly truncate to just `core`.
        let parsed = parse_dependency_table(&table(
            "core, store (a deliberate deviation — see the crate's own Cargo.toml comment)",
        ))
        .unwrap();
        assert_eq!(
            parsed["roundhouse-x"],
            vec![
                "roundhouse-core".to_string(),
                "roundhouse-store".to_string()
            ]
        );

        // Here the em dash is at the top level (outside any parens), so the
        // cut must apply and only `core, store` survive.
        let parsed2 = parse_dependency_table(&table(
            "core, store — no direct `roundhouse-net` edge of its own",
        ))
        .unwrap();
        assert_eq!(
            parsed2["roundhouse-x"],
            vec![
                "roundhouse-core".to_string(),
                "roundhouse-store".to_string()
            ]
        );
    }

    #[test]
    fn three_name_spellings_all_normalize_the_same_way() {
        let parsed =
            parse_dependency_table(&table("core, `roundhouse-store`, **provider**")).unwrap();
        assert_eq!(
            parsed["roundhouse-x"],
            vec![
                "roundhouse-core".to_string(),
                "roundhouse-provider".to_string(),
                "roundhouse-store".to_string(),
            ]
        );
    }

    #[test]
    fn unknown_dependency_token_is_a_parse_error_not_a_silent_drop() {
        let err = parse_dependency_table(&table("core, not-a-real-crate")).unwrap_err();
        match err {
            ParseError::UnknownDependency { crate_name, token } => {
                assert_eq!(crate_name, "roundhouse-x");
                assert_eq!(token, "roundhouse-not-a-real-crate");
            }
            other => panic!("expected UnknownDependency, got {other:?}"),
        }
    }

    #[test]
    fn a_row_that_does_not_split_into_exactly_three_cells_is_a_parse_error() {
        let doc = format!("{HEADER_ROW}\n|---|---|---|\n| `roundhouse-x` | only two cells |\n");
        let err = parse_dependency_table(&doc).unwrap_err();
        assert!(matches!(err, ParseError::MalformedRow { .. }));
    }

    #[test]
    fn unbalanced_parens_are_a_parse_error() {
        let err = parse_dependency_table(&table("core, store (unterminated")).unwrap_err();
        assert!(matches!(err, ParseError::UnbalancedParens { .. }));
    }

    #[test]
    fn missing_header_is_a_parse_error() {
        let err = parse_dependency_table("no table here at all").unwrap_err();
        assert_eq!(err, ParseError::TableNotFound);
    }
}
