//! Edit executor with fail-closed semantics on ambiguous matches.

use std::path::Path;

use crate::error::ToolError;
use crate::write::write_file;

/// Outcome of a successful edit operation.
pub struct EditOutcome {
    /// Unified diff of the change.
    pub diff: String,
}

/// Edits a file by replacing the first (and only) occurrence of `find` with `replace`.
///
/// This function implements fail-closed semantics (S-TOOL-3): if the search text
/// appears 0 times or 2+ times, returns an error and the file on disk is provably
/// byte-for-byte unchanged. This design prevents silent corruption from ambiguous
/// matches or accidental no-ops.
///
/// This is especially important because this tool is eventually driven by LLM
/// tool-call output, which may be mistaken or adversarial. Silently editing the
/// wrong occurrence (or guessing) on ambiguous input would be a real data-corruption
/// risk on a user's actual files. The strict refuse-to-guess posture is non-negotiable,
/// not just a nice-to-have.
///
/// The actual write is atomic via `write_file` (Task 15), which uses temp+rename
/// on the same filesystem.
pub async fn edit_file(path: &Path, find: &str, replace: &str) -> Result<EditOutcome, ToolError> {
    let original = tokio::fs::read_to_string(path).await?;

    // Count occurrences of the search text. Fail closed on 0 or 2+ matches
    // to prevent silent corruption or ambiguous edits (S-TOOL-3).
    let occurrences = original.matches(find).count();
    if occurrences == 0 {
        return Err(ToolError::NoMatch);
    }
    if occurrences > 1 {
        return Err(ToolError::AmbiguousMatch(occurrences));
    }

    // Exactly one match: safe to replace.
    let updated = original.replacen(find, replace, 1);
    let diff = diffy::create_patch(&original, &updated).to_string();

    // write_file is atomic (temp+rename, Task 15) — either the whole new content lands or
    // the original file is left exactly as it was.
    write_file(path, updated.as_bytes()).await?;

    Ok(EditOutcome { diff })
}
