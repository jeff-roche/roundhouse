//! The "blocked-anywhere" query (S-OBS-4): one indexed scan across every session's
//! `tasks` row that finds every currently `Suspended` task — approvals, elicits,
//! peer waits, workflow gates alike — kind-agnostic on purpose, so a Phase 5 `flow`
//! gate needs no change here. This is the foundational query the attention-queue UI
//! (§3.2) is built on: a human operator needs to see everything blocked-on-them
//! across their entire workspace in one fast query, not per-session polling.
//!
//! Follows `suspended.rs`'s already-shipped, real precedent (`suspended_tasks`)
//! rather than the task brief's fictional fine-grained `tasks.status` values: the
//! real `tasks` table's `state` CHECK constraint allows exactly one generic
//! `'Suspended'` value for every suspend reason (`migrations.rs`) — the actual
//! reason detail lives only in the `suspend_reason_json` column. So this query
//! filters SQL-side only on `state = 'Suspended'` (backed by
//! `idx_tasks_suspended`, migration 0005) and deserializes the real `SuspendReason`
//! from `suspend_reason_json` in Rust, exactly like `suspended_tasks` does.
//!
//! Unlike `suspended_tasks`, `blocked_anywhere` also reads back `tasks.kind` (via
//! `parse_task_kind`, below) and `tasks.suspended_since` — `suspended_tasks` never
//! needed either. `tasks.kind` is written as `TaskKind`'s `Debug` representation
//! (`tasks_view::task_kind_as_sql_str`), and — per that function's own doc comment —
//! no code had ever needed to parse it back until now; `parse_task_kind` is that
//! first real reader.
//!
//! **This is a fragile, implicit, untyped cross-crate contract, not a compiler-
//! enforced one** — the same category of risk `cost.rs`'s
//! `provider_and_model_from_output` doc comment calls out for its own analogous
//! situation, stated here with the same explicitness: `#[derive(Debug)]`'s output
//! format is not a stable, guaranteed serialization format. There is nothing tying
//! `task_kind_as_sql_str` (the writer, in `tasks_view.rs`) to `parse_task_kind`
//! (the reader, below) at compile time — a future Rust toolchain change to how
//! `derive(Debug)` formats struct variants, or someone adding/renaming a field on
//! `TaskKind::Plugin`, would silently desync them, and the failure mode would only
//! surface at runtime (as `parse_task_kind` returning `None` for a value it used
//! to parse, or worse, if the new shape happened to still parse, as a wrong
//! result). Anyone touching `TaskKind`'s definition or `task_kind_as_sql_str`
//! needs to know `parse_task_kind` depends on the exact current shape.
//!
//! A hand-rolled parser (rather than a real `Display`/`FromStr` round-trip pair
//! added to `TaskKind` itself, in `roundhouse-core`) was a deliberate, narrower
//! scope call for this task specifically — it keeps the change contained to this
//! one reader in `roundhouse-store` rather than touching the shared core type and
//! its writer. It is not the only reasonable design, and it is not necessarily the
//! permanent one: if a second crate ever needs to read `tasks.kind` back into a
//! `TaskKind`, that is the point to reconsider a real `Display`/`FromStr` pair on
//! `TaskKind` (with an explicit `vendor:verb` encoding for `Plugin`, as
//! `tasks_view.rs`'s own doc comment already speculates) so both crates share one
//! source of truth instead of each hand-rolling their own parser against
//! `Debug`'s output.

use roundhouse_core::{SessionId, SuspendReason, TaskId, TaskKind, Timestamp};

use crate::{pool::StorePool, StoreError};

/// One task found `Suspended` anywhere in the whole daemon: which session it
/// belongs to, its kind, its real (not placeholder) `SuspendReason`, and how long
/// it has been waiting.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockedTask {
    pub session_id: SessionId,
    pub task_id: TaskId,
    pub kind: TaskKind,
    pub reason: SuspendReason,
    pub since: Timestamp,
}

/// One row read back from the `tasks` table for a `Suspended` task:
/// `(task_id, session_id, kind, suspend_reason_json, suspended_since)`.
type BlockedRow = (String, String, String, Option<String>, Option<i64>);

/// The one query the attention queue is built on: every `Suspended` task across
/// every session, ordered by how long it has been waiting (oldest first) — the
/// natural order for an operator working through a queue.
///
/// Backed by `idx_tasks_suspended` (a partial index on `tasks(state,
/// suspended_since) WHERE state = 'Suspended'`), so the query is a fast index
/// range scan rather than a full-table scan even at 10,000-session scale
/// (S-OBS-4's ≤50ms budget).
///
/// Fail-closed, matching `suspended_tasks`'s established convention: a `Suspended`
/// row with a `NULL`/malformed `suspend_reason_json`, a `NULL`/unparseable
/// `suspended_since`, or an unparseable `kind` is a hard `StoreError` for that row
/// — never silently skipped, never defaulted to something plausible-looking.
pub async fn blocked_anywhere(store: &StorePool) -> Result<Vec<BlockedTask>, StoreError> {
    let conn = store.pool.get().await?;

    let rows_result = conn
        .interact(|c| -> Result<Vec<BlockedRow>, rusqlite::Error> {
            let mut stmt = c.prepare_cached(
                "SELECT task_id, session_id, kind, suspend_reason_json, suspended_since \
                 FROM tasks \
                 WHERE state = 'Suspended' \
                 ORDER BY suspended_since ASC",
            )?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .map_err(|e| StoreError::Interact(e.to_string()))?;

    let rows = rows_result.map_err(StoreError::Sqlite)?;

    let mut blocked = Vec::with_capacity(rows.len());
    for (task_id_str, session_id_str, kind_str, reason_json, suspended_since) in rows {
        let task_id =
            TaskId::from_uuid(uuid::Uuid::parse_str(&task_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt task_id in tasks table: {e}"))
            })?);
        let session_id =
            SessionId::from_uuid(uuid::Uuid::parse_str(&session_id_str).map_err(|e| {
                StoreError::Interact(format!("corrupt session_id in tasks table: {e}"))
            })?);

        let kind = parse_task_kind(&kind_str).ok_or_else(|| {
            StoreError::Interact(format!(
                "corrupt tasks.kind for task {task_id}: {kind_str:?} is not a valid \
                 TaskKind Debug representation"
            ))
        })?;

        let Some(reason_json) = reason_json else {
            return Err(StoreError::Interact(format!(
                "data inconsistency: tasks row for task {task_id} has state = 'Suspended' \
                 but suspend_reason_json is NULL (Task 0.5 sets both together — this should \
                 never happen)"
            )));
        };
        let reason: SuspendReason = serde_json::from_str(&reason_json).map_err(|e| {
            StoreError::Interact(format!(
                "corrupt suspend_reason_json for task {task_id}: {e}"
            ))
        })?;

        let Some(suspended_since) = suspended_since else {
            return Err(StoreError::Interact(format!(
                "data inconsistency: tasks row for task {task_id} has state = 'Suspended' \
                 but suspended_since is NULL (Task 0.5 sets both together — this should \
                 never happen)"
            )));
        };
        let since = Timestamp::from_unix_nanos(suspended_since);

        blocked.push(BlockedTask {
            session_id,
            task_id,
            kind,
            reason,
            since,
        });
    }

    Ok(blocked)
}

/// Parses `tasks.kind` back into a `TaskKind`. The column is written via
/// `tasks_view::task_kind_as_sql_str` as `TaskKind`'s `Debug` representation —
/// every flat variant Debug-formats to its bare name (`"Shell"`, `"Elicit"`, ...),
/// and the one struct variant, `Plugin { vendor, verb }`, Debug-formats to
/// `Plugin { vendor: "x", verb: "y" }`. This is the first real reader of that
/// column (see `tasks_view.rs`'s own comment: "no code parses `tasks.kind` back
/// into a `TaskKind` today") — returns `None` for anything that doesn't match one
/// of `TaskKind`'s real variants, so a corrupt/unrecognized value becomes the
/// caller's fail-closed `StoreError`, never a silent guess.
fn parse_task_kind(s: &str) -> Option<TaskKind> {
    match s {
        "Chat" => Some(TaskKind::Chat),
        "Infer" => Some(TaskKind::Infer),
        "Shell" => Some(TaskKind::Shell),
        "Read" => Some(TaskKind::Read),
        "Write" => Some(TaskKind::Write),
        "Edit" => Some(TaskKind::Edit),
        "Find" => Some(TaskKind::Find),
        "Http" => Some(TaskKind::Http),
        "Web" => Some(TaskKind::Web),
        "Mcp" => Some(TaskKind::Mcp),
        "Git" => Some(TaskKind::Git),
        "Memory" => Some(TaskKind::Memory),
        "Agent" => Some(TaskKind::Agent),
        "Message" => Some(TaskKind::Message),
        "Compact" => Some(TaskKind::Compact),
        "Checkpoint" => Some(TaskKind::Checkpoint),
        "Plan" => Some(TaskKind::Plan),
        "Elicit" => Some(TaskKind::Elicit),
        "Flow" => Some(TaskKind::Flow),
        "Report" => Some(TaskKind::Report),
        other => parse_plugin_task_kind(other),
    }
}

/// Parses the `Plugin { vendor: "..", verb: ".." }` Debug form specifically.
/// Deliberately a hand-rolled, careful string parse (not a general Debug
/// parser) — the exact literal shape Rust's derived `Debug` produces for a
/// struct variant with two `String` fields, including the quoting/escaping
/// `Debug`'s `String` impl applies to each field value.
fn parse_plugin_task_kind(s: &str) -> Option<TaskKind> {
    let rest = s.strip_prefix("Plugin { vendor: ")?;
    let (vendor, rest) = parse_debug_quoted_string(rest)?;
    let rest = rest.strip_prefix(", verb: ")?;
    let (verb, rest) = parse_debug_quoted_string(rest)?;
    let rest = rest.strip_prefix(" }")?;
    if !rest.is_empty() {
        return None;
    }
    Some(TaskKind::Plugin { vendor, verb })
}

/// Parses one `Debug`-quoted Rust string literal (e.g. `"foo\"bar"`) from the
/// start of `s`, returning the unescaped value and the remaining tail.
///
/// Handles every escape form Rust's `Debug` impl for `char`/`str`/`String` can
/// emit: `\"`, `\\`, `\n`, `\r`, `\t`, `\0` (NUL), and `\u{XXXX}` (emitted for
/// any other non-printable/control/grapheme-extending codepoint — see
/// `char::escape_debug`, which is what the derived `Debug` for `String` fields
/// uses under the hood). Fail-closed on anything else: an escape letter this
/// function does not specifically recognize returns `None` (the whole string
/// is rejected as unparseable) rather than being pushed through as a literal
/// character. That fallback-rejects-instead-of-guesses behavior is a
/// deliberate fix for a real bug this function used to have: an earlier
/// version's fallback arm stripped the backslash and kept the escape letter
/// itself (`other => out.push(other)`), which silently produced a WRONG
/// decoded value instead of failing — concretely, `"\u{7}"` (one BEL control
/// character) and `"u{7}"` (four literal ASCII characters) both decoded to
/// the same four-character string `u{7}`, a genuine identity collision
/// between two different `TaskKind::Plugin` values. With every escape form
/// `Debug` can actually emit now handled explicitly, this function's
/// "reject anything unrecognized" fallback is unreachable for any real
/// `Debug`-formatted `String` field — it exists purely as the fail-closed
/// backstop for corrupted/hand-edited `tasks.kind` data, matching this
/// crate's established convention.
fn parse_debug_quoted_string(s: &str) -> Option<(String, &str)> {
    let s = s.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &s[i + 1..])),
            '\\' => {
                let (_, next) = chars.next()?;
                match next {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    '0' => out.push('\0'),
                    'u' => {
                        let (_, open_brace) = chars.next()?;
                        if open_brace != '{' {
                            return None;
                        }
                        let mut hex = String::new();
                        loop {
                            let (_, hc) = chars.next()?;
                            if hc == '}' {
                                break;
                            }
                            hex.push(hc);
                        }
                        let code = u32::from_str_radix(&hex, 16).ok()?;
                        let decoded = char::from_u32(code)?;
                        out.push(decoded);
                    }
                    // Fail closed: any other escape letter is not one Rust's
                    // Debug impl actually emits — reject rather than guess.
                    _ => return None,
                }
            }
            other => out.push(other),
        }
    }
    None // unterminated string literal
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix-round-1 regression test, matching the security auditor's exact
    /// reproduction shape: two DIFFERENT `TaskKind::Plugin` values — one whose
    /// `vendor` is a single real BEL control character (`\u{7}`, which Rust's
    /// `Debug` for `str` renders as the four-character escape sequence
    /// `\u{7}`), the other whose `vendor` is the literal four-character string
    /// `u{7}` — must parse to two DIFFERENT, correct results now, not collide.
    /// Before the fix, the old fallback (`other => out.push(other)`) stripped
    /// the backslash off `\u{7}` and pushed `u` through literally, so both
    /// inputs decoded to the same wrong string `u{7}`.
    #[test]
    fn plugin_vendor_with_real_control_char_and_literal_escape_text_do_not_collide() {
        let real_control_char = TaskKind::Plugin {
            vendor: "\u{7}".into(), // one real BEL character
            verb: "v".into(),
        };
        let literal_escape_text = TaskKind::Plugin {
            vendor: "u{7}".into(), // four literal ASCII characters
            verb: "v".into(),
        };

        // Confirm the premise: these are genuinely different TaskKind values,
        // and Rust's Debug format for them is genuinely different text too
        // (the whole bug was that two different Debug outputs decoded to the
        // same wrong TaskKind).
        assert_ne!(real_control_char, literal_escape_text);
        let real_debug = format!("{real_control_char:?}");
        let literal_debug = format!("{literal_escape_text:?}");
        assert_ne!(real_debug, literal_debug);

        let parsed_real = parse_task_kind(&real_debug);
        let parsed_literal = parse_task_kind(&literal_debug);

        assert_eq!(
            parsed_real,
            Some(real_control_char),
            "a real BEL control character in vendor must round-trip exactly"
        );
        assert_eq!(
            parsed_literal,
            Some(literal_escape_text),
            "the literal four-character text \"u{{7}}\" in vendor must round-trip exactly"
        );
        assert_ne!(
            parsed_real, parsed_literal,
            "two different Plugin values must never parse to the same result"
        );
    }

    /// `\0` (NUL) must decode to an actual NUL character, not be rejected or
    /// mangled.
    #[test]
    fn plugin_vendor_with_nul_round_trips() {
        let kind = TaskKind::Plugin {
            vendor: "a\0b".into(),
            verb: "v".into(),
        };
        let debug = format!("{kind:?}");
        assert_eq!(parse_task_kind(&debug), Some(kind));
    }

    /// A multi-byte non-ASCII `\u{...}` escape (not just a single-digit one)
    /// must also decode correctly — exercises the hex-digit accumulation loop
    /// with more than one digit.
    #[test]
    fn plugin_vendor_with_multi_digit_unicode_escape_round_trips() {
        let kind = TaskKind::Plugin {
            vendor: "\u{1F600}".into(), // an emoji: a real, multi-hex-digit codepoint
            verb: "v".into(),
        };
        let debug = format!("{kind:?}");
        assert_eq!(parse_task_kind(&debug), Some(kind));
    }

    /// A genuinely unrecognized escape sequence — one Rust's own `Debug` impl
    /// never actually emits — must be rejected (`None`), not silently mangled
    /// into some plausible-looking wrong value. Hand-constructed directly
    /// (rather than via a real `TaskKind`) since `Debug` itself won't produce
    /// this shape; this pins the fail-closed backstop for corrupted/hand-
    /// edited `tasks.kind` data.
    #[test]
    fn unrecognized_escape_sequence_is_rejected_not_mangled() {
        let corrupt = r#"Plugin { vendor: "\q", verb: "v" }"#;
        assert_eq!(
            parse_task_kind(corrupt),
            None,
            "an escape sequence Debug never emits must be rejected, not silently decoded"
        );
    }

    /// A malformed `\u{...}` escape (missing the closing brace) must also be
    /// rejected, not panic or hang.
    #[test]
    fn malformed_unicode_escape_is_rejected_not_panicking() {
        let corrupt = r#"Plugin { vendor: "\u{41", verb: "v" }"#;
        assert_eq!(parse_task_kind(corrupt), None);
    }

    /// Every flat unit variant must still parse correctly after the fix —
    /// pins the non-Plugin path, which the fix did not touch.
    #[test]
    fn unit_variants_round_trip() {
        for kind in [
            TaskKind::Chat,
            TaskKind::Infer,
            TaskKind::Shell,
            TaskKind::Read,
            TaskKind::Write,
            TaskKind::Edit,
            TaskKind::Find,
            TaskKind::Http,
            TaskKind::Web,
            TaskKind::Mcp,
            TaskKind::Git,
            TaskKind::Memory,
            TaskKind::Agent,
            TaskKind::Message,
            TaskKind::Compact,
            TaskKind::Checkpoint,
            TaskKind::Plan,
            TaskKind::Elicit,
            TaskKind::Flow,
            TaskKind::Report,
        ] {
            let debug = format!("{kind:?}");
            assert_eq!(parse_task_kind(&debug), Some(kind));
        }
    }
}
