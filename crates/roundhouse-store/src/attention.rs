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
//! no code has ever needed to parse it back until now; `parse_task_kind` is that
//! first real reader.

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
/// start of `s`, returning the unescaped value and the remaining tail. Handles
/// the escape sequences Rust's `Debug` impl for `str`/`String` actually emits
/// (`\"`, `\\`, `\n`, `\r`, `\t`) — sufficient for `vendor`/`verb` values, which
/// are plugin-supplied identifiers, not arbitrary binary data.
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
                    other => out.push(other),
                }
            }
            other => out.push(other),
        }
    }
    None // unterminated string literal
}
