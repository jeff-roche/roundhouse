//! The canonical, model-facing tool catalog: `ToolDef`s for the five
//! built-in executors plus MCP-discovered tools, and the name-based
//! registry that maps a `ContentBlock::ToolUse { name, .. }` the model
//! sends back to a dispatch target.
//!
//! This is upstream of the agent loop's dispatch step (Task 5): nothing in
//! the codebase built a `ToolDef` for `roundhouse-tools`' `read`/`write`/
//! `edit`/`find`/`shell` executors before this module existed, so a model
//! could never actually be offered the ability to call them. `ToolDef`'s
//! only sanctioned constructors are `roundhouse_provider::tool_def_from_schema`
//! (typed, repo-authored tools — S-TOOL-9, §12.7) and `ToolDef::from_wire_parts`
//! (untrusted wire-sourced schemas from an MCP server, stamped with
//! `Provenance`); builtins go through the former.

use roundhouse_core::TaskKind;
use roundhouse_provider::{tool_def_from_schema, ToolDef};

/// Where a resolved tool name dispatches to: one of the five built-in
/// executors (carrying the `TaskKind` that names it), or a specific tool on
/// a specific MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolTarget {
    Builtin(TaskKind),
    Mcp { server: String, tool: String },
}

/// Resolves a model-facing tool name to its dispatch target.
///
/// **Invariant that makes this unambiguous:** the five built-in names
/// (`"read"`, `"write"`, `"edit"`, `"find"`, `"shell"`) are bare literal
/// tokens with no `__` in them, while every MCP tool name is namespaced as
/// `"{server}__{tool}"` by `roundhouse_mcp::namespace::build_namespaced_name`
/// (`crates/roundhouse-mcp/src/namespace.rs`) before it ever reaches this
/// registry or a model. A builtin name therefore can never collide with an
/// MCP name by construction: the builtin set is closed and enumerated
/// below, so any input matching one of those five literals is a builtin,
/// and any other input containing `"__"` is presumptively MCP-shaped.
/// Anything matching neither shape (bare unknown name, or `"__"` absent)
/// resolves to `None` — an unresolvable tool name, which the caller must
/// treat as a dispatch error rather than guessing.
///
/// **The `(server, tool)` split below is a shape test, not authoritative
/// recovery of the original names.** It splits on the *first* `"__"`,
/// but `build_namespaced_name` does not guarantee that's the only `"__"`
/// in the string: a server id may itself sanitize to something containing
/// `__`, and a name that would exceed 64 chars is truncated and suffixed
/// with an 8-hex-char blake3 hash, which no longer round-trips to the
/// original tool name at all. A real caller that needs the actual
/// `(ServerId, original tool name)` pair for dispatch must resolve it
/// through `ToolNamespace::resolve`'s lookup table (built at discovery
/// time), not by re-parsing the namespaced string — this function only
/// tells the caller "this name is MCP-shaped, go look it up," it is not a
/// substitute for that lookup.
pub fn resolve_tool_target(name: &str) -> Option<ToolTarget> {
    match name {
        "read" => Some(ToolTarget::Builtin(TaskKind::Read)),
        "write" => Some(ToolTarget::Builtin(TaskKind::Write)),
        "edit" => Some(ToolTarget::Builtin(TaskKind::Edit)),
        "find" => Some(ToolTarget::Builtin(TaskKind::Find)),
        "shell" => Some(ToolTarget::Builtin(TaskKind::Shell)),
        other => other
            .split_once("__")
            .map(|(server, tool)| ToolTarget::Mcp {
                server: server.to_string(),
                tool: tool.to_string(),
            }),
    }
}

/// Typed parameter shape for the `read` builtin, mirroring
/// `read_file(path: &Path)` in `crates/roundhouse-tools/src/read.rs`.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct ReadParams {
    /// Path to the file to read.
    path: String,
}

/// Typed parameter shape for the `write` builtin, mirroring
/// `write_file(path: &Path, contents: &[u8])` in
/// `crates/roundhouse-tools/src/write.rs`. `contents` is modeled as a JSON
/// string (the model can only ever produce text arguments); the executor's
/// `&[u8]` is that string's UTF-8 bytes.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct WriteParams {
    /// Path to the file to write (created if absent, overwritten if present).
    path: String,
    /// The full file contents to write.
    contents: String,
}

/// Typed parameter shape for the `edit` builtin, mirroring
/// `edit_file(path: &Path, find: &str, replace: &str)` in
/// `crates/roundhouse-tools/src/edit.rs`.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct EditParams {
    /// Path to the file to edit.
    path: String,
    /// Exact text to find. Must occur exactly once in the file, or the
    /// edit is rejected (S-TOOL-3 fail-closed semantics).
    find: String,
    /// Text to replace the single match with.
    replace: String,
}

/// Typed parameter shape for the `find` builtin, mirroring
/// `find_files(root: &Path, pattern: &str)` in
/// `crates/roundhouse-tools/src/find.rs`.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct FindParams {
    /// Base directory the search is rooted at.
    root: String,
    /// Glob pattern relative to `root` (e.g. `"**/*.rs"`). Absolute
    /// patterns and `..` escapes outside `root` are rejected.
    pattern: String,
}

/// Typed parameter shape for the `shell` builtin, mirroring
/// `run_shell(program: &str, argv: &[String], cwd: &Path)` in
/// `crates/roundhouse-tools/src/shell/mod.rs`.
#[derive(schemars::JsonSchema)]
#[allow(dead_code)] // fields exist only to shape the schemars-derived JSON Schema
struct ShellParams {
    /// Program to execute directly (never through a shell interpreter).
    program: String,
    /// Arguments passed to `program`, as discrete argv entries.
    argv: Vec<String>,
    /// Working directory the program runs in.
    cwd: String,
}

/// Builds one `ToolDef` per built-in executor (`read`/`write`/`edit`/`find`/
/// `shell`), via `tool_def_from_schema` so each one's JSON Schema is
/// `schemars`-generated from a typed params struct above — never
/// hand-written JSON — matching the exact same S-TOOL-9 discipline the rest
/// of the codebase's typed tools follow. Each params struct's doc comment
/// cites the `roundhouse-tools` executor function it mirrors; if that
/// executor's signature ever changes, this is the other half that must
/// change with it.
pub fn builtin_tool_defs() -> Vec<ToolDef> {
    vec![
        tool_def_from_schema::<ReadParams>("read", "Read a file's contents by path."),
        tool_def_from_schema::<WriteParams>(
            "write",
            "Write (create or overwrite) a file's contents.",
        ),
        tool_def_from_schema::<EditParams>(
            "edit",
            "Replace one exact, unambiguous occurrence of text in a file. \
             Fails if the text occurs zero times or more than once.",
        ),
        tool_def_from_schema::<FindParams>(
            "find",
            "Glob-search for files rooted at a base directory.",
        ),
        tool_def_from_schema::<ShellParams>(
            "shell",
            "Run a program (via direct exec, never a shell interpreter) and capture its output.",
        ),
    ]
}

/// A model-facing tool name was claimed by more than one `ToolDef`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ToolCatalogError {
    /// `name` was offered by two or more sources — a builtin and an MCP
    /// server, or two MCP servers. A model cannot safely be offered two
    /// tools under one name (it would resolve to whichever definition
    /// happened to load last), so this is a hard error rather than a
    /// silent shadow.
    #[error(
        "tool name collision: `{name}` is claimed by more than one tool definition \
         (a builtin and/or an MCP-discovered tool) — refusing to offer an ambiguous \
         tool catalog to the model"
    )]
    NameCollision { name: String },
}

/// Merges the built-in catalog with MCP-discovered `ToolDef`s, rejecting any
/// name collision (builtin-vs-MCP or MCP-vs-MCP) as a hard error rather than
/// silently letting the later entry shadow the earlier one — an operator
/// misconfiguration (an MCP server declaring a tool literally named
/// `"edit"`, or two MCP servers whose namespacing collides) must fail
/// closed, not hand the model an ambiguous tool catalog.
pub fn merged_tool_defs(mcp: &[ToolDef]) -> Result<Vec<ToolDef>, ToolCatalogError> {
    let mut merged = builtin_tool_defs();
    let mut seen: std::collections::HashSet<String> =
        merged.iter().map(|d| d.name().to_string()).collect();

    for def in mcp {
        if !seen.insert(def.name().to_string()) {
            return Err(ToolCatalogError::NameCollision {
                name: def.name().to_string(),
            });
        }
        merged.push(def.clone());
    }

    Ok(merged)
}
