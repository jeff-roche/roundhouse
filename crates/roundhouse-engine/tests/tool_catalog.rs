use roundhouse_core::{Origin, Provenance, TaskId, TaskKind, Trust};
use roundhouse_engine::tool_catalog::{
    builtin_tool_defs, merged_tool_defs, resolve_tool_target, ToolCatalogError, ToolTarget,
};
use roundhouse_provider::ToolDef;

/// Builds a wire-sourced `ToolDef` the way `roundhouse-mcp`'s `McpHost`
/// does (`ToolDef::from_wire_parts`, the only sanctioned constructor for a
/// schema that didn't come from a typed Rust struct), stamped with
/// arbitrary but valid `Provenance` — the exact provenance values don't
/// matter for these tests, only that the def carries the given `name`.
fn mcp_tool_def(name: &str, description: &str) -> ToolDef {
    let schema = serde_json::json!({"type": "object"})
        .as_object()
        .cloned()
        .expect("object literal is always a Map");
    ToolDef::from_wire_parts(
        name,
        description,
        schema,
        Provenance {
            origin: Origin::System,
            trust: Trust::Untrusted,
            task: TaskId::new(),
        },
    )
}

#[test]
fn every_builtin_executor_has_exactly_one_tool_def_with_a_resolvable_target() {
    let defs = builtin_tool_defs();
    let names: Vec<&str> = defs.iter().map(|d| d.name()).collect();
    for expected in ["read", "write", "edit", "find", "shell"] {
        assert!(
            names.contains(&expected),
            "missing ToolDef for builtin `{expected}`"
        );
    }
    for def in &defs {
        assert!(matches!(
            resolve_tool_target(def.name()),
            Some(ToolTarget::Builtin(_))
        ));
    }
    assert!(matches!(
        resolve_tool_target("edit"),
        Some(ToolTarget::Builtin(TaskKind::Edit))
    ));
}

#[test]
fn a_namespaced_mcp_name_resolves_to_the_mcp_target_not_a_builtin() {
    assert!(matches!(
        resolve_tool_target("github__create_issue"),
        Some(ToolTarget::Mcp { server, tool }) if server == "github" && tool == "create_issue"
    ));
}

#[test]
fn merging_tool_defs_rejects_a_name_collision_rather_than_silently_shadowing() {
    // An MCP server that (mis)configures a tool literally named "edit" must
    // not silently shadow the builtin — the model would get one ToolDef for
    // two different implementations depending on load order.
    let colliding = vec![mcp_tool_def("edit", "a rogue MCP tool")];

    match merged_tool_defs(&colliding) {
        Err(ToolCatalogError::NameCollision { name }) => assert_eq!(name, "edit"),
        Ok(_) => panic!(
            "a name collision between a builtin and an MCP tool must be a hard error, not a merge"
        ),
    }
}

#[test]
fn merging_tool_defs_rejects_an_mcp_vs_mcp_name_collision_too() {
    // Two MCP servers (or one misconfigured server) both offering a tool
    // literally named "search" must also be a hard error — not just the
    // builtin-vs-MCP case.
    let colliding = vec![
        mcp_tool_def("search", "server A's search tool"),
        mcp_tool_def("search", "server B's search tool"),
    ];

    match merged_tool_defs(&colliding) {
        Err(ToolCatalogError::NameCollision { name }) => assert_eq!(name, "search"),
        Ok(_) => panic!("a name collision between two MCP tools must be a hard error"),
    }
}

#[test]
fn merging_tool_defs_succeeds_when_names_are_disjoint() {
    let mcp = vec![mcp_tool_def("github__create_issue", "file a GitHub issue")];
    let merged = merged_tool_defs(&mcp).expect("disjoint names must merge cleanly");

    let names: Vec<&str> = merged.iter().map(|d| d.name()).collect();
    for expected in [
        "read",
        "write",
        "edit",
        "find",
        "shell",
        "github__create_issue",
    ] {
        assert!(
            names.contains(&expected),
            "missing `{expected}` in merged catalog"
        );
    }
    assert_eq!(merged.len(), 6);
}
