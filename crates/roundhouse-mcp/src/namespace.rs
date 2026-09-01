use crate::wire::DiscoverResult;
use roundhouse_core::{Origin, Provenance, TaskId, Trust};
use roundhouse_policy::ServerId;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NamespacedToolDef {
    pub namespaced_name: String,
    pub server: ServerId,
    pub original_name: String,
    /// UNTRUSTED per §6.8 regardless of server reputation.
    pub description: String,
    pub description_provenance: Provenance,
    pub input_schema: serde_json::Value,
}

/// `Debug` is required by the brief's own collision test (`expect_err`
/// needs `Ok: Debug`).
#[derive(Debug)]
pub struct ToolNamespace {
    lookup: HashMap<String, (ServerId, String)>,
    tools: Vec<NamespacedToolDef>,
}

/// Sanitizes a server id into a namespace-prefix-safe token: lowercase
/// ASCII alnum and `-`/`_` only, everything else becomes `_`.
fn sanitize(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Most model-facing tool-name fields cap out around 64 chars across
/// providers; if `{server}__{tool}` would exceed that, truncate and append
/// an 8-hex-char blake3 suffix of the *original* namespaced name so
/// collisions after truncation are still astronomically unlikely.
const MAX_NAME_LEN: usize = 64;

fn build_namespaced_name(server: &str, tool: &str) -> String {
    let full = format!("{}__{}", sanitize(server), sanitize(tool));
    if full.len() <= MAX_NAME_LEN {
        return full;
    }
    let hash = blake3::hash(full.as_bytes());
    let suffix = &hash.to_hex()[..8];
    let keep = MAX_NAME_LEN - 1 - suffix.len();
    format!("{}_{}", &full[..keep], suffix)
}

/// finding 5: `sanitize()` lowercases server ids before building a
/// namespaced name, so two differently-cased server ids that sanitize to
/// the same prefix (`"GitHub"`/`"github"`) would otherwise silently
/// collide — the second `lookup.insert` would overwrite the first
/// server's entry with no error, leaving the model holding a tool name
/// that now dispatches to the wrong server. `ToolNamespace::build` detects
/// this and refuses instead of overwriting.
#[derive(Debug, Clone, thiserror::Error)]
#[error("namespace collision: '{namespaced_name}' would be claimed by both server '{first_server}' and server '{second_server}' after sanitization — rename one of the two servers in config")]
pub struct NamespaceCollisionError {
    pub namespaced_name: String,
    pub first_server: String,
    pub second_server: String,
}

impl ToolNamespace {
    pub fn build(
        discovered: &[(ServerId, TaskId, DiscoverResult)],
    ) -> Result<Self, NamespaceCollisionError> {
        let mut lookup: HashMap<String, (ServerId, String)> = HashMap::new();
        let mut tools = Vec::new();

        for (server, discovery_task, discovery) in discovered {
            for tool in &discovery.tools {
                let namespaced_name = build_namespaced_name(&server.0, &tool.name);
                if let Some((existing_server, _)) = lookup.get(&namespaced_name) {
                    if existing_server != server {
                        return Err(NamespaceCollisionError {
                            namespaced_name,
                            first_server: existing_server.0.clone(),
                            second_server: server.0.clone(),
                        });
                    }
                    // Same server re-registering the same namespaced name
                    // (e.g. a server listing a tool twice) is not a
                    // cross-server collision — harmless, same origin, fall
                    // through and overwrite.
                }
                lookup.insert(namespaced_name.clone(), (server.clone(), tool.name.clone()));
                tools.push(NamespacedToolDef {
                    namespaced_name,
                    server: server.clone(),
                    original_name: tool.name.clone(),
                    description: tool.description.clone(),
                    description_provenance: Provenance {
                        origin: Origin::System,
                        trust: Trust::Untrusted,
                        task: *discovery_task,
                    },
                    input_schema: tool.input_schema.clone(),
                });
            }
        }

        Ok(Self { lookup, tools })
    }

    pub fn resolve(&self, namespaced_name: &str) -> Option<(&ServerId, &str)> {
        self.lookup
            .get(namespaced_name)
            .map(|(s, t)| (s, t.as_str()))
    }

    pub fn tools(&self) -> &[NamespacedToolDef] {
        &self.tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::McpToolDef;

    fn tool_def(name: &str) -> McpToolDef {
        McpToolDef {
            name: name.into(),
            description: "<script>steal secrets</script>".into(),
            input_schema: serde_json::json!({}),
        }
    }

    #[test]
    fn same_tool_name_on_two_servers_does_not_collide() {
        let discovery_task = TaskId::new();
        let discovered = vec![
            (
                ServerId("github".into()),
                discovery_task,
                DiscoverResult {
                    protocol_version: "2026-07-28".into(),
                    tools: vec![tool_def("search")],
                },
            ),
            (
                ServerId("gitlab".into()),
                discovery_task,
                DiscoverResult {
                    protocol_version: "2026-07-28".into(),
                    tools: vec![tool_def("search")],
                },
            ),
        ];

        let ns = ToolNamespace::build(&discovered).unwrap();
        assert_eq!(ns.tools().len(), 2);

        let names: Vec<&str> = ns
            .tools()
            .iter()
            .map(|t| t.namespaced_name.as_str())
            .collect();
        assert_ne!(names[0], names[1]);

        let (server_a, tool_a) = ns.resolve(names[0]).unwrap();
        assert_eq!(tool_a, "search");
        assert!(server_a.0 == "github" || server_a.0 == "gitlab");
    }

    #[test]
    fn tool_descriptions_carry_untrusted_provenance() {
        let discovery_task = TaskId::new();
        let discovered = vec![(
            ServerId("github".into()),
            discovery_task,
            DiscoverResult {
                protocol_version: "2026-07-28".into(),
                tools: vec![tool_def("search")],
            },
        )];
        let ns = ToolNamespace::build(&discovered).unwrap();
        let def = &ns.tools()[0];
        assert!(matches!(def.description_provenance.trust, Trust::Untrusted));
        assert_eq!(def.description_provenance.task, discovery_task);
    }

    #[test]
    fn cross_case_server_ids_that_sanitize_to_the_same_prefix_are_rejected_not_overwritten() {
        // finding 5: "GitHub" and "github" both sanitize to "github" — the
        // resulting namespaced names collide even though the two configured
        // servers are distinct. Silently overwriting the first server's
        // lookup entry would misroute a model's tool call to the wrong
        // server; this must be a hard error instead.
        let discovery_task = TaskId::new();
        let discovered = vec![
            (
                ServerId("GitHub".into()),
                discovery_task,
                DiscoverResult {
                    protocol_version: "2026-07-28".into(),
                    tools: vec![tool_def("search")],
                },
            ),
            (
                ServerId("github".into()),
                discovery_task,
                DiscoverResult {
                    protocol_version: "2026-07-28".into(),
                    tools: vec![tool_def("search")],
                },
            ),
        ];

        let err = ToolNamespace::build(&discovered).expect_err(
            "differently-cased server ids sanitizing to the same prefix must be rejected",
        );
        assert_eq!(err.namespaced_name, "github__search");
    }
}
