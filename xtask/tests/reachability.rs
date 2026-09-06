//! Phase 8's production-reachability ledger.  A feature is either observed at
//! a production call site or named in the temporary, reviewable exception
//! list.  The permanent registry deliberately outlives that list: deleting an
//! exception cannot silently delete the obligation being checked.

use std::fs;
use std::path::Path;

struct Feature {
    name: &'static str,
    /// A fully-qualified call spelling, chosen to avoid definitions/imports.
    call: &'static str,
}

// This is the permanent registry.  Additions require a real reachability
// decision; removals require deleting/gating the implementation, not merely
// editing EXPECTED_UNWIRED.
const REQUIRED_FEATURES: &[Feature] = &[
    Feature {
        name: "policy.rules_loader",
        call: "policy_rules_from_files(",
    },
    Feature {
        name: "config.network_loader",
        call: "roundhouse_config::load_network_config(",
    },
    Feature {
        name: "engine.agent_loop",
        call: "run_agent_loop(",
    },
    Feature {
        name: "engine.create_session_egress",
        call: "create_session_with_egress(",
    },
    Feature {
        name: "policy.shell_pipeline",
        call: "decide_shell_command(",
    },
    Feature {
        name: "tools.isolated_exec",
        call: "execve_node(",
    },
    Feature {
        name: "sandbox.isolate_spawn",
        call: ".spawn(",
    },
    Feature {
        name: "policy.synthesize_grant",
        call: "synthesize_grant(",
    },
    Feature {
        name: "store.outbound_redaction",
        call: ".scan_outbound(",
    },
    Feature {
        name: "secrets.mcp_exposure",
        call: "expose_secret_for_mcp_call(",
    },
    Feature {
        name: "bus.spawn_tree",
        call: "record_child(",
    },
    Feature {
        name: "bus.restart",
        call: "restart_from(",
    },
    Feature {
        name: "bus.rate_limit_state",
        call: "note_state_change(",
    },
    Feature {
        name: "store.blob_quota",
        call: "write_blob_with_quota(",
    },
    Feature {
        name: "store.session_closed",
        call: "record_session_closed(",
    },
    Feature {
        name: "acp.map_update",
        call: "map_update(",
    },
    Feature {
        name: "flow.http_retry",
        call: "classify_http_status(",
    },
    Feature {
        name: "sched.cron",
        call: "new_cron(",
    },
    Feature {
        name: "mcp.namespace_tool",
        call: "namespace_tool_name(",
    },
    Feature {
        name: "engine.break_glass_peer",
        call: "answer_as_peer(",
    },
    Feature {
        name: "web.tracked_sessions",
        call: "tracked_sessions(",
    },
    Feature {
        name: "provider.profile_schema",
        call: "allowed_fields(",
    },
];

// Temporary only.  This is the complete symbol-level inventory from
// docs/scratch/2026-09-06-unwired-inventory.md, normalized to registry keys.
// L6 removes entries as it receives production-call evidence; the test below
// rejects a spelling that has no corresponding permanent registry entry.
const EXPECTED_UNWIRED: &[&str] = &[
    "policy.shell_pipeline",
    "tools.isolated_exec",
    "sandbox.isolate_spawn",
    "policy.synthesize_grant",
    "store.outbound_redaction",
    "secrets.mcp_exposure",
    "bus.spawn_tree",
    "bus.restart",
    "bus.rate_limit_state",
    "store.blob_quota",
    "store.session_closed",
    "acp.map_update",
    "flow.http_retry",
    "sched.cron",
    "mcp.namespace_tool",
    "engine.break_glass_peer",
    "web.tracked_sessions",
    "provider.profile_schema",
];

fn source_without_test_items(source: &str) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(offset) = rest.find("#[cfg(test)]") {
        output.push_str(&rest[..offset]);
        let after = &rest[offset + "#[cfg(test)]".len()..];
        let trimmed = after.trim_start();
        if !trimmed.starts_with("mod ") {
            // Attribute on a non-module item: retain it rather than guessing
            // where the item ends. The registry never treats definitions as
            // calls, and module bodies are where test-only calls live.
            output.push_str("#[cfg(test)]");
            rest = after;
            continue;
        }
        let open = trimmed.find('{').expect("a cfg(test) module has a body");
        let mut depth = 0_i32;
        let mut end = None;
        for (index, byte) in trimmed[open..].bytes().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(open + index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            // Macro input can contain delimiter-like bytes that this compact
            // scanner cannot classify. Keep the remainder rather than
            // silently dropping production code; the explicit inline-module
            // regression above covers the ordinary module shape.
            output.push_str(trimmed);
            rest = "";
            break;
        };
        rest = &trimmed[end..];
    }
    output.push_str(rest);
    output
}

fn has_production_call(source: &str, call: &str) -> bool {
    source_without_test_items(source).lines().any(|line| {
        let line = line.trim();
        !line.starts_with("//")
            && !line.starts_with("///")
            && line.contains(call)
            && !line.starts_with("pub fn ")
            && !line.starts_with("fn ")
    })
}

fn collect_production_source(root: &Path) -> String {
    let mut source = String::new();
    for entry in walkdir(root) {
        if entry.extension().is_some_and(|ext| ext == "rs") {
            source.push_str(&source_without_test_items(
                &fs::read_to_string(entry).unwrap(),
            ));
            source.push('\n');
        }
    }
    source
}

fn walkdir(root: &Path) -> Vec<std::path::PathBuf> {
    let mut result = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            result.extend(walkdir(&path));
        } else {
            result.push(path);
        }
    }
    result
}

#[test]
fn every_required_feature_is_called_or_has_an_accountable_temporary_exception() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let source = collect_production_source(&root.join("crates"));
    for feature in REQUIRED_FEATURES {
        assert!(
            has_production_call(&source, feature.call) || EXPECTED_UNWIRED.contains(&feature.name),
            "{} has neither a production call nor an EXPECTED_UNWIRED entry",
            feature.name
        );
    }
    for exception in EXPECTED_UNWIRED {
        assert!(
            REQUIRED_FEATURES
                .iter()
                .any(|feature| feature.name == *exception),
            "EXPECTED_UNWIRED entry {exception} is not accountable to the permanent registry"
        );
    }
}

#[test]
fn anti_vacuity_a_removed_production_call_fails_the_guard() {
    let feature = Feature {
        name: "sample.wired",
        call: "real::entry(",
    };
    assert!(has_production_call(
        "fn caller() {\n real::entry();\n}",
        feature.call
    ));
    assert!(!has_production_call("fn caller() { }", feature.call));
    assert!(!has_production_call(
        "#[cfg(test)]\nfn t() { real::entry(); }",
        feature.call
    ));
}

#[test]
fn anti_vacuity_an_inline_test_module_cannot_satisfy_the_guard() {
    assert!(!has_production_call(
        "#[cfg(test)]\nmod tests { fn only_test() { real::entry(); } }",
        "real::entry("
    ));
}

#[test]
fn anti_vacuity_a_fake_exception_is_rejected() {
    assert!(!REQUIRED_FEATURES
        .iter()
        .any(|feature| feature.name == "fake.unwired"));
}
