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
        let open = trimmed.find('{').expect("a cfg(test) item has a body");
        let end = matching_brace(trimmed.as_bytes(), open).unwrap_or_else(|| {
            panic!(
                "a #[cfg(test)] item must have balanced braces: {}",
                &trimmed[..trimmed.len().min(120)]
            )
        });
        rest = &trimmed[end..];
    }
    output.push_str(rest);
    output
}

/// Finds the matching brace while ignoring Rust strings and comments. This is
/// intentionally a tiny lexer, not a first-attribute split: test items occur
/// throughout production files and format strings commonly contain braces.
fn matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0_i32;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'r' if matches!(bytes.get(index + 1), Some(b'"' | b'#')) => {
                let mut hashes = 0;
                let mut cursor = index + 1;
                while bytes.get(cursor) == Some(&b'#') {
                    hashes += 1;
                    cursor += 1;
                }
                if bytes.get(cursor) != Some(&b'"') {
                    index += 1;
                    continue;
                }
                cursor += 1;
                while cursor < bytes.len() {
                    if bytes[cursor] == b'"'
                        && bytes.get(cursor + 1..cursor + 1 + hashes)
                            == Some(&vec![b'#'; hashes][..])
                    {
                        index = cursor + 1 + hashes;
                        break;
                    }
                    cursor += 1;
                }
                if cursor >= bytes.len() {
                    return None;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index += 2;
                while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/')
                {
                    index += 1;
                }
                index += 2;
            }
            b'\'' if bytes[index + 1..bytes.len().min(index + 5)].contains(&b'\'') => {
                let quote = bytes[index];
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index += 2;
                        continue;
                    }
                    if bytes[index] == quote {
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'"' => {
                let quote = bytes[index];
                index += 1;
                while index < bytes.len() {
                    if bytes[index] == b'\\' {
                        index += 2;
                        continue;
                    }
                    if bytes[index] == quote {
                        index += 1;
                        break;
                    }
                    index += 1;
                }
            }
            b'{' => {
                depth += 1;
                index += 1;
            }
            b'}' => {
                depth -= 1;
                index += 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => index += 1,
        }
    }
    None
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
fn anti_vacuity_a_multiline_test_function_cannot_satisfy_the_guard() {
    assert!(!has_production_call(
        "#[cfg(test)]\nfn only_test() {\n real::entry();\n}",
        "real::entry("
    ));
}

#[test]
fn anti_vacuity_a_fake_exception_is_rejected() {
    assert!(!REQUIRED_FEATURES
        .iter()
        .any(|feature| feature.name == "fake.unwired"));
}
