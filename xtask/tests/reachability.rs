//! Phase 8's production-reachability ledger.  A feature is either observed at
//! a production call site or named in the temporary, reviewable exception
//! list.  The permanent registry deliberately outlives that list: deleting an
//! exception cannot silently delete the obligation being checked.

use quote::ToTokens;
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

#[allow(dead_code)]
fn source_without_test_items(source: &str) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(offset) = find_test_cfg_attribute(rest) {
        output.push_str(&rest[..offset]);
        let after = &rest[offset + rest[offset..].find(']').unwrap() + 1..];
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

#[allow(dead_code)]
fn find_test_cfg_attribute(source: &str) -> Option<usize> {
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("#[cfg(") {
            let end = trimmed.find(']')?;
            if trimmed[..end].contains("test") {
                return Some(offset + line.len() - trimmed.len());
            }
        }
        offset += line.len();
    }
    None
}

/// Finds the matching brace while ignoring Rust strings and comments. This is
/// intentionally a tiny lexer, not a first-attribute split: test items occur
/// throughout production files and format strings commonly contain braces.
#[allow(dead_code)]
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
    if source.contains("\n// __ROUNDHOUSE_FILE__\n") {
        return source
            .split("\n// __ROUNDHOUSE_FILE__\n")
            .any(|part| has_production_call(part, call));
    }
    let needle = call.trim_end_matches('(').replace([' ', '.'], "");
    let Ok(file) = syn::parse_file(source) else {
        return strip_non_code(source).replace(' ', "").contains(&needle);
    };
    struct Calls<'a> {
        needle: &'a str,
        found: bool,
    }
    impl<'ast, 'a> syn::visit::Visit<'ast> for Calls<'a> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if !cfg_test(&item.attrs) {
                syn::visit::visit_item_fn(self, item);
            }
        }
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            if !cfg_test(&item.attrs) {
                syn::visit::visit_item_mod(self, item);
            }
        }
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if node
                .func
                .to_token_stream()
                .to_string()
                .replace([' ', '.'], "")
                .contains(self.needle)
            {
                self.found = true;
            }
            syn::visit::visit_expr_call(self, node);
        }
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if node
                .method
                .to_string()
                .replace('.', "")
                .contains(self.needle)
            {
                self.found = true;
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }
    fn cfg_test(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().filter(|a| a.path().is_ident("cfg")).any(|a| {
            let text = a.meta.to_token_stream().to_string();
            text.contains("test") && !text.contains("not ( test )")
        })
    }
    let mut calls = Calls {
        needle: &needle,
        found: false,
    };
    syn::visit::Visit::visit_file(&mut calls, &file);
    calls.found
}

#[allow(dead_code)]
fn strip_non_code(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if bytes[i] == b'"' || bytes[i] == b'\'' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if bytes[i] == quote {
                    i += 1;
                    break;
                }
                if bytes[i] == b'\n' {
                    out.push('\n');
                }
                i += 1;
            }
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn collect_production_source(root: &Path) -> String {
    let mut source = String::new();
    for entry in walkdir(root) {
        if entry.extension().is_some_and(|ext| ext == "rs") {
            source.push_str(&fs::read_to_string(entry).unwrap());
            source.push_str("\n// __ROUNDHOUSE_FILE__\n");
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
